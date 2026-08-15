#!/usr/bin/env python3
"""Evidence-first CVE correlation for CLVX.

The NVD 2.0 API is treated as the authoritative source for version/CPE
applicability.  CLVX deliberately separates an affected software version
from a confirmed remotely exploitable vulnerability.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import Any
from utils.exploitability import is_not_a_vulnerability, has_condition_language

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CPE_RE = re.compile(r'^cpe:2\.3:[aho]:[^:]+:[^:]+:[^:]+(?::[^:]*){7}$', re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = "CLVX/4.5.3 Exposure Assessment"




def _valid_cpe_name(cpe_name: str) -> bool:
    if not isinstance(cpe_name, str):
        return False
    cpe_name = cpe_name.strip()
    if '{' in cpe_name or '}' in cpe_name or not _CPE_RE.fullmatch(cpe_name):
        return False
    parts = cpe_name.split(':')
    if len(parts) != 13:
        return False
    # NVD requires concrete part/vendor/product/version for cpeName queries.
    return all(parts[i] not in ('', '*') for i in (2, 3, 4, 5))

def _request(url: str, timeout: int = 10) -> dict[str, Any]:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        vals = metrics.get(key) or []
        if vals:
            data = vals[0].get("cvssData", {}) or {}
            return {
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "attack_vector": data.get("attackVector"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "attack_requirements": data.get("attackRequirements"),
                "exploit_maturity": data.get("exploitMaturity"),
            }
    return {}


def _cpe_components(cpe: str) -> dict[str, str]:
    parts = cpe.split(":")
    if len(parts) >= 13 and parts[0] == "cpe" and parts[1] == "2.3":
        names = ("part", "vendor", "product", "version", "update", "edition", "language",
                 "sw_edition", "target_sw", "target_hw", "other")
        return {name: parts[idx] for idx, name in enumerate(names, start=2)}
    return {}


def _short_criteria(criteria: str) -> str:
    c = _cpe_components(criteria)
    if not c:
        return criteria
    return f"{c.get('vendor','*')}:{c.get('product','*')}:{c.get('version','*')}"


def _criteria_matches_target(criteria: str, target_cpe: str) -> bool:
    """Match stable CPE identity fields; NVD already performed version-range matching."""
    a = _cpe_components(criteria)
    b = _cpe_components(target_cpe)
    if not a or not b:
        return False
    for key in ("part", "vendor", "product", "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"):
        av, bv = a.get(key, "*"), b.get(key, "*")
        if av != "*" and bv != "*" and av.lower() != bv.lower():
            return False
    av, bv = a.get("version", "*"), b.get("version", "*")
    return av == "*" or bv == "*" or av.lower() == bv.lower()


def _walk_conditions(node: dict[str, Any], target_cpe: str, inherited_and: bool = False) -> tuple[bool, bool, list[str]]:
    """Return (target_match, conditional_dependency, requirements)."""
    operator = str(node.get("operator", "OR")).upper()
    negate = bool(node.get("negate"))
    current_and = inherited_and or operator == "AND"
    matched = False
    conditional = False
    requirements: list[str] = []
    target_candidates: list[dict[str, Any]] = []

    for cm in node.get("cpeMatch", []) or []:
        criteria = str(cm.get("criteria") or cm.get("cpe23Uri") or "")
        vulnerable = bool(cm.get("vulnerable"))
        if not criteria:
            continue
        if vulnerable and _criteria_matches_target(criteria, target_cpe):
            matched = True
            target_candidates.append(cm)
        if current_and and (not vulnerable or not _criteria_matches_target(criteria, target_cpe)):
            requirements.append(_short_criteria(criteria))

    if matched and (current_and or negate or requirements):
        conditional = True

    for child in node.get("children", []) or []:
        child_matched, child_cond, child_req = _walk_conditions(child, target_cpe, current_and)
        matched = matched or child_matched
        conditional = conditional or child_cond
        requirements.extend(child_req)

    return matched, conditional, list(dict.fromkeys(requirements))


def _configuration_assessment(item: dict[str, Any], target_cpe: str) -> tuple[bool, bool, list[str]]:
    raw_configs = item.get("cve", {}).get("configurations") or []
    configs = raw_configs if isinstance(raw_configs, list) else [raw_configs]
    any_match = False
    conditional = False
    requirements: list[str] = []
    for config in configs:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) or []:
            matched, cond, req = _walk_conditions(node, target_cpe)
            any_match = any_match or matched
            conditional = conditional or cond
            requirements.extend(req)
    return any_match, conditional, list(dict.fromkeys(requirements))


def _description_is_conditional(description: str) -> bool:
    return has_condition_language(description)


def _parse_cve(item: dict[str, Any], target_cpe: str) -> dict[str, Any] | None:
    cve = item.get("cve", {}) or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    status = str(cve.get("vulnStatus") or "").lower()
    if status in {"rejected", "reject"}:
        return None
    desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = _cvss(cve)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    config_match, conditional, requirements = _configuration_assessment(item, target_cpe)
    # The NVD cpeName filter itself is authoritative: if a CVE is returned for
    # an exact CPE query, NVD considers that CPE matched against an applicability
    # statement, including version ranges. We do not manufacture a match when
    # local configuration parsing cannot reproduce the same range semantics.
    nvd_match = True
    conditional = conditional or _description_is_conditional(desc)
    not_a_vulnerability = is_not_a_vulnerability(desc)
    vendor_context = any(
        token in desc.lower() for token in ("rhel ", "red hat enterprise", "debian ", "ubuntu ", "centos ")
    )
    return {
        "cve": cve_id,
        "description": desc,
        "score": cvss.get("score"),
        "severity": cvss.get("severity"),
        "vector": cvss.get("vector"),
        "attack_vector": cvss.get("attack_vector"),
        "privileges_required": cvss.get("privileges_required"),
        "user_interaction": cvss.get("user_interaction"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "references": refs[:10],
        "vendor_references": _vendor_references(refs),
        "source": "NVD",
        "nvd_cpe_match": nvd_match,
        "config_match": config_match,
        "conditional": conditional,
        "requirements": requirements,
        "vendor_context": vendor_context,
        "not_a_vulnerability": not_a_vulnerability,
    }


def _vendor_references(refs: list[str]) -> list[str]:
    official = []
    for ref in refs:
        host = urllib.parse.urlparse(ref).netloc.lower()
        if any(token in host for token in (
            "apache.org", "openssh.com", "openbsd.org", "proftpd.org", "nginx.org",
            "microsoft.com", "ubuntu.com", "debian.org", "redhat.com", "access.redhat.com",
            "oracle.com", "cloud.google.com", "docs.aws.amazon.com", "cloudflare.com",
        )):
            official.append(ref)
    return official[:5]


@lru_cache(maxsize=256)
def _search_nvd_cpe_cached(cpe_name: str, timeout: int, limit: int) -> tuple[str, str | None, tuple[dict[str, Any], ...]]:
    params = urllib.parse.urlencode([
        ("cpeName", cpe_name),
        ("isVulnerable", ""),
        ("resultsPerPage", min(max(int(limit), 1), 50)),
    ])
    url = f"{NVD_URL}?{params}"
    try:
        data = _request(url, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return "error", f"NVD HTTP {exc.code}", tuple()
    except Exception as exc:
        return "error", f"NVD request failed: {type(exc).__name__}: {exc}", tuple()
    out: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []) or []:
        parsed = _parse_cve(item, cpe_name)
        if parsed:
            out.append(parsed)
    uniq: dict[str, dict[str, Any]] = {row["cve"]: row for row in out}
    return "ok", None, tuple(uniq.values())


def search_nvd_cpe(cpe_name: str, timeout: int = 8, limit: int = 20) -> dict[str, Any]:
    if not _valid_cpe_name(cpe_name):
        return {"status": "error", "error": "Invalid CPE name; NVD query skipped.", "items": []}
    status, error, rows = _search_nvd_cpe_cached(cpe_name, timeout, limit)
    return {"status": status, "error": error, "items": _enrich_kev(list(rows))}


@lru_cache(maxsize=1)
def _kev_index() -> dict[str, dict[str, Any]]:
    try:
        data = _request(KEV_URL, timeout=8)
        return {x.get("cveID"): x for x in data.get("vulnerabilities", []) if x.get("cveID")}
    except Exception:
        return {}


def _enrich_kev(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kev = _kev_index()
    for row in rows:
        item = kev.get(row.get("cve"))
        row["kev"] = bool(item)
        if item:
            row["kev_date_added"] = item.get("dateAdded")
            row["kev_due_date"] = item.get("dueDate")
            row["kev_required_action"] = item.get("requiredAction")
            row["kev_ransomware"] = item.get("knownRansomwareCampaignUse")
    return rows


def classify_advisory(adv: dict[str, Any]) -> str:
    """Classify an NVD record conservatively.

    NOT_A_VULNERABILITY is reserved for authoritative records such as
    CVE-2016-5387 whose description explicitly says the identifier is not a
    vulnerability. VERSION_AFFECTED means only that the NVD considers the
    detected CPE/version vulnerable; it is not exploit confirmation.
    """
    if adv.get("not_a_vulnerability"):
        return "NOT_A_VULNERABILITY"
    if not adv.get("nvd_cpe_match"):
        return "ADVISORY"
    if adv.get("conditional"):
        return "CONDITIONAL"
    return "VERSION_AFFECTED"
