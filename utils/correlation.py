#!/usr/bin/env python3
"""Asset-aware vulnerability correlation and conclusion engine."""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from utils.advisories import classify_advisory, search_nvd_cpe
from utils.exploitability import assess


def _asset_host(row: dict) -> str:
    target = str(row.get("target") or "")
    try:
        parsed = urlsplit(target if "://" in target else f"//{target}")
        return str(parsed.hostname or target).lower()
    except Exception:
        return target.lower()


def _asset_key(row: dict) -> tuple:
    host = _asset_host(row)
    port = row.get("port") or ""
    product = str(row.get("service") or row.get("product") or "").lower()
    version = str(row.get("version") or "").lower()
    return host, port, product, version


def _service_key(row: dict) -> tuple:
    product = str(row.get("service") or row.get("product") or "").lower()
    version = str(row.get("version") or "").lower()
    port = row.get("port") or ""
    return product, version, str(port)


def _priority(adv: dict, state: str, exploitability: str) -> str:
    if state == "NOT_A_VULNERABILITY":
        return "N/A"
    score = float(adv.get("score") or 0)
    sev = str(adv.get("severity") or "").upper()
    if adv.get("kev"):
        if exploitability in {"NETWORK_RELEVANT", "REMOTE_CONDITIONAL"}:
            return "URGENT"
        return "HIGH"
    if exploitability == "NETWORK_RELEVANT":
        if score >= 9.0 or sev == "CRITICAL":
            return "CRITICAL"
        if score >= 7.0 or sev == "HIGH":
            return "HIGH"
        if score >= 4.0 or sev == "MEDIUM":
            return "MEDIUM"
        return "LOW"
    if exploitability == "REMOTE_CONDITIONAL":
        return "HIGH" if score >= 9.0 else "MEDIUM" if score >= 4.0 else "LOW"
    if state == "VERSION_AFFECTED":
        return "REVIEW"
    if state == "CONDITIONAL":
        return "REVIEW"
    return "LOW"


def _conclusion_note(adv: dict, row: dict, state: str, exploit: dict) -> str:
    if exploit.get("record_kind") == "NOT_A_VULNERABILITY":
        return exploit.get("conclusion", "Authoritative record does not represent a vulnerability.")
    notes = []
    if state == "VERSION_AFFECTED":
        notes.append("NVD CPE/version match.")
    if adv.get("requirements"):
        notes.append("Additional conditions: " + ", ".join(adv["requirements"][:2]) + ".")
    if adv.get("vendor_context") or row.get("platform"):
        notes.append("Downstream package/backport status is not verifiable from a remote banner.")
    notes.append(exploit.get("conclusion", "Exploitation is not confirmed by CLVX."))
    return " ".join(notes)


def _choose_correlation_candidates(rows: list[dict]) -> list[dict]:
    """Prefer concrete exposed endpoints over duplicate server fingerprints."""
    by_service: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        cpe = row.get("cpe")
        product = row.get("service") or row.get("product")
        version = row.get("version")
        if not cpe or not product or not version or str(version).lower() == "unknown":
            continue
        by_service[_service_key(row)].append(row)

    chosen: list[dict] = []
    for _, items in by_service.items():
        endpoints = [r for r in items if r.get("role") == "service_endpoint" and r.get("module") == "exposure/portscan"]
        if endpoints:
            # Correlate the same product/version once per exposed endpoint.
            seen = set()
            for row in endpoints:
                key = _asset_key(row)
                if key not in seen:
                    chosen.append(row)
                    seen.add(key)
        else:
            # Fall back to a fingerprint only when no concrete endpoint exists.
            chosen.append(items[0])
    return chosen


def correlate_service_findings(rows: list[dict], timeout: int = 8, limit_per_service: int = 50) -> list[dict]:
    out = list(rows)
    candidates = _choose_correlation_candidates(rows)
    exposure_rows = [
        r for r in rows
        if r.get("module") == "exposure/portscan" and str(r.get("state", "")).upper() == "CONFIRMED"
    ]

    cache: dict[str, dict] = {}
    failures: list[dict] = []
    valid_queries = 0

    for row in candidates:
        cpe = row["cpe"]
        if cpe not in cache:
            cache[cpe] = search_nvd_cpe(cpe, timeout=timeout, limit=limit_per_service)
        result = cache[cpe]
        if result["status"] != "ok":
            failures.append({"row": row, "error": result["error"] or "NVD query failed"})
            continue
        valid_queries += 1

        for adv in result["items"]:
            state = classify_advisory(adv)
            exploit = assess(adv, row, exposure_rows=exposure_rows)
            if exploit.get("record_kind") == "NOT_A_VULNERABILITY":
                state = "NOT_A_VULNERABILITY"

            priority = _priority(adv, state, exploit.get("exploitability", "UNKNOWN"))
            severity = str(adv.get("severity") or "INFO").upper()
            detail = _conclusion_note(adv, row, state, exploit)
            out.append({
                "module": "engine/correlation",
                "state": state,
                "severity": severity,
                "priority": priority,
                "check": f"{adv.get('cve')} — {row.get('service')} {row.get('version')}",
                "target": row.get("target", ""),
                "detail": detail,
                "product": row.get("service"),
                "service": row.get("service"),
                "version": row.get("version"),
                "port": row.get("port"),
                "cpe": cpe,
                "confidence": "HIGH" if state in {"VERSION_AFFECTED", "NOT_A_VULNERABILITY"} else "MEDIUM",
                "role": row.get("role"),
                "package_context": row.get("platform") or "unknown",
                "advisory": adv,
                "exploitability": exploit.get("exploitability"),
                "surface_verified": exploit.get("surface_verified"),
                "conclusion_reason": exploit.get("conclusion"),
                "attack_requirements": exploit.get("attack_requirements"),
            })

    if failures:
        if valid_queries == 0:
            affected = ", ".join(sorted({str(f["row"].get("service") or "unknown") for f in failures}))
            out.append({
                "module": "engine/correlation",
                "state": "NOT_ASSESSED",
                "severity": "INFO",
                "check": "NVD vulnerability correlation unavailable",
                "target": _asset_host(failures[0]["row"]),
                "detail": f"No NVD query completed successfully for the identified service(s): {affected}.",
                "confidence": "HIGH",
                "source_errors": [f["error"] for f in failures],
            })
        else:
            out.append({
                "module": "engine/correlation",
                "state": "PARTIAL",
                "severity": "INFO",
                "check": "NVD vulnerability correlation partial",
                "target": _asset_host(failures[0]["row"]),
                "detail": f"NVD responded for {valid_queries} service query(s), but {len(failures)} query(s) failed. Failed services are not treated as clean.",
                "confidence": "HIGH",
                "source_errors": [f["error"] for f in failures],
            })
    return out


def deduplicate_findings(rows: list[dict]) -> list[dict]:
    unique: list[dict] = []
    seen: set[tuple] = set()
    for row in rows:
        advisory = row.get("advisory") or {}
        if advisory.get("cve"):
            # CVE + logical service/version + canonical asset avoids repeating the
            # same advisory through hostname and IP fingerprints.
            key = (advisory.get("cve"), _service_key(row), _asset_key(row)[:2])
        elif row.get("module") == "exposure/portscan":
            key = (row.get("state"), row.get("module"), _asset_key(row), row.get("check"))
        else:
            key = (row.get("state"), row.get("check"), row.get("target"), row.get("detail"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return unique


def summary(rows: list[dict]) -> dict[str, int]:
    counts = defaultdict(int)
    for row in rows:
        counts[str(row.get("state", "OBSERVED")).upper()] += 1
    return dict(counts)
