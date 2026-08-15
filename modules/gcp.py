#!/usr/bin/env python3
"""Google Cloud / Google Front End exposure assessment."""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.http_client import CLVXHTTPClient


class GCPRecon(BaseModule):
    NAME = "cloud/gcp"
    DESCRIPTION = "Google Cloud / Google Front End exposure assessment"
    REFERENCES = [
        "https://cloud.google.com/armor/docs/cloud-armor-overview",
        "https://cloud.google.com/vpc/docs/firewalls",
        "https://cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings",
    ]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target domain or URL")
        self._add_option("PROJECT", "", False, "GCP project ID for authenticated firewall review")
        self._add_option("TIMEOUT", "8", False, "HTTP timeout in seconds")
        self._add_option("CVES", "true", False, "Correlate identified products with NVD advisories")

    def run(self) -> list:
        if not self._validate():
            return []
        target = self.get_option("TARGET").strip()
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        timeout = int(self.get_option("TIMEOUT") or 8)
        client = CLVXHTTPClient(timeout=timeout)
        findings: list[dict] = []
        print_section(f"GCP Exposure — {target}")

        code, body, headers = client.get(url, follow_redirects=False)
        if code == 0:
            findings.append(self._finding("NOT_ASSESSED", "HTTP reachability", target, "Request could not be completed."))
        else:
            lh = {k.lower(): str(v) for k, v in headers.items()}
            evidence = []
            if "x-cloud-trace-context" in lh:
                evidence.append("x-cloud-trace-context")
            if any("google" in v.lower() for v in lh.values()):
                evidence.append("Google response header")
            if "x-goog-iap-generated-response" in lh:
                evidence.append("x-goog-iap-generated-response")
            if evidence:
                print(f"  {Colors.CYAN}[OBSERVED]{Colors.RESET} Google Cloud / Front End indicators: {', '.join(evidence)}")
                findings.append(self._finding("INFO", "Google Cloud Front End observed", target, "; ".join(evidence)))
                findings[-1]["confidence"] = "MEDIUM"
            else:
                print_status("No Google Cloud HTTP fingerprint observed.", "info")

            server = lh.get("server", "")
            if server:
                print(f"  {Colors.DARK_GRAY}Server:{Colors.RESET} {server}")


        project = self.get_option("PROJECT").strip()
        if project:
            findings.extend(self._project_firewalls(project))
        else:
            print_status("GCP project review not requested; public observation only.", "info")

        return findings

    def _project_firewalls(self, project: str) -> list[dict]:
        findings: list[dict] = []
        gcloud = shutil.which("gcloud")
        if not gcloud:
            findings.append(self._finding("NOT_ASSESSED", "GCP firewall inventory", project, "gcloud is not installed."))
            return findings
        cmd = [gcloud, "compute", "firewall-rules", "list", f"--project={project}", "--format=json"]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=20)
            rules = json.loads(out or "[]")
        except Exception as exc:
            findings.append(self._finding("NOT_ASSESSED", "GCP firewall inventory", project, f"gcloud query failed: {exc}"))
            return findings
        for rule in rules:
            allowed = rule.get("allowed", [])
            ranges = rule.get("sourceRanges", [])
            if "0.0.0.0/0" in ranges or "::/0" in ranges:
                ports = []
                for item in allowed:
                    ports.extend(item.get("ports", []))
                sev = "HIGH" if not ports or any(p in {"22", "3389", "3306", "5432", "6379", "9200"} for p in ports) else "MEDIUM"
                detail = f"Rule {rule.get('name','?')} allows Internet-wide source range(s); ports={','.join(ports) or 'all'}"
                findings.append(self._finding(sev, "GCP firewall rule exposed to Internet", project, detail))
        if not findings:
            findings.append(self._finding("INFO", "GCP firewall inventory", project, f"Reviewed {len(rules)} rule(s); no Internet-wide allow rule matched the current checks."))
        return findings
