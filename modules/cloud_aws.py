#!/usr/bin/env python3
"""AWS public exposure assessment."""
from __future__ import annotations

import json
import shutil
import subprocess
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.http_client import CLVXHTTPClient

class AWSRecon(BaseModule):
    NAME = "cloud/aws"
    DESCRIPTION = "AWS CloudFront / ELB / API Gateway fingerprinting and authenticated security-group review"
    REFERENCES = [
        "https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html",
        "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html",
        "https://docs.aws.amazon.com/vpc/latest/userguide/security-groups.html",
    ]

    def _define_options(self):
        self._add_option("TARGET", "", True, "Target domain or URL")
        self._add_option("PROFILE", "", False, "AWS CLI profile")
        self._add_option("CVES", "true", False, "Correlate identified products with NVD advisories")
        self._add_option("TIMEOUT", "8", False, "HTTP timeout in seconds")

    def run(self) -> list:
        if not self._validate():
            return []
        target = self.get_option("TARGET").strip()
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        client = CLVXHTTPClient(timeout=int(self.get_option("TIMEOUT") or 8))
        findings = []
        print_section(f"AWS Exposure — {target}")
        code, body, headers = client.get(url, follow_redirects=False)
        if code:
            lh = {k.lower(): str(v) for k,v in headers.items()}
            if any(k.startswith("x-amz-cf-") for k in lh):
                print(f"  {Colors.CYAN}[OBSERVED]{Colors.RESET} AWS CloudFront indicators detected")
                findings.append(self._finding("INFO", "AWS CloudFront observed", target, ", ".join(k for k in lh if k.startswith("x-amz-cf-"))))
                findings[-1]["confidence"] = "HIGH"
            elif "awselb" in lh.get("server", "").lower() or "awselb" in " ".join(lh.values()).lower():
                findings.append(self._finding("INFO", "AWS load balancer indicator", target, "AWS ELB-style response indicator observed."))
                findings[-1]["confidence"] = "MEDIUM"
            else:
                print_status("No strong AWS HTTP fingerprint observed.", "info")

        aws = shutil.which("aws")
        if aws:
            args = [aws, "ec2", "describe-security-groups", "--output", "json"]
            profile = self.get_option("PROFILE").strip()
            if profile:
                args += ["--profile", profile]
            try:
                data = json.loads(subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, timeout=25))
                for sg in data.get("SecurityGroups", []):
                    for perm in sg.get("IpPermissions", []):
                        ports = self._ports(perm)
                        ranges = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                        ranges += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                        if "0.0.0.0/0" in ranges or "::/0" in ranges:
                            sev = "HIGH" if not ports or any(p in {"22", "3389", "3306", "5432", "6379", "9200"} for p in ports) else "MEDIUM"
                            findings.append(self._finding(sev, "AWS security group allows Internet source", sg.get("GroupId", "?"), f"Ports={','.join(ports) or 'all'}"))
            except Exception as exc:
                findings.append(self._finding("NOT_ASSESSED", "AWS security-group inventory", target, f"AWS CLI query failed: {exc}"))
        else:
            findings.append(self._finding("NOT_ASSESSED", "AWS security-group inventory", target, "aws CLI not installed; authenticated inventory not assessed."))

        return findings

    @staticmethod
    def _ports(perm):
        proto = perm.get("IpProtocol")
        if proto == "-1":
            return ["all"]
        fp = perm.get("FromPort")
        tp = perm.get("ToPort")
        if fp is None:
            return [proto or "unknown"]
        if fp == tp:
            return [str(fp)]
        return [f"{fp}-{tp}"]
