#!/usr/bin/env python3
# modules/cloud_azure.py — Azure cloud reconnaissance for CLVX

import re
import socket
import json
import urllib.request
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.http_client import CLVXHTTPClient

AZURE_SUFFIXES = [
    ".azurewebsites.net", ".blob.core.windows.net", ".table.core.windows.net",
    ".queue.core.windows.net", ".file.core.windows.net", ".dfs.core.windows.net",
    ".azurecontainer.io", ".azurecr.io", ".azure-api.net", ".azurefd.net",
    ".trafficmanager.net", ".servicebus.windows.net", ".database.windows.net",
    ".documents.azure.com", ".search.windows.net", ".onmicrosoft.com",
    ".sharepoint.com", ".microsoftonline.com",
]

BLOB_CONTAINERS = [
    "public", "assets", "static", "media", "images", "files",
    "backup", "backups", "data", "uploads", "web", "logs",
    "documents", "docs", "content", "cdn", "store",
]

TENANT_ENDPOINTS = [
    "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
    "https://login.windows.net/{domain}/FederationMetadata/2007-06/FederationMetadata.xml",
    "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
]


class AzureRecon(BaseModule):

    NAME        = "cloud/azure"
    DESCRIPTION = "Azure cloud recon — blob storage enum, tenant discovery, subdomain mapping, service detection"
    REFERENCES  = [
        "https://github.com/NetSPI/MicroBurst",
        "https://docs.microsoft.com/en-us/azure/storage/blobs/",
        "https://github.com/dafthack/MSOLSpray",
    ]

    def _define_options(self):
        self._add_option("TARGET",    "",     True,  "Target domain or org name (e.g. contoso.com)")
        self._add_option("ENUM_BLOB", "true", False, "Enumerate Azure Blob Storage (true/false)")
        self._add_option("TENANT",    "true", False, "Discover Azure tenant info (true/false)")
        self._add_option("SUBDOMAINS","true", False, "Enumerate Azure subdomains (true/false)")
        self._add_option("TIMEOUT",   "8",    False, "Request timeout in seconds")
        self._add_option("THREADS",   "10",   False, "Parallel threads for enumeration")

    def run(self) -> list:
        if not self._validate():
            return []

        target    = self.get_option("TARGET").strip().lower()
        target    = re.sub(r"https?://", "", target).rstrip("/")
        org       = target.split(".")[0]
        enum_blob = self.get_option("ENUM_BLOB").lower() == "true"
        do_tenant = self.get_option("TENANT").lower()    == "true"
        do_subs   = self.get_option("SUBDOMAINS").lower()== "true"
        timeout   = int(self.get_option("TIMEOUT") or 8)
        threads   = int(self.get_option("THREADS") or 10)

        client   = CLVXHTTPClient(timeout=timeout, delay=0.2)
        findings = []

        print_section(f"Azure Cloud Recon — {target}")

        if do_tenant:
            print_status("Discovering Azure tenant information...", "run")
            findings += self._discover_tenant(target, org, client, timeout)
            print()

        if enum_blob:
            print_status("Enumerating Azure Blob Storage accounts...", "run")
            findings += self._enum_blob_storage(org, client, threads)
            print()

        if do_subs:
            print_status("Enumerating Azure-specific subdomains...", "run")
            findings += self._enum_azure_subdomains(org, target, client)
            print()

        print_status("Detecting Azure services from response headers...", "run")
        findings += self._detect_azure_services(f"https://{target}", client)

        print()
        print_status(
            f"Azure recon complete. {Colors.WHITE}{len(findings)}{Colors.RESET} finding(s).", "ok"
        )
        return findings

    def _discover_tenant(self, domain: str, org: str,
                         client: CLVXHTTPClient, timeout: int) -> list:
        findings = []
        for ep_template in TENANT_ENDPOINTS:
            url = ep_template.replace("{domain}", domain)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CLVX/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
                    tenant_id = data.get("token_endpoint", "").split("/")[3]
                    issuer    = data.get("issuer", "")
                    if tenant_id:
                        print(f"  {Colors.CYAN}[TENANT]{Colors.RESET} "
                              f"ID: {Colors.BOLD}{Colors.WHITE}{tenant_id}{Colors.RESET}")
                        print(f"  {Colors.DARK_GRAY}Issuer   {Colors.RESET}: {issuer}")
                        findings.append(self._finding(
                            "INFO", "Azure Tenant Discovered",
                            domain, f"Tenant ID: {tenant_id} | Issuer: {issuer}"
                        ))
                        break
            except Exception:
                pass

        if not findings:
            print_status("Could not discover tenant info for this domain.", "warn")
        return findings

    def _enum_blob_storage(self, org: str, client: CLVXHTTPClient,
                           threads: int) -> list:
        findings = []
        names = [
            org, f"{org}storage", f"{org}store", f"{org}backup",
            f"{org}data", f"{org}assets", f"{org}static", f"{org}web",
            f"{org}files", f"{org}media", f"{org}cdn", f"{org}logs",
            f"backup{org}", f"assets{org}", f"static{org}",
        ]

        import concurrent.futures

        def check_account(name: str):
            results = []
            base_url = f"https://{name}.blob.core.windows.net"
            code, body, headers = client.get(base_url, follow_redirects=False)
            if code in (200, 400, 403, 404, 409):
                sev = "INFO"
                print(f"  {Colors.CYAN}[EXISTS]{Colors.RESET} "
                      f"{Colors.WHITE}{name}.blob.core.windows.net{Colors.RESET} → HTTP {code}")
                results.append(self._finding(
                    sev, "Azure Storage Account Found",
                    base_url, f"Account '{name}' exists (HTTP {code})"
                ))
                for container in BLOB_CONTAINERS:
                    c_url  = f"{base_url}/{container}?restype=container&comp=list"
                    c_code, c_body, _ = client.get(c_url, follow_redirects=False)
                    if c_code == 200:
                        files = len(re.findall(r"<Name>([^<]+)</Name>", c_body))
                        print(f"    {Colors.RED}[OPEN]{Colors.RESET} "
                              f"Container '{Colors.WHITE}{container}{Colors.RESET}' "
                              f"— {Colors.GREEN}{files} file(s){Colors.RESET}")
                        results.append(self._finding(
                            "CRITICAL" if files > 0 else "HIGH",
                            f"Public Blob Container: {container}",
                            c_url,
                            f"Container publicly accessible — {files} object(s)"
                        ))
                    elif c_code == 403:
                        print(f"    {Colors.YELLOW}[DENY]{Colors.RESET} "
                              f"Container '{container}' exists but private (403)")
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for batch in ex.map(check_account, names):
                findings.extend(batch)

        exposed = [f for f in findings if "Public Blob" in f["check"]]
        if exposed:
            print_status(
                f"{Colors.RED}{len(exposed)}{Colors.RESET} public blob container(s) found!", "ok"
            )
        else:
            print_status("No public blob containers found.", "info")
        return findings

    def _enum_azure_subdomains(self, org: str, domain: str,
                                client: CLVXHTTPClient) -> list:
        findings = []
        targets  = []
        for suffix in AZURE_SUFFIXES:
            targets.append(f"{org}{suffix}")
            targets.append(f"{org}-{suffix.lstrip('.')}")

        for fqdn in targets:
            try:
                ip = socket.gethostbyname(fqdn)
                code, _, _ = client.get(f"https://{fqdn}", follow_redirects=False)
                sev = "HIGH" if code == 200 else "LOW"
                print(f"  {Colors.GREEN}[RESOLVE]{Colors.RESET} "
                      f"{Colors.WHITE}{fqdn:<55}{Colors.RESET} "
                      f"{Colors.DARK_GRAY}{ip}{Colors.RESET} → HTTP {code}")
                findings.append(self._finding(
                    sev, "Azure Subdomain Active",
                    fqdn, f"IP: {ip} | HTTP {code}"
                ))
            except socket.gaierror:
                if any(s in fqdn for s in [".azurewebsites.net", ".blob.core.windows.net"]):
                    print(f"  {Colors.YELLOW}[NXDOMAIN]{Colors.RESET} "
                          f"{Colors.DARK_GRAY}{fqdn}{Colors.RESET} "
                          f"— {Colors.YELLOW}potential takeover candidate{Colors.RESET}")
                    findings.append(self._finding(
                        "MEDIUM", "Azure Subdomain Takeover Candidate",
                        fqdn,
                        "NXDOMAIN on Azure-owned subdomain — may be claimable"
                    ))
        return findings

    def _detect_azure_services(self, url: str, client: CLVXHTTPClient) -> list:
        findings = []
        code, _, headers = client.get(url, follow_redirects=False)
        lower = {k.lower(): v.lower() for k, v in headers.items()}

        azure_sigs = {
            "Azure Front Door":   ["x-azure-ref", "x-fd-healthprobe"],
            "Azure App Service":  ["x-aspnet-version", "x-powered-by-plesk"],
            "Azure CDN":          ["x-ec-custom-error", "x-cache-status"],
            "Azure API Mgmt":     ["ocp-apim-request-id", "ocp-apim-trace-id"],
        }

        for svc, sig_keys in azure_sigs.items():
            if any(k in lower for k in sig_keys):
                print(f"  {Colors.CYAN}[AZURE]{Colors.RESET} "
                      f"{Colors.WHITE}{svc}{Colors.RESET} detected via headers")
                findings.append(self._finding(
                    "INFO", f"Azure Service: {svc}", url, "Detected via response headers"
                ))

        if not findings:
            print_status("No Azure service headers detected.", "info")
        return findings
