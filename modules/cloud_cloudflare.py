#!/usr/bin/env python3
# modules/cloud_cloudflare.py — Cloudflare bypass and real IP discovery for CLVX

import re
import socket
import json
import urllib.request
import urllib.parse
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.http_client import CLVXHTTPClient

CF_RANGES_V4 = [
    "173.245.48.", "103.21.244.", "103.22.200.", "103.31.4.",
    "141.101.64.", "108.162.192.", "190.93.240.", "188.114.96.",
    "197.234.240.", "198.41.128.", "162.158.", "104.16.",
    "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "131.0.72.",
]


def is_cloudflare_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in CF_RANGES_V4)


class CloudflareBypass(BaseModule):

    NAME        = "cloud/cloudflare"
    DESCRIPTION = "Discover real IP behind Cloudflare — DNS history, CT logs, email headers, Shodan, subdomains"
    REFERENCES  = [
        "https://github.com/christophetd/CloudFlair",
        "https://github.com/erbbysam/DNSGrep",
        "https://crt.sh",
    ]

    def _define_options(self):
        self._add_option("TARGET",      "",      True,  "Target domain (e.g. target.com)")
        self._add_option("SHODAN_KEY",  "",      False, "Shodan API key (optional but recommended)")
        self._add_option("TIMEOUT",     "10",    False, "Request timeout in seconds")
        self._add_option("VERIFY_IP",   "true",  False, "Verify each candidate IP by host header (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        domain     = self.get_option("TARGET").strip().lower()
        domain     = re.sub(r"https?://", "", domain).rstrip("/")
        shodan_key = self.get_option("SHODAN_KEY") or ""
        timeout    = int(self.get_option("TIMEOUT") or 10)
        verify     = self.get_option("VERIFY_IP").lower() == "true"

        client   = CLVXHTTPClient(timeout=timeout, delay=0.5)
        findings = []
        candidates = {}

        print_section(f"Cloudflare Bypass — {domain}")

        print_status("Confirming Cloudflare presence...", "run")
        cf_active = self._confirm_cloudflare(domain, client)
        if cf_active:
            print_status(
                f"{Colors.YELLOW}Cloudflare detected{Colors.RESET} — starting real IP discovery", "waf"
            )
            findings.append(self._finding("INFO", "Cloudflare Detected", domain,
                                          "Target is behind Cloudflare CDN/WAF"))
        else:
            print_status("Cloudflare not detected — target may be directly accessible.", "info")
        print()

        print_status("Querying historical DNS records...", "run")
        candidates.update(self._dns_history(domain, timeout))

        print_status("Searching Certificate Transparency logs...", "run")
        candidates.update(self._crt_sh_lookup(domain, timeout))

        print_status("Checking DNS records for IP leaks (MX, SPF, TXT)...", "run")
        candidates.update(self._dns_record_leaks(domain))

        print_status("Testing subdomains that may bypass Cloudflare...", "run")
        candidates.update(self._subdomain_scan(domain, client))

        if shodan_key:
            print_status("Querying Shodan for origin IPs...", "run")
            candidates.update(self._shodan_search(domain, shodan_key, timeout))
        else:
            print_status("Shodan key not set — skipping (set SHODAN_KEY for better results)", "warn")

        print()
        print_status(f"Found {Colors.WHITE}{len(candidates)}{Colors.RESET} candidate IP(s):", "info")
        print()

        non_cf = {ip: src for ip, src in candidates.items()
                  if not is_cloudflare_ip(ip)}

        if not non_cf:
            print_status("All discovered IPs are Cloudflare ranges — no bypass found.", "warn")
        else:
            for ip, sources in non_cf.items():
                src_str = ", ".join(sources) if isinstance(sources, list) else sources
                print(f"  {Colors.GREEN}[CANDIDATE]{Colors.RESET} "
                      f"{Colors.BOLD}{Colors.WHITE}{ip:<20}{Colors.RESET} "
                      f"{Colors.DARK_GRAY}via: {src_str}{Colors.RESET}")

                verified = False
                if verify:
                    verified = self._verify_origin(ip, domain, client)
                    if verified:
                        print(f"    {Colors.BOLD}{Colors.RED}[VERIFIED]{Colors.RESET} "
                              f"Host header confirmed — this is the origin server!")
                        findings.append(self._finding(
                            "CRITICAL", "Real IP Found (Verified)",
                            ip, f"Origin IP confirmed via Host header | Sources: {src_str}"
                        ))
                    else:
                        findings.append(self._finding(
                            "HIGH", "Real IP Candidate (Unverified)",
                            ip, f"Sources: {src_str}"
                        ))
                else:
                    findings.append(self._finding(
                        "HIGH", "Real IP Candidate",
                        ip, f"Sources: {src_str}"
                    ))

        print()
        print_status(
            f"Cloudflare bypass complete. "
            f"{Colors.WHITE}{len([f for f in findings if f['severity'] in ('CRITICAL','HIGH')])}"
            f"{Colors.RESET} real IP candidate(s) found.",
            "ok"
        )
        return findings

    def _confirm_cloudflare(self, domain: str, client: CLVXHTTPClient) -> bool:
        try:
            ip = socket.gethostbyname(domain)
            if is_cloudflare_ip(ip):
                return True
        except Exception:
            pass
        _, _, headers = client.get(f"https://{domain}", follow_redirects=False)
        lower = {k.lower(): v.lower() for k, v in headers.items()}
        return any(k in lower for k in ["cf-ray", "cf-cache-status"]) or \
               "cloudflare" in lower.get("server", "")

    def _dns_history(self, domain: str, timeout: int) -> dict:
        candidates = {}
        apis = [
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
        ]
        for api_url in apis:
            try:
                req  = urllib.request.Request(api_url,
                        headers={"User-Agent": "CLVX/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", body)
                for ip in ips:
                    if not is_cloudflare_ip(ip) and not ip.startswith(("127.", "10.", "192.168.", "172.")):
                        candidates.setdefault(ip, []).append("dns-history")
            except Exception:
                pass
        return candidates

    def _crt_sh_lookup(self, domain: str, timeout: int) -> dict:
        candidates = {}
        try:
            url  = f"https://crt.sh/?q=%.{domain}&output=json"
            req  = urllib.request.Request(url, headers={"User-Agent": "CLVX/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())

            subdomains = set()
            for entry in data:
                names = entry.get("name_value", "").split("\n")
                for n in names:
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        subdomains.add(n)

            print_status(
                f"Found {Colors.WHITE}{len(subdomains)}{Colors.RESET} subdomains via CT logs",
                "info"
            )
            for sub in list(subdomains)[:30]:
                try:
                    ip = socket.gethostbyname(sub)
                    if not is_cloudflare_ip(ip):
                        candidates.setdefault(ip, []).append(f"crt.sh:{sub}")
                        print(f"    {Colors.CYAN}• {sub}{Colors.RESET} → "
                              f"{Colors.GREEN}{ip}{Colors.RESET} (not CF)")
                except Exception:
                    pass
        except Exception:
            pass
        return candidates

    def _dns_record_leaks(self, domain: str) -> dict:
        candidates = {}
        import subprocess, shutil

        if not shutil.which("dig"):
            return candidates

        tld_part = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain

        for rtype in ["MX", "TXT", "NS", "SOA"]:
            try:
                out = subprocess.check_output(
                    ["dig", "+short", rtype, domain],
                    timeout=5, text=True, stderr=subprocess.DEVNULL
                )
                ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", out)
                hosts = re.findall(r"[\w.-]+\." + re.escape(tld_part), out)
                for ip in ips:
                    if not is_cloudflare_ip(ip) and not ip.startswith(("127.", "10.")):
                        candidates.setdefault(ip, []).append(f"DNS-{rtype}")
                        print(f"  {Colors.YELLOW}[DNS {rtype}]{Colors.RESET} "
                              f"IP leak: {Colors.WHITE}{ip}{Colors.RESET}")
                for host in hosts:
                    try:
                        ip = socket.gethostbyname(host)
                        if not is_cloudflare_ip(ip):
                            candidates.setdefault(ip, []).append(f"DNS-{rtype}:{host}")
                    except Exception:
                        pass
            except Exception:
                pass
        return candidates

    def _subdomain_scan(self, domain: str, client: CLVXHTTPClient) -> dict:
        candidates = {}
        bypass_subs = [
            "direct", "origin", "direct-connect", "cpanel", "webmail",
            "ftp", "smtp", "mail", "email", "blog", "dev", "staging",
            "test", "api", "backend", "admin", "vpn", "ssh", "sftp",
        ]
        for sub in bypass_subs:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                if not is_cloudflare_ip(ip):
                    candidates.setdefault(ip, []).append(f"subdomain:{fqdn}")
                    print(f"  {Colors.GREEN}[NON-CF]{Colors.RESET} "
                          f"{Colors.WHITE}{fqdn}{Colors.RESET} → {Colors.GREEN}{ip}{Colors.RESET}")
                else:
                    print(f"  {Colors.DARK_GRAY}[CF]{Colors.RESET} "
                          f"{fqdn} → {ip}")
            except Exception:
                pass
        return candidates

    def _shodan_search(self, domain: str, api_key: str, timeout: int) -> dict:
        candidates = {}
        try:
            query   = urllib.parse.quote(f'hostname:"{domain}"')
            url     = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&facets=ip"
            req     = urllib.request.Request(url, headers={"User-Agent": "CLVX/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())

            matches = data.get("matches", [])
            print_status(
                f"Shodan returned {Colors.WHITE}{len(matches)}{Colors.RESET} result(s)", "info"
            )
            for match in matches:
                ip = match.get("ip_str", "")
                if ip and not is_cloudflare_ip(ip):
                    port    = match.get("port", "?")
                    product = match.get("product", "")
                    candidates.setdefault(ip, []).append(f"shodan:{port}")
                    print(f"  {Colors.RED}[SHODAN]{Colors.RESET} "
                          f"{Colors.WHITE}{ip}:{port}{Colors.RESET} "
                          f"{Colors.DARK_GRAY}{product}{Colors.RESET}")
        except Exception as e:
            print_status(f"Shodan query failed: {e}", "warn")
        return candidates

    def _verify_origin(self, ip: str, domain: str,
                       client: CLVXHTTPClient) -> bool:
        for scheme in ("https", "http"):
            url  = f"{scheme}://{ip}/"
            code, body, _ = client.get(
                url,
                headers={"Host": domain},
                follow_redirects=False
            )
            if code in (200, 301, 302, 403):
                return True
        return False
