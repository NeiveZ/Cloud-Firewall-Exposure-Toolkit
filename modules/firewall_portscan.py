#!/usr/bin/env python3
# modules/firewall_portscan.py — Evasive port scanning for CLVX (no Nmap dependency)

import socket
import struct
import time
import concurrent.futures
import random
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

COMMON_PORTS = {
    21: "FTP",       22: "SSH",       23: "Telnet",    25: "SMTP",
    53: "DNS",       80: "HTTP",      110: "POP3",     143: "IMAP",
    443: "HTTPS",    445: "SMB",      993: "IMAPS",    995: "POP3S",
    1433: "MSSQL",   1521: "Oracle",  3306: "MySQL",   3389: "RDP",
    5432: "Postgres",5900: "VNC",     6379: "Redis",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt",8888: "Jupyter",27017: "MongoDB",9200: "Elastic",
}

TIMING_PROFILES = {
    "paranoid":  {"delay": 5.0,  "timeout": 10, "desc": "5s delay — IDS evasion max"},
    "sneaky":    {"delay": 1.5,  "timeout": 5,  "desc": "1.5s delay — slow scan"},
    "polite":    {"delay": 0.4,  "timeout": 3,  "desc": "0.4s delay — moderate"},
    "normal":    {"delay": 0.1,  "timeout": 2,  "desc": "0.1s delay — default"},
    "aggressive":{"delay": 0.0,  "timeout": 1,  "desc": "No delay — fast"},
}


class FirewallPortScan(BaseModule):

    NAME        = "firewall/portscan"
    DESCRIPTION = "Evasive TCP port scanner — timing control, source port manipulation, banner grabbing, ACK probe"
    REFERENCES  = [
        "https://nmap.org/book/man-bypass-firewalls-ids.html",
        "https://attack.mitre.org/techniques/T1046/",
    ]

    def _define_options(self):
        self._add_option("TARGET",       "",         True,  "Target IP or hostname")
        self._add_option("PORTS",        "top100",   False, "Ports: top100 | all | 22,80,443 | 1-1024")
        self._add_option("TIMING",       "normal",   False, "Timing: paranoid | sneaky | polite | normal | aggressive")
        self._add_option("THREADS",      "50",       False, "Concurrent connections")
        self._add_option("SOURCE_PORT",  "0",        False, "Source port (0=random, 53=DNS bypass, 80=HTTP bypass)")
        self._add_option("BANNER",       "true",     False, "Grab service banners (true/false)")
        self._add_option("ACK_PROBE",    "false",    False, "Send ACK probe to detect stateful firewall (true/false, needs root)")
        self._add_option("JITTER",       "0",        False, "Random jitter added to delay in ms (0=none)")
        self._add_option("RANDOMIZE",    "true",     False, "Randomize port scan order (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        target      = self.get_option("TARGET").strip()
        ports_spec  = self.get_option("PORTS") or "top100"
        timing_name = self.get_option("TIMING") or "normal"
        threads     = int(self.get_option("THREADS") or 50)
        src_port    = int(self.get_option("SOURCE_PORT") or 0)
        do_banner   = self.get_option("BANNER").lower() == "true"
        do_ack      = self.get_option("ACK_PROBE").lower() == "true"
        jitter_ms   = int(self.get_option("JITTER") or 0)
        randomize   = self.get_option("RANDOMIZE").lower() == "true"

        timing = TIMING_PROFILES.get(timing_name, TIMING_PROFILES["normal"])
        delay  = timing["delay"]
        to     = timing["timeout"]

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            print_status(f"Cannot resolve target: {e}", "error")
            return []

        ports = self._parse_ports(ports_spec)
        if randomize:
            random.shuffle(ports)

        print_section(f"Evasive Port Scan — {target} ({ip})")
        print_status(f"Ports    : {Colors.WHITE}{len(ports)}{Colors.RESET}", "info")
        print_status(f"Timing   : {Colors.WHITE}{timing_name}{Colors.RESET} "
                     f"{Colors.DARK_GRAY}({timing['desc']}){Colors.RESET}", "info")
        print_status(f"Threads  : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print_status(f"Src Port : {Colors.WHITE}{src_port if src_port else 'random'}{Colors.RESET}", "info")
        print_status(f"Jitter   : {Colors.WHITE}{jitter_ms}ms{Colors.RESET}", "info")
        print_status(f"Randomize: {Colors.WHITE}{randomize}{Colors.RESET}", "info")
        print()

        findings  = []
        open_ports = []
        total     = len(ports)
        completed = 0
        lock      = __import__("threading").Lock()

        def scan_port(port: int):
            nonlocal completed
            actual_delay = delay
            if jitter_ms > 0:
                actual_delay += random.randint(0, jitter_ms) / 1000
            if actual_delay > 0:
                time.sleep(actual_delay)

            result = self._tcp_connect(ip, port, to, src_port, do_banner)

            with lock:
                completed += 1
                print(f"  {Colors.DARK_GRAY}[{completed:>5}/{total}]{Colors.RESET} "
                      f"Scanning port {port:<6}...", end="\r")

            if result:
                with lock:
                    print(" " * 70 + "\r", end="")
                    svc    = COMMON_PORTS.get(port, "unknown")
                    banner = result.get("banner", "")
                    b_str  = f"  {Colors.DARK_GRAY}│ {banner[:50]}{Colors.RESET}" if banner else ""
                    print(f"  {Colors.BOLD}{Colors.GREEN}[OPEN]{Colors.RESET} "
                          f"{Colors.WHITE}{port:<6}{Colors.RESET}"
                          f"{Colors.CYAN}{svc:<14}{Colors.RESET}"
                          f"{b_str}")
                    open_ports.append(result)
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(scan_port, ports))

        print(" " * 70)
        print()

        if do_ack:
            findings += self._ack_probe(ip, [p["port"] for p in open_ports[:5]])

        for op in open_ports:
            findings.append(self._finding(
                "INFO",
                f"Open Port: {op['port']}/{COMMON_PORTS.get(op['port'],'?')}",
                f"{ip}:{op['port']}",
                op.get("banner", "")
            ))

        print_status(
            f"Scan complete. {Colors.GREEN}{len(open_ports)}{Colors.RESET} "
            f"open port(s) on {Colors.CYAN}{target}{Colors.RESET}.",
            "ok"
        )

        if open_ports:
            print()
            from utils.colors import print_table
            print_table(
                ["Port", "Service", "Banner"],
                [(p["port"], COMMON_PORTS.get(p["port"], "?"),
                  p.get("banner", "")[:50]) for p in open_ports]
            )

        return findings

    def _tcp_connect(self, ip: str, port: int, timeout: float,
                     src_port: int, grab_banner: bool):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if src_port > 0:
                try:
                    sock.bind(("", src_port))
                except Exception:
                    pass

            result = sock.connect_ex((ip, port))

            if result == 0:
                banner = ""
                if grab_banner:
                    try:
                        sock.settimeout(1.5)
                        if port in (80, 8080, 8000, 8008):
                            sock.send(b"HEAD / HTTP/1.0\r\nHost: " +
                                      ip.encode() + b"\r\n\r\n")
                        else:
                            sock.send(b"\r\n")
                        raw    = sock.recv(256)
                        banner = raw.decode("utf-8", errors="replace").strip().split("\n")[0]
                    except Exception:
                        pass
                sock.close()
                return {"port": port, "banner": banner}

            sock.close()
        except Exception:
            pass
        return None

    def _ack_probe(self, ip: str, ports: list) -> list:
        """Send TCP ACK packets to detect stateful vs stateless firewall.
        Requires root/CAP_NET_RAW. Falls back gracefully."""
        findings = []
        print_status("ACK probe to detect firewall type...", "run")

        try:
            import os
            if os.geteuid() != 0:
                print_status("ACK probe requires root — skipping.", "warn")
                return findings

            for port in ports[:3]:
                raw = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_TCP)
                raw.settimeout(2)
                tcp_header = self._build_tcp_ack(ip, port)
                raw.sendto(tcp_header, (ip, 0))
                try:
                    data, _ = raw.recvfrom(1024)
                    if data:
                        print(f"  {Colors.GREEN}[UNFILTERED]{Colors.RESET} "
                              f"Port {port} — RST received (stateless/no firewall)")
                        findings.append(self._finding(
                            "INFO", "ACK Probe: Unfiltered",
                            f"{ip}:{port}", "RST received — port likely unfiltered"
                        ))
                except socket.timeout:
                    print(f"  {Colors.YELLOW}[FILTERED]{Colors.RESET} "
                          f"Port {port} — no response (stateful firewall)")
                    findings.append(self._finding(
                        "INFO", "ACK Probe: Filtered",
                        f"{ip}:{port}", "No RST — stateful firewall likely blocking"
                    ))
                raw.close()

        except Exception as e:
            print_status(f"ACK probe failed: {e}", "warn")

        return findings

    def _build_tcp_ack(self, dst_ip: str, dst_port: int) -> bytes:
        """Build a raw TCP ACK packet (checksum left at 0 — see README caveat)."""
        src_port = random.randint(1024, 65535)
        seq      = random.randint(0, 2**32 - 1)
        ack_seq  = 0
        doff     = 5
        flags    = 0x10
        window   = socket.htons(5840)
        checksum = 0
        urg_ptr  = 0
        offset   = (doff << 4) | 0

        tcp_header = struct.pack("!HHLLBBHHH",
            src_port, dst_port, seq, ack_seq,
            offset, flags, window, checksum, urg_ptr
        )
        return tcp_header

    def _parse_ports(self, spec: str) -> list:
        spec = spec.strip().lower()
        if spec == "top100":
            return list(COMMON_PORTS.keys()) + [
                20, 69, 79, 88, 111, 119, 135, 137, 139, 161,
                389, 500, 514, 587, 636, 993, 995, 1080, 1194,
                1723, 2049, 2222, 3000, 4444, 5000, 8000, 8001,
                8008, 8081, 9000, 9090, 9300, 10000, 50000,
            ]
        if spec == "all":
            return list(range(1, 65536))
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                try:
                    ports.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return sorted(set(ports))
