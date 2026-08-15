#!/usr/bin/env python3
"""Conservative service identification helpers used after an open TCP port is found."""
from __future__ import annotations
import re, socket, ssl

COMMON = {21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',111:'rpcbind',135:'msrpc',139:'netbios-ssn',143:'imap',443:'https',445:'smb',465:'smtps',587:'smtp',993:'imaps',995:'pop3s',1433:'mssql',1521:'oracle',3306:'mysql',3389:'rdp',5432:'postgresql',5900:'vnc',6379:'redis',8080:'http-alt',8443:'https-alt',8888:'http-alt',9200:'elasticsearch',27017:'mongodb'}

VERSION_PATTERNS = [
 (re.compile(r'OpenSSH[_/ ]([0-9][\w.]*)', re.I),'openssh'),
 (re.compile(r'(vsftpd)[/ ]([0-9][\w.]*)', re.I),'vsftpd'),
 (re.compile(r'(ProFTPD)[/ ]([0-9][\w.]*)', re.I),'proftpd'),
 (re.compile(r'(Postfix)[/ ]([0-9][\w.]*)', re.I),'postfix'),
 (re.compile(r'(Exim)[/ ]([0-9][\w.]*)', re.I),'exim'),
 (re.compile(r'(nginx)[/ ]([0-9][\w.]*)', re.I),'nginx'),
 (re.compile(r'(Apache)[/ ]([0-9][\w.]*)', re.I),'apache http server'),
 (re.compile(r'(Microsoft-IIS)[/ ]([0-9][\w.]*)', re.I),'microsoft iis'),
 (re.compile(r'(Redis)[/ ]([0-9][\w.]*)', re.I),'redis'),
 (re.compile(r'(MongoDB)[/ ]([0-9][\w.]*)', re.I),'mongodb'),
 (re.compile(r'(ELASTICSEARCH)[/ ]([0-9][\w.]*)', re.I),'elasticsearch'),
]

CPE_MAP = {
    'proftpd': 'cpe:2.3:a:proftpd:proftpd:{v}:*:*:*:*:*:*:*',
    'vsftpd': 'cpe:2.3:a:vsftpd:vsftpd:{v}:*:*:*:*:*:*:*',
    'openssh': 'cpe:2.3:a:openbsd:openssh:{v}:*:*:*:*:*:*:*',
    'apache http server': 'cpe:2.3:a:apache:http_server:{v}:*:*:*:*:*:*:*',
    'nginx': 'cpe:2.3:a:nginx:nginx:{v}:*:*:*:*:*:*:*',
    'redis': 'cpe:2.3:a:redis:redis:{v}:*:*:*:*:*:*:*',
    'mongodb': 'cpe:2.3:a:mongodb:mongodb:{v}:*:*:*:*:*:*:*',
    'elasticsearch': 'cpe:2.3:a:elastic:elasticsearch:{v}:*:*:*:*:*:*:*',
    'microsoft iis': 'cpe:2.3:a:microsoft:iis:{v}:*:*:*:*:*:*:*',
}

PLATFORMS = ('debian', 'ubuntu', 'red hat', 'rhel', 'centos', 'rocky', 'alma', 'fedora', 'suse')
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8443, 8888, 443}


_SAFE_CPE_VERSION = re.compile(r'^[A-Za-z0-9._+~-]+$')

def cpe_for_service(service: str, version: str | None) -> str | None:
    if not version or not service or str(version).lower() == 'unknown':
        return None
    version = str(version).strip()
    if not _SAFE_CPE_VERSION.fullmatch(version):
        return None
    template = CPE_MAP.get(service.lower())
    if not template:
        return None
    cpe = template.format(v=version)
    parts = cpe.split(':')
    if len(parts) != 13 or '{' in cpe or '}' in cpe:
        return None
    if parts[0] != 'cpe' or parts[1] != '2.3' or any(not parts[i] or parts[i] == '*' for i in (2, 3, 4)):
        return None
    return cpe


def _extract_version(match: re.Match[str]) -> str | None:
    groups = match.groups()
    if not groups:
        return None
    # Patterns with a product + version capture return the final capture;
    # legacy single-capture patterns return that capture directly.
    return groups[-1]


def _platform_hint(text: str) -> str | None:
    low = text.lower()
    for token in PLATFORMS:
        if token in low:
            return token
    return None


def probe(ip: str, port: int, timeout: float = 2.5, host: str | None = None) -> dict:
    out = {
        'service': COMMON.get(port, 'unknown'), 'version': None, 'banner': '', 'tls': None,
        'evidence': [], 'confidence': 'LOW', 'platform': None, 'role': 'service_endpoint'
    }
    raw = b''
    request_host = host or ip
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if port in HTTP_PORTS:
                if port in {443, 8443}:
                    # The explicit TLS probe below handles SNI/certificate evidence.
                    pass
                else:
                    s.sendall((f"HEAD / HTTP/1.0\r\nHost: {request_host}\r\nUser-Agent: CLVX/4.4\r\nConnection: close\r\n\r\n").encode())
            else:
                s.sendall(b'\r\n')
            s.settimeout(1.5)
            raw = s.recv(2048)
    except Exception:
        raw = b''

    text = raw.decode('utf-8', 'replace').replace('\x00', ' ').strip()
    out['banner'] = text.splitlines()[0][:220] if text else ''
    if text:
        out['evidence'].append('service banner')
        out['confidence'] = 'HIGH'

    if port in HTTP_PORTS and text:
        m = re.search(r'(?im)^server:\s*([^\r\n]+)', text)
        if m:
            server = m.group(1).strip()
            out['banner'] = server[:220]
            for pat, name in VERSION_PATTERNS:
                vm = pat.search(server)
                if vm:
                    out['service'] = name
                    out['version'] = _extract_version(vm)
                    out['evidence'].append('HTTP Server header')
                    out['confidence'] = 'HIGH'
                    break

    for pat, name in VERSION_PATTERNS:
        m = pat.search(text)
        if m:
            out['service'] = name
            out['version'] = _extract_version(m)
            out['evidence'].append('banner version')
            out['confidence'] = 'HIGH'
            break

    if text:
        out['platform'] = _platform_hint(text)
    elif port in COMMON:
        out['confidence'] = 'MEDIUM'
        out['evidence'].append('TCP reachability only')

    if port in {443, 8443}:
        tls = probe_tls(ip, port, timeout, host=request_host)
        if tls:
            out['tls'] = tls
            out['evidence'].append('TLS handshake')

    # Port-based service names without a confirming banner are explicitly
    # marked as inferred, not identified.
    if out['confidence'] == 'MEDIUM' and port in {53, 25, 110, 143, 445}:
        out['service_identified'] = False
    else:
        out['service_identified'] = bool(out['version'] or text)

    return out


def probe_tls(ip: str, port: int, timeout: float = 3.0, host: str | None = None) -> dict | None:
    server_name = host or ip
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name if not _is_ip(server_name) else None) as s:
                cert = s.getpeercert()
                return {
                    'protocol': s.version(),
                    'cipher': s.cipher()[0] if s.cipher() else None,
                    'subject': dict(x[0] for x in cert.get('subject', []) if x) if cert else {},
                    'issuer': dict(x[0] for x in cert.get('issuer', []) if x) if cert else {},
                    'not_after': cert.get('notAfter') if cert else None,
                    'hostname': server_name,
                }
    except Exception:
        return None


def _is_ip(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False
