#!/usr/bin/env python3
"""Polite TCP exposure assessment with evidence-backed service identification."""
from __future__ import annotations
import concurrent.futures, socket
from modules.base import BaseModule
from modules.service_probe import COMMON, probe, cpe_for_service
from utils.colors import Colors, print_status, print_section

class FirewallPortScan(BaseModule):
    NAME='exposure/portscan'
    DESCRIPTION='Polite TCP exposure assessment with conservative service identification'
    REFERENCES=['https://nmap.org/book/man-port-scanning.html']
    def _define_options(self):
        self._add_option('TARGET','',True,'Target IP or hostname')
        self._add_option('PORTS','top100',False,'Ports: top100 | 22,80,443 | 1-1024')
        self._add_option('TIMING','polite',False,'Timing: polite | normal')
        self._add_option('THREADS','12',False,'Concurrent connections')
        self._add_option('LIVE','true',False,'Print live service discoveries during the scan')
    def run(self) -> list[dict]:
        if not self._validate(): return []
        target=self.get_option('TARGET').strip(); ports=self._parse_ports(self.get_option('PORTS') or 'top100')
        timing=(self.get_option('TIMING') or 'polite').lower(); threads=max(1,min(32,int(self.get_option('THREADS') or 12)))
        timeout=3.0 if timing=='polite' else 2.0
        try:
            infos=socket.getaddrinfo(target,None,type=socket.SOCK_STREAM)
            ips=[]
            for x in infos:
                ip=x[4][0]
                if ip not in ips: ips.append(ip)
        except Exception as exc:
            return [self._finding('NOT_ASSESSED','Target resolution',target,str(exc))]
        live=self.get_option('LIVE').lower() == 'true'
        print_section(f'Firewall Exposure — {target}')
        print(f'  Target IPs : {", ".join(ips)}')
        print(f'  Candidates : {len(ports)}')
        print(f'  Timing     : {timing}')
        print(f'  Threads    : {threads}')
        open_rows=[]

        def one(item):
            ip, port = item
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    try:
                        return ('ok', ip, port, probe(ip, port, timeout, host=target), None)
                    except Exception as exc:
                        return ('probe_error', ip, port, None, f'{type(exc).__name__}: {exc}')
            except OSError:
                return None

        probe_errors = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(one, [(ip, p) for ip in ips for p in ports]):
                if not res:
                    continue
                status, ip, port, detail, error = res
                if status == 'probe_error':
                    probe_errors.append((ip, port, error or 'service probe failed'))
                    continue
                open_rows.append((ip, port, detail))
                svc = detail.get('service', COMMON.get(port, 'unknown'))
                if live:
                    label = '[OPEN]'
                    extra = detail.get('version') or (detail.get('banner', '')[:70] if detail.get('banner') else 'reachable; service not confirmed')
                    print(f'  {Colors.GREEN}{label}{Colors.RESET} {ip}:{port:<5} {Colors.CYAN}{svc:<18}{Colors.RESET} {extra}')
        findings=[]
        for ip,port,detail in open_rows:
            svc=detail.get('service',COMMON.get(port,'unknown')); version=detail.get('version')
            identified=bool(detail.get('service_identified'))
            if port in {21,23,3389,6379,9200,27017}: sev='HIGH'
            elif port in {22,25,53,110,143,445,3306,5432}: sev='MEDIUM'
            else: sev='INFO'
            if identified:
                check=f'Reachable TCP service: {port}/{svc}'
                evidence=detail.get('banner','') or 'service banner observed'
            else:
                check=f'Reachable TCP endpoint: {port}'
                evidence='TCP connection succeeded; service identification not confirmed.'
            f=self._finding(sev,check,f'{ip}:{port}',evidence)
            f.update(state='CONFIRMED',confidence=detail.get('confidence','MEDIUM'),service=svc,version=version or 'unknown',port=port,
                     service_identified=identified,role='service_endpoint',platform=detail.get('platform'))
            if detail.get('banner'):
                f['banner']=detail['banner']
            if detail.get('evidence'):
                f['evidence']=detail['evidence']
            cpe=cpe_for_service(svc, version)
            if cpe: f['cpe']=cpe
            if detail.get('tls'): f['tls']=detail['tls']
            findings.append(f)
        for ip, port, error in probe_errors:
            findings.append(self._finding(
                'INFO',
                f'Service identification failed: {port}/tcp',
                f'{ip}:{port}',
                error,
            ) | {'state': 'NOT_ASSESSED', 'confidence': 'LOW', 'role': 'service_endpoint', 'port': port})
        if not open_rows: print_status('No open TCP ports observed in the selected set.','info')
        elif live: print_status(f'{len(open_rows)} open endpoint(s) observed.','ok')
        if probe_errors and live:
            print_status(f'{len(probe_errors)} service probe(s) failed; open TCP observations were preserved.','warn')
        return findings

    @staticmethod
    def _service_cpe(service, version):
        return cpe_for_service(service, version)

    def _parse_ports(self,spec):
        if spec=='top100':
            return sorted(set(list(COMMON)+[20,69,79,88,119,161,389,500,636,1080,1194,1723,2049,2222,3000,4444,5000,8000,8001,8008,8081,9000,9090,10000]))
        out=[]
        for part in spec.split(','):
            part=part.strip()
            try:
                if '-' in part:
                    a,b=part.split('-',1); out.extend(range(int(a),int(b)+1))
                else: out.append(int(part))
            except ValueError: continue
        return sorted({p for p in out if 1<=p<=65535})
