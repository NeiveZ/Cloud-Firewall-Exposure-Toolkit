#!/usr/bin/env python3
from __future__ import annotations
import contextlib, io
from urllib.parse import urlsplit
from modules.base import BaseModule
from modules.evade_detect import WAFDetector
from modules.cloud_cloudflare import CloudflareExposure
from modules.cloud_azure import AzureRecon
from modules.cloud_aws import AWSRecon
from modules.gcp import GCPRecon
from modules.firewall_portscan import FirewallPortScan
from utils.colors import Colors, print_status, print_section

class FullAssessment(BaseModule):
    NAME='core/full'
    DESCRIPTION='Correlated exposure assessment with staged collection and final evidence model'
    REFERENCES=[]
    def _define_options(self):
        self._add_option('TARGET','',True,'Target URL or domain')
        self._add_option('PORTS','top100',False,'Port set')
        self._add_option('CVES','true',False,'Correlate identified versions with NVD/CISA KEV')

    @staticmethod
    def _quiet_run(obj):
        """Run a child module without duplicating its detailed terminal output."""
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            return obj.run()

    def run(self) -> list[dict]:
        if not self._validate(): return []
        target=self.get_option('TARGET').strip()
        parsed=urlsplit(target if '://' in target else 'https://'+target)
        host=parsed.hostname or target
        rows=[]
        print_section(f'Full Assessment — {target}')

        # Stage 1: Web / WAF
        print(f'  {Colors.CYAN}[1/4]{Colors.RESET} Web / WAF fingerprinting')
        detect=WAFDetector(); detect.set_option('TARGET',target); detect.set_option('CVES','false')
        try:
            rows.extend(self._quiet_run(detect))
        except Exception as exc:
            rows.append(self._finding('NOT_ASSESSED','Module failure: detect/web',target,str(exc)))

        observed=' '.join(str(r.get('check',''))+' '+str(r.get('detail',''))+' '+str(r.get('product','')) for r in rows).lower()

        # Stage 2: provider-specific checks only when public evidence is strong enough.
        print(f'  {Colors.CYAN}[2/4]{Colors.RESET} Cloud/provider assessment')
        provider_jobs=[]
        if 'cloudflare' in observed: provider_jobs.append((CloudflareExposure,{'TARGET':host}))
        if any(x in observed for x in ('aws','cloudfront','awselb')): provider_jobs.append((AWSRecon,{'TARGET':target,'CVES':'false'}))
        if any(x in observed for x in ('azure','azure front door')): provider_jobs.append((AzureRecon,{'TARGET':target,'ENUM_BLOB':'false','TENANT':'true','SUBDOMAINS':'false'}))
        if 'google' in observed or 'google front end' in observed: provider_jobs.append((GCPRecon,{'TARGET':target,'CVES':'false'}))
        if provider_jobs:
            for cls,opts in provider_jobs:
                obj=cls()
                for k,v in opts.items():
                    if k in obj.options: obj.set_option(k,v)
                try: rows.extend(self._quiet_run(obj))
                except Exception as exc: rows.append(self._finding('NOT_ASSESSED',f'Module failure: {cls.NAME}',target,str(exc)))
        else:
            rows.append(self._finding('NOT_ASSESSED','Provider-specific control-plane review',host,'No public provider fingerprint was strong enough to select an authenticated control-plane module.'))

        # Stage 3: service exposure
        print(f'  {Colors.CYAN}[3/4]{Colors.RESET} Service exposure and identification')
        portscan=FirewallPortScan(); portscan.set_option('TARGET',host); portscan.set_option('PORTS',self.get_option('PORTS')); portscan.set_option('TIMING','polite'); portscan.set_option('THREADS','12'); portscan.set_option('LIVE','false')
        try: rows.extend(self._quiet_run(portscan))
        except Exception as exc: rows.append(self._finding('NOT_ASSESSED','Module failure: exposure/portscan',host,str(exc)))

        # Stage 4 is deliberately kept as a marker. CVE correlation runs in the
        # main engine so it is performed once, after all service observations are known.
        print(f'  {Colors.CYAN}[4/4]{Colors.RESET} Evidence correlation and conclusion engine')
        return rows
