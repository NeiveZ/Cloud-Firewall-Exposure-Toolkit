#!/usr/bin/env python3
"""Evidence-first web/WAF/CDN/server detection for authorized assessments."""
from __future__ import annotations
import re
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section
from utils.http_client import CLVXHTTPClient

FINGERPRINTS=[
 ('Cloudflare','WAF/CDN','header',('cf-ray','cf-cache-status','cf-request-id')),
 ('AWS CloudFront','CDN','header',('x-amz-cf-id','x-amz-cf-pop')),
 ('AWS WAF','WAF','header',('x-amzn-waf-action',)),
 ('Azure Front Door','WAF/CDN','header',('x-azure-ref','x-fd-healthprobe')),
 ('Google Front End','CDN/LB','header',('x-goog-iap-generated-response','x-cloud-trace-context')),
 ('Akamai','WAF/CDN','header',('akamai-grn','x-akamai-transformed')),
 ('Fastly','CDN','header',('x-fastly-request-id','x-served-by')),
 ('Sucuri','WAF','header',('x-sucuri-id','x-sucuri-cache')),
 ('Imperva','WAF','header',('x-iinfo',)),
 ('ModSecurity','WAF','text',('mod_security','modsecurity')),
('Cloudflare Bot/Managed Challenge','WAF','cookie',('__cf_bm','cf_clearance')),
('AWS load balancer','Load Balancer','cookie',('awselb','awsalbcors')),
('Imperva','WAF','cookie',('incap_ses','visid_incap')),
('Akamai','WAF/CDN','cookie',('ak_bmsc','bm_sz')),
('Azure App Gateway/Front Door','WAF/CDN','cookie',('arrAffinity','arrAffinitySameSite')),
]
PRODUCTS={
 'nginx':('nginx','cpe:2.3:a:nginx:nginx:{}:*:*:*:*:*:*:*'),
 'apache':('apache http server','cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*'),
 'microsoft-iis':('microsoft iis','cpe:2.3:a:microsoft:iis:{}:*:*:*:*:*:*:*'),
 'openssh':('openssh','cpe:2.3:a:openbsd:openssh:{}:*:*:*:*:*:*:*'),
 'redis':('redis','cpe:2.3:a:redis:redis:{}:*:*:*:*:*:*:*'),
 'mongodb':('mongodb','cpe:2.3:a:mongodb:mongodb:{}:*:*:*:*:*:*:*'),
 'elasticsearch':('elasticsearch','cpe:2.3:a:elasticsearch:elasticsearch:{}:*:*:*:*:*:*:*'),
}

class WAFDetector(BaseModule):
    NAME='detect/web'
    DESCRIPTION='WAF, CDN, HTTP server and TLS evidence with conservative CVE correlation'
    REFERENCES=['https://nvd.nist.gov/developers/vulnerabilities']
    def _define_options(self):
        self._add_option('TARGET','',True,'Target URL')
        self._add_option('TIMEOUT','8',False,'HTTP timeout')
        self._add_option('ACTIVE','false',False,'Low-impact authorized behavior checks')
        self._add_option('CVES','true',False,'Correlate exact product versions with NVD')
    def run(self):
        if not self._validate(): return []
        target=self.get_option('TARGET').strip().rstrip('/')
        if not target.startswith(('http://','https://')): target='https://'+target
        client=CLVXHTTPClient(timeout=int(self.get_option('TIMEOUT') or 8))
        findings=[]; print_section(f'Web / WAF Detection — {target}')
        code,body,headers,meta=client.get_detailed(target,follow_redirects=False)
        if code==0:
            return [self._finding('NOT_ASSESSED','HTTP reachability',target,meta.get('error','request failed'))]
        lh={k.lower():str(v) for k,v in headers.items()}
        for name,cat,kind,patterns in FINGERPRINTS:
            hits=[]
            for p in patterns:
                if kind=='header' and p in lh: hits.append(p)
                elif kind=='text' and p in body.lower(): hits.append(p)
                elif kind=='cookie' and p in lh.get('set-cookie','').lower(): hits.append(p)
            if hits:
                f=self._finding('INFO',f'{name} observed',target,', '.join(hits))
                f.update(state='OBSERVED',confidence='HIGH' if len(hits)>=2 else 'MEDIUM',product=name,category=cat)
                findings.append(f)
                print(f'  {Colors.CYAN}[OBSERVED]{Colors.RESET} {name:<20} {cat:<10} {", ".join(hits)}')
        server=lh.get('server',''); powered=lh.get('x-powered-by','')
        product_info=self._identify_product(server+' '+powered)
        if product_info:
            product,version,cpe=product_info
            f=self._finding('INFO',f'Server fingerprint: {product}',target,server or powered)
            f.update(state='OBSERVED',confidence='HIGH' if version else 'MEDIUM',product=product,version=version or 'unknown',cpe=cpe,role='server_fingerprint')
            findings.append(f)
            print(f'  {Colors.YELLOW}[SERVER]{Colors.RESET} {product} {version or "version unknown"}')
        tls=self._tls_evidence(target, client)
        if tls:
            f=self._finding('INFO','TLS evidence observed',target,f"protocol={tls.get('protocol')} cipher={tls.get('cipher')} subject={tls.get('subject')}")
            f.update(state='OBSERVED',confidence='HIGH',tls=tls); findings.append(f)
        for header,severity in [('strict-transport-security','MEDIUM'),('content-security-policy','LOW'),('x-content-type-options','LOW'),('referrer-policy','LOW')]:
            if header not in lh and target.startswith('https://'):
                findings.append(self._finding(severity,f'Missing security header: {header}',target,'Header not present'))
        if target.startswith('http://'):
            https_target = 'https://' + target.split('://', 1)[1]
            https_code, https_body, https_headers, https_meta = client.get_detailed(https_target, follow_redirects=False)
            if https_code:
                tls = self._tls_evidence(https_target, client)
                detail = f'HTTPS endpoint reachable with HTTP {https_code}.'
                if tls:
                    detail += f' TLS={tls.get("protocol")} cipher={tls.get("cipher") or "unknown"}.'
                f = self._finding('INFO', 'HTTPS endpoint observed', https_target, detail)
                f.update(state='OBSERVED', confidence='HIGH', tls=tls or {})
                findings.append(f)
                h2 = {k.lower(): str(v) for k, v in https_headers.items()}
                if 'strict-transport-security' not in h2:
                    findings.append(self._finding('MEDIUM', 'Missing security header: strict-transport-security', https_target, 'Header not present on HTTPS response'))
        if self.get_option('ACTIVE').lower()=='true':
            findings.extend(self._behavior_checks(target,client,code))
        return findings
    def _fingerprint(self, headers, body):
        lower={str(k).lower():str(v).lower() for k,v in headers.items()}
        body_l=body.lower()
        out=[]
        for name,cat,kind,patterns in FINGERPRINTS:
            hits=[]
            for pattern in patterns:
                if kind=='header' and pattern in lower: hits.append(pattern)
                elif kind=='text' and pattern in body_l: hits.append(pattern)
                elif kind=='cookie' and pattern in lower.get('set-cookie',''): hits.append(pattern)
            if hits: out.append((name,cat,', '.join(sorted(set(hits)))))
        # Keep direct server fingerprints compatible with the legacy helper.
        server=lower.get('server','')
        if 'cloudflare' in server and not any(x[0]=='Cloudflare' for x in out): out.append(('Cloudflare','WAF/CDN','server'))
        return out

    def _identify_product(self,text):
        s=text.strip(); low=s.lower()
        patterns=[(r'nginx[/ ]([0-9][\w.]*)','nginx'),(r'apache[/ ]([0-9][\w.]*)','apache'),(r'microsoft-iis[/ ]([0-9][\w.]*)','microsoft-iis'),(r'openssh[_/ ]([0-9][\w.]*)','openssh'),(r'redis[/ ]([0-9][\w.]*)','redis'),(r'mongodb[/ ]([0-9][\w.]*)','mongodb'),(r'elasticsearch[/ ]([0-9][\w.]*)','elasticsearch')]
        for pat,key in patterns:
            m=re.search(pat,s,re.I)
            if m:
                product,cpe=PRODUCTS[key]; return product,m.group(1),cpe
        for key,(product,cpe) in PRODUCTS.items():
            if key in low: return product,None,cpe
        return None
    def _tls_evidence(self,target,client):
        if not target.startswith('https://'): return None
        return getattr(client,'tls_probe',lambda u:None)(target)
    def _behavior_checks(self,target,client,baseline):
        findings=[]
        for label,suffix in [('reserved-character canary','?clvx_canary=%3C%3E'),('duplicate-parameter canary','?clvx_canary=1&clvx_canary=1')]:
            code,_,_,meta=client.get_detailed(target+suffix,follow_redirects=False)
            if code==0: continue
            state='OBSERVED'; detail=f'HTTP {code}; no exploit conclusion is made.'
            sev='INFO'
            if code in (403,406,429): detail=f'HTTP {code}; request was blocked or rate-limited.'
            elif code==baseline: detail=f'HTTP {code}; canary accepted. This is not proof of WAF weakness.'
            f=self._finding(sev,f'WAF behavior: {label}',target,detail); f.update(state=state,confidence='LOW'); findings.append(f)
        return findings
