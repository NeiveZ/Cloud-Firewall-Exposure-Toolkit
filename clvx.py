#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import os
import shutil
import socket
import sys
from pathlib import Path

from utils.correlation import correlate_service_findings, deduplicate_findings, summary

TOOL = 'CLVX'
TAGLINE = 'Cloud, WAF & Firewall Exposure Assessment'
VERSION = '4.5.3'
SEPARATOR = '|-----------------------------------------------------------------------|'

COMMANDS = {
    'detect': {'module':'modules.evade_detect','class':'WAFDetector','summary':'WAF/CDN/service fingerprinting and safe behavior assessment'},
    'cloudflare': {'module':'modules.cloud_cloudflare','class':'CloudflareExposure','summary':'Cloudflare exposure and origin-confidence assessment'},
    'aws': {'module':'modules.cloud_aws','class':'AWSRecon','summary':'AWS edge fingerprinting and authenticated security-group review'},
    'azure': {'module':'modules.cloud_azure','class':'AzureRecon','summary':'Azure service and storage exposure checks'},
    'gcp': {'module':'modules.gcp','class':'GCPRecon','summary':'Google Cloud / Front End and firewall exposure checks'},
    'portscan': {'module':'modules.firewall_portscan','class':'FirewallPortScan','summary':'Polite TCP exposure and service identification'},
    'full': {'module':'modules.full','class':'FullAssessment','summary':'Correlated cloud, WAF, service and vulnerability assessment'},
}

C = {
    'reset':'\033[0m','bold':'\033[1m','dim':'\033[90m','red':'\033[91m','green':'\033[92m',
    'yellow':'\033[93m','cyan':'\033[96m','blue':'\033[94m','white':'\033[97m','magenta':'\033[95m'
}
USE_COLOR = sys.stdout.isatty()


def c(kind: str, value: object) -> str:
    return C[kind] + str(value) + C['reset'] if USE_COLOR else str(value)


def banner():
    print('')
    print(c('red', '   ██████╗██╗     ██╗   ██╗██╗  ██╗'))
    print(c('red', '  ██╔════╝██║     ██║   ██║╚██╗██╔╝'))
    print(c('red', '  ██║     ██║     ██║   ██║ ╚███╔╝'))
    print(c('red', '  ██║     ██║     ██║   ██║ ██╔██╗'))
    print(c('red', '  ╚██████╗███████╗╚██████╔╝██╔╝ ██╗'))
    print(c('red', '   ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝'))
    print(f'{c("bold","CLVX")}  |  {c("white", TAGLINE)}')
    print(f'{c("cyan", f"Version {VERSION}")}  |  Precision evidence & conclusion engine')


def load_class(spec):
    return getattr(importlib.import_module(spec['module']), spec['class'])


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog='clvx.sh',
        description='CLVX — evidence-first cloud, WAF and firewall exposure assessment.'
    )
    p.add_argument('command', nargs='?', choices=list(COMMANDS))
    p.add_argument('-u','--url')
    p.add_argument('-d','--domain')
    p.add_argument('-t','--target')
    p.add_argument('-p','--ports',default='top100')
    p.add_argument('--project')
    p.add_argument('--active',action='store_true')
    p.add_argument('--authorized',action='store_true')
    p.add_argument('--cves',dest='cves',action=argparse.BooleanOptionalAction,default=True)
    p.add_argument('--report',action='store_true')
    p.add_argument('--json',action='store_true')
    p.add_argument('--txt',action='store_true')
    p.add_argument('--out')
    p.add_argument('--verbose',action='store_true')
    p.add_argument('--no-color',action='store_true')
    return p.parse_args(argv)


def rows_flat(obj):
    if not obj:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]


def severity_color(sev):
    s=(sev or '').upper()
    if s in {'CRITICAL','URGENT'}: return 'red'
    if s in {'HIGH'}: return 'yellow'
    if s in {'MEDIUM'}: return 'magenta'
    if s in {'LOW'}: return 'blue'
    if s in {'VERSION_AFFECTED','CONDITIONAL','NETWORK_RELEVANT','REMOTE_CONDITIONAL'}: return 'cyan'
    if s in {'NOT_A_VULNERABILITY','ADVISORY'}: return 'dim'
    if s in {'INFO','OBSERVED','NOT_ASSESSED','PARTIAL'}: return 'white'
    return 'white'


def state_color(state):
    s=(state or '').upper()
    return {
        'VERSION_AFFECTED':'cyan', 'CONDITIONAL':'yellow', 'ADVISORY':'dim',
        'NOT_A_VULNERABILITY':'dim', 'NOT_ASSESSED':'magenta', 'PARTIAL':'yellow',
        'OBSERVED':'cyan', 'CONFIRMED':'green'
    }.get(s, 'white')


def _section(title: str):
    print(c('red', SEPARATOR))
    print(c('bold', title))


def _print_cve_compact(r: dict, verbose: bool = False):
    adv = r.get('advisory') or {}
    state = str(r.get('state','ADVISORY')).upper()
    sev = str(adv.get('severity') or r.get('severity') or 'INFO').upper()
    priority = str(r.get('priority') or 'REVIEW').upper()
    cve = adv.get('cve') or 'CVE-UNKNOWN'
    product = r.get('product') or r.get('service') or 'software'
    version = r.get('version') or 'unknown'
    score = adv.get('score')
    av = adv.get('attack_vector') or 'n/a'
    pr = adv.get('privileges_required') or 'n/a'
    ui = adv.get('user_interaction') or 'n/a'
    at = adv.get('attack_requirements') or 'n/a'
    kev = 'YES' if adv.get('kev') else 'NO'
    exploit = r.get('exploitability') or 'UNKNOWN'
    target = r.get('target') or ''
    location = c('yellow', target)
    print(f'  {c(state_color(state), f"[{state}]")} {c(severity_color(priority), f"[{priority}]")} {cve}  {product} {version}  {location}')
    if state == 'NOT_A_VULNERABILITY':
        print('      Record type : non-vulnerability advisory/mitigation metadata')
        return
    applicability = 'CPE/version match' if adv.get('nvd_cpe_match') else 'not established'
    print(f'      Applicability: {applicability}  |  Network: {exploit}')
    print(f'      CVSS        : {score if score is not None else "n/a"} {sev}  |  KEV: {kev}')
    if r.get('conclusion_reason'):
        reason = str(r.get('conclusion_reason') or '').strip()
    if reason:
        if verbose:
            print(f'      Assessment   : {reason}')
        else:
            compact = reason if len(reason) <= 220 else reason[:217].rstrip() + '...'
            print(f'      Assessment   : {compact}')
    if verbose:
        print(f'      Vector      : AV:{av} PR:{pr} UI:{ui} AT:{at}')
        refs = adv.get('vendor_references') or adv.get('references') or []
        if refs:
            print(f'      Reference   : {refs[0]}')
        desc = ' '.join(str(adv.get('description') or '').split())
        if desc:
            print(f'      Details     : {desc[:560]}')
        reqs = adv.get('requirements') or []
        if reqs:
            print(f'      Conditions  : {", ".join(reqs[:5])}')


def _print_service(r: dict):
    sev = str(r.get('severity','INFO')).upper()
    service = r.get('service') or 'unknown'
    version = r.get('version') or 'unknown'
    target = r.get('target') or ''
    identified = r.get('service_identified', True)
    label = f'{service} {version}' if identified else f'{service} (inferred)'
    print(f'  {c(severity_color(sev), f"[{sev}]")} {r.get("check", "")}  {label}  {c("yellow", target)}')
    if r.get('confidence'):
        print(f'      Confidence : {r["confidence"]}')
    if r.get('detail'):
        print(f'      Evidence   : {r["detail"][:260]}')


def _print_observation(r: dict, verbose: bool = False):
    sev = str(r.get('severity','INFO')).upper()
    state = str(r.get('state','OBSERVED')).upper()
    print(f'  {c(state_color(state), f"[{state}]")} {c(severity_color(sev), f"[{sev}]")} {r.get("check","")}  {c("yellow", r.get("target", ""))}')
    if r.get('detail'):
        print(f'      {r["detail"][:360]}')
    if verbose and r.get('evidence'):
        print(f'      Evidence   : {r["evidence"]}')
    if verbose and r.get('source_errors'):
        for err in r['source_errors'][:5]:
            print(f'      Source error: {err}')


def _service_group_key(r: dict):
    return (
        str(r.get('service') or r.get('product') or 'unknown').lower(),
        str(r.get('version') or 'unknown').lower(),
    )



def print_priority(rows):
    """Show a compact, explicitly non-confirmatory priority view."""
    vuln_states = {'VERSION_AFFECTED', 'CONDITIONAL'}
    candidates = [r for r in rows if str(r.get('state', '')).upper() in vuln_states]
    exposure = [
        r for r in rows
        if r.get('module') == 'exposure/portscan'
        and str(r.get('state', '')).upper() == 'CONFIRMED'
        and str(r.get('severity', 'INFO')).upper() in {'CRITICAL', 'HIGH'}
    ]

    def pval(r):
        value = str(r.get('priority') or 'REVIEW').upper()
        return value

    critical = [r for r in candidates if pval(r) in {'CRITICAL', 'URGENT'}]
    high = [r for r in candidates if pval(r) == 'HIGH']
    medium = [r for r in candidates if pval(r) == 'MEDIUM']

    ranked = sorted(
        candidates,
        key=lambda r: (
            0 if pval(r) in {'CRITICAL', 'URGENT'} else 1 if pval(r) == 'HIGH' else 2 if pval(r) == 'MEDIUM' else 3,
            0 if (r.get('advisory') or {}).get('kev') else 1,
            -(float((r.get('advisory') or {}).get('score') or 0)),
            str((r.get('advisory') or {}).get('cve') or ''),
        ),
    )

    seen = set()
    top = []
    for r in ranked:
        cve = (r.get('advisory') or {}).get('cve')
        key = (cve, r.get('service'), r.get('version'), r.get('port'))
        if cve and key not in seen:
            top.append(r)
            seen.add(key)
        if len(top) >= 3:
            break

    if not (critical or high or medium or exposure):
        return

    _section('PRIORITY')
    print('  Priority candidates — not confirmed vulnerabilities')
    print(f'  Critical candidates : {len(critical)}')
    print(f'  High candidates     : {len(high)}')
    print(f'  Medium candidates   : {len(medium)}')
    if exposure:
        for r in exposure[:2]:
            svc = f"{r.get('service') or 'service'} {r.get('version') or ''}".strip()
            print(f'  {c("red", "[EXPOSURE]")} {svc}  {c("yellow", r.get("target", ""))}')
    for r in top:
        adv = r.get('advisory') or {}
        cve = adv.get('cve') or 'CVE-UNKNOWN'
        product = r.get('service') or r.get('product') or 'software'
        version = r.get('version') or 'unknown'
        priority = pval(r)
        label = f'[{priority}]'
        print(f'  {c(severity_color(priority), label)} {cve} — {product} {version}')


def print_findings(rows, verbose=False):
    exposure = [r for r in rows if r.get('module') == 'exposure/portscan' and str(r.get('state')).upper() == 'CONFIRMED']
    vuln_states = {'VERSION_AFFECTED','CONDITIONAL'}
    vuln = [r for r in rows if str(r.get('state')).upper() in vuln_states]
    advisories = [r for r in rows if str(r.get('state')).upper() == 'ADVISORY']
    not_vuln = [r for r in rows if str(r.get('state')).upper() == 'NOT_A_VULNERABILITY']
    observed = [r for r in rows if str(r.get('state')).upper() == 'OBSERVED']
    not_assessed = [r for r in rows if str(r.get('state')).upper() == 'NOT_ASSESSED']
    partial = [r for r in rows if str(r.get('state')).upper() == 'PARTIAL']

    print_priority(rows)

    if exposure:
        _section('EXPOSURE')
        for r in exposure:
            _print_service(r)

    if vuln:
        _section('VULNERABILITY ASSESSMENT')
        groups = {}
        for r in vuln:
            groups.setdefault(_service_group_key(r), []).append(r)
        for (service, version), items in sorted(groups.items()):
            ports = sorted({str(x.get('port')) for x in items if x.get('port')})
            port_text = f' | ports: {", ".join(ports)}' if ports else ''
            print(f'  {c("bold", service)} {version}{port_text}')
            ordered = sorted(items, key=lambda r: (
                0 if r.get('exploitability') == 'NETWORK_RELEVANT' else 1,
                0 if (r.get('advisory') or {}).get('kev') else 1,
                -(float((r.get('advisory') or {}).get('score') or 0)),
            ))
            limit = len(ordered) if verbose else min(4, len(ordered))
            for r in ordered[:limit]:
                _print_cve_compact(r, verbose=verbose)
            if len(ordered) > limit:
                print(f'      ... {len(ordered)-limit} additional result(s) for this service; use --verbose for all.')
            print('')

    if advisories and verbose:
        _section('ADVISORIES')
        for r in advisories:
            _print_cve_compact(r, verbose=True)

    if observed:
        _section('SECURITY OBSERVATIONS')
        for r in observed:
            _print_observation(r, verbose=verbose)

    if not_vuln and verbose:
        _section('NON-VULNERABILITY RECORDS')
        for r in not_vuln:
            _print_observation(r, verbose=True)

    if partial:
        _section('PARTIAL')
        for r in partial:
            label = r.get('check', 'Partial assessment')
            detail = r.get('detail', '')
            print(f'  {c("yellow", "[PARTIAL]")} {label}')
            if verbose and detail:
                print(f'      {detail}')
                if r.get('source_errors'):
                    for err in r['source_errors'][:5]:
                        print(f'      Source error: {err}')

    if not_assessed:
        _section('NOT ASSESSED')
        for r in not_assessed:
            label = r.get('check', 'Assessment not completed')
            print(f'  {c("magenta", "[NOT_ASSESSED]")} {label}')
            if verbose:
                _print_observation(r, verbose=True)


def print_summary(rows):
    counts = summary(rows)
    kev_count = sum(1 for r in rows if (r.get('advisory') or {}).get('kev'))
    services = sum(1 for r in rows if r.get('module') == 'exposure/portscan' and r.get('state') == 'CONFIRMED')
    network_relevant = sum(1 for r in rows if r.get('exploitability') == 'NETWORK_RELEVANT')
    remote_conditional = sum(1 for r in rows if r.get('exploitability') == 'REMOTE_CONDITIONAL')
    local_adjacent = sum(1 for r in rows if r.get('exploitability') == 'LOCAL_OR_ADJACENT')
    priority_critical = sum(1 for r in rows if str(r.get('state','')).upper() in {'VERSION_AFFECTED','CONDITIONAL'} and str(r.get('priority','')).upper() in {'CRITICAL','URGENT'})
    priority_high = sum(1 for r in rows if str(r.get('state','')).upper() in {'VERSION_AFFECTED','CONDITIONAL'} and str(r.get('priority','')).upper() == 'HIGH')
    priority_medium = sum(1 for r in rows if str(r.get('state','')).upper() in {'VERSION_AFFECTED','CONDITIONAL'} and str(r.get('priority','')).upper() == 'MEDIUM')
    incomplete = counts.get('PARTIAL', 0) + counts.get('NOT_ASSESSED', 0)
    confidence = 'HIGH' if incomplete == 0 else 'LIMITED' if incomplete >= 2 else 'MEDIUM'
    products = {(str(r.get('service') or r.get('product') or '').lower(), str(r.get('version') or '').lower()) for r in rows if r.get('module') == 'exposure/portscan' and r.get('service') and r.get('version') and r.get('version') != 'unknown'}
    _section('ASSESSMENT SUMMARY')
    print(f'  Assessment confidence     : {confidence}')
    print(f'  Priority candidates       : Critical {priority_critical} | High {priority_high} | Medium {priority_medium}')
    print(f'  Services observed         : {services}')
    print(f'  Unique software/version   : {len(products)}')
    print(f'  CPE/version matches       : {counts.get("VERSION_AFFECTED",0)}')
    print(f'  Network-relevant matches  : {network_relevant}')
    print(f'  Remote-conditional        : {remote_conditional}')
    print(f'  Local/adjacent context    : {local_adjacent}')
    print(f'  Conditional assessments   : {counts.get("CONDITIONAL",0)}')
    print(f'  Advisory-only results     : {counts.get("ADVISORY",0)}')
    print(f'  Confirmed vulnerabilities : {counts.get("CONFIRMED_VULNERABILITY",0)}')
    print(f'  Non-vulnerability records : {counts.get("NOT_A_VULNERABILITY",0)}')
    print(f'  Security observations     : {counts.get("OBSERVED",0)}')
    print(f'  Partial checks            : {counts.get("PARTIAL",0)}')
    print(f'  Not assessed              : {counts.get("NOT_ASSESSED",0)}')
    print(f'  KEV-linked CVEs          : {kev_count}')


def save_report(command, rows, args):
    if not (args.report or args.json or args.txt or args.out):
        return
    out=Path(args.out or Path('reports')/f'clvx_{command}_{dt.datetime.now().strftime("%Y%m%d_%H%M%S")}')
    out.parent.mkdir(parents=True,exist_ok=True)
    data={
        'tool':TOOL,'version':VERSION,'command':command,
        'timestamp':dt.datetime.now().isoformat(),
        'summary':summary(rows),'findings':rows,
        'interpretation': {
            'VERSION_AFFECTED':'NVD exact CPE/version applicability matched; exploitability is assessed separately.',
            'CONDITIONAL':'Additional deployment conditions or privileges remain unverified.',
            'ADVISORY':'Related advisory exists but applicability is not established.',
            'CONFIRMED':'Directly observed exposure, not automatic proof of exploitability.',
        }
    }
    if args.json or args.report: out.with_suffix('.json').write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')
    if args.txt or args.report:
        lines=[f'CLVX {VERSION}',f'Command: {command}',f'Timestamp: {data["timestamp"]}','']
        for r in rows:
            lines.append(f'[{r.get("state","OBSERVED")}] [{r.get("severity","INFO")}] {r.get("check","")} :: {r.get("detail","")}')
        out.with_suffix('.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    if args.report:
        md=['# CLVX Assessment',f'- Version: {VERSION}',f'- Command: {command}',f'- Timestamp: {data["timestamp"]}','', '## Summary']
        for k,v in data['summary'].items(): md.append(f'- {k}: {v}')
        md.append('')
        md.append('## Findings')
        for r in rows:
            md.append(f'- **{r.get("severity","INFO")} / {r.get("state","OBSERVED")}** {r.get("check","")} — {r.get("target","")}')
            if r.get('detail'): md.append(f'  - Evidence: {r["detail"]}')
            adv=r.get('advisory') or {}
            if adv.get('cve'): md.append(f'  - CVE: {adv.get("cve")} | CVSS: {adv.get("score") or "n/a"} | KEV: {"yes" if adv.get("kev") else "no"}')
        out.with_suffix('.md').write_text('\n'.join(md)+'\n',encoding='utf-8')


def health():
    print('CLVX health check')
    checks=[]
    modules=('modules.evade_detect','modules.cloud_cloudflare','modules.cloud_azure','modules.cloud_aws','modules.gcp','modules.firewall_portscan','modules.full')
    for name in modules:
        try:
            importlib.import_module(name); checks.append((name,'OK','loaded'))
        except Exception as exc:
            checks.append((name,'FAIL',str(exc)))
    checks.append(('Python','OK' if sys.version_info >= (3,10) else 'WARN',sys.version.split()[0]))
    checks.append(('dig','OK' if shutil.which('dig') else 'WARN',shutil.which('dig') or 'not installed'))
    for tool in ('aws','az','gcloud','nmap'):
        checks.append((tool,'OK' if shutil.which(tool) else 'WARN',shutil.which(tool) or 'optional/not installed'))
    try:
        socket.gethostbyname('example.com'); checks.append(('DNS','OK','resolver available'))
    except Exception as e:
        checks.append(('DNS','WARN',str(e)))
    for n,s,d in checks:
        print(f'  {n:<28} {s:<5} {d}')
    return 0 if all(s!='FAIL' for _,s,_ in checks) else 1


def show_help():
    banner()
    print('Usage: ./clvx.sh <command> [options]\n')
    for k,v in COMMANDS.items(): print(f'  {k:<12} {v["summary"]}')
    print('\nCommon options:')
    print('  -u, --url URL           Web target for WAF/CDN/service checks')
    print('  -d, --domain DOMAIN     Domain target for cloud/provider checks')
    print('  -t, --target TARGET     Host/IP target for TCP exposure assessment')
    print('  -p, --ports PORTS       top100, comma list, or range (e.g. 1-1024)')
    print('  --project PROJECT       Authenticated GCP project inventory')
    print('  --active --authorized   Enable low-impact active WAF canaries')
    print('  --no-cves               Disable NVD/CISA vulnerability enrichment')
    print('  --report                Write JSON, TXT and Markdown reports')
    print('  --verbose               Show full advisory descriptions and coverage details')
    print('  --no-color              Disable ANSI color output')
    print('\nConclusion states:')
    print('  CONFIRMED          Directly observed exposure; not automatic exploit proof')
    print('  VERSION_AFFECTED   NVD matched the detected CPE/version; not exploit confirmation')
    print('  CONDITIONAL        Additional deployment conditions remain unverified')
    print('  ADVISORY           Related CVE exists but applicability is not established')
    print('  NOT_A_VULNERABILITY Authoritative record is not a vulnerability')
    print('  PARTIAL            Some source checks completed; others failed')
    print('  NOT_ASSESSED       Required verification was not possible')
    print('\nExamples:')
    print('  ./clvx.sh detect -u https://example.com')
    print('  ./clvx.sh cloudflare -d example.com')
    print('  ./clvx.sh gcp -d example.com --project MY_PROJECT')
    print('  ./clvx.sh portscan -t 203.0.113.10 -p top100')
    print('  ./clvx.sh full -u https://example.com')
    print('  ./clvx.sh full -u https://example.com --verbose --report')


def main(argv=None):
    global USE_COLOR
    argv=sys.argv[1:] if argv is None else argv
    if '--no-color' in argv: USE_COLOR=False
    if not argv or argv[0] in ('-h','--help'):
        show_help(); return 0
    if argv[0] in ('--version','-v'):
        print(f'{TOOL} {VERSION}'); return 0
    if argv[0]=='--check':
        banner(); return health()

    args=parse_args(argv); cmd=args.command
    if not cmd:
        show_help(); return 2
    banner()
    spec=COMMANDS[cmd]
    cls=load_class(spec); obj=cls()
    target=args.url or args.domain or args.target
    if target and 'TARGET' in obj.options: obj.set_option('TARGET',target)
    elif target and 'DOMAIN' in obj.options: obj.set_option('DOMAIN',target)
    if 'PORTS' in obj.options: obj.set_option('PORTS',args.ports)
    if 'CVES' in obj.options: obj.set_option('CVES','true' if args.cves else 'false')
    if 'ACTIVE' in obj.options: obj.set_option('ACTIVE','true' if args.active and args.authorized else 'false')
    if 'PROJECT' in obj.options and args.project: obj.set_option('PROJECT',args.project)
    if 'AUTHORIZED' in obj.options: obj.set_option('AUTHORIZED','true' if args.authorized else 'false')

    print(SEPARATOR)
    print(f'Command : {cmd}')
    if target: print(f'Target  : {target}')
    print(f'Purpose : {spec["summary"]}')
    print(SEPARATOR)

    rows=rows_flat(obj.run())
    if args.cves:
        rows=correlate_service_findings(rows, timeout=10, limit_per_service=25)
    rows=deduplicate_findings(rows)
    if not rows:
        print(c('yellow','No findings returned. A missing result does not prove safety.'))
    else:
        print_findings(rows, verbose=args.verbose)
        print_summary(rows)
    save_report(cmd,rows,args)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
