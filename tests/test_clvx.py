from modules.evade_detect import WAFDetector
from modules.gcp import GCPRecon
from modules.firewall_portscan import FirewallPortScan
from utils import advisories


def test_waf_fingerprint():
    obj = WAFDetector()
    hits = obj._fingerprint({'cf-ray':'abc','server':'cloudflare'}, '')
    assert any(h[0]=='Cloudflare' for h in hits)


def test_gcp_module_loads():
    obj = GCPRecon()
    assert 'TARGET' in obj.options and 'PROJECT' in obj.options


def test_port_parser():
    obj = FirewallPortScan()
    ports = obj._parse_ports('80,443,8000-8002')
    assert ports == [80,443,8000,8001,8002]


def test_service_cpe():
    obj = FirewallPortScan()
    assert obj._service_cpe('nginx', '1.25.3') == 'cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*'


def test_nvd_cpe_parser(monkeypatch):
    cpe = 'cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*'
    sample={
      'vulnerabilities':[{
        'cve':{
          'id':'CVE-2099-0001',
          'published':'2099-01-01T00:00:00.000',
          'descriptions':[{'lang':'en','value':'Test vulnerability'}],
          'metrics':{'cvssMetricV31':[{'cvssData':{
              'baseScore':9.8,'baseSeverity':'CRITICAL','vectorString':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
              'attackVector':'NETWORK','privilegesRequired':'NONE','userInteraction':'NONE'}}]},
          'references':[{'url':'https://nvd.nist.gov/vuln/detail/CVE-2099-0001'}],
          'configurations': {'nodes':[{'operator':'OR','cpeMatch':[{'vulnerable':True,'criteria':cpe}]}]},
        }
      }]
    }
    monkeypatch.setattr(advisories, '_request', lambda *a, **k: sample)
    monkeypatch.setattr(advisories, '_kev_index', lambda: {'CVE-2099-0001': {'dateAdded':'2099-01-02'}})
    out=advisories.search_nvd_cpe(cpe)
    assert out['status'] == 'ok'
    assert out['items'][0]['cve']=='CVE-2099-0001'
    assert out['items'][0]['kev'] is True
    assert out['items'][0]['attack_vector'] == 'NETWORK'


def test_nvd_cpe_query_failure_is_not_clean_result(monkeypatch):
    def fail(*a, **k):
        raise RuntimeError('provider unavailable')
    monkeypatch.setattr(advisories, '_request', fail)
    advisories._search_nvd_cpe_cached.cache_clear()
    result = advisories.search_nvd_cpe('cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*')
    assert result['status'] == 'error'
    assert result['items'] == []
    advisories._search_nvd_cpe_cached.cache_clear()


def test_advisory_classification_exact_and_conditional():
    from utils.advisories import classify_advisory
    exact = {
        "cve": "CVE-2099-0002", "nvd_cpe_match": True, "conditional": False,
        "description": "A vulnerability affects product versions before 1.2.3."
    }
    conditional = {
        "cve": "CVE-2099-0003", "nvd_cpe_match": True, "conditional": True,
        "description": "A vulnerability exists when the optional module is enabled."
    }
    legacy = {"cve": "CVE-2099-0004", "cpe_match": True, "conditional": False, "description": "test"}
    assert classify_advisory(exact) == "VERSION_AFFECTED"
    assert classify_advisory(conditional) == "CONDITIONAL"
    assert classify_advisory(legacy) == "ADVISORY"


def test_correlation_deduplicates_same_cve():
    from utils.correlation import deduplicate_findings
    rows = [
        {"state":"VERSION_AFFECTED", "target":"1.2.3:443", "advisory":{"cve":"CVE-2099-0002"}},
        {"state":"VERSION_AFFECTED", "target":"1.2.3:443", "advisory":{"cve":"CVE-2099-0002"}},
    ]
    assert len(deduplicate_findings(rows)) == 1


def test_openssh_banner_version_extraction(monkeypatch):
    from modules import service_probe

    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def sendall(self, data):
            pass
        def settimeout(self, value):
            pass
        def recv(self, size):
            return b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n"

    monkeypatch.setattr(service_probe.socket, 'create_connection', lambda *a, **k: FakeSocket())
    out = service_probe.probe('127.0.0.1', 22, timeout=1)
    assert out['service'] == 'openssh'
    assert out['version'] == '6.0p1'
    assert service_probe.cpe_for_service(out['service'], out['version']) == 'cpe:2.3:a:openbsd:openssh:6.0p1:*:*:*:*:*:*:*'


def test_invalid_cpe_is_rejected_before_nvd(monkeypatch):
    from utils import advisories
    advisories._search_nvd_cpe_cached.cache_clear()
    called = {'value': False}
    def should_not_call(*args, **kwargs):
        called['value'] = True
        return {}
    monkeypatch.setattr(advisories, '_request', should_not_call)
    result = advisories.search_nvd_cpe('cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*')
    assert result['status'] == 'error'
    assert 'Invalid CPE' in result['error']
    assert result['items'] == []
    assert called['value'] is False


def test_nvd_valid_cpe_query_uses_vulnerability_filter(monkeypatch):
    from utils import advisories
    advisories._search_nvd_cpe_cached.cache_clear()
    seen = {}
    sample = {'vulnerabilities': []}
    def fake_request(url, timeout=10):
        seen['url'] = url
        return sample
    monkeypatch.setattr(advisories, '_request', fake_request)
    cpe = 'cpe:2.3:a:apache:http_server:2.2.22:*:*:*:*:*:*:*'
    result = advisories.search_nvd_cpe(cpe)
    assert result['status'] == 'ok'
    assert 'cpeName=' in seen['url']
    assert 'isVulnerable=' in seen['url']


def test_service_probe_failure_isolated(monkeypatch):
    from modules import firewall_portscan
    obj = firewall_portscan.FirewallPortScan()
    obj.set_option('TARGET', '127.0.0.1')
    obj.set_option('PORTS', '22')
    obj.set_option('THREADS', '1')
    obj.set_option('LIVE', 'false')

    class FakePool:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def map(self, fn, items):
            yield ('probe_error', '127.0.0.1', 22, None, 'IndexError: no such group')

    monkeypatch.setattr(firewall_portscan.concurrent.futures, 'ThreadPoolExecutor', FakePool)
    monkeypatch.setattr(firewall_portscan.socket, 'getaddrinfo', lambda *a, **k: [(2,1,6,'',('127.0.0.1',0))])
    rows = obj.run()
    assert rows and rows[0]['state'] == 'NOT_ASSESSED'



def test_not_a_vulnerability_record_is_filtered():
    from utils.exploitability import is_not_a_vulnerability
    assert is_not_a_vulnerability('The vendor states this mitigation has been assigned the identifier CVE-2016-5387; in other words, this is not a CVE ID for a vulnerability.')


def test_remote_plausible_exploitability():
    from utils.exploitability import assess
    adv = {
        'description': 'Remote attacker can trigger the issue.',
        'attack_vector': 'NETWORK',
        'privileges_required': 'NONE',
        'user_interaction': 'NONE',
        'attack_requirements': 'NONE',
        'conditional': False,
        'requirements': [],
    }
    row = {'service':'proftpd','version':'1.3.4a'}
    exposure = [{'module':'exposure/portscan','state':'CONFIRMED','service':'proftpd','version':'1.3.4a'}]
    out = assess(adv, row, exposure_rows=exposure)
    assert out['exploitability'] == 'NETWORK_RELEVANT'


def test_remote_conditional_with_privilege_requirement():
    from utils.exploitability import assess
    adv = {
        'description': 'Requires authenticated users to trigger the issue.',
        'attack_vector': 'NETWORK',
        'privileges_required': 'LOW',
        'user_interaction': 'NONE',
        'attack_requirements': 'NONE',
        'conditional': True,
        'requirements': [],
    }
    row = {'service':'proftpd','version':'1.3.4a'}
    exposure = [{'module':'exposure/portscan','state':'CONFIRMED','service':'proftpd','version':'1.3.4a'}]
    out = assess(adv, row, exposure_rows=exposure)
    assert out['exploitability'] == 'REMOTE_CONDITIONAL'


def test_non_network_is_not_remote_exploitable():
    from utils.exploitability import assess
    adv = {
        'description': 'Local users can trigger the issue.',
        'attack_vector': 'LOCAL',
        'privileges_required': 'LOW',
        'user_interaction': 'NONE',
        'attack_requirements': 'NONE',
        'conditional': True,
        'requirements': ['local user'],
    }
    row = {'service':'openssh','version':'6.0p1'}
    exposure = [{'module':'exposure/portscan','state':'CONFIRMED','service':'openssh','version':'6.0p1'}]
    out = assess(adv, row, exposure_rows=exposure)
    assert out['exploitability'] == 'LOCAL_OR_ADJACENT'


def test_summary_counts_not_vulnerability():
    from utils.correlation import summary
    counts = summary([{'state':'NOT_A_VULNERABILITY'}])
    assert counts['NOT_A_VULNERABILITY'] == 1



def test_cvss_v4_attack_requirements_are_parsed():
    from utils.advisories import _cvss
    cve = {
        'metrics': {
            'cvssMetricV40': [{
                'cvssData': {
                    'baseScore': 8.6,
                    'baseSeverity': 'HIGH',
                    'vectorString': 'CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
                    'attackVector': 'NETWORK',
                    'attackComplexity': 'LOW',
                    'attackRequirements': 'PRESENT',
                    'privilegesRequired': 'LOW',
                    'userInteraction': 'NONE',
                }
            }]
        }
    }
    out = _cvss(cve)
    assert out['attack_requirements'] == 'PRESENT'
    assert out['attack_vector'] == 'NETWORK'
    assert out['privileges_required'] == 'LOW'


def test_network_relevant_name_is_precise():
    from utils.exploitability import assess
    adv = {
        'description': 'Remote attacker can trigger the issue.',
        'attack_vector': 'NETWORK',
        'privileges_required': 'NONE',
        'user_interaction': 'NONE',
        'attack_requirements': 'NONE',
        'conditional': False,
        'requirements': [],
    }
    row = {'service':'proftpd','version':'1.3.4a'}
    exposure = [{'module':'exposure/portscan','state':'CONFIRMED','service':'proftpd','version':'1.3.4a'}]
    out = assess(adv, row, exposure_rows=exposure)
    assert out['exploitability'] == 'NETWORK_RELEVANT'


def test_non_condition_platform_text_does_not_force_conditional():
    from utils.advisories import _parse_cve
    item = {
        'cve': {
            'id': 'CVE-2099-0099',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang':'en','value':'A vulnerability affects Debian packages for product version 1.0.'}],
            'metrics': {},
            'references': [],
            'configurations': {'nodes':[{'operator':'OR','cpeMatch':[{'vulnerable':True,'criteria':'cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*'}]}]},
        }
    }
    out = _parse_cve(item, 'cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*')
    assert out['vendor_context'] is True
    assert out['conditional'] is False


def test_rejected_nvd_record_is_ignored():
    from utils.advisories import _parse_cve
    item = {'cve': {'id':'CVE-2099-0100','vulnStatus':'Rejected','descriptions':[{'lang':'en','value':'Rejected record'}]}}
    assert _parse_cve(item, 'cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*') is None


def test_correlation_skips_invalid_cpe_without_marking_nvd_unavailable(monkeypatch):
    from utils.correlation import correlate_service_findings
    good = {'module':'exposure/portscan','state':'CONFIRMED','target':'127.0.0.1:80','service':'nginx','version':'1.25.3','port':80,'role':'service_endpoint','cpe':'cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*'}
    bad = {'module':'web/waf','state':'OBSERVED','target':'http://example.test','service':'apache http server','version':'2.2.22','role':'server_fingerprint','cpe':'cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*'}
    monkeypatch.setattr('utils.correlation.search_nvd_cpe', lambda cpe, **kwargs: {'status':'ok','error':None,'items':[]})
    rows = correlate_service_findings([good, bad])
    assert not any(r.get('check') == 'NVD vulnerability correlation unavailable' for r in rows)


def test_correlation_prefers_endpoint_over_server_fingerprint(monkeypatch):
    from utils.correlation import correlate_service_findings
    endpoint = {'module':'exposure/portscan','state':'CONFIRMED','target':'203.0.113.10:80','service':'apache http server','version':'2.2.22','port':80,'role':'service_endpoint','cpe':'cpe:2.3:a:apache:http_server:2.2.22:*:*:*:*:*:*:*'}
    fingerprint = {'module':'web/waf','state':'OBSERVED','target':'http://example.test','service':'apache http server','version':'2.2.22','role':'server_fingerprint','cpe':'cpe:2.3:a:apache:http_server:2.2.22:*:*:*:*:*:*:*'}
    calls=[]
    monkeypatch.setattr('utils.correlation.search_nvd_cpe', lambda cpe, **kwargs: (calls.append(cpe) or {'status':'ok','error':None,'items':[]}))
    correlate_service_findings([endpoint, fingerprint])
    assert calls == [endpoint['cpe']]


def test_correlation_partial_nvd_failure_is_explicit(monkeypatch):
    from utils.correlation import correlate_service_findings
    a = {'module':'exposure/portscan','state':'CONFIRMED','target':'203.0.113.10:80','service':'nginx','version':'1.25.3','port':80,'role':'service_endpoint','cpe':'cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*'}
    b = {'module':'exposure/portscan','state':'CONFIRMED','target':'203.0.113.10:22','service':'openssh','version':'6.0p1','port':22,'role':'service_endpoint','cpe':'cpe:2.3:a:openbsd:openssh:6.0p1:*:*:*:*:*:*:*'}
    def fake(cpe, **kwargs):
        if 'openssh' in cpe:
            return {'status':'error','error':'NVD HTTP 503','items':[]}
        return {'status':'ok','error':None,'items':[]}
    monkeypatch.setattr('utils.correlation.search_nvd_cpe', fake)
    rows = correlate_service_findings([a,b])
    partial = [r for r in rows if r.get('state') == 'PARTIAL']
    assert len(partial) == 1
    assert '1 query(s) failed' in partial[0]['detail']


def test_grouped_console_output_does_not_duplicate_service_group(capsys):
    import clvx
    rows = [
        {'state':'VERSION_AFFECTED','severity':'HIGH','priority':'HIGH','service':'nginx','version':'1.25.3','target':'203.0.113.10:80','port':80,'exploitability':'NETWORK_RELEVANT','advisory':{'cve':'CVE-2099-0001','severity':'HIGH','score':8.0,'attack_vector':'NETWORK','privileges_required':'NONE','user_interaction':'NONE','attack_requirements':'NONE','kev':False,'nvd_cpe_match':True},'conclusion_reason':'network-relevant'},
        {'state':'VERSION_AFFECTED','severity':'MEDIUM','priority':'REVIEW','service':'nginx','version':'1.25.3','target':'203.0.113.10:80','port':80,'exploitability':'REMOTE_CONDITIONAL','advisory':{'cve':'CVE-2099-0002','severity':'MEDIUM','score':5.0,'attack_vector':'NETWORK','privileges_required':'LOW','user_interaction':'NONE','attack_requirements':'NONE','kev':False,'nvd_cpe_match':True},'conclusion_reason':'conditional'},
    ]
    clvx.print_findings(rows, verbose=False)
    out = capsys.readouterr().out
    lines = [line.strip() for line in out.splitlines()]
    assert 'nginx 1.25.3 | ports: 80' in lines
    assert out.count('nginx 1.25.3 | ports: 80') == 1
    assert 'PRIORITY' in out
    assert 'CVE-2099-0001' in out and 'CVE-2099-0002' in out


def test_summary_reports_network_relevance(capsys):
    import clvx
    clvx.print_summary([{'state':'VERSION_AFFECTED','exploitability':'NETWORK_RELEVANT','advisory':{'kev':False}}])
    out = capsys.readouterr().out
    assert 'Network-relevant matches  : 1' in out


def test_priority_labels_are_explicitly_non_confirmatory(capsys):
    import clvx
    rows = [{
        'state':'VERSION_AFFECTED','severity':'CRITICAL','priority':'CRITICAL',
        'service':'apache http server','version':'2.2.22','target':'203.0.113.10:80',
        'port':80,'exploitability':'NETWORK_RELEVANT',
        'advisory':{'cve':'CVE-2099-0101','severity':'CRITICAL','score':9.8,'kev':False},
        'conclusion_reason':'Version affected; exploitation is not confirmed.'
    }]
    clvx.print_findings(rows, verbose=False)
    out = capsys.readouterr().out
    assert 'Priority candidates — not confirmed vulnerabilities' in out
    assert 'Critical candidates : 1' in out
    assert 'Potential critical' not in out


def test_summary_has_unique_software_count(capsys):
    import clvx
    rows = [
        {'state':'CONFIRMED','module':'exposure/portscan','service':'apache','version':'2.2.22'},
        {'state':'CONFIRMED','module':'exposure/portscan','service':'apache','version':'2.2.22'},
    ]
    clvx.print_summary(rows)
    out = capsys.readouterr().out
    assert 'Unique software/version   : 1' in out
