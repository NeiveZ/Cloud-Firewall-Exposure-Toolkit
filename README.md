# CLVX — Cloud, WAF & Firewall Exposure Assessment

CLVX is an **evidence-first security assessment toolkit** for authorized exposure management. Its purpose is not to produce the largest possible list of alerts. Its purpose is to answer, with a defensible chain of evidence:

> **What is exposed, what service is actually there, which software/version is observable, which vulnerability records match that software, which conditions remain unknown, and what deserves attention first?**

CLVX is deliberately conservative. It separates **observed exposure**, **software/version applicability**, **network relevance**, **deployment conditions**, and **confirmed vulnerability**. A failed provider query is never interpreted as a clean result, and a matching CVE is never presented as proof of successful exploitation.

---

## Design philosophy

CLVX follows a simple rule throughout the codebase:

```text
Evidence
   ↓
Identification
   ↓
Correlation
   ↓
Applicability
   ↓
Exploitability context
   ↓
Priority
   ↓
Conclusion
```

This means the tool intentionally distinguishes:

```text
Open port                ≠ vulnerability
WAF detected             ≠ WAF weakness
Cloud provider detected  ≠ cloud control-plane exposure
CVE exists               ≠ CVE applies to this deployment
Affected version         ≠ exploit confirmed
Network attack vector    ≠ remotely exploitable in this deployment
Provider failure         ≠ clean assessment
```

The result is designed for a security analyst who needs to know **why** a result exists, not only that it exists.

---

## Assessment pipeline

```text
Target
  ↓
Web / WAF / CDN fingerprinting
  ↓
Cloud-provider identification
  ↓
Public service exposure
  ↓
Service + product + version identification
  ↓
CPE normalization
  ↓
NVD applicability matching
  ↓
Deployment / condition analysis
  ↓
Network relevance assessment
  ↓
Contextual prioritization
  ↓
Analyst conclusion
```

The `full` command executes this pipeline and consolidates the evidence so a service is not repeatedly reported as unrelated findings just because it was observed by multiple modules.

Detailed methodology is available in [METHODOLOGY.md](METHODOLOGY.md).

---

# What CLVX assesses

## Web, WAF and CDN

CLVX can collect passive evidence for common edge and application-security technologies, including:

- Cloudflare
- AWS CloudFront / AWS edge indicators
- AWS WAF indicators
- Azure Front Door / Azure indicators
- Google Front End indicators
- Akamai
- Fastly
- Sucuri
- Imperva
- ModSecurity indicators

It can also collect:

- HTTP security headers
- HTTPS/TLS observations
- server fingerprints
- response and cookie indicators
- optional low-impact active WAF checks when explicitly authorized

A provider fingerprint is an **observation**. CLVX does not infer a specific control-plane policy from a public HTTP header alone.

### Active WAF assessment

Active WAF canaries are intentionally conservative and require explicit authorization:

```bash
./clvx.sh detect -u https://example.com --active --authorized
```

An accepted canary does **not** automatically mean the WAF is vulnerable. It is treated as behavioral evidence that requires interpretation.

---

## Cloud environments

CLVX supports four cloud/edge ecosystems:

### Cloudflare

- edge/CDN fingerprinting
- Cloudflare network classification
- origin-candidate analysis
- Host/SNI-aware observation
- cautious origin confidence

A non-Cloudflare IP is not automatically an origin. CLVX distinguishes an **origin candidate** from an **observed route match**.

### AWS

- CloudFront / AWS edge indicators
- public HTTP observations
- optional authenticated Security Group review
- identification of Internet-wide rules such as `0.0.0.0/0` and `::/0`

An open or broadly permitted security rule is treated as **exposure context**, not an automatic exploitable vulnerability.

### Azure

- Azure Front Door / service indicators
- public service observations
- optional authenticated NSG review
- storage exposure checks
- conservative handling of stale/orphaned DNS candidates

An unresolved CNAME or NXDOMAIN result is not automatically treated as subdomain takeover.

### Google Cloud / GCP

- Google Front End indicators
- `x-goog-*` evidence
- optional authenticated Compute Engine firewall review
- Internet-wide rule identification for `0.0.0.0/0` and `::/0`

Public Google Front End evidence does **not** by itself prove that Cloud Armor is enabled or configured.

---

# Network exposure and service identification

The port assessment is designed for **exposure identification**, not stealth or evasion.

It supports:

- IPv4 and IPv6 resolution
- conservative TCP reachability checks
- service/banner identification
- deterministic concurrency
- basic TLS evidence where applicable
- preserved open-port observations even when a service probe fails

The relationship is:

```text
TCP reachable
   ↓
service identified?
   ├── yes → product/version/evidence
   └── no  → endpoint observed, service not confirmed
```

An open port is an exposure finding, not automatically a vulnerability.

---

# Vulnerability intelligence

CLVX uses the **NVD CVE API 2.0** as its primary vulnerability source and the **CISA Known Exploited Vulnerabilities (KEV)** catalog as a prioritization signal.

Official sources:

- NVD Vulnerability API: https://nvd.nist.gov/developers/vulnerabilities
- NVD CPE / product data: https://nvd.nist.gov/developers/products
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CVSS documentation: https://www.first.org/cvss/

## CPE-first correlation

The intended relationship is:

```text
service
  ↓
product
  ↓
version
  ↓
valid CPE
  ↓
NVD cpeName + isVulnerable
  ↓
applicability
```

If a valid CPE cannot be produced, CLVX does not invent a vulnerability record. The affected portion is treated as `PARTIAL` or `NOT_ASSESSED` depending on the scope of the failure.

CLVX also filters rejected NVD records and recognizes authoritative non-vulnerability records.

---

# Conclusion states

## `CONFIRMED`

A directly observed exposure or other evidence-backed condition.

This state **does not automatically mean exploitation was confirmed**.

## `VERSION_AFFECTED`

The detected CPE/version matched an NVD applicability statement.

This is strong version evidence, but it does not prove that every deployment condition is present.

## `CONDITIONAL`

A match exists but an additional requirement remains unresolved, such as:

- optional module/feature
- configuration
- authentication
- privilege
- local execution context
- X11-related condition
- package/distribution context

## `ADVISORY`

A related vulnerability record exists, but the evidence is insufficient to associate it confidently with the observed deployment.

## `NOT_A_VULNERABILITY`

The authoritative record is an advisory, mitigation identifier or other non-vulnerability record. It is not counted as a vulnerability.

## `OBSERVED`

A technical property was observed but is not itself proof of a vulnerability.

## `PARTIAL`

Some independent assessment steps completed successfully while another source/query failed.

**Partial is not clean.**

## `NOT_ASSESSED`

Required evidence or authorization was unavailable, so the specific assessment could not be completed.

**Not assessed is not safe.**

---

# Network relevance and exploitability context

CLVX separates applicability from exploitability context.

### `NETWORK_RELEVANT`

The vulnerability record has a network attack vector and the corresponding service was independently observed as reachable.

It means:

> **the issue is relevant to an exposed network service.**

It does not mean the exploit was executed.

### `REMOTE_CONDITIONAL`

The corresponding service is exposed, but one or more additional conditions remain unresolved.

### `NETWORK_NOT_VERIFIED`

A network attack vector is present, but CLVX could not independently establish exposure of the matching service.

### `LOCAL_OR_ADJACENT`

The CVE's attack model is not purely network-based. Remote exposure alone is not enough to establish remote exploitability.

The distinction is deliberate:

```text
CVE exists
   ≠
Version affected
   ≠
Condition present
   ≠
Externally reachable
   ≠
Network relevant
   ≠
Remotely exploitable
   ≠
Exploit confirmed
```

---

# Analyst-oriented output

The standard CLI is intentionally compact.

A typical assessment is organized as:

```text
PRIORITY
  priority candidates — not confirmed vulnerabilities

EXPOSURE
  externally reachable services

VULNERABILITY ASSESSMENT
  grouped by product/version/service

SECURITY OBSERVATIONS
  technical observations that are not automatically vulnerabilities

PARTIAL
  independent checks that did not fully complete

NOT ASSESSED
  checks that could not be performed

ASSESSMENT SUMMARY
  executive counts and confidence
```

### Priority is deliberately non-confirmatory

The standard output uses labels such as:

```text
Priority candidates
Critical candidates
High candidates
Medium candidates
```

This avoids the dangerous interpretation that a CVSS score automatically means the host is confirmed vulnerable.

### Standard vs verbose output

Standard mode keeps each CVE focused on:

- state
- priority/severity
- CVE
- service/version
- applicability
- network context
- CVSS / KEV
- short assessment

Use:

```bash
./clvx.sh full -u https://example.com --verbose
```

for the full evidence set, including:

- vector components
- references
- long descriptions
- source errors
- additional conditions
- detailed provider context

---

# Commands

## WAF / web assessment

```bash
./clvx.sh detect -u https://example.com
```

Authorized active assessment:

```bash
./clvx.sh detect -u https://example.com --active --authorized
```

## Cloudflare

```bash
./clvx.sh cloudflare -d example.com
```

## AWS

```bash
./clvx.sh aws -d example.com
```

## Azure

```bash
./clvx.sh azure -d example.com
```

## Google Cloud / GCP

Public assessment:

```bash
./clvx.sh gcp -d example.com
```

Authenticated Compute Engine firewall review:

```bash
./clvx.sh gcp -d example.com --project MY_PROJECT
```

## Port/service exposure

```bash
./clvx.sh portscan -t 203.0.113.10 -p top100
```

Custom ports:

```bash
./clvx.sh portscan -t 203.0.113.10 -p 22,80,443,8080
```

Range:

```bash
./clvx.sh portscan -t 203.0.113.10 -p 1-1024
```

## Full assessment

```bash
./clvx.sh full -u https://example.com
```

Detailed assessment:

```bash
./clvx.sh full -u https://example.com --verbose
```

Report generation:

```bash
./clvx.sh full -u https://example.com --report
```

## Environment diagnostics

```bash
./clvx.sh --check
```

Version:

```bash
./clvx.sh --version
```

---

# Understanding a result

A correct interpretation of a CLVX finding should follow this order:

```text
1. Is the asset/service actually reachable?
2. Is the service identification reliable?
3. Is the product/version known?
4. Is the CPE valid?
5. Does NVD say that CPE/version is affected?
6. Are additional deployment conditions known?
7. Is the service relevant to the CVE's attack vector?
8. Is there a KEV signal?
9. What remains unverified?
10. What should be remediated first?
```

This prevents the common mistake of reading a CVE list as a list of confirmed vulnerabilities.

---

# Reports

Reports are optional.

```bash
./clvx.sh full -u https://example.com --report
```

The report package can contain JSON, TXT and Markdown representations of the assessment.

Default execution does **not** write reports automatically.

---

# Accuracy and safety model

CLVX deliberately avoids these shortcuts:

```text
Open port                ≠ vulnerability
WAF detected             ≠ WAF weakness
Cloud provider detected  ≠ cloud control-plane exposure
CVE keyword hit          ≠ applicable CVE
Affected version         ≠ confirmed exploitation
Network vector           ≠ exploit confirmed
Provider failure         ≠ clean assessment
Partial check            ≠ safe
Not assessed             ≠ safe
```

The project is optimized for **defensible assessment**, not maximum alert count.

---

# Testing

The repository contains regression tests for:

- WAF fingerprinting
- GCP module loading
- port parsing
- service/CPE mapping
- OpenSSH banner extraction
- NVD query construction
- invalid CPE rejection
- NVD provider failure handling
- rejected-record filtering
- CVE deduplication
- applicability classification
- network relevance classification
- conditional exploitability
- analyst-oriented console grouping
- summary reporting

Run:

```bash
pytest -q
```

The project should also pass:

```bash
python3 -m py_compile clvx.py modules/*.py utils/*.py
./clvx.sh --check
./clvx.sh --help
./clvx.sh --version
```

---

# Security and authorization

CLVX is intended for:

- assets you own
- environments where you have written authorization
- controlled security labs
- internal exposure management
- approved assessment engagements

The standard assessment path does not use stealth or evasion mechanisms. Active WAF checks require explicit `--authorized` use and are intentionally low-impact.

Cloud control-plane analysis must only be performed against accounts, subscriptions and projects you are authorized to inspect.

See:

- [ETHICS.md](ETHICS.md)
- [SECURITY.md](SECURITY.md)
- [METHODOLOGY.md](METHODOLOGY.md)

---

# Project status

**CLVX 4.5.3 — Final Analyst Output**

The current release emphasizes:

- evidence-first discovery
- service and version identification
- CPE-first vulnerability correlation
- conservative applicability analysis
- network relevance and exploitability context
- contextual priority candidates
- explicit partial and unknown states
- compact standard CLI output
- detailed `--verbose` investigation mode
- optional structured reports

The project should still be validated against controlled Cloudflare, AWS, Azure, GCP, WAF and firewall environments before being treated as a production-grade assessment authority.

---

# License

See [LICENSE](LICENSE).
