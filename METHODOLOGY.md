# CLVX Conclusion Methodology

CLVX separates observation, version applicability and vulnerability confirmation.

```text
Discovery
  -> Service identification
  -> Product/version evidence
  -> CPE mapping
  -> NVD applicability
  -> Deployment-condition analysis
  -> Exploitability context
  -> Conclusion
```

## Conclusion states

### CONFIRMED
Directly observed exposure, such as a reachable TCP endpoint or a service banner. This does not mean the endpoint is exploitable.

### VERSION_AFFECTED
NVD matched the detected CPE/version against a vulnerable applicability statement. This is a software/version result, not exploit confirmation.

### CONDITIONAL
The version matches, but extra requirements remain unresolved, such as a module, configuration, feature, local access, operating-system package condition, or another deployment prerequisite.

### ADVISORY
A related CVE/advisory exists, but available evidence is insufficient to establish that the deployment is affected.

### OBSERVED
A technical property was observed but is not itself proof of a vulnerability.

### NOT_ASSESSED
The required verification could not be completed. This is never interpreted as safe.

## Vulnerability sources

- NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
- NVD CPE Match Criteria API 2.0: https://nvd.nist.gov/developers/products
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Important interpretation rule

CLVX does not use product-name keyword matching as proof of a vulnerability. A CVE is correlated from an exact CPE query and then classified according to the conditions represented by authoritative vulnerability data.

A high CVSS score does not by itself mean the target is remotely exploitable. Attack vector, privileges, user interaction, deployment conditions and evidence quality still matter.

## Downstream packages

Remote banners can expose an upstream-looking version while a distribution has backported a security fix without changing that upstream version string. CLVX therefore does not claim that an upstream version match proves the installed package is still vulnerable.

## Network relevance and exploitability

CLVX deliberately avoids using `AV:N` as a synonym for "remotely exploitable". A network vector is combined with observed service exposure, privileges required, user interaction, CVSS v4 Attack Requirements when present, and explicit deployment-condition indicators.

The engine uses these labels:

- `NETWORK_RELEVANT` — network vector and matching exposed service observed.
- `REMOTE_CONDITIONAL` — network vector and exposed service observed, but prerequisites remain unresolved.
- `NETWORK_NOT_VERIFIED` — network vector exists but the matching service exposure was not independently established.
- `LOCAL_OR_ADJACENT` — non-network attack vector; external reachability alone does not establish exploitability.

`PARTIAL` means a source answered for part of the assessment while one or more independent queries failed. `NOT_ASSESSED` means the required verification did not complete. Neither state means safe.
