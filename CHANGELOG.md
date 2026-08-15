# Changelog

## 4.5.3 — Final Analyst Output

- Refined the priority block to explicitly label entries as **priority candidates**, never confirmed vulnerabilities.
- Added distinct counts for critical, high and medium priority candidates.
- Added a compact top-priority view while preserving full per-service details under `--verbose`.
- Reduced standard CVE assessment text while keeping applicability, network context, CVSS/KEV and a concise decision.
- Added unique software/version count to the assessment summary.
- Clarified that `VERSION_AFFECTED` is not equivalent to exploitation confirmation.
- Preserved `PARTIAL` and `NOT_ASSESSED` as explicit uncertainty states.
- Updated NVD User-Agent to 4.5.3.
- Finalized regression coverage for analyst-oriented output.

## 4.5.2 — Analyst Output

- Added a compact `PRIORITY` section to standard terminal output.
- Added contextual critical/urgent, high and medium priority counts.
- Added a short list of top-priority findings without flooding the terminal.
- Reduced CVE detail in standard mode to applicability, network context, CVSS/KEV and conclusion.
- Moved CVSS vector components, references, full descriptions and conditions behind `--verbose`.
- Compactified `PARTIAL` and `NOT_ASSESSED` output in standard mode while preserving diagnostics under `--verbose`.
- Added an assessment-confidence indicator to the summary.
- Preserved deterministic per-service vulnerability grouping.
- Updated the NVD User-Agent to 4.5.2.
- Updated regression tests for analyst-oriented output.

## 4.5.1 — Reliability & Analyst Output

- Fixed mixed NVD coverage reporting so one invalid or failed CPE query no longer makes the entire correlation look unavailable.
- Correlation prefers concrete exposed service endpoints over duplicate server-header fingerprints.
- Reframed remote relevance as `NETWORK_RELEVANT` and `REMOTE_CONDITIONAL`.
- Separated package/vendor context from true conditional applicability.
- Rejected NVD records are filtered before correlation.
- Vulnerability output is grouped by product/version and limited per service in normal mode.
- Added explicit `PARTIAL` source status and richer summary fields.
- Reduced repeated CVE detail in standard terminal output.

## 4.5.0 — Applicability & Exploitability

- Added final applicability/exploitability assessment layer.
- Added explicit `VERSION_AFFECTED`, `CONDITIONAL`, `ADVISORY`, `NOT_A_VULNERABILITY` and `NOT_ASSESSED` conclusions.
- Added CVSS Attack Requirements context when available.
- Added CISA KEV enrichment.
- Improved conditional reasoning for deployment requirements and privilege context.
- Preserved a strict distinction between affected versions and confirmed exploitation.

## 4.4.1 — Regression Fixes

- Fixed OpenSSH service probe capture-group regression.
- Isolated service-probe failures so one parser cannot abort the port assessment.
- Added strict CPE validation before NVD queries.
- Corrected NVD `isVulnerable` query construction.
- Added regression tests for service identification and NVD query safety.

## 4.4.0 — Conclusion Engine

- Introduced the evidence-first conclusion pipeline.
- Added CPE/version applicability matching.
- Added downstream package/backport caveats.
- Added vulnerability grouping and consolidated full-assessment output.

## 4.3.0 — Vulnerability Correlation

- Reworked NVD correlation around exact CPE applicability.
- Added CVE deduplication and grouped vulnerability output.
- Added conservative applicability states and service-to-CPE mappings.

## 4.2.0 — Precision Exposure

- Added service/version identification after port discovery.
- Added TLS evidence and CISA KEV enrichment.
- Added Cloudflare to the correlated assessment flow.
