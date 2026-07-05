# CLVX

> Cloud & Firewall Exposure Toolkit — cloud metadata, WAF fingerprinting, and exposure checks.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Category](https://img.shields.io/badge/Category-Cloud%20Exposure-06b6d4?style=flat-square)
![Status](https://img.shields.io/badge/Interface-Direct%20CLI-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

---

## Overview

CLVX helps identify cloud and firewall exposure indicators during authorized assessments.

The project is now CLI-based and avoids interactive framework-style commands.

---

## Features

- WAF and CDN fingerprinting.
- Cloud metadata exposure checks.
- AWS/Azure/GCP public exposure indicators.
- Header-based cloud detection.
- Firewall behavior observations.
- Polite port checks.
- JSON/TXT/HTML report generation.
- Clean risk summary.

---

## Installation

```bash
git clone https://github.com/NeiveZ/CLVX.git
cd CLVX
chmod +x clvx.sh
./clvx.sh --install
```

Validate:

```bash
./clvx.sh --check
```

---

## Usage

```bash
./clvx.sh <command> [options]
```

Help:

```bash
./clvx.sh --help
```

---

## Commands

### Detect WAF/CDN/cloud headers

```bash
./clvx.sh detect -u https://example.com
```

### Cloud metadata check

```bash
./clvx.sh metadata -u http://169.254.169.254 --authorized
```

### AWS exposure check

```bash
./clvx.sh aws -d example.com
```

### Azure exposure check

```bash
./clvx.sh azure -d example.com
```

### GCP exposure check

```bash
./clvx.sh gcp -d example.com
```

### Polite port scan

```bash
./clvx.sh portscan -t 192.168.1.10 -p 80,443 --timing polite
```

---

## Output Example

```text
CLVX Exposure Summary

Target       https://example.com
Command      detect
Findings     4

Severity     Target              Check             Detail
INFO         example.com         CDN               Cloudflare detected
LOW          example.com         Server Header     Header disclosure
MEDIUM       example.com         Security Headers  Missing CSP
```

---

## Recommended Procedure

1. Start with passive detection:

```bash
./clvx.sh detect -u https://example.com
```

2. Review cloud hints:

```bash
./clvx.sh aws -d example.com
./clvx.sh azure -d example.com
./clvx.sh gcp -d example.com
```

3. Run authorized metadata checks only inside permitted cloud environments:

```bash
./clvx.sh metadata --provider aws --authorized
```

4. Export reports:

```bash
./clvx.sh detect -u https://example.com --json --txt --out reports/clvx_example
```

---

## Safety

Metadata and firewall behavior checks must only be used in scoped environments. Do not run active evasion or probing against third-party assets.

---

## License

MIT License.
