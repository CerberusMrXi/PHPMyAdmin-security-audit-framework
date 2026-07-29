# PHPMyAdmin Security Assessment Framework

**Authorized security auditing for phpMyAdmin deployments**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Authorized%20Use%20Only-red)](#disclaimer)
[![Async](https://img.shields.io/badge/Runtime-asyncio%20%2B%20aiohttp-green)](#)
[![Reports](https://img.shields.io/badge/Reports-HTML%20%7C%20JSON%20%7C%20CSV%20%7C%20Markdown-informational)](#reporting)
[![Status](https://img.shields.io/badge/Status-Research%20%2F%20Red%20Team-orange)](#)

> Dual-mode toolkit for **authorized** phpMyAdmin security assessments: a non-destructive audit engine (`pma_audit.py`) and a full assessment framework (`pma_audit_full.py`) with CVE checks and engagement reporting.

---

## Disclaimer

This project is intended **only** for:

- Authorized penetration tests and security assessments  
- Controlled lab / CTF environments  
- Defensive validation and patch verification  

**Unauthorized access to computer systems is illegal.** You are solely responsible for complying with applicable laws and obtaining **written permission** before testing any target. The authors accept no liability for misuse.

Both tools require interactive confirmation of authorization before scanning begins.

---

## Overview

| Component | File | Role |
|-----------|------|------|
| **Audit Engine** | `pma_audit.py` | Plugin-based, non-destructive security audit |
| **Full Framework** | `pma_audit_full.py` | End-to-end assessment: detection + CVE module checks + rich reporting |
| **Config** | `config.yaml` | Plugin enablement, scan profiles, report options |
| **Dependencies** | `requirements.txt` | Python package requirements |
| **Container** | `Dockerfile` | Optional containerized audit runner |

| Item | Detail |
|------|--------|
| Target | phpMyAdmin installations |
| Language | Python 3.9+ |
| Author | Sudeepa Wanigarathna |
| Primary use | Red team / blue team validation under contract |

---

## Which tool should I use?

| Need | Use |
|------|-----|
| Safe configuration & exposure review | **`pma_audit.py`** |
| Quick / full scan profiles via YAML | **`pma_audit.py`** |
| Import targets from Nmap XML | **`pma_audit.py`** |
| CVE module validation + exploit result tracking | **`pma_audit_full.py`** |
| Rich CLI (tables, panels) + multi-format exploit reports | **`pma_audit_full.py`** |

**Recommended flow:** run the audit engine first, then use the full framework only within a clearly scoped, authorized engagement.

---

## Features

### Audit Engine (`pma_audit.py`)

- **Plugin architecture** — modular checks, selectively enabled via CLI or YAML  
- **Async scanning** — concurrent plugin execution with `aiohttp`  
- **Severity model** — CRITICAL / HIGH / MEDIUM / LOW / INFO with CVSS and MITRE ATT&CK fields  
- **Scan modes** — `--quick` and `--full`, plus custom `--plugins`  
- **Target import** — Nmap XML (`--nmap`) and Burp export hooks (`--burp`)  
- **Reporting** — Markdown + HTML reports under `reports/`  

### Full Framework (`pma_audit_full.py`)

- **Two-phase workflow** — vulnerability detection, then controlled module checks  
- **CVE coverage** — known phpMyAdmin issues (e.g. CVE-2015-6830, CVE-2018-19968, CVE-2019-11768, CVE-2020-5504)  
- **Additional checks** — default credentials patterns, configuration exposure  
- **Rich terminal UI** — progress, summary tables, and finding panels  
- **Reporting** — HTML, Markdown, and CSV engagement artifacts  

---

## Audit plugins

| Plugin | Description |
|--------|-------------|
| `version_detection` | Detect phpMyAdmin version and known vulnerable builds |
| `security_headers` | Evaluate HTTP security headers |
| `exposed_interfaces` | Identify exposed or sensitive endpoints |
| `cookie_security` | Review cookie flags and session hardening |
| `tls_configuration` | Assess TLS/HTTPS posture |
| `directory_listing` | Detect directory listing exposure |
| `weak_http_methods` | Flag risky HTTP methods |
| `backup_exposure` | Search for exposed backup artifacts |
| `server_banner` | Analyze server / software banners |

Enable or disable plugins in `config.yaml`:

```yaml
enabled_plugins:
  - version_detection
  - security_headers
  - exposed_interfaces
  - cookie_security
  - tls_configuration
  - directory_listing
  - weak_http_methods
  - backup_exposure
  - server_banner

scan_profiles:
  quick:
    timeout: 10
    max_connections: 5
    enabled_plugins:
      - version_detection
      - security_headers
      - exposed_interfaces
  full:
    timeout: 30
    max_connections: 20
    retries: 3
    enabled_plugins: all
```

---

## Requirements

- Python **3.9+**
- Network access to an **authorized** target
- Written authorization for the engagement scope

---

## Installation

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>
python3 -m venv venv
source venv/bin/activate          # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Optional: setup helper

```bash
chmod +x setup.py
./setup.py
source venv/bin/activate
```

### Docker (audit engine)

```bash
docker build -t pma-audit .
docker run --rm -it -v "$(pwd)/reports:/app/reports" pma-audit https://lab.example/phpmyadmin
```

---

## Quick start

### 1. Non-destructive audit

```bash
python pma_audit.py https://lab.example/phpmyadmin
```

Confirm authorization when prompted (`yes`).

### 2. Quick or full audit profile

```bash
python pma_audit.py https://lab.example/phpmyadmin --quick
python pma_audit.py https://lab.example/phpmyadmin --full
```

### 3. Custom plugins & config

```bash
python pma_audit.py https://lab.example/phpmyadmin \
  -c config.yaml \
  -o reports \
  --plugins version_detection,security_headers,tls_configuration
```

### 4. Import from Nmap

```bash
python pma_audit.py unused -o reports --nmap scan.xml
```

### 5. Full assessment framework

```bash
python pma_audit_full.py https://lab.example/phpmyadmin -o reports
```

List available modules:

```bash
python pma_audit_full.py https://lab.example/phpmyadmin --list-exploits
```

Run a single named module (authorized lab only):

```bash
python pma_audit_full.py https://lab.example/phpmyadmin --exploit Config_Exposure
```

---

## CLI reference

### `pma_audit.py`

```text
python pma_audit.py TARGET [options]
```

| Argument | Description |
|----------|-------------|
| `target` | Target URL (e.g. `https://example.com/phpmyadmin`) |
| `-c`, `--config` | YAML/JSON configuration file |
| `-o`, `--output` | Report output directory (default: `reports`) |
| `--quick` | Quick scan mode |
| `--full` | Full scan mode |
| `--plugins` | Comma-separated plugin names |
| `--nmap` | Import hosts from Nmap XML |
| `--burp` | Import targets from Burp Suite export |

### `pma_audit_full.py`

```text
python pma_audit_full.py TARGET [options]
```

| Argument | Description |
|----------|-------------|
| `target` | Target URL |
| `-o`, `--output` | Report output directory (default: `reports`) |
| `--list-exploits` | List modules and exit |
| `--exploit` | Run a specific module by name |
| `--no-scan` | Skip detection phase; run modules only |
| `--version` | Show framework version |

---

## Reporting

Reports are written to the output directory (default `reports/`):

| Format | Audit engine | Full framework |
|--------|--------------|----------------|
| Markdown | Yes | Yes |
| HTML | Yes | Yes |
| JSON / structured | Via findings model | Findings + exploit results |
| CSV | Config-supported | Yes |

Typical artifacts include executive summary, severity counts, CVSS, MITRE mapping, remediation notes, and evidence fields suitable for engagement documentation.

---

## Project structure

```text
.
├── pma_audit.py           # Plugin-based audit engine
├── pma_audit_full.py      # Full assessment & CVE framework
├── config.yaml            # Default scan / plugin configuration
├── requirements.txt       # Python dependencies
├── setup.py               # Environment bootstrap helper
├── Dockerfile             # Container image for audit engine
├── reports/               # Generated assessment reports
├── .gitignore
└── README.md              # This file
```

---

## Mitigation guidance

If an assessment finds a vulnerable or misconfigured phpMyAdmin instance:

1. Upgrade phpMyAdmin to a **current, supported release**  
2. Restrict access (VPN, IP allowlists, reverse-proxy auth)  
3. Disable unused features and remove sample / leftover files  
4. Enforce HTTPS with strong TLS and secure cookie flags  
5. Rotate credentials and review logs after any confirmed exposure  
6. Re-run `pma_audit.py` to verify remediation  

---

## Responsible use

- Test **only** systems you own or have written authorization to assess  
- Prefer `pma_audit.py` for initial discovery and hardening review  
- Keep scope, evidence, and reports confidential per engagement terms  
- Disclose findings through proper channels when applicable  

---

## Contributing

Improvements to detection accuracy, reporting, plugin coverage, and defensive documentation are welcome. Open an issue or pull request with:

- Clear description of the change  
- How it was validated in a lab environment  
- Confirmation that no unauthorized targets were used  

---

## License

Provided for **authorized security testing and educational research only**.  
No warranty is provided. Use at your own risk and in compliance with the law.

---

## Author

**Sudeepa Wanigarathna**

---

<p align="center">
  <sub>For authorized security research · phpMyAdmin assessment toolkit</sub>
</p>
