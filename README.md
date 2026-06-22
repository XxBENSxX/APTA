# APTA — AI-Powered Penetration Testing Assistant

> A Final Year Project (PFA) by EMSI Cybersecurity Engineering Student

APTA is a Linux-based CLI tool that acts as an **intelligent analysis layer** on top of existing penetration testing tools. It does not replace tools like Nmap, Nikto, or WhatWeb — it makes their output understandable, correlated, and actionable through AI-powered interpretation.

---

## What APTA Does

1. **Orchestrates** Nmap, Nikto, and WhatWeb scans against a target
2. **Parses** raw tool outputs into a structured, normalized format
3. **Searches** for known CVEs based on detected service versions
4. **Correlates** findings across all tools to identify compound risks
5. **Analyzes** everything using Claude AI (Anthropic) for human-readable interpretation
6. **Generates** a professional PDF security report

---

## Architecture

```
Target IP/URL
     │
     ▼
┌─────────────────────────────────────┐
│         Orchestration Layer          │
│  (runs Nmap + Nikto + WhatWeb)      │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│         Parsing & Normalization      │
│  (structured finding objects)        │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      CVE Enrichment Layer            │
│  (NIST NVD API lookup by version)   │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      Correlation Engine              │
│  (cross-tool finding analysis)       │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      AI Interpretation Layer         │
│  (Claude API — grounded prompting)  │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      PDF Report Generator            │
│  (professional security report)      │
└─────────────────────────────────────┘
```

---

## Requirements

- Linux (Ubuntu/Debian recommended)
- Python 3.8+
- The following tools installed:
  - `nmap`
  - `nikto`
  - `whatweb`

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/APTA.git
cd APTA

# 2. Run the installer (installs system tools + Python dependencies)
chmod +x install.sh
sudo ./install.sh

# 3. Configure your API key
cp .env.example .env
nano .env   # Paste your Anthropic API key here
```

---

## Usage

```bash
# Basic scan
python3 apta.py --target 192.168.1.1

# Scan a web target (enables Nikto + WhatWeb)
python3 apta.py --target http://192.168.1.1

# Specify output report name
python3 apta.py --target 192.168.1.1 --output my_report

# Skip AI analysis (faster, no API key needed)
python3 apta.py --target 192.168.1.1 --no-ai
```

---

## Output

APTA generates:
- **Live terminal output** with color-coded findings during scan
- **PDF report** saved to `./reports/` with full AI analysis

---

## Ethical Disclaimer

**APTA is a decision-support and educational tool for authorized penetration testing only.**

Only use this tool against systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors accept no responsibility for misuse.

---

## Project Context

This tool was developed as a Final Year Project (PFA) at EMSI (École Marocaine des Sciences de l'Ingénieur) in the Cybersecurity Engineering program.

**Academic positioning:** Cybersecurity engineering project with an AI-augmented analysis component. The innovation lies in the correlation and interpretation pipeline, not in the scanning techniques themselves.
