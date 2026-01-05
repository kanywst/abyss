# Abyss 🌌 - Deep Insight OSINT Tool

**Abyss** is a high-performance, professional-grade OSINT (Open Source Intelligence) command-line tool written in Rust. It is designed for researchers and security professionals to perform **passive reconnaissance**, **active vulnerability checks**, and **automated intelligence analysis** on web infrastructure.

Unlike standard scanners, Abyss doesn't just collect data; it analyzes it. By correlating DNS, HTTP, SSL, Subdomain, and Threat Intelligence data, it provides a logical assessment of a target's security posture and ownership footprint.

## ✨ Features

- **🧠 Intelligence Engine:** Automatically analyzes gathered data to produce an **Executive Summary**, **Risk Score (0-100)**, and actionable **Security Recommendations**.
- **🔍 Passive Subdomain Enumeration:** Leverages Certificate Transparency (CT) logs via `crt.sh` to find hidden subdomains without touching the target's infrastructure.
- **🛡️ Infrastructure Fingerprinting:** Identifies WAF/CDN layers (Cloudflare, Akamai), CMS platforms, and extracts tracking IDs (Google Analytics, AdSense).
- **📂 Sensitive File Discovery:** scans for exposed critical files (e.g., `.env`, `.git/config`, `backup.sql`) that often lead to identity leakage (inspired by the Mangamura case).
- **💀 Active Vulnerability Checks:** Integrates with **InternetDB (Shodan)** to identify open ports, CPEs, and unpatched vulnerabilities (CVEs) for the target IP.
- **📋 Security Audit:** Diagnoses missing security headers (HSTS, CSP, X-Frame-Options) and evaluates the overall attack surface.
- **📜 Deep SSL/TLS Inspection:** Full extraction of Subject Alternative Names (SANs) and Issuer details.
- **🕵️ Asynchronous Whois:** Custom TCP-based client that follows referral chains to the actual registrar.
- **🌐 Passive DNS & GeoIP:** Maps A, MX, and TXT records to physical locations and ISPs.
- **📊 Full-Disclosure HTML Report:** Generates a modern, HUD-style interactive dashboard containing **100% of the gathered data** with zero truncation.
- **🚀 Concurrent Architecture:** Built on `tokio` for lightning-fast, non-blocking parallel execution of all modules.

## 🛠️ Tech Stack

- **Runtime:** [Tokio](https://tokio.rs/) (Async I/O)
- **HTTP Client:** [Reqwest](https://docs.rs/reqwest/)
- **DNS Resolver:** [Hickory Resolver](https://hickory-dns.org/)
- **Threat Intel:** InternetDB (Shodan) API
- **Intelligence:** Custom Rule Engine
- **SSL Parsing:** [Rustls](https://github.com/rustls/rustls) & [x509-parser](https://docs.rs/x509-parser/)
- **HTML Generation:** Custom Template Engine (Single File HTML)

## 🚀 Installation

### Option 1: Via Homebrew (macOS / Linux)

You can install Abyss directly using Homebrew.

**Using the included Formula (Local):**

```bash
brew install --build-from-source Formula/abyss.rb
```

**Using a Custom Tap (Recommended once published):**

```bash
brew tap yourusername/abyss
brew install abyss
```

### Option 2: Build from Source (Rust)

Ensure you have the [Rust toolchain](https://rustup.rs/) installed.

```bash
# Clone and build
git clone https://github.com/yourusername/abyss.git
cd abyss
cargo install --path .
```

## 📖 Usage

### Comprehensive Scan with Intelligence Report

Generate both a JSON output (stdout) and a beautiful HTML dashboard:

```bash
abyss --target example.com --html report.html
```

### Pipe JSON into Data Pipelines

```bash
abyss --target example.com | jq '.dns.a_records'
```

### Investigation Workflow

1. Run scan: `abyss --target target.com --html report.html`
2. Open `report.html` in your browser.
3. Review the **Risk Score** and **Recommendations**.
4. Check **Sensitive Files** for any accidentally exposed backups or config files.
5. Explore the **Subdomain List** and **Shodan Vulnerabilities** to find unhardened origin servers.

## ⚖️ Disclaimer

Abyss is intended for **legal security research and authorized testing only**. While it primarily relies on passive data sources (OSINT), features like sensitive file scanning involve active requests to the target server.
**Do not scan targets you do not own or have explicit permission to test.** The authors assume no liability for misuse.
