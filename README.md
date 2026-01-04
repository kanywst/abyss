# Abyss 🌌 - Deep Insight OSINT Tool

**Abyss** is a high-performance, professional-grade OSINT (Open Source Intelligence) command-line tool written in Rust. It is designed for researchers and security professionals to perform **passive reconnaissance** and **automated intelligence analysis** on web infrastructure.

Unlike standard scanners, Abyss doesn't just collect data; it analyzes it. By correlating DNS, HTTP, SSL, and Subdomain data, it provides a logical assessment of a target's security posture and ownership footprint without ever performing aggressive scanning.

## ✨ Features (v0.3.0 "Deep Insight")

- **🧠 Intelligence Engine:** Automatically analyzes gathered data to produce an **Executive Summary**, **Risk Score (0-100)**, and actionable **Security Recommendations**.
- **🔍 Passive Subdomain Enumeration:** Leverages Certificate Transparency (CT) logs via `crt.sh` to find hidden subdomains without touching the target's infrastructure.
- **🛡️ Infrastructure Fingerprinting:** Identifies WAF/CDN layers (Cloudflare, Akamai, etc.), CMS platforms (WordPress, Drupal), and tracking IDs (Google Analytics, AdSense).
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
4. Explore the **Subdomain List** and **SANs** to find unhardened origin servers.

## ⚖️ Disclaimer

Abyss is intended for **passive OSINT research only**. It does not perform port scanning, brute-forcing, or any form of aggressive interaction that could be classified as an attack. Use responsibly and comply with local laws.

---
*Built with 🦀 in Rust for a deeper, more transparent web.*
