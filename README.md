# Abyss 🌌

**Abyss** is a high-performance, professional-grade OSINT (Open Source Intelligence) command-line tool written in Rust. It is designed for researchers and security professionals to perform **passive reconnaissance** on web infrastructure and ownership.

By analyzing publicly available data—DNS records, HTTP headers, SSL certificates, and content fingerprints—Abyss helps reveal the underlying technologies and potential origin identities of a target domain without ever performing aggressive scanning.

## ✨ Features

- **🚀 Concurrent Analysis:** Built on `tokio` for lightning-fast, non-blocking parallel execution of all scan modules.
- **🔍 Content Fingerprinting:** Extracts Google Analytics IDs (`UA-`/`G-`), AdSense IDs (`pub-`), and CMS metadata to find links between different domains.
- **🛡️ WAF/CDN Detection:** Identifies if a target is behind Cloudflare, Akamai, AWS CloudFront, or other protection layers.
- **📜 Deep SSL/TLS Inspection:** Parses X.509 certificates to extract Subject Alternative Names (SANs) and Issuer details, often revealing hidden subdomains or hosting providers.
- **🌐 Passive DNS & GeoIP:** Retrieves A, MX, and TXT records, and maps IP addresses to their physical location and ISP.
- **🕵️ Intelligent Whois:** A custom-built asynchronous Whois client that follows referral servers to get the most accurate registration data.
- **🤖 Robots.txt Discovery:** Automatically finds and parses `robots.txt` to uncover paths the administrator intended to hide from search engines.
- **⚡ Modern UX:** Features rich progress bars powered by `indicatif` and structured logging with `tracing`.
- **📊 JSON Output:** Emits structured JSON to `stdout`, making it perfect for piping into `jq` or other data pipelines.

## 🛠️ Tech Stack (2026 Modern Edition)

- **Runtime:** [Tokio](https://tokio.rs/) (Async I/O)
- **HTTP Client:** [Reqwest](https://docs.rs/reqwest/) (with HTTP/3 & Brotli support)
- **DNS Resolver:** [Hickory Resolver](https://hickory-dns.org/) (formerly Trust-DNS)
- **HTML Parsing:** [Scraper](https://docs.rs/scraper/) & [Regex](https://docs.rs/regex/)
- **SSL Parsing:** [Rustls](https://github.com/rustls/rustls) & [x509-parser](https://docs.rs/x509-parser/)
- **CLI/UX:** [Clap v4](https://docs.rs/clap/), [Indicatif](https://docs.rs/indicatif/), [Tracing](https://docs.rs/tracing/)

## 🚀 Installation

Ensure you have the [Rust toolchain](https://rustup.rs/) installed.

```bash
# Clone the repository
git clone https://github.com/yourusername/abyss.git
cd abyss

# Build the project
cargo build --release

# The binary will be available at
./target/release/abyss --help
```

## 📖 Usage

### Basic Scan
```bash
abyss --target example.com
```

### Save Output to File
Since the tool prints logs to `stderr` and JSON to `stdout`, you can easily save the data:
```bash
abyss --target example.com > result.json
```

### Verbose Mode
Enable debug logs to see the underlying connection steps:
```bash
abyss --target example.com --verbose
```

## ⚖️ Disclaimer

Abyss is intended for **passive OSINT research only**. It does not perform port scanning, brute-forcing, or any form of aggressive interaction that could be classified as an attack. Always ensure your research complies with local laws and the terms of service of the target infrastructure.

---
*Built with 🦀 in Rust for a safer, more transparent web.*
