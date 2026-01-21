use crate::core::Result;
use crate::models::TargetData;
use std::fs::File;
use std::io::Write;

pub fn generate_report(data: &TargetData, path: &str) -> Result<()> {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Abyss Total Recall: {}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --border: #334155;
        }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background-color: var(--bg-primary); color: var(--text-primary); margin: 0; padding: 0; }}
        .container {{ max-width: 1600px; margin: 0 auto; padding: 40px 20px; }}
        header {{ border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: center; }}
        h1 {{ margin: 0; font-size: 2.5rem; background: linear-gradient(90deg, var(--accent), #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px; }}
        .card {{ background: var(--bg-secondary); border-radius: 12px; padding: 25px; border: 1px solid var(--border); overflow: hidden; }}
        .card h2 {{ margin-top: 0; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 10px; font-size: 1.2rem; }}
        ul {{ list-style: none; padding: 0; }}
        li {{ padding: 8px 0; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; font-size: 0.9rem; word-break: break-all; }}
        li:last-child {{ border-bottom: none; }}
        .tag {{ background: var(--border); padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }}
        .danger {{ color: var(--danger); font-weight: bold; }}
        .scroll-box {{ max-height: 400px; overflow-y: auto; background: #0f172a; border-radius: 8px; padding: 10px; }}
        .screenshot {{ width: 100%; border-radius: 8px; border: 1px solid var(--border); margin-top: 10px; }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Abyss Total Recall</h1>
                <p style="color: var(--text-secondary);">Target Domain: <strong>{}</strong></p>
            </div>
            <div style="text-align: right;">
                <div class="tag">0.2.0 Final</div>
                <div style="font-size: 0.8rem; margin-top: 5px;">{}</div>
            </div>
        </header>

        <div class="grid">
            <!-- 1. URLScan Screenshot (NEW: Visual Evidence) -->
            <div class="card" style="grid-column: span 2;">
                <h2>📸 Visual Evidence (Latest Screenshot)</h2>
                {}
            </div>

            <!-- 2. Attribution & Operator ID -->
            <div class="card" style="border-color: var(--accent);">
                <h2>🕵️ Operator Attribution</h2>
                <ul>
                    <li><span>Favicon Hash</span> <strong><a href="https://www.shodan.io/search?query=http.favicon.hash:{}" target="_blank">{}</a></strong></li>
                    <li><span>GA / Tracking IDs</span> <span>{}</span></li>
                    <li><span>AdSense / Ads</span> <span>{}</span></li>
                    <li><span>Affiliate / Pixel IDs</span> <span>{}</span></li>
                    <li><span>Crypto Wallets</span> <span>{}</span></li>
                    <li><span>Phone Numbers</span> <span>{}</span></li>
                    <li><span>Emails</span> <span>{}</span></li>
                </ul>
            </div>

            <!-- 3. Secrets & Leaks -->
            <div class="card" style="border-color: var(--danger);">
                <h2>🔑 Exposed Secrets & Leaked Keys</h2>
                <div class="scroll-box">
                    {}
                </div>
                 <p style="margin-top: 10px;"><a href="{}" target="_blank">🔎 Deep Search GitHub</a></p>
            </div>

            <!-- 4. Threat Intel (AlienVault & Shodan) -->
            <div class="card" style="border-color: var(--warning);">
                <h2>☣️ Threat Intelligence & Vulnerabilities</h2>
                <ul>
                    <li><span>Shodan Open Ports</span> <span class="tag">{}</span></li>
                    <li><span>Known Vulnerabilities (CVE)</span> <span class="danger">{}</span></li>
                    <li><span>AlienVault Malware Samples</span> <span>{}</span></li>
                    <li><span>Threat Tags</span> <span>{}</span></li>
                </ul>
            </div>

            <!-- 5. GeoIP & Infrastructure (GeoIP, DNS, Reverse DNS) -->
            <div class="card">
                <h2>🌍 Infrastructure Mapping</h2>
                <ul>
                    <li><span>Primary IP</span> <strong>{}</strong></li>
                    <li><span>Location</span> <span>{}, {}</span></li>
                    <li><span>ISP / ASN</span> <span>{} ({})</span></li>
                    <li><span>Cloud Provider</span> <span class="tag">{}</span></li>
                    <li><span>Server Banner</span> <span>{}</span></li>
                    <li><span>MX Banners</span> <span>{}</span></li>
                </ul>
            </div>

            <!-- 6. DNS & Network Neighbors (Reverse DNS) -->
            <div class="card">
                <h2>🕸️ Network Neighbors (Reverse DNS)</h2>
                <div class="scroll-box">
                    <ul>{}</ul>
                </div>
            </div>

            <!-- 7. Certificate Transparency (crt.sh) -->
            <div class="card">
                <h2>📜 SSL Certificate Intelligence (Related Domains)</h2>
                <div class="scroll-box">
                    <ul>{}</ul>
                </div>
            </div>

            <!-- 8. Wayback Machine (Time Travel) -->
            <div class="card">
                <h2>🕰️ Time Travel (Wayback Archives)</h2>
                <div class="scroll-box">
                    <ul>{}</ul>
                </div>
            </div>

            <!-- 9. JS Deep Dive -->
            <div class="card">
                <h2>📜 JavaScript Deep Analysis</h2>
                <div class="scroll-box">
                    <ul>{}</ul>
                </div>
            </div>

            <!-- 10. Sensitive Files (Robots, Sitemap, Security) -->
            <div class="card">
                <h2>📂 Sensitive Config Files</h2>
                <ul>
                    <li><span>Security.txt</span> <span>{}</span></li>
                    <li><span>Robots.txt Lines</span> <span>{}</span></li>
                    <li><span>Sitemap Entries</span> <span>{}</span></li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"#,
        data.target,                                      // 1
        data.target,                                      // 2
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), // 3
        render_screenshot(&data.urlscan),                 // 4
        data.attribution.favicon_hash.unwrap_or(0),       // 5
        data.attribution
            .favicon_hash
            .map(|h| h.to_string())
            .unwrap_or("-".to_string()), // 6
        data.attribution.ga_ids.join(", "),               // 7
        data.attribution.adsense_ids.join(", "),          // 8
        data.attribution.affiliate_ids.join(", "),        // 9
        data.attribution.crypto_wallets.join(", "),       // 10
        data.attribution.phone_numbers.join(", "),        // 11
        data.attribution.emails.join(", "),               // 12
        render_secrets(&data.secrets),                    // 13
        data.github_leaks
            .first()
            .map(|x| x.file_url.clone())
            .unwrap_or("#".to_string()), // 14
        data.shodan
            .as_ref()
            .map(|s| s
                .ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default(), // 15
        data.shodan
            .as_ref()
            .map(|s| s.vulns.join(", "))
            .unwrap_or_default(), // 16
        data.alienvault.malware_samples.len(),            // 17
        data.alienvault.related_tags.join(", "),          // 18
        data.geo_intelligence.ip,                         // 19
        data.geo_intelligence.city,
        data.geo_intelligence.country, // 20, 21
        data.geo_intelligence.isp,
        data.geo_intelligence.asn, // 22, 23
        data.cloud
            .as_ref()
            .map(|c| c.name.clone())
            .unwrap_or("Unknown".to_string()), // 24
        data.http
            .as_ref()
            .map(|h| h.server.clone())
            .unwrap_or_default(), // 25
        data.attribution.mx_banners.len(), // 26
        render_list(&data.passive_dns), // 27
        render_list(&data.ssl_intelligence.identities), // 28
        render_archives(&data.archives), // 29
        render_js(
            &data
                .http
                .as_ref()
                .map(|h| h.js_analysis.clone())
                .unwrap_or_default()
        ), // 30
        data.http
            .as_ref()
            .and_then(|h| h.security_txt.as_ref().map(|_| "Found"))
            .unwrap_or("Not Found"), // 31
        data.http.as_ref().map(|h| h.robots_txt.len()).unwrap_or(0), // 32
        data.http.as_ref().map(|h| h.sitemaps.len()).unwrap_or(0)  // 33
    );

    let mut file = File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}

fn render_screenshot(urlscan: &[crate::models::UrlScanRecord]) -> String {
    if let Some(record) = urlscan.first() {
        return format!(
            "<img src='{}' class='screenshot' alt='Latest Screenshot'><p style='font-size:0.8rem; color:var(--text-secondary);'>Taken on: {} (<a href='{}' target='_blank'>View Full Result</a>)</p>",
            record.screenshot, record.time, record.result_url
        );
    }
    "<p>No visual evidence available.</p>".to_string()
}

fn render_secrets(secrets: &[crate::models::SecretFound]) -> String {
    if secrets.is_empty() {
        return "<p style='color: var(--success);'>No secrets detected.</p>".to_string();
    }
    let mut s = String::from("<ul>");
    for x in secrets {
        s.push_str(&format!(
            "<li><span class='danger'>{}</span> <span class='tag'>{}</span></li>",
            x.kind, x.severity
        ));
    }
    s.push_str("</ul>");
    s
}

fn render_list(list: &[String]) -> String {
    if list.is_empty() {
        return "<li>No data found</li>".to_string();
    }
    list.iter()
        .take(200)
        .map(|x| format!("<li>{}</li>", x))
        .collect::<String>() // Increase to 200
}

fn render_archives(list: &[crate::models::ArchiveRecord]) -> String {
    if list.is_empty() {
        return "<li>No snapshots found</li>".to_string();
    }
    list.iter().take(100).map(|x| format!( // Increase to 100
        "<li><a href='http://web.archive.org/web/{}id_/{}' target='_blank'>{}</a> <span class='tag'>{}</span></li>",
        x.timestamp, x.url, x.timestamp, x.status
    )).collect::<String>()
}

fn render_js(list: &[crate::models::JsFileResult]) -> String {
    if list.is_empty() {
        return "<li>No JS data</li>".to_string();
    }
    list.iter().map(|x| format!(
        "<li><div><strong>{}</strong></div><div style='font-size:0.8rem'>Endpoints: {} | Secrets: <span class='danger'>{}</span></div></li>",
        x.url, x.endpoints.len(), x.secrets.len()
    )).collect::<String>()
}
