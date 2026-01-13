use crate::intelligence::Intelligence;
use crate::models::TargetInfo;
use anyhow::Result;
use std::fs::File;
use std::io::Write;

pub fn generate_html_report(info: &TargetInfo, intel: &Intelligence, filename: &str) -> Result<()> {
    let json_data = serde_json::to_string(info)?;
    let intel_json = serde_json::to_string(intel)?;

    let template = r###"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Abyss Intelligence: __DOMAIN__</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({ startOnLoad: true, theme: 'dark' });
    </script>
    <style>
        :root { --bg: #02040a; --card: #0d1117; --primary: #58a6ff; --secondary: #bc8cff; --accent: #3fb950; --danger: #f85149; --warn: #d29922; --text: #c9d1d9; --text-muted: #8b949e; --border: #30363d; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; line-height: 1.5; padding: 2rem; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-end; }
        h1 { font-size: 2rem; font-weight: 800; letter-spacing: -0.03em; color: #fff; }
        .dashboard { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.5rem; }
        .col-span-12 { grid-column: span 12; } .col-span-8 { grid-column: span 8; } .col-span-4 { grid-column: span 4; } .col-span-6 { grid-column: span 6; } .col-span-3 { grid-column: span 3; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; display: flex; flex-direction: column; height: 100%; }
        .card-header { font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 1rem; letter-spacing: 0.05em; }
        .risk-hero { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border: 1px solid var(--secondary); margin-bottom: 2rem; padding: 2rem; border-radius: 12px; display: flex; gap: 3rem; align-items: center; }
        .risk-score { font-size: 4rem; font-weight: 900; line-height: 1; font-family: 'JetBrains Mono'; color: var(--secondary); }
        .summary-text { font-size: 1.2rem; font-weight: 400; color: #fff; line-height: 1.6; }
        .finding { padding: 1rem; border-left: 4px solid var(--primary); background: rgba(88,166,255,0.05); margin-bottom: 1rem; border-radius: 0 4px 4px 0; }
        .finding.severity-Critical { border-color: var(--danger); }
        .finding.severity-High { border-color: var(--warn); }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { text-align: left; padding: 0.5rem; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        td { padding: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.03); vertical-align: top; }
        .scroll { max-height: 400px; overflow-y: auto; scrollbar-width: thin; }
        .pre { font-family: 'JetBrains Mono'; font-size: 0.8rem; background: #000; padding: 1rem; border-radius: 4px; overflow-x: auto; color: #8b949e; }
        .badge { padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; background: var(--border); color: var(--text); }
        .badge.vuln { background: var(--danger); color: #fff; }
        .badge.tech { background: rgba(188,140,255,0.1); color: var(--secondary); border: 1px solid rgba(188,140,255,0.3); }
        .sensitive-item { color: var(--danger); font-family: 'JetBrains Mono'; font-size: 0.85rem; margin-bottom: 0.2rem; }
        .tracking-id { color: var(--accent); font-weight: 700; font-family: 'JetBrains Mono'; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>__DOMAIN__</h1>
                <p style="color: var(--text-muted);">Passive Intelligence Deep Reconnaissance</p>
            </div>
            <div style="text-align: right;">
                <div class="font-mono" style="color: var(--secondary); font-weight: 700;">ABYSS</div>
                <div id="gen-date" style="font-size: 0.8rem; color: var(--text-muted);"></div>
            </div>
        </header>

        <div class="risk-hero">
            <div style="text-align: center;">
                <div class="risk-score" id="risk-val">0</div>
                <div style="font-size: 0.75rem; font-weight: 800; text-transform: uppercase; margin-top: 0.5rem;" id="risk-level">Risk Score</div>
            </div>
            <div class="summary-text" id="intel-summary"></div>
        </div>

        <div class="dashboard">
            <!-- Left Column: Attribution & Sensitivity -->
            <div class="card col-span-4">
                <div class="card-header">Target Attribution</div>
                <table style="margin-top: 0;">
                    <tr><td>Country</td><td id="attr-country">-</td></tr>
                    <tr><td>Operator</td><td id="attr-operator">-</td></tr>
                    <tr><td>Setup</td><td id="attr-setup">-</td></tr>
                    <tr><td>WAF / CDN</td><td id="attr-waf">-</td></tr>
                    <tr><td>Favicon Hash</td><td id="attr-favicon" class="font-mono">-</td></tr>
                </table>
                <div id="logic-reasoning" style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);"></div>
                
                <div class="card-header" style="margin-top: 2rem;">Sensitive Files (OSINT)</div>
                <div id="sensitive-files-list" class="scroll"></div>

                <div class="card-header" style="margin-top: 2rem;">Tracking & Ads IDs</div>
                <div id="tracking-ids" class="scroll"></div>
            </div>

            <!-- Main Column: Findings & Tech -->
            <div class="card col-span-8">
                <div class="card-header">Vulnerabilities & Findings</div>
                <div id="findings-container" class="scroll"></div>
                
                <div class="card-header" style="margin-top: 2rem;">Technology Stack</div>
                <div id="tech-stack-list" style="display: flex; gap: 0.5rem; flex-wrap: wrap;"></div>
            </div>

            <!-- Bottom Sections -->
            <div class="card col-span-12">
                <div class="card-header">Connection Pathway (Visualized)</div>
                <div class="mermaid" id="pathway-graph" style="display: flex; justify-content: center; background: #0d1117; padding: 1rem; border-radius: 6px;">
                    graph LR
                        Start((User)) --> Loading
                </div>
            </div>

            <div class="card col-span-4">
                <div class="card-header">SSL / TLS Certificate</div>
                <div class="scroll">
                    <table>
                        <tr><td>Subject CN</td><td id="ssl-cn" class="font-mono" style="font-size: 0.8rem;">-</td></tr>
                        <tr><td>Issuer</td><td id="ssl-issuer" class="font-mono" style="font-size: 0.8rem;">-</td></tr>
                        <tr><td>Valid From</td><td id="ssl-from" style="font-size: 0.8rem;">-</td></tr>
                        <tr><td>Valid To</td><td id="ssl-to" style="font-size: 0.8rem;">-</td></tr>
                    </table>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-top: 1rem;">SANs (Alt Names)</p>
                    <div id="ssl-sans" class="font-mono" style="font-size: 0.75rem; color: var(--text-muted); word-break: break-all;"></div>
                </div>
            </div>

            <div class="card col-span-4">
                <div class="card-header">DNS Infrastructure</div>
                <div class="scroll">
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">A Records</p>
                    <div id="dns-a" class="font-mono" style="font-size: 0.8rem; margin-bottom: 0.5rem;"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">MX Records</p>
                    <div id="dns-mx" class="font-mono" style="font-size: 0.8rem; margin-bottom: 0.5rem;"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">TXT Records</p>
                    <div id="dns-txt" class="font-mono" style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.5rem;"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">ISP Info</p>
                    <div id="geo-info" style="font-size: 0.8rem; color: var(--text-muted);"></div>
                </div>
            </div>

            <div class="card col-span-4">
                <div class="card-header">Discovered Subdomains</div>
                <div id="subdomains-list" class="scroll font-mono" style="font-size: 0.75rem; color: var(--text-muted);"></div>
            </div>

            <div class="card col-span-6">
                <div class="card-header">Content Intel</div>
                <div class="scroll">
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">Emails Found</p>
                    <div id="email-list" class="font-mono" style="margin-bottom: 1rem; color: var(--secondary);"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">Social Media</p>
                    <div id="social-list" class="font-mono" style="font-size: 0.8rem; margin-bottom: 1rem;"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">External Connections</p>
                    <div id="link-list" class="font-mono" style="font-size: 0.75rem; color: var(--text-muted);"></div>
                </div>
            </div>

            <div class="card col-span-6">
                <div class="card-header">Infrastructure (Shodan)</div>
                <div class="scroll">
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">Open Ports</p>
                    <div id="ports-list" style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;"></div>
                    
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">Vulnerabilities</p>
                    <div id="vulns-list" style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;"></div>

                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">Software (CPEs)</p>
                    <div id="cpe-list" class="font-mono" style="font-size: 0.7rem; color: var(--text-muted);"></div>
                </div>
            </div>

            <!-- Full Disclosure Raw Section -->
            <div class="card col-span-12">
                <div class="card-header">Raw Analysis Data & Export</div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <div>
                        <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">WHOIS Data</p>
                        <pre class="pre scroll" id="whois-content" style="height: 300px;"></pre>
                    </div>
                    <div>
                        <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">Redirect Chain</p>
                        <div id="redirect-chain" class="font-mono" style="font-size: 0.8rem; padding: 1rem; background: #000; border-radius: 4px; margin-bottom: 1rem;"></div>
                        <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem;">Robots.txt Rules</p>
                        <div id="robots-list" class="font-mono" style="font-size: 0.8rem; padding: 1rem; background: #000; border-radius: 4px;"></div>
                    </div>
                </div>
                <details style="margin-top: 1rem;">
                    <summary style="cursor: pointer; font-size: 0.85rem; color: var(--text-muted);">Show Full JSON Output</summary>
                    <textarea class="pre" style="width: 100%; height: 300px; border: none; margin-top: 0.5rem;" readonly>__JSON_DATA__</textarea>
                </details>
            </div>
        </div>
    </div>

    <script>
        const data = __JSON_DATA__;
        const intel = __INTEL_DATA__;
        document.getElementById('gen-date').textContent = new Date().toLocaleString();
        const el = id => document.getElementById(id);

        // Header & Risk
        el('risk-val').textContent = intel.risk_score;
        el('risk-level').textContent = intel.risk_level + ' Risk';
        el('intel-summary').innerHTML = intel.summary.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');

        // Attribution
        const attr = intel.attribution || {};
        el('attr-country').textContent = attr.probable_country || 'Unknown';
        el('attr-operator').textContent = attr.operator_type || 'Unknown';
        el('attr-setup').textContent = attr.infra_setup || 'Unknown';
        el('attr-waf').textContent = data.http?.waf || 'Direct Exposure';
        el('attr-favicon').textContent = data.http?.fingerprint?.favicon_hash || 'None';
        el('logic-reasoning').innerHTML = (attr.logic_reasoning || []).map(r => `• ${r}`).join('<br>');

        // Findings
        el('findings-container').innerHTML = (intel.findings || []).map(f => `
            <div class="finding severity-${f.severity}">
                <div style="font-weight: 700; color: #fff;">${f.title}</div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.5rem;">${f.description}</div>
                <div style="font-size: 0.8rem; color: var(--primary);"><b>Recommendation:</b> ${f.recommendation}</div>
            </div>
        `).join('') || 'No major findings detected.';

        // Tech Stack
        el('tech-stack-list').innerHTML = (data.http?.fingerprint?.tech_stack || []).map(t => `<span class="badge tech">${t}</span>`).join(' ');

        // DNS
        el('dns-a').innerHTML = (data.dns?.a_records || []).join('<br>') || 'No A records';
        el('dns-mx').innerHTML = (data.dns?.mx_records || []).join('<br>') || 'No MX records';
        el('dns-txt').innerHTML = (data.dns?.txt_records || []).join('<br>') || 'No TXT records';
        el('geo-info').innerHTML = `ISP: ${data.dns?.geo_ip?.isp || 'Unknown'}<br>IP: ${data.dns?.geo_ip?.ip || '-'}`;

        // SSL
        const ssl = data.ssl || {};
        el('ssl-cn').textContent = ssl.subject_cn || '-';
        el('ssl-issuer').textContent = ssl.issuer || '-';
        el('ssl-from').textContent = ssl.valid_from || '-';
        el('ssl-to').textContent = ssl.valid_to || '-';
        el('ssl-sans').textContent = (ssl.sans || []).join(', ') || 'None';

        // Subdomains
        el('subdomains-list').innerHTML = (data.subdomains || []).map(s => `<div>${s}</div>`).join('') || 'None found';

        // Content
        el('email-list').innerHTML = (data.http?.fingerprint?.emails || []).join('<br>') || 'None';
        el('social-list').innerHTML = (data.http?.fingerprint?.social_links || []).join('<br>') || 'None';
        el('link-list').innerHTML = (data.http?.fingerprint?.external_links || []).map(l => `<div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${l}</div>`).join('') || 'None';
        
        // Tracking IDs
        const fp = data.http?.fingerprint || {};
        let trackHtml = '';
        if(fp.ga_ids?.length) trackHtml += `<div><b>GA:</b> <span class="tracking-id">${fp.ga_ids.join(', ')}</span></div>`;
        if(fp.adsense_ids?.length) trackHtml += `<div><b>AdSense:</b> <span class="tracking-id">${fp.adsense_ids.join(', ')}</span></div>`;
        if(fp.crypto_wallets?.length) trackHtml += `<div style="margin-top:0.5rem; border-top:1px dashed #333; padding-top:0.5rem;"><b>Crypto:</b><br>${fp.crypto_wallets.map(w => `<span class="badge" style="background:var(--warn); color:#000;">${w}</span>`).join(' ')}</div>`;
        el('tracking-ids').innerHTML = trackHtml || 'No tracking IDs found.';

        // Shodan
        const sho = data.shodan || {};
        el('ports-list').innerHTML = (sho.ports || []).map(p => `<span class="badge">${p}</span>`).join(' ');
        el('vulns-list').innerHTML = (sho.vulns || []).map(v => `<span class="badge vuln">${v}</span>`).join(' ') || 'Clean';
        el('cpe-list').innerHTML = (sho.cpes || []).join('<br>') || 'None';

        // Sensitive Files
        const sens = data.http?.sensitive_files || [];
        el('sensitive-files-list').innerHTML = sens.length > 0 
            ? sens.map(f => `<div class="sensitive-item">🚨 FOUND: ${f}</div>`).join('')
            : '<div style="color: var(--accent); font-size: 0.85rem;">Clean (No leaks found)</div>';

        // Raw Data
        el('whois-content').textContent = data.whois || 'No WHOIS available.';
        el('redirect-chain').innerHTML = (data.http?.redirect_chain || []).map((u, i) => `<div>${i+1}. ${u}</div>`).join('');
        el('robots-list').innerHTML = (data.http?.robots_txt || []).map(r => `<div>Disallow: ${r}</div>`).join('') || 'None';

        // Mermaid Graph Generation
        let graph = 'graph LR\n';
        graph += '    User((User)) -->|Start Scan| D[Domain: ' + data.domain + ']\n';
        
        // DNS Path
        if (data.dns) {
            graph += '    D -->|Resolve| DNS{DNS}\n';
            if (data.dns.a_records && data.dns.a_records.length > 0) {
                 data.dns.a_records.forEach((ip, i) => {
                     let nodeId = 'IP' + i;
                     graph += `    DNS -->|A Record| ${nodeId}[${ip}]\n`;
                     
                     // GeoIP Link
                     if (data.dns.geo_ip && data.dns.geo_ip.ip === ip) {
                         graph += `    ${nodeId} -->|Hosted In| GEO[${data.dns.geo_ip.country} / ${data.dns.geo_ip.isp.replace(/[^a-zA-Z0-9 ]/g, '')}]\n`;
                     }
                 });
            }
        }

        // Redirect Path
        if (data.http && data.http.redirect_chain && data.http.redirect_chain.length > 0) {
             let chain = data.http.redirect_chain;
             chain.forEach((url, i) => {
                 let safeUrl = url.replace(/["'()]/g, '');
                 if (safeUrl.length > 30) safeUrl = safeUrl.substring(0, 27) + '...';
                 let nodeId = 'R' + i;
                 if (i === 0) {
                     graph += `    D -.->|HTTP Req| ${nodeId}(${safeUrl})\n`;
                 } else {
                     graph += `    R${i-1} -->|3xx Redirect| ${nodeId}(${safeUrl})\n`;
                 }
             });
        }

        // Final Node attributes
        graph += '    classDef default fill:#0d1117,stroke:#30363d,stroke-width:1px,color:#c9d1d9;\n';
        graph += '    classDef accent fill:#1f6feb,stroke:#58a6ff,color:#fff;\n';
        graph += '    class GEO accent;\n';

        el('pathway-graph').textContent = graph;
    </script>
</body>
</html>
"###;

    let final_html = template
        .replace("__DOMAIN__", &info.domain)
        .replace("__JSON_DATA__", &json_data)
        .replace("__INTEL_DATA__", &intel_json);

    let mut file = File::create(filename)?;
    file.write_all(final_html.as_bytes())?;
    Ok(())
}
