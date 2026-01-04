use anyhow::Result;
use crate::models::TargetInfo;
use crate::intelligence::Intelligence;
use std::fs::File;
use std::io::Write;

pub fn generate_html_report(info: &TargetInfo, intel: &Intelligence, filename: &str) -> Result<()> {
    let json_data = serde_json::to_string(info)?;
    let intel_json = serde_json::to_string(intel)?;
    
    let html = format!(r###"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Abyss Full Report: {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {{ 
            --bg-body: #050505;
            --bg-card: #0a0a0a;
            --bg-header: rgba(5, 5, 5, 0.9);
            --accent-primary: #00f3ff;
            --accent-secondary: #bd00ff;
            --accent-warn: #ffb800;
            --accent-danger: #ff003c;
            --text-main: #e0e6ed;
            --text-muted: #6e7681;
            --border: #1f1f1f;
            --code-bg: #000;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            font-size: 14px;
            line-height: 1.5;
            padding-bottom: 100px;
        }}

        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 0 2rem;
        }}

        /* Header */
        header {{
            position: sticky;
            top: 0;
            z-index: 100;
            background: var(--bg-header);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 0;
            margin-bottom: 2rem;
        }}

        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        h1 {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-main);
            margin: 0;
        }}

        .logo {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: var(--accent-primary);
            font-size: 1.25rem;
            letter-spacing: 0.1em;
        }}

        /* Grid */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 1.5rem;
        }}
        .col-span-4 {{ grid-column: span 4; }}
        .col-span-6 {{ grid-column: span 6; }}
        .col-span-8 {{ grid-column: span 8; }}
        .col-span-12 {{ grid-column: span 12; }}

        /* Cards */
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }}
        .card-header {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            background: rgba(255,255,255,0.02);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-title {{
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--accent-primary);
        }}
        .card-body {{ padding: 0; flex: 1; }} /* Removed padding for full-width tables */
        .card-content {{ padding: 1rem; }} /* Internal padding if needed */

        /* Tables (Full Data) */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            font-family: 'JetBrains Mono', monospace;
        }}
        th {{
            text-align: left;
            padding: 0.5rem 1rem;
            color: var(--text-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border);
            background: rgba(255,255,255,0.01);
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 0.5rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            word-break: break-all; /* Ensure long strings wrap */
        }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}

        /* Lists */
        .data-list {{
            list-style: none;
            max-height: 500px; /* Allow taller lists */
            overflow-y: auto;
        }}
        .data-list li {{
            padding: 0.5rem 1rem;
            border-bottom: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }}
        .data-list li:last-child {{ border-bottom: none; }}

        /* Preformatted Text (Whois, JSON) */
        .pre-block {{
            background: var(--code-bg);
            color: #a5b3ce;
            padding: 1rem;
            margin: 0;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            border: none;
            width: 100%;
            max-height: 600px;
            overflow-y: auto;
        }}

        /* Status Badges */
        .badge {{
            display: inline-block;
            padding: 0.1rem 0.4rem;
            border-radius: 2px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            font-family: 'Inter', sans-serif;
        }}
        .badge.blue {{ background: rgba(0, 243, 255, 0.1); color: var(--accent-primary); border: 1px solid rgba(0, 243, 255, 0.3); }}
        .badge.purple {{ background: rgba(189, 0, 255, 0.1); color: var(--accent-secondary); border: 1px solid rgba(189, 0, 255, 0.3); }}
        .badge.red {{ background: rgba(255, 0, 60, 0.1); color: var(--accent-danger); border: 1px solid rgba(255, 0, 60, 0.3); }}

        /* Risk Meter */
        .risk-section {{
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 2rem;
            background: linear-gradient(90deg, rgba(255,0,60,0.05) 0%, transparent 100%);
        }}
        .risk-score {{
            font-size: 3rem;
            font-weight: 800;
            line-height: 1;
            font-family: 'JetBrains Mono', monospace;
        }}
        .risk-desc {{ flex: 1; }}
        .risk-title {{ font-size: 1.2rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--text-main); }}
        .risk-summary {{ color: var(--text-muted); font-size: 0.95rem; }}

        /* Footer */
        footer {{
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <header>
        <div class="container header-content">
            <div>
                <h1>{domain}</h1>
                <div style="color: var(--text-muted); font-size: 0.85rem;">Comprehensive Intelligence Report</div>
            </div>
            <div class="logo">ABYSS v0.3</div>
        </div>
    </header>

    <div class="container">
        
        <!-- Risk & Summary -->
        <div class="card mb-4" style="margin-bottom: 2rem;">
            <div class="risk-section">
                <div style="text-align:center">
                    <div class="risk-score" id="risk-val">0</div>
                    <div style="font-size:0.8rem; text-transform:uppercase; letter-spacing:0.1em; color:var(--text-muted)">Risk Score</div>
                </div>
                <div class="risk-desc">
                    <div class="risk-title" id="risk-level">Analysis</div>
                    <div class="risk-summary" id="risk-summary-text"></div>
                </div>
            </div>
        </div>

        <div class="dashboard">
            
            <!-- Findings -->
            <div class="card col-span-12">
                <div class="card-header"><div class="card-title">Security Findings</div></div>
                <div class="card-body">
                    <div id="findings-table"></div>
                </div>
            </div>

            <!-- DNS Records (ALL) -->
            <div class="card col-span-6">
                <div class="card-header">
                    <div class="card-title">DNS Records (Full)</div>
                    <div class="badge blue" id="dns-count">0 Records</div>
                </div>
                <div class="card-body">
                    <div id="dns-table"></div>
                </div>
            </div>

            <!-- Subdomains (ALL) -->
            <div class="card col-span-6">
                <div class="card-header">
                    <div class="card-title">Subdomains (Full List)</div>
                    <div class="badge purple" id="sub-count">0 Found</div>
                </div>
                <div class="card-body">
                    <ul class="data-list" id="subdomain-list"></ul>
                </div>
            </div>

            <!-- HTTP Headers (ALL) -->
            <div class="card col-span-6">
                <div class="card-header"><div class="card-title">HTTP Headers</div></div>
                <div class="card-body">
                    <div id="headers-table"></div>
                </div>
            </div>

            <!-- Redirects & Robots -->
            <div class="card col-span-6">
                <div class="card-header"><div class="card-title">Navigation & Robots</div></div>
                <div class="card-body">
                    <div class="card-content">
                        <div style="margin-bottom:1rem"><strong>Redirect Chain:</strong></div>
                        <ul class="data-list" id="redirect-list" style="margin-bottom:1rem; max-height:none; border:1px solid var(--border); border-radius:4px;"></ul>
                        
                        <div style="margin-bottom:1rem"><strong>Robots.txt:</strong></div>
                        <pre class="pre-block" id="robots-content" style="max-height:200px; border:1px solid var(--border); border-radius:4px;"></pre>
                    </div>
                </div>
            </div>

            <!-- SSL / SANs (ALL) -->
            <div class="card col-span-12">
                <div class="card-header">
                    <div class="card-title">SSL Certificate & SANs</div>
                    <div class="badge blue" id="sans-badge">0 SANs</div>
                </div>
                <div class="card-body">
                    <div class="card-content">
                        <table style="margin-bottom:1rem">
                            <tr><th style="width:20%">Subject CN</th><td id="ssl-cn">-</td></tr>
                            <tr><th>Issuer</th><td id="ssl-issuer">-</td></tr>
                            <tr><th>Validity</th><td id="ssl-valid">-</td></tr>
                        </table>
                        <div style="font-weight:600; margin-bottom:0.5rem; color:var(--text-muted)">Subject Alternative Names (Full List)</div>
                        <div id="sans-container" style="max-height:300px; overflow-y:auto; border:1px solid var(--border);"></div>
                    </div>
                </div>
            </div>

            <!-- WHOIS (RAW) -->
            <div class="card col-span-12">
                <div class="card-header"><div class="card-title">WHOIS Record (Raw)</div></div>
                <div class="card-body">
                    <pre class="pre-block" id="whois-raw"></pre>
                </div>
            </div>

            <!-- Raw JSON Export -->
            <div class="card col-span-12">
                <div class="card-header"><div class="card-title">Full Technical Data (JSON Export)</div></div>
                <div class="card-body">
                    <textarea class="pre-block" style="height:300px; resize:vertical; background:#000;" readonly>{json_data}</textarea>
                </div>
            </div>

        </div>
    </div>

    <footer>
        Generated by Abyss OSINT Tool &bull; No data was truncated in this report.
    </footer>

    <script>
        const data = {json_data};
        const intel = {intel_json};
        const el = id => document.getElementById(id);
        const safe = (val) => (val === null || val === undefined) ? '' : val;

        // --- Risk ---
        el('risk-val').textContent = intel.risk_score;
        el('risk-val').style.color = intel.risk_score > 50 ? '#ff003c' : (intel.risk_score > 20 ? '#ffb800' : '#00f3ff');
        el('risk-level').textContent = intel.risk_level + " Risk Assessment";
        // Convert markdown bold to html
        el('risk-summary-text').innerHTML = intel.summary.replace(/\*\*(.*?)\*\*/g, '<strong style="color:#fff">$1</strong>');

        // --- Findings ---
        if (intel.findings.length === 0) {{
            el('findings-table').innerHTML = '<div style="padding:1rem; color:var(--text-muted)">No critical findings.</div>';
        }} else {{
            let fHtml = '<table><thead><tr><th style="width:10%">Severity</th><th style="width:25%">Finding</th><th>Description & Recommendation</th></tr></thead><tbody>';
            intel.findings.forEach(f => {{
                let color = f.severity === 'High' || f.severity === 'Critical' ? 'red' : (f.severity === 'Medium' ? 'purple' : 'blue');
                fHtml += `<tr>
                    <td><span class="badge ${{color}}">${{f.severity}}</span></td>
                    <td><strong>${{f.title}}</strong></td>
                    <td>
                        <div style="margin-bottom:0.5rem">${{f.description}}</div>
                        <div style="background:rgba(0,243,255,0.05); padding:0.5rem; border-left:2px solid var(--accent-primary); font-size:0.8rem">
                            <strong>Fix:</strong> ${{f.recommendation}}
                        </div>
                    </td>
                </tr>`;
            }});
            fHtml += '</tbody></table>';
            el('findings-table').innerHTML = fHtml;
        }}

        // --- DNS ---
        const dns = data.dns || {{}};
        let allDns = [];
        (dns.a_records || []).forEach(r => allDns.push({{type: 'A', val: r}}));
        (dns.mx_records || []).forEach(r => allDns.push({{type: 'MX', val: r}}));
        (dns.txt_records || []).forEach(r => allDns.push({{type: 'TXT', val: r}}));
        
        el('dns-count').textContent = allDns.length + ' Records';
        if (allDns.length === 0) {{
            el('dns-table').innerHTML = '<div style="padding:1rem">No records found</div>';
        }} else {{
            let dHtml = '<table><tbody>';
            allDns.forEach(d => {{
                dHtml += `<tr><td style="width:50px"><span class="badge blue">${{d.type}}</span></td><td>${{d.val}}</td></tr>`;
            }});
            dHtml += '</tbody></table>';
            el('dns-table').innerHTML = dHtml;
        }}

        // --- Subdomains ---
        const subs = data.subdomains || [];
        el('sub-count').textContent = subs.length + ' Unique';
        el('subdomain-list').innerHTML = subs.length 
            ? subs.map(s => `<li>${{s}}</li>`).join('')
            : '<li style="color:var(--text-muted)">No subdomains found in CT logs.</li>';

        // --- Headers ---
        const headers = data.http?.headers || {{}};
        let hHtml = '<table><tbody>';
        Object.entries(headers).forEach(([k, v]) => {{
            hHtml += `<tr><td style="width:30%; color:var(--accent-primary)">${{k}}</td><td>${{v}}</td></tr>`;
        }});
        hHtml += '</tbody></table>';
        el('headers-table').innerHTML = hHtml;

        // --- Redirects & Robots ---
        const redirects = data.http?.redirect_chain || [];
        el('redirect-list').innerHTML = redirects.map(r => `<li>${{r}}</li>`).join('');
        
        const robots = data.http?.robots_txt || [];
        el('robots-content').textContent = robots.length ? robots.join('\n') : 'No robots.txt or empty.';

        // --- SSL ---
        const ssl = data.ssl;
        if (ssl) {{
            el('ssl-cn').textContent = ssl.subject_cn;
            el('ssl-issuer').textContent = ssl.issuer;
            el('ssl-valid').textContent = `${{ssl.valid_from}} -> ${{ssl.valid_to}}`;
            
            el('sans-badge').textContent = (ssl.sans || []).length + ' SANs';
            let sansHtml = '<table><tbody>';
            (ssl.sans || []).forEach(s => sansHtml += `<tr><td>${{s}}</td></tr>`);
            sansHtml += '</tbody></table>';
            el('sans-container').innerHTML = sansHtml;
        }} else {{
            el('ssl-cn').textContent = 'No SSL Info';
        }}

        // --- Whois ---
        el('whois-raw').textContent = safe(data.whois) || 'No WHOIS data retrieved.';

    </script>
</body>
</html>
"###, domain = info.domain, json_data = json_data, intel_json = intel_json);

    let mut file = File::create(filename)?;
    file.write_all(html.as_bytes())?;
    
    Ok(())
}
