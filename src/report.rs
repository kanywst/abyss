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
    <style>
        :root { --bg: #02040a; --card: #0d1117; --primary: #58a6ff; --secondary: #bc8cff; --accent: #3fb950; --danger: #f85149; --warn: #d29922; --text: #c9d1d9; --text-muted: #8b949e; --border: #30363d; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; line-height: 1.5; padding: 2rem; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-end; }
        h1 { font-size: 2rem; font-weight: 800; letter-spacing: -0.03em; color: #fff; }
        .dashboard { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.5rem; }
        .col-span-12 { grid-column: span 12; } .col-span-8 { grid-column: span 8; } .col-span-4 { grid-column: span 4; } .col-span-6 { grid-column: span 6; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; display: flex; flex-direction: column; height: 100%; }
        .card-header { font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 1rem; letter-spacing: 0.05em; }
        .risk-hero { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); border: 1px solid var(--secondary); margin-bottom: 2rem; padding: 2rem; border-radius: 12px; display: flex; gap: 3rem; align-items: center; }
        .risk-score { font-size: 4rem; font-weight: 900; line-height: 1; font-family: 'JetBrains Mono'; color: var(--secondary); }
        .summary-text { font-size: 1.2rem; font-weight: 400; color: #fff; line-height: 1.6; }
        .finding { padding: 1rem; border-left: 4px solid var(--primary); background: rgba(88,166,255,0.05); margin-bottom: 1rem; border-radius: 0 4px 4px 0; }
        .finding.severity-Critical { border-color: var(--danger); }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th { text-align: left; padding: 0.5rem; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        td { padding: 0.5rem; border-bottom: 1px solid rgba(255,255,255,0.03); vertical-align: top; }
        .scroll { max-height: 400px; overflow-y: auto; scrollbar-width: thin; }
        .pre { font-family: 'JetBrains Mono'; font-size: 0.8rem; background: #000; padding: 1rem; border-radius: 4px; overflow-x: auto; color: #8b949e; }
        .badge { padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; background: var(--border); color: var(--text); }
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
                <div class="font-mono" style="color: var(--secondary); font-weight: 700;">ABYSS v0.1.0</div>
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
            <div class="card col-span-4">
                <div class="card-header">Target Attribution</div>
                <table style="margin-top: 0;">
                    <tr><td>Country</td><td id="attr-country">-</td></tr>
                    <tr><td>Operator</td><td id="attr-operator">-</td></tr>
                    <tr><td>Setup</td><td id="attr-setup">-</td></tr>
                    <tr><td>Favicon</td><td id="attr-favicon" class="font-mono">-</td></tr>
                </table>
                <div id="logic-reasoning" style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);"></div>
            </div>

            <div class="card col-span-8">
                <div class="card-header">Vulnerabilities & Findings</div>
                <div id="findings-container" class="scroll"></div>
            </div>

            <div class="card col-span-6">
                <div class="card-header">Content Intel</div>
                <div class="scroll">
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">Emails</p>
                    <div id="email-list" class="font-mono" style="margin-bottom: 1rem;"></div>
                    <p style="font-size: 0.8rem; font-weight: 700; color: var(--primary);">Links</p>
                    <div id="link-list" class="font-mono" style="font-size: 0.8rem; color: var(--text-muted);"></div>
                </div>
            </div>

            <div class="card col-span-6">
                <div class="card-header">Exposed Services</div>
                <div class="scroll">
                    <div id="ports-list" style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;"></div>
                    <table id="shodan-details"></table>
                </div>
            </div>

            <div class="card col-span-12">
                <div class="card-header">WHOIS & Data Export</div>
                <pre class="pre scroll" id="whois-content" style="margin-bottom: 1rem;"></pre>
                <textarea class="pre" style="width: 100%; height: 200px; border: none;" readonly>__JSON_DATA__</textarea>
            </div>
        </div>
    </div>

    <script>
        const data = __JSON_DATA__;
        const intel = __INTEL_DATA__;
        document.getElementById('gen-date').textContent = new Date().toLocaleString();
        const el = id => document.getElementById(id);

        el('risk-val').textContent = intel.risk_score;
        el('risk-level').textContent = intel.risk_level + ' Risk';
        el('intel-summary').innerHTML = intel.summary.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');

        const attr = intel.attribution || {};
        el('attr-country').textContent = attr.probable_country;
        el('attr-operator').textContent = attr.operator_type;
        el('attr-setup').textContent = attr.infra_setup;
        el('attr-favicon').textContent = data.http?.fingerprint?.favicon_hash || 'None';
        el('logic-reasoning').innerHTML = (attr.logic_reasoning || []).map(r => `• ${r}`).join('<br>');

        el('findings-container').innerHTML = (intel.findings || []).map(f => `
            <div class="finding severity-${f.severity}">
                <div style="font-weight: 700;">${f.title}</div>
                <div style="font-size: 0.85rem; color: var(--text-muted);">${f.description}</div>
            </div>
        `).join('') || 'No findings.';

        el('email-list').innerHTML = (data.http?.fingerprint?.emails || []).join('<br>');
        el('link-list').innerHTML = (data.http?.fingerprint?.external_links || []).join('<br>');
        el('whois-content').textContent = data.whois || 'No WHOIS.';
        
        const sho = data.shodan || {};
        el('ports-list').innerHTML = (sho.ports || []).map(p => `<span class="badge">${p}</span>`).join(' ');
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
