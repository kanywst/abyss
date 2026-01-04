use crate::models::TargetInfo;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Intelligence {
    pub risk_score: u8, // 0 (Safe) - 100 (Critical)
    pub risk_level: String, // Low, Medium, High, Critical
    pub summary: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String, // Info, Low, Medium, High, Critical
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

pub fn analyze_target(info: &TargetInfo) -> Intelligence {
    let mut findings = Vec::new();
    let mut score = 0;

    // --- 1. WAF / CDN Analysis ---
    if let Some(http) = &info.http {
        if let Some(waf) = &http.waf {
            findings.push(Finding {
                id: "INFRA-01".to_string(),
                severity: "Info".to_string(),
                title: format!("Protected by {}", waf),
                description: format!("The target is behind {}, which masks the origin IP and provides protection against DDoS and web attacks.", waf),
                recommendation: "Direct IP scanning will likely fail. Focus on application logic errors or finding the origin IP via other means (e.g. historical DNS).".to_string(),
            });
        } else {
            score += 10;
            findings.push(Finding {
                id: "INFRA-02".to_string(),
                severity: "Medium".to_string(),
                title: "No WAF Detected".to_string(),
                description: "No common Web Application Firewall (Cloudflare, Akamai, etc.) signatures were detected. The origin server might be directly exposed.".to_string(),
                recommendation: "Consider implementing a WAF to protect against common web attacks and hide the origin infrastructure.".to_string(),
            });
        }

        // --- 2. Security Headers Analysis ---
        let issues = &http.security_issues;
        if !issues.is_empty() {
            let count = issues.len();
            let severity = if count > 3 { "High" } else { "Medium" };
            score += 5 * count as u8;
            
            findings.push(Finding {
                id: "SEC-01".to_string(),
                severity: severity.to_string(),
                title: format!("Missing {} Security Headers", count),
                description: format!("The web server is missing critical security headers: {}. This increases susceptibility to XSS, Clickjacking, and Man-in-the-Middle attacks.", issues.join(", ")),
                recommendation: "Implement HSTS, Content-Security-Policy, and X-Frame-Options to harden the browser security posture.".to_string(),
            });
        }

        // --- 3. CMS / Technology ---
        if let Some(cms) = &http.fingerprint.cms {
            findings.push(Finding {
                id: "TECH-01".to_string(),
                severity: "Info".to_string(),
                title: format!("CMS Detected: {}", cms),
                description: format!("The site appears to be running on {}. CMS platforms often have specific vulnerability patterns.", cms),
                recommendation: format!("Check for known vulnerabilities (CVEs) associated with {} and ensure it is updated to the latest version.", cms),
            });
        }
    }

    // --- 4. Subdomains / Attack Surface ---
    if !info.subdomains.is_empty() {
        let count = info.subdomains.len();
        let dev_envs: Vec<_> = info.subdomains.iter()
            .filter(|s| s.contains("dev") || s.contains("test") || s.contains("stage") || s.contains("admin"))
            .collect();

        if !dev_envs.is_empty() {
            score += 20;
            findings.push(Finding {
                id: "SURFACE-01".to_string(),
                severity: "High".to_string(),
                title: "Sensitive Subdomains Exposed".to_string(),
                description: format!("Potentially sensitive non-production environments found: {:?}. These often have weaker security configurations than production.", dev_envs),
                recommendation: "Ensure development and staging environments are not publicly accessible or are protected by strong authentication (VPN/SSO).".to_string(),
            });
        }

        findings.push(Finding {
            id: "SURFACE-02".to_string(),
            severity: "Info".to_string(),
            title: format!("Attack Surface: {} Subdomains", count),
            description: "A larger number of subdomains increases the attack surface. Each subdomain represents a potential entry point.".to_string(),
            recommendation: "Regularly audit these subdomains and decommission unused ones to reduce risk.".to_string(),
        });
    }

    // --- 5. SSL / TLS ---
    if let Some(ssl) = &info.ssl {
        // Simple check: Valid To
        // In a real scenario, we'd parse the date properly.
        // For MVP, just acknowledging it exists.
        if ssl.sans.len() > 10 {
             findings.push(Finding {
                id: "SSL-01".to_string(),
                severity: "Info".to_string(),
                title: "Shared SSL Certificate".to_string(),
                description: format!("The certificate covers {} domains (SANs). This is common for Cloudflare/CDNs but can also reveal related business domains.", ssl.sans.len()),
                recommendation: "Review the SAN list to identify other potential targets or related infrastructure owned by the same entity.".to_string(),
            });
        }
    } else {
        score += 30;
        findings.push(Finding {
            id: "SSL-02".to_string(),
            severity: "High".to_string(),
            title: "No SSL/TLS Detected".to_string(),
            description: "Could not retrieve SSL certificate information. The service might be actively refusing connections or not using HTTPS.".to_string(),
            recommendation: "Enforce HTTPS for all services to ensure data confidentiality and integrity.".to_string(),
        });
    }

    // --- Scoring Logic ---
    if score > 100 { score = 100; }
    let risk_level = match score {
        0..=20 => "Low",
        21..=50 => "Medium",
        51..=80 => "High",
        _ => "Critical",
    }.to_string();

    // --- Summary Generation ---
    let summary = format!(
        "Abyss Analysis concludes a **{} Risk** posture for {}. Key concerns include {}. The infrastructure appears to be {} with a {} attack surface ({} subdomains).",
        risk_level,
        info.domain,
        if findings.is_empty() { "no obvious issues" } else { &findings[0].title },
        if let Some(h) = &info.http { h.waf.as_deref().unwrap_or("directly exposed") } else { "unknown" },
        if info.subdomains.len() > 10 { "broad" } else { "minimal" },
        info.subdomains.len()
    );

    Intelligence {
        risk_score: score,
        risk_level,
        summary,
        findings,
    }
}
