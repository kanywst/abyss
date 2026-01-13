use crate::models::TargetInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Intelligence {
    pub risk_score: u8,
    pub risk_level: String,
    pub summary: String,
    pub attribution: Attribution,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Attribution {
    pub probable_country: String,
    pub operator_type: String,
    pub infra_setup: String,
    pub logic_reasoning: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

pub fn analyze_target(info: &TargetInfo) -> Intelligence {
    let mut findings = Vec::new();
    let mut score = 0;
    let mut attr = Attribution::default();
    let mut reasoning = Vec::new();

    // --- 1. Infrastructure Attribution ---
    let ip_country = info
        .dns
        .geo_ip
        .as_ref()
        .map(|g| g.country.clone())
        .unwrap_or_default();
    attr.probable_country = if !ip_country.is_empty() {
        ip_country
    } else {
        "Unknown".to_string()
    };
    reasoning.push(format!(
        "Server infrastructure is physically hosted in {}.",
        attr.probable_country
    ));

    if let Some(shodan) = &info.shodan {
        if !shodan.ports.is_empty() {
            reasoning.push(format!(
                "Active services detected on {} ports: {:?}.",
                shodan.ports.len(),
                shodan.ports
            ));
        }
        if !shodan.tags.is_empty() {
            reasoning.push(format!(
                "Shodan identifies this host as: {:?}.",
                shodan.tags
            ));
        }
    }

    // --- 2. Identity & Concealment ---
    let mut is_shady = false;
    if let Some(whois) = &info.whois {
        if whois.contains("Privacy") || whois.contains("REDACTED") || whois.contains("Withheld") {
            is_shady = true;
            reasoning.push(
                "WHOIS identity is deliberately masked using a privacy proxy service.".to_string(),
            );
        }
    }

    if let Some(http) = &info.http {
        if http.waf.is_some() {
            attr.infra_setup = "Proxy-layered (WAF Protected)".to_string();
            reasoning
                .push("A WAF/CDN layer is used to obfuscate the real origin server.".to_string());
        } else {
            attr.infra_setup = "Directly Exposed Server".to_string();
            score += 15;
        }

        if let Some(hash) = http.fingerprint.favicon_hash {
            match hash {
                0 => reasoning.push("Favicon is empty or failed to hash.".to_string()),
                -127686963 => reasoning.push("Known Favicon: WordPress default icon.".to_string()),
                1490706056 => reasoning.push("Known Favicon: Apache default page icon.".to_string()),
                _ => reasoning.push(format!("Unique Favicon MMH3: {}. This can be used to track the operator across the web.", hash)),
            }
        }
    }

    attr.operator_type = if is_shady {
        "Anonymous Operator".to_string()
    } else {
        "Likely Commercial / Known Entity".to_string()
    };

    // --- 3. Vulnerability Findings ---
    if let Some(shodan) = &info.shodan {
        if !shodan.vulns.is_empty() {
            score += 50;
            findings.push(Finding {
                id: "VULN-01".to_string(),
                severity: "Critical".to_string(),
                title: "Known Vulnerabilities Detected".to_string(),
                description: format!(
                    "External databases identify known CVEs on this IP: {:?}.",
                    shodan.vulns
                ),
                recommendation: "Patch the server software and restrict port exposure immediately."
                    .to_string(),
            });
        }
    }

    if let Some(http) = &info.http {
        if !http.security_issues.is_empty() {
            score += 20;
            findings.push(Finding {
                id: "SEC-01".to_string(),
                severity: "High".to_string(),
                title: "Poor Security Header Hygiene".to_string(),
                description: format!("Critical headers missing: {:?}.", http.security_issues),
                recommendation:
                    "Deploy HSTS, CSP, and X-Frame-Options to prevent browser-based attacks."
                        .to_string(),
            });
        }

        if !http.sensitive_files.is_empty() {
            score += 80;
            findings.push(Finding {
                id: "SEC-02".to_string(),
                severity: "Critical".to_string(),
                title: "Exposed Sensitive Files Found".to_string(),
                description: format!(
                    "Found {} publicly accessible sensitive files/backups: {:?}. This is a critical information leak.",
                    http.sensitive_files.len(),
                    http.sensitive_files
                ),
                recommendation: "Immediately remove these files from the web server and investigate if they have been accessed by unauthorized parties."
                    .to_string(),
            });
        }
    }

    // --- 4. Content Intelligence ---
    if let Some(http) = &info.http {
        if !http.fingerprint.emails.is_empty() {
            findings.push(Finding {
                id: "INTEL-01".to_string(),
                severity: "Info".to_string(),
                title: "Exposed Email Addresses".to_string(),
                description: format!("Found {} email addresses in the page content. These can be used for attribution or phishing.", http.fingerprint.emails.len()),
                recommendation: "Evaluate if these emails belong to administrators or customers.".to_string(),
            });
        }

        // Pirate / Operator Fingerprints
        if !http.fingerprint.crypto_wallets.is_empty() {
            findings.push(Finding {
                id: "INTEL-02".to_string(),
                severity: "Medium".to_string(),
                title: "Cryptocurrency Wallets Detected".to_string(),
                description: format!("Found crypto addresses: {:?}. These are high-value indicators for tracking illicit revenue streams.", http.fingerprint.crypto_wallets),
                recommendation: "Check these addresses against blockchain explorers and known abuse databases.".to_string(),
            });
        }

        if !http.fingerprint.ga_ids.is_empty() || !http.fingerprint.adsense_ids.is_empty() {
             findings.push(Finding {
                id: "INTEL-03".to_string(),
                severity: "Medium".to_string(),
                title: "Ad/Analytics Trackers Found".to_string(),
                description: format!("GA IDs: {:?}, AdSense: {:?}. These IDs often link multiple sites to a single operator.", http.fingerprint.ga_ids, http.fingerprint.adsense_ids),
                recommendation: "Perform reverse lookups on these IDs (e.g., using DNSLytics or PublicWWW) to find the operator's other websites.".to_string(),
            });
        }
    }

    // --- 5. Summary & Scoring ---
    if score > 100 {
        score = 100;
    }
    let risk_level = match score {
        0..=30 => "Low",
        31..=60 => "Medium",
        61..=85 => "High",
        _ => "Critical",
    }
    .to_string();

    attr.logic_reasoning = reasoning;

    let summary = format!("Abyss Intelligence identifies this as a {} project with a {} risk profile. The identity is {} and it uses a {} setup.", 
        attr.operator_type, risk_level, if is_shady { "deliberately concealed" } else { "transparent" }, attr.infra_setup);

    Intelligence {
        risk_score: score,
        risk_level,
        summary,
        attribution: attr,
        findings,
    }
}
