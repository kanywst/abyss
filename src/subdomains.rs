use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn scan_subdomains(domain: &str) -> Result<Vec<String>> {
    // crt.sh API (Certificate Transparency logs)
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; Abyss/1.0)")
        .build()?;

    let resp = client.get(&url).send().await?;
    
    if !resp.status().is_success() {
        return Ok(vec![]);
    }

    let entries: Vec<CrtShEntry> = resp.json().await.unwrap_or_default();
    
    let mut subdomains = HashSet::new();
    for entry in entries {
        // name_value can be multiline or wildcards
        for line in entry.name_value.lines() {
            let clean = line.replace("*.", "");
            if clean.contains(domain) && clean != domain {
                subdomains.insert(clean);
            }
        }
    }

    let mut result: Vec<String> = subdomains.into_iter().collect();
    result.sort();
    
    // Limit for display sanity
    if result.len() > 100 {
        result.truncate(100);
    }
    
    Ok(result)
}
