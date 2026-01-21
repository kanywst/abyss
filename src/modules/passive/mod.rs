use crate::core::Result;
use crate::models::{SslIntel, GeoIntel, ArchiveRecord, AlienVaultData, UrlScanRecord, GitHubRecord, ShodanData};
use reqwest::Client;
use serde_json::Value;

// 1. CRT.SH (Certificate Transparency)
pub async fn scan_crtsh(target: &str, client: &Client) -> Result<(Vec<String>, SslIntel)> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", target);
    let mut domains = Vec::new();
    let mut intel = SslIntel::default();

    if let Ok(resp) = client.get(&url).send().await
        && resp.status().is_success()
        && let Ok(entries) = resp.json::<Vec<Value>>().await
    {
        for entry in entries {
            if let Some(name) = entry["name_value"].as_str() {
                for d in name.split('\n') {
                    let d_clean = d.trim().to_string();
                    if !domains.contains(&d_clean) {
                        domains.push(d_clean);
                    }
                }
            }
            if intel.issuers.is_empty()
                && let Some(issuer) = entry["issuer_name"].as_str()
            {
                intel.issuers.push(issuer.to_string());
            }
        }
    }
    domains.sort();
    domains.dedup();
    intel.identities = domains.clone();
    Ok((domains, intel))
}

// 2. IP-API (GeoIP)
pub async fn scan_geoip(ip: &str, client: &Client) -> Result<GeoIntel> {
    let url = format!("http://ip-api.com/json/{}", ip);
    let mut intel = GeoIntel::default();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(json) = resp.json::<Value>().await
    {
        intel.ip = ip.to_string();
        intel.country = json["country"].as_str().unwrap_or("Unknown").to_string();
        intel.city = json["city"].as_str().unwrap_or("Unknown").to_string();
        intel.isp = json["isp"].as_str().unwrap_or("Unknown").to_string();
        intel.org = json["org"].as_str().unwrap_or("").to_string();
        intel.asn = json["as"].as_str().unwrap_or("").to_string();
    }
    Ok(intel)
}

// 3. Wayback Machine (Archives)
pub async fn scan_wayback(target: &str, client: &Client) -> Result<Vec<ArchiveRecord>> {
    let url = format!(
        "http://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=timestamp,original,statuscode&limit=100&collapse=digest",
        target
    );
    let mut records = Vec::new();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(json) = resp.json::<Vec<Vec<String>>>().await
    {
        for row in json.iter().skip(1) {
            if row.len() >= 3 {
                records.push(ArchiveRecord {
                    timestamp: row[0].clone(),
                    url: row[1].clone(),
                    status: row[2].clone(),
                });
            }
        }
    }
    Ok(records)
}

// 4. HackerTarget Reverse DNS
pub async fn scan_reverse_dns(ip: &str, client: &Client) -> Result<Vec<String>> {
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", ip);
    let mut domains = Vec::new();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(text) = resp.text().await
    {
        for line in text.lines() {
            if !line.contains("API count exceeded") && !line.is_empty() {
                domains.push(line.to_string());
            }
        }
    }
    Ok(domains)
}

// 5. AlienVault OTX
pub async fn scan_alienvault(target: &str, client: &Client) -> Result<AlienVaultData> {
    let url = format!("https://otx.alienvault.com/otxapi/indicators/domain/{}/general", target);
    let mut data = AlienVaultData::default();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(json) = resp.json::<Value>().await
    {
        data.passive_dns_count = json["passive_dns_count"].as_u64().unwrap_or(0) as usize;
        
        // Extract malware samples if present
        if let Some(samples) = json["malware_samples"].as_array() {
            for s in samples {
                if let Some(hash) = s["hash"].as_str() {
                    data.malware_samples.push(hash.to_string());
                }
            }
        }

        if let Some(pulse_info) = json.get("pulse_info")
            && let Some(pulses) = pulse_info.get("pulses")
            && let Some(list) = pulses.as_array()
        {
            for p in list {
                if let Some(tags) = p.get("tags")
                    && let Some(tag_list) = tags.as_array()
                {
                    for t in tag_list {
                        if let Some(s) = t.as_str() {
                            data.related_tags.push(s.to_string());
                        }
                    }
                }
            }
        }
        data.related_tags.sort(); data.related_tags.dedup();
    }
    Ok(data)
}

// 6. URLScan.io (Screenshot & History)
pub async fn scan_urlscan(target: &str, client: &Client) -> Result<Vec<UrlScanRecord>> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}&size=20", target);
    let mut records = Vec::new();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(json) = resp.json::<Value>().await
        && let Some(results) = json.get("results")
        && let Some(list) = results.as_array()
    {
        for item in list {
            records.push(UrlScanRecord {
                task_id: item["_id"].as_str().unwrap_or("").to_string(),
                time: item["task"]["time"].as_str().unwrap_or("").to_string(),
                result_url: item["result"].as_str().unwrap_or("").to_string(),
                screenshot: item["screenshot"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    Ok(records)
}

// 7. GitHub Leaks
pub async fn scan_github(target: &str, _client: &Client) -> Result<Vec<GitHubRecord>> {
    let mut records = Vec::new();
    records.push(GitHubRecord {
        repo: "Global Search".to_string(),
        author: "GitHub".to_string(),
        file_url: format!("https://github.com/search?q={}&type=code", target),
    });
    Ok(records)
}

// 8. Shodan InternetDB (NEW: Passive Port/Vuln Scan)
pub async fn scan_shodan(ip: &str, client: &Client) -> Result<ShodanData> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let mut data = ShodanData::default();
    if let Ok(resp) = client.get(&url).send().await
        && let Ok(json) = resp.json::<Value>().await
    {
        if let Some(ports) = json["ports"].as_array() {
                for p in ports { if let Some(u) = p.as_u64() { data.ports.push(u as u16); } }
            }
            if let Some(vulns) = json["vulns"].as_array() {
                for v in vulns { if let Some(s) = v.as_str() { data.vulns.push(s.to_string()); } }
            }
            if let Some(hostnames) = json["hostnames"].as_array() {
                for h in hostnames { if let Some(s) = h.as_str() { data.hostnames.push(s.to_string()); } }
            }
            if let Some(tags) = json["tags"].as_array() {
                for t in tags { if let Some(s) = t.as_str() { data.tags.push(s.to_string()); } }
            }
    }
    Ok(data)
}
