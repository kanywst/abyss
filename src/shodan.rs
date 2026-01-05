use crate::models::ShodanInfo;
use anyhow::Result;
use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct InternetDbResponse {
    pub ip: String,
    pub ports: Option<Vec<u16>>,
    pub cpes: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub vulns: Option<Vec<String>>,
}

pub async fn scan_internetdb(ip: &str) -> Result<Option<ShodanInfo>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; Abyss/1.0)")
        .build()?;

    let resp = client.get(&url).send().await?;

    if !resp.status().is_success() {
        // 404 means no info found, which is valid
        return Ok(None);
    }

    let data: InternetDbResponse = resp.json().await.unwrap_or_default();

    Ok(Some(ShodanInfo {
        ip: data.ip,
        ports: data.ports.unwrap_or_default(),
        cpes: data.cpes.unwrap_or_default(),
        hostnames: data.hostnames.unwrap_or_default(),
        tags: data.tags.unwrap_or_default(),
        vulns: data.vulns.unwrap_or_default(),
    }))
}
