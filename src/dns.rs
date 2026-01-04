use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use crate::models::{DnsInfo, GeoIpInfo};
use serde::Deserialize;

#[derive(Deserialize)]
struct IpApiReponse {
    status: String,
    country: Option<String>,
    isp: Option<String>,
    query: String, // The IP
}

pub async fn scan_dns(domain: &str) -> Result<DnsInfo> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let mut info = DnsInfo::default();

    // A Records
    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        for ip in response.iter() {
            info.a_records.push(ip.to_string());
        }
    }

    // MX Records
    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            info.mx_records.push(mx.exchange().to_string());
        }
    }

    // TXT Records
    if let Ok(response) = resolver.txt_lookup(domain).await {
        for txt in response.iter() {
            // TXT records can contain multiple character strings
            info.txt_records.push(txt.to_string());
        }
    }

    // GeoIP for the first A record
    if let Some(ip) = info.a_records.first() {
        if let Ok(geo) = fetch_geoip(ip).await {
            info.geo_ip = Some(geo);
        }
    }

    Ok(info)
}

async fn fetch_geoip(ip: &str) -> Result<GeoIpInfo> {
    let url = format!("http://ip-api.com/json/{}", ip);
    let resp: IpApiReponse = reqwest::get(&url).await?.json().await?;

    if resp.status == "success" {
        Ok(GeoIpInfo {
            ip: resp.query,
            country: resp.country.unwrap_or_default(),
            isp: resp.isp.unwrap_or_default(),
        })
    } else {
        Err(anyhow::anyhow!("GeoIP lookup failed"))
    }
}