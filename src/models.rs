use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    pub domain: String,
    pub dns: DnsInfo,
    pub http: Option<HttpInfo>,
    pub ssl: Option<SslInfo>,
    pub subdomains: Vec<String>,
    pub whois: Option<String>,
    pub shodan: Option<ShodanInfo>, // 追加: Shodan情報
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DnsInfo {
    pub a_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub geo_ip: Option<GeoIpInfo>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GeoIpInfo {
    pub ip: String,
    pub country: String,
    pub isp: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HttpInfo {
    pub url: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub redirect_chain: Vec<String>,
    pub waf: Option<String>,
    pub robots_txt: Vec<String>,
    pub fingerprint: Fingerprint,
    pub security_issues: Vec<String>,
    pub sensitive_files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Fingerprint {
    pub page_title: Option<String>,       // New
    pub meta_description: Option<String>, // New
    pub favicon_hash: Option<i32>,        // New (Shodan format mmh3)
    pub generator: Option<String>,
    pub cms: Option<String>,
    pub ga_ids: Vec<String>,
    pub adsense_ids: Vec<String>,
    pub social_links: Vec<String>,
    pub emails: Vec<String>,
    pub external_links: Vec<String>,
    pub tech_stack: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SslInfo {
    pub issuer: String,
    pub subject_cn: String,
    pub sans: Vec<String>,
    pub valid_from: String,
    pub valid_to: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShodanInfo {
    pub ip: String,
    pub ports: Vec<u16>,
    pub cpes: Vec<String>,
    pub hostnames: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
}
