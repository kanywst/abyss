use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TargetData {
    pub target: String,
    pub dns: DnsData,
    pub http: Option<HttpData>,
    pub attribution: AttributionData,
    pub secrets: Vec<SecretFound>,
    pub cloud: Option<CloudProvider>,

    // Intelligence
    pub ssl_intelligence: SslIntel,
    pub geo_intelligence: GeoIntel,
    pub passive_dns: Vec<String>,
    pub archives: Vec<ArchiveRecord>,
    pub alienvault: AlienVaultData,
    pub urlscan: Vec<UrlScanRecord>,
    pub github_leaks: Vec<GitHubRecord>,
    pub shodan: Option<ShodanData>, // NEW: Shodan InternetDB
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DnsData {
    pub a: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub txt: Vec<String>,
    pub axfr: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HttpData {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub server: String,
    pub tech_stack: Vec<String>,
    pub meta_generator: Option<String>,
    pub js_analysis: Vec<JsFileResult>,
    pub robots_txt: Vec<String>,      // NEW
    pub sitemaps: Vec<String>,        // NEW
    pub security_txt: Option<String>, // NEW
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct JsFileResult {
    pub url: String,
    pub endpoints: Vec<String>,
    pub secrets: Vec<SecretFound>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AttributionData {
    pub ga_ids: Vec<String>,
    pub adsense_ids: Vec<String>,
    pub verification_codes: Vec<String>,
    pub crypto_wallets: Vec<String>,
    pub social_links: Vec<String>,
    pub emails: Vec<String>,
    pub phone_numbers: Vec<String>,
    pub favicon_hash: Option<i32>,
    pub mx_banners: Vec<String>,
    pub affiliate_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SecretFound {
    pub kind: String,
    pub value: String,
    pub location: String,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CloudProvider {
    pub name: String,
    pub risk_level: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SslIntel {
    pub identities: Vec<String>,
    pub issuers: Vec<String>,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GeoIntel {
    pub ip: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    pub asn: String,
    pub org: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ArchiveRecord {
    pub timestamp: String,
    pub url: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AlienVaultData {
    pub passive_dns_count: usize,
    pub malware_samples: Vec<String>,
    pub related_tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UrlScanRecord {
    pub task_id: String,
    pub time: String,
    pub result_url: String,
    pub screenshot: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GitHubRecord {
    pub file_url: String,
    pub repo: String,
    pub author: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShodanData {
    pub ports: Vec<u16>,
    pub vulns: Vec<String>,
    pub hostnames: Vec<String>,
    pub tags: Vec<String>,
}
