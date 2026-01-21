use crate::core::AbyssError;
use crate::core::Result;
use crate::models::{AttributionData, HttpData, JsFileResult, SecretFound};
use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Client;
use std::collections::HashSet;
use std::io::Cursor;

static SECRET_PATTERNS: Lazy<Vec<(&'static str, Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            "AWS Access Key",
            Regex::new(r"(?i)\bAKIA[0-9A-Z]{16}\b").unwrap(),
            "CRITICAL",
        ),
        (
            "Google API Key",
            Regex::new(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
            "High",
        ),
        (
            "Slack Token",
            Regex::new(r"xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}").unwrap(),
            "CRITICAL",
        ),
        (
            "Stripe Secret",
            Regex::new(r"(?i)sk_live_[0-9a-zA-Z]{24}").unwrap(),
            "CRITICAL",
        ),
        (
            "Private Key",
            Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap(),
            "CRITICAL",
        ),
        (
            "Generic API Key",
            Regex::new(r#"(?i)(api_key|apikey|access_token)[\s:=]+['"]([a-zA-Z0-9\-_]{20,})['"]"#)
                .unwrap(),
            "Medium",
        ),
    ]
});

pub async fn scan_http(
    target: &str,
    client: &Client,
    concurrency: usize,
) -> Result<(Option<HttpData>, Vec<SecretFound>, AttributionData)> {
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Ok((None, vec![], AttributionData::default())),
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    // Basic Info
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let title = extract_title(&body);
    let tech_stack = detect_tech(&body, &headers);
    let meta_generator = extract_generator(&body);

    // Deep Mining (HTML)
    let mut secrets = mine_secrets(&body, &url);
    let mut attribution = mine_attribution(&body);

    // JS Deep Dive
    let (js_analysis, js_secrets, js_attribution) =
        deep_dive_js(client, &url, &body, concurrency).await;

    // Robots/Sitemaps/Security
    let robots = fetch_file_lines(client, &url, "/robots.txt").await;
    let sitemap_raw = fetch_file(client, &url, "/sitemap.xml")
        .await
        .unwrap_or_default();
    let re_loc = Regex::new(r"(?i)<loc>(.*?)</loc>").unwrap();
    let sitemaps = re_loc
        .captures_iter(&sitemap_raw)
        .map(|c| c[1].to_string())
        .collect::<Vec<_>>();
    let security = fetch_file(client, &url, "/.well-known/security.txt")
        .await
        .ok();

    // Merge JS findings
    secrets.extend(js_secrets);
    attribution.ga_ids.extend(js_attribution.ga_ids);
    attribution.adsense_ids.extend(js_attribution.adsense_ids);
    attribution
        .affiliate_ids
        .extend(js_attribution.affiliate_ids);
    attribution
        .verification_codes
        .extend(js_attribution.verification_codes);

    // Dedup
    attribution.ga_ids.sort();
    attribution.ga_ids.dedup();
    attribution.adsense_ids.sort();
    attribution.adsense_ids.dedup();
    attribution.affiliate_ids.sort();
    attribution.affiliate_ids.dedup();
    attribution.verification_codes.sort();
    attribution.verification_codes.dedup();

    // Favicon Hash
    if let Ok(hash) = fetch_favicon_hash(client, &url, &body).await {
        attribution.favicon_hash = Some(hash);
    }

    let http_data = HttpData {
        url: url.clone(),
        status,
        title,
        server,
        tech_stack,
        meta_generator,
        js_analysis,
        robots_txt: robots,
        sitemaps,
        security_txt: security,
    };

    Ok((Some(http_data), secrets, attribution))
}

async fn fetch_file_lines(client: &Client, base: &str, path: &str) -> Vec<String> {
    if let Ok(text) = fetch_file(client, base, path).await {
        return text.lines().map(|s| s.to_string()).collect();
    }
    vec![]
}

async fn fetch_file(client: &Client, base: &str, path: &str) -> Result<String> {
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let resp = client.get(&url).send().await?;
    if resp.status().is_success() {
        return Ok(resp.text().await?);
    }
    Err(AbyssError::Unknown("File not found".to_string()))
}

async fn deep_dive_js(
    client: &Client,
    base_url: &str,
    html: &str,
    concurrency: usize,
) -> (Vec<JsFileResult>, Vec<SecretFound>, AttributionData) {
    let mut results = Vec::new();
    let mut all_secrets = Vec::new();
    let mut combined_attr = AttributionData::default();
    let re_script = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
    let mut scripts = Vec::new();
    for cap in re_script.captures_iter(html) {
        scripts.push(resolve_url(base_url, &cap[1]));
    }
    scripts.sort();
    scripts.dedup();

    use std::sync::Arc;
    use tokio::sync::Semaphore;
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();

    for script_url in scripts.into_iter().take(50) {
        let client = client.clone();
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await.ok();
            if let Ok(resp) = client.get(&script_url).send().await {
                if let Ok(js_content) = resp.text().await {
                    let js_secrets = mine_secrets(&js_content, &script_url);
                    let js_attr = mine_attribution(&js_content);
                    let endpoints = mine_endpoints(&js_content);
                    return Some((script_url, js_secrets, js_attr, endpoints));
                }
            }
            None
        });
    }

    while let Some(res) = set.join_next().await {
        if let Ok(Some((url, js_secrets, js_attr, endpoints))) = res {
            if !js_secrets.is_empty() || !endpoints.is_empty() {
                results.push(JsFileResult {
                    url,
                    endpoints,
                    secrets: js_secrets.clone(),
                });
            }
            all_secrets.extend(js_secrets);
            combined_attr.ga_ids.extend(js_attr.ga_ids);
            combined_attr.adsense_ids.extend(js_attr.adsense_ids);
            combined_attr.affiliate_ids.extend(js_attr.affiliate_ids);
            combined_attr
                .verification_codes
                .extend(js_attr.verification_codes);
        }
    }

    (results, all_secrets, combined_attr)
}

fn resolve_url(base: &str, path: &str) -> String {
    if path.starts_with("http") {
        return path.to_string();
    }
    if path.starts_with("//") {
        return format!("https:{}", path);
    }
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn mine_endpoints(js: &str) -> Vec<String> {
    let mut eps = Vec::new();
    let re_url = Regex::new(r#"https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9._/-]+"#).unwrap();
    for cap in re_url.captures_iter(js) {
        let u = cap[0].to_string();
        if !u.contains("w3.org")
            && !u.contains("google")
            && !u.contains("facebook")
            && !u.contains("twitter")
        {
            eps.push(u);
        }
    }
    eps.sort();
    eps.dedup();
    eps
}

fn extract_title(html: &str) -> String {
    let re = Regex::new(r"(?i)<title>(.*?)</title>").unwrap();
    re.captures(html)
        .map(|c| c[1].to_string())
        .unwrap_or_default()
}

fn extract_generator(html: &str) -> Option<String> {
    let re =
        Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).unwrap();
    re.captures(html).map(|c| c[1].to_string())
}

fn detect_tech(html: &str, headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut tech = HashSet::new();
    let lower_html = html.to_lowercase();

    // Frameworks & CMS
    if lower_html.contains("wp-content") || lower_html.contains("wordpress") {
        tech.insert("WordPress".to_string());
    }
    if lower_html.contains("react") {
        tech.insert("React".to_string());
    }
    if lower_html.contains("vue") {
        tech.insert("Vue.js".to_string());
    }
    if lower_html.contains("next.js") || lower_html.contains("_next/static") {
        tech.insert("Next.js".to_string());
    }
    if lower_html.contains("nuxt") {
        tech.insert("Nuxt.js".to_string());
    }
    if lower_html.contains("jquery") {
        tech.insert("jQuery".to_string());
    }
    if lower_html.contains("bootstrap") {
        tech.insert("Bootstrap".to_string());
    }
    if lower_html.contains("tailwind") {
        tech.insert("Tailwind CSS".to_string());
    }

    // Infrastructure & CDN
    if headers.contains_key("x-vercel-id") {
        tech.insert("Vercel".to_string());
    }
    if headers.contains_key("x-amz-cf-id") {
        tech.insert("CloudFront".to_string());
    }
    if headers.contains_key("cf-ray")
        || headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("cloudflare")
    {
        tech.insert("Cloudflare".to_string());
    }
    if headers.contains_key("x-powered-by") {
        if let Ok(v) = headers.get("x-powered-by").unwrap().to_str() {
            tech.insert(format!("Powered by {}", v));
        }
    }

    tech.into_iter().collect()
}

fn mine_secrets(body: &str, url: &str) -> Vec<SecretFound> {
    let mut found = Vec::new();
    for (kind, re, severity) in SECRET_PATTERNS.iter() {
        for cap in re.captures_iter(body) {
            let val = if cap.len() > 2 {
                cap[2].to_string()
            } else {
                cap[0].to_string()
            };
            found.push(SecretFound {
                kind: kind.to_string(),
                value: val.chars().take(30).collect::<String>(),
                location: url.to_string(),
                severity: severity.to_string(),
            });
        }
    }
    found
}

fn mine_attribution(body: &str) -> AttributionData {
    let mut data = AttributionData::default();
    let mut unique_ga = HashSet::new();
    let mut unique_ads = HashSet::new();
    let mut unique_wallet = HashSet::new();
    let mut unique_social = HashSet::new();
    let mut unique_email = HashSet::new();
    let mut unique_verify = HashSet::new();
    let mut unique_phone = HashSet::new();
    let mut unique_affiliate = HashSet::new();

    let re_ga = Regex::new(r"\b(UA-\d+-\d+|G-[A-Z0-9]{10})\b").unwrap();
    for cap in re_ga.captures_iter(body) {
        unique_ga.insert(cap[0].to_string());
    }
    let re_ads = Regex::new(r"\bpub-\d{16}\b").unwrap();
    for cap in re_ads.captures_iter(body) {
        unique_ads.insert(cap[0].to_string());
    }

    // Improved verification regex: match name then content, or content then name
    let re_verify_name_content = Regex::new(r#"(?i)<meta[^>]+name=["'](google-site-verification|facebook-domain-verification|apple-domain-verification|yandex-verification)["'][^>]+content=["']([^"']+)["']"#).unwrap();
    for cap in re_verify_name_content.captures_iter(body) {
        unique_verify.insert(format!("{}: {}", &cap[1], &cap[2]));
    }
    let re_verify_content_name = Regex::new(r#"(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["'](google-site-verification|facebook-domain-verification|apple-domain-verification|yandex-verification)["']"#).unwrap();
    for cap in re_verify_content_name.captures_iter(body) {
        unique_verify.insert(format!("{}: {}", &cap[2], &cap[1]));
    }
    let re_btc = Regex::new(r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b").unwrap();
    let re_eth = Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap();
    for cap in re_btc.captures_iter(body) {
        unique_wallet.insert(format!("BTC: {}", &cap[0]));
    }
    for cap in re_eth.captures_iter(body) {
        unique_wallet.insert(format!("ETH: {}", &cap[0]));
    }
    let re_social = Regex::new(r#"https?://(www\.)?(twitter\.com|x\.com|facebook\.com|instagram\.com|t\.me|discord\.gg|github\.com)/[a-zA-Z0-9_.]+"#).unwrap();
    for cap in re_social.captures_iter(body) {
        unique_social.insert(cap[0].to_string());
    }
    let re_email = Regex::new(r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#).unwrap();
    for cap in re_email.captures_iter(body) {
        unique_email.insert(cap[0].to_string());
    }
    let re_phone =
        Regex::new(r#"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,4}"#).unwrap();
    for cap in re_phone.captures_iter(body) {
        let s = cap[0].to_string();
        if s.len() > 9 && s.len() < 20 {
            unique_phone.insert(s);
        }
    }
    let re_fb_pixel = Regex::new(r#"fbq\(['"]init['"],\s*['"]([0-9]+)['"]\)"#).unwrap();
    for cap in re_fb_pixel.captures_iter(body) {
        unique_affiliate.insert(format!("FB Pixel: {}", &cap[1]));
    }
    let re_amazon = Regex::new(r#"[?&]tag=([a-zA-Z0-9-]+-22)"#).unwrap();
    for cap in re_amazon.captures_iter(body) {
        unique_affiliate.insert(format!("Amazon: {}", &cap[1]));
    }

    data.ga_ids = unique_ga.into_iter().collect();
    data.adsense_ids = unique_ads.into_iter().collect();
    data.verification_codes = unique_verify.into_iter().collect();
    data.crypto_wallets = unique_wallet.into_iter().collect();
    data.social_links = unique_social.into_iter().collect();
    data.emails = unique_email.into_iter().collect();
    data.phone_numbers = unique_phone.into_iter().collect();
    data.affiliate_ids = unique_affiliate.into_iter().collect();
    data
}

async fn fetch_favicon_hash(client: &Client, base_url: &str, html: &str) -> Result<i32> {
    let mut favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
    let re_icon =
        Regex::new(r#"(?i)<link[^>]+rel=["']?.*icon.*["']?[^>]+href=["']([^"']+)["']"#).unwrap();
    if let Some(cap) = re_icon.captures(html) {
        let href = &cap[1];
        if href.starts_with("http") {
            favicon_url = href.to_string();
        } else if href.starts_with("//") {
            favicon_url = format!("https:{}", href);
        } else {
            favicon_url = format!(
                "{}/{}",
                base_url.trim_end_matches('/'),
                href.trim_start_matches('/')
            );
        }
    }
    let resp = client.get(&favicon_url).send().await?;
    if !resp.status().is_success() {
        return Err(AbyssError::Unknown("Favicon not found".to_string()));
    }
    let bytes = resp.bytes().await?;
    let b64 = general_purpose::STANDARD.encode(&bytes);
    let mut b64_formatted = String::new();
    for (i, c) in b64.chars().enumerate() {
        b64_formatted.push(c);
        if (i + 1) % 76 == 0 {
            b64_formatted.push('\n');
        }
    }
    b64_formatted.push('\n');
    let hash = murmur3::murmur3_32(&mut Cursor::new(b64_formatted), 0)?;
    Ok(hash as i32)
}
