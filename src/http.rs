use crate::models::{Fingerprint, HttpInfo};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use murmur3::murmur3_32;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

pub async fn scan_http(domain: &str) -> Result<HttpInfo> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("http://{}", domain)
    };

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (compatible; Abyss/1.0; +https://github.com/kanywst/abyss)")
        .build()?;

    let mut current_url = base_url;
    let mut chain = Vec::new();
    let mut final_response = None;

    for _ in 0..10 {
        let resp = client.get(&current_url).send().await?;
        chain.push(current_url.clone());

        if resp.status().is_redirection() {
            if let Some(loc) = resp.headers().get("location") {
                let mut next_url = loc.to_str()?.to_string();
                if !next_url.starts_with("http") {
                    let parsed_base = reqwest::Url::parse(&current_url)?;
                    next_url = parsed_base.join(&next_url)?.to_string();
                }
                current_url = next_url;
                continue;
            }
        }
        final_response = Some(resp);
        break;
    }

    let response = final_response.ok_or_else(|| anyhow::anyhow!("Failed to get response"))?;
    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (key, value) in response.headers().iter() {
        headers.insert(
            key.to_string().to_lowercase(),
            value.to_str().unwrap_or_default().to_string(),
        );
    }

    let waf = detect_waf(&headers);
    let security_issues = check_security_headers(&headers);
    let body = response.text().await?;
    let mut fingerprint = analyze_content(&body);

    if let Ok(hash) = fetch_favicon_hash(&client, &chain[0], &body).await {
        fingerprint.favicon_hash = Some(hash);
    }

    let robots_txt = fetch_robots(&client, &chain[0]).await.unwrap_or_default();

    // Scan for sensitive files (Based on Mangamura case study)
    let sensitive_files = scan_sensitive_files(&client, &chain[0]).await;

    Ok(HttpInfo {
        url: chain.last().unwrap().clone(),
        status,
        headers,
        redirect_chain: chain,
        waf,
        robots_txt,
        fingerprint,
        security_issues,
        sensitive_files,
    })
}

async fn fetch_favicon_hash(client: &reqwest::Client, base_url: &str, html: &str) -> Result<i32> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("link[rel*='icon']").unwrap();
    let mut favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
    if let Some(link) = document.select(&selector).next() {
        if let Some(href) = link.value().attr("href") {
            if href.starts_with("http") {
                favicon_url = href.to_string();
            } else {
                if let Ok(parsed_base) = reqwest::Url::parse(base_url) {
                    if let Ok(joined) = parsed_base.join(href) {
                        favicon_url = joined.to_string();
                    }
                }
            }
        }
    }
    let resp = client.get(favicon_url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to download favicon"));
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
    let hash = murmur3_32(&mut Cursor::new(b64_formatted), 0)?;
    Ok(hash as i32)
}

fn detect_waf(headers: &HashMap<String, String>) -> Option<String> {
    let h = |k: &str| headers.get(k).map(|s| s.to_lowercase());
    if h("server").map_or(false, |s| s.contains("cloudflare")) || headers.contains_key("cf-ray") {
        return Some("Cloudflare".to_string());
    }
    if h("server").map_or(false, |s| s.contains("akamai"))
        || headers.contains_key("x-akamai-transformed")
    {
        return Some("Akamai".to_string());
    }
    if headers.contains_key("x-amz-cf-id") {
        return Some("Amazon CloudFront".to_string());
    }
    None
}

fn check_security_headers(headers: &HashMap<String, String>) -> Vec<String> {
    let mut issues = Vec::new();
    if !headers.contains_key("strict-transport-security") {
        issues.push("Missing HSTS".to_string());
    }
    if !headers.contains_key("content-security-policy") {
        issues.push("Missing CSP".to_string());
    }
    if !headers.contains_key("x-frame-options") {
        issues.push("Missing X-Frame-Options".to_string());
    }
    issues
}

async fn fetch_robots(client: &reqwest::Client, base_url: &str) -> Result<Vec<String>> {
    let url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Ok(vec![]);
    }
    let text = resp.text().await?;
    let disallows = text
        .lines()
        .filter(|l| l.to_lowercase().starts_with("disallow:"))
        .map(|l| {
            let parts: Vec<&str> = l.splitn(2, ':').collect();
            parts.get(1).unwrap_or(&"").trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect();
    Ok(disallows)
}

async fn scan_sensitive_files(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    let files = vec![
        ".env",
        ".git/config",
        ".git/HEAD",
        "backup.sql",
        "database.sql",
        "dump.sql",
        "users.sql",
        "backup.tar.gz",
        "backup.zip",
        "www.zip",
        "config.php.bak",
        "wp-config.php.bak",
        "phpinfo.php",
    ];

    let mut found = Vec::new();
    let base = base_url.trim_end_matches('/');

    for f in files {
        let url = format!("{}/{}", base, f);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                found.push(url);
            }
        }
    }

    found
}

fn analyze_content(html_content: &str) -> Fingerprint {
    let document = Html::parse_document(html_content);
    let mut fp = Fingerprint::default();
    let mut tech = HashSet::new();

    let title_selector = Selector::parse("title").unwrap();
    if let Some(title) = document.select(&title_selector).next() {
        fp.page_title = Some(title.inner_html().trim().to_string());
    }

    let desc_selector = Selector::parse("meta[name='description']").unwrap();
    if let Some(desc) = document.select(&desc_selector).next() {
        if let Some(content) = desc.value().attr("content") {
            fp.meta_description = Some(content.to_string());
        }
    }

    if html_content.contains("/wp-content/") {
        fp.cms = Some("WordPress".to_string());
        tech.insert("WordPress".to_string());
    }
    if html_content.contains("react") {
        tech.insert("React".to_string());
    }
    if html_content.contains("vue") {
        tech.insert("Vue.js".to_string());
    }
    if html_content.contains("jquery") {
        tech.insert("jQuery".to_string());
    }

    // Improved Email Regex
    if let Ok(re_email) = Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}") {
        for cap in re_email.captures_iter(html_content) {
            fp.emails.push(cap[0].to_string());
        }
    }

    // Social Links
    if let Ok(re_link) = Regex::new(r"https?://[a-zA-Z0-9./-]+") {
        let social_domains = vec![
            "facebook.com",
            "twitter.com",
            "x.com",
            "instagram.com",
            "linkedin.com",
            "youtube.com",
            "t.me",
            "discord.gg",
            "discord.com/invite",
        ];
        for cap in re_link.captures_iter(html_content) {
            let link = cap[0].to_string();
            let mut is_social = false;
            for s in &social_domains {
                if link.contains(s) {
                    fp.social_links.push(link.clone());
                    is_social = true;
                    break;
                }
            }
            if !is_social {
                fp.external_links.push(link);
            }
        }
    }

    // Google Analytics UA & G-ID
    if let Ok(re_ua) = Regex::new(r"UA-\d+-\d+") {
        for cap in re_ua.captures_iter(html_content) {
            fp.ga_ids.push(cap[0].to_string());
        }
    }
    if let Ok(re_gid) = Regex::new(r"G-[A-Z0-9]{10}") {
        for cap in re_gid.captures_iter(html_content) {
            fp.ga_ids.push(cap[0].to_string());
        }
    }

    // AdSense
    if let Ok(re_ads) = Regex::new(r"pub-\d{16}") {
        for cap in re_ads.captures_iter(html_content) {
            fp.adsense_ids.push(cap[0].to_string());
        }
    }

    // Crypto Wallets
    // BTC: 1 or 3 start, 26-35 length (simplified) or bc1 (bech32)
    if let Ok(re_btc) = Regex::new(
        r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})",
    ) {
        for cap in re_btc.captures_iter(html_content) {
            fp.crypto_wallets.push(format!("BTC: {}", &cap[0]));
        }
    }
    // ETH: 0x start, 40 hex chars
    if let Ok(re_eth) = Regex::new(r"\b0x[a-fA-F0-9]{40}\b") {
        for cap in re_eth.captures_iter(html_content) {
            fp.crypto_wallets.push(format!("ETH: {}", &cap[0]));
        }
    }

    fp.tech_stack = tech.into_iter().collect();
    fp
}
