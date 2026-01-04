use anyhow::Result;
use crate::models::{HttpInfo, Fingerprint};
use scraper::{Html, Selector};
use regex::Regex;
use std::collections::HashMap;

pub async fn scan_http(domain: &str) -> Result<HttpInfo> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("http://{}", domain)
    };

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (compatible; Abyss/1.0; +https://github.com/yourusername/abyss)")
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
    for (k, v) in response.headers().iter() {
        headers.insert(k.to_string(), v.to_str().unwrap_or_default().to_string());
    }
    
    let waf = detect_waf(&headers);
    let security_issues = check_security_headers(&headers); // 診断実行

    let body = response.text().await?;
    let fingerprint = analyze_content(&body);
    let robots_txt = fetch_robots(&client, &chain[0]).await.unwrap_or_default();

    Ok(HttpInfo {
        url: chain.last().unwrap().clone(),
        status,
        headers,
        redirect_chain: chain,
        waf,
        robots_txt,
        fingerprint,
        security_issues,
    })
}

fn detect_waf(headers: &HashMap<String, String>) -> Option<String> {
    let h = |k: &str| headers.get(k).map(|s| s.to_lowercase());
    
    if h("server").map_or(false, |s| s.contains("cloudflare")) || headers.contains_key("cf-ray") {
        return Some("Cloudflare".to_string());
    }
    if h("server").map_or(false, |s| s.contains("akamai")) || headers.contains_key("x-akamai-transformed") {
        return Some("Akamai".to_string());
    }
    if headers.contains_key("x-amz-cf-id") {
        return Some("Amazon CloudFront".to_string());
    }
    None
}

fn check_security_headers(headers: &HashMap<String, String>) -> Vec<String> {
    let mut issues = Vec::new();
    let lower_headers: HashMap<String, String> = headers.iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    if !lower_headers.contains_key("strict-transport-security") {
        issues.push("Missing HSTS (Strict-Transport-Security)".to_string());
    }
    if !lower_headers.contains_key("content-security-policy") {
        issues.push("Missing CSP (Content-Security-Policy)".to_string());
    }
    if !lower_headers.contains_key("x-frame-options") {
        issues.push("Missing X-Frame-Options".to_string());
    }
    if !lower_headers.contains_key("x-content-type-options") {
        issues.push("Missing X-Content-Type-Options".to_string());
    }
    
    issues
}

async fn fetch_robots(client: &reqwest::Client, base_url: &str) -> Result<Vec<String>> {
    let url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() { return Ok(vec![]); }
    
    let text = resp.text().await?;
    let disallows = text.lines()
        .filter(|l| l.to_lowercase().starts_with("disallow:"))
        .map(|l| {
            let parts: Vec<&str> = l.splitn(2, ':').collect();
            parts.get(1).unwrap_or(&"").trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect();
    Ok(disallows)
}

fn analyze_content(html_content: &str) -> Fingerprint {
    let document = Html::parse_document(html_content);
    let mut fp = Fingerprint::default();

    if html_content.contains("/wp-content/") { fp.cms = Some("WordPress".to_string()); }
    else if html_content.contains("Drupal.settings") { fp.cms = Some("Drupal".to_string()); }

    let selector = Selector::parse("meta[name='generator']").unwrap();
    if let Some(element) = document.select(&selector).next() {
        if let Some(content) = element.value().attr("content") {
            fp.generator = Some(content.to_string());
        }
    }

    let re_social = Regex::new(r#"(facebook\.com|twitter\.com|instagram\.com|t\.me)/[a-zA-Z0-9_\.]+"#).unwrap();
    for cap in re_social.captures_iter(html_content) {
        let link = cap[0].to_string();
        if !fp.social_links.contains(&link) { fp.social_links.push(link); }
    }

    let re_ua = Regex::new(r"UA-\d+-\d+").unwrap();
    let re_g = Regex::new(r"G-[A-Z0-9]{6,}").unwrap();
    let re_pub = Regex::new(r"pub-\d{16}").unwrap();

    for cap in re_ua.captures_iter(html_content) {
        let s = cap[0].to_string();
        if !fp.ga_ids.contains(&s) { fp.ga_ids.push(s); }
    }
    for cap in re_g.captures_iter(html_content) {
        let s = cap[0].to_string();
        if !fp.ga_ids.contains(&s) { fp.ga_ids.push(s); }
    }
    for cap in re_pub.captures_iter(html_content) {
        let s = cap[0].to_string();
        if !fp.adsense_ids.contains(&s) { fp.adsense_ids.push(s); }
    }

    fp
}