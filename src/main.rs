mod core;
mod models;
mod modules;

use clap::Parser;
use colored::*;
use core::config::AbyssConfig;
use models::TargetData;
use std::time::Instant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AbyssConfig::parse();
    let start_time = Instant::now();

    if !config.quiet {
        print_banner();
        log_info(&format!(
            "Starting Deep Intelligence Scan (0.2.0) for: {}",
            config.target.cyan().bold()
        ));
    }

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; Abyss/3.5; +https://github.com/takumaniwa/abyss)")
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // --- Phase 1: Core Recon ---
    if !config.quiet {
        log_info("Phase 1: Scanning target infrastructure...");
    }
    let dns_task = modules::dns::scan_dns(&config.target);
    let http_task = modules::http::scan_http(&config.target, &client);
    let (dns_res, http_res) = tokio::join!(dns_task, http_task);

    let (dns_data, cloud_res) = dns_res.unwrap_or_else(|e| {
        if !config.quiet {
            log_error(&format!("DNS Scan Failed: {}", e));
        }
        (Default::default(), None)
    });

    let (http_data, secrets, mut attribution) = http_res.unwrap_or_else(|e| {
        if !config.quiet {
            log_error(&format!("HTTP Scan Failed: {}", e));
        }
        (None, vec![], Default::default())
    });

    // Infrastructure Probing
    for txt in &dns_data.txt {
        if txt.contains("google-site-verification") || txt.contains("facebook-domain-verification")
        {
            attribution
                .verification_codes
                .push(format!("DNS TXT: {}", txt));
        }
    }
    if !dns_data.mx.is_empty() {
        let banners = modules::infrastructure::grab_mx_banners(&dns_data.mx).await;
        attribution.mx_banners = banners;
    }

    let primary_ip = dns_data.a.first().cloned().unwrap_or_default();

    // --- Phase 2: Total Recall ---
    if !config.quiet {
        log_info("Phase 2: Querying global intelligence networks...");
    }
    let crt_task = modules::passive::scan_crtsh(&config.target, &client);
    let wayback_task = modules::passive::scan_wayback(&config.target, &client);
    let otx_task = modules::passive::scan_alienvault(&config.target, &client);
    let urlscan_task = modules::passive::scan_urlscan(&config.target, &client);
    let github_task = modules::passive::scan_github(&config.target, &client);

    // IP-dependent
    let geo_task = if !primary_ip.is_empty() {
        Some(modules::passive::scan_geoip(&primary_ip, &client))
    } else {
        None
    };
    let rev_dns_task = if !primary_ip.is_empty() {
        Some(modules::passive::scan_reverse_dns(&primary_ip, &client))
    } else {
        None
    };
    let shodan_task = if !primary_ip.is_empty() {
        Some(modules::passive::scan_shodan(&primary_ip, &client))
    } else {
        None
    };

    let (crt_res, wayback_res, otx_res, urlscan_res, github_res) =
        tokio::join!(crt_task, wayback_task, otx_task, urlscan_task, github_task);

    let geo_res = if let Some(t) = geo_task {
        t.await.ok()
    } else {
        None
    };
    let rev_dns_res = if let Some(t) = rev_dns_task {
        t.await.ok()
    } else {
        None
    };
    let shodan_res = if let Some(t) = shodan_task {
        t.await.ok()
    } else {
        None
    };

    let (_passive_subdomains, ssl_intel) = crt_res.unwrap_or_default();
    let archives = wayback_res.unwrap_or_default();
    let alienvault = otx_res.unwrap_or_default();
    let urlscan = urlscan_res.unwrap_or_default();
    let github_leaks = github_res.unwrap_or_default();
    let geo_intel = geo_res.unwrap_or_default();
    let passive_dns_domains = rev_dns_res.unwrap_or_default();

    let result = TargetData {
        target: config.target.clone(),
        dns: dns_data,
        http: http_data,
        attribution,
        secrets,
        cloud: cloud_res,
        ssl_intelligence: ssl_intel,
        geo_intelligence: geo_intel,
        passive_dns: passive_dns_domains,
        archives,
        alienvault,
        urlscan,
        github_leaks,
        shodan: shodan_res,
    };

    let json = serde_json::to_string_pretty(&result)?;
    println!("{}", json);

    if let Some(path) = config.html {
        if !config.quiet {
            log_info(&format!(
                "Generating Comprehensive Report: {}",
                path.green()
            ));
        }
        modules::reporting::generate_report(&result, &path)?;
    }

    if !config.quiet {
        let duration = start_time.elapsed();
        log_success(&format!("Scan completed in {:.2?}", duration));
    }
    Ok(())
}

fn print_banner() {
    let banner = r#"
    ___    ____  __  _______ _____
   /   |  / __ )/ / / / ___// ___/
  / /| | / __  / /_/ /\__ \ \__ \ 
 / ___ |/ /_/ /\__, /___/ /___/ / 
/_/  |_/_____/ /____//____//____/  
      TOTAL RECALL 0.2.0
"#;
    eprintln!("{}", banner.purple().bold());
}

fn log_info(msg: &str) {
    eprintln!("{} {}", "[*]".blue(), msg);
}
fn log_success(msg: &str) {
    eprintln!("{} {}", "[+]".green(), msg);
}
fn log_error(msg: &str) {
    eprintln!("{} {}", "[!]".red().bold(), msg);
}
