mod dns;
mod http;
mod intelligence;
mod models;
mod report;
mod shodan;
mod ssl;
mod subdomains;
mod whois;

use anyhow::Result;
use clap::Parser;
use models::TargetInfo;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain (e.g., example.com)
    #[arg(short, long)]
    target: String,

    /// Output HTML report to file
    #[arg(long)]
    html: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let target = args.target;

    eprintln!("[*] Starting Abyss scan for: {}", target);

    let dns_future = dns::scan_dns(&target);
    let http_future = http::scan_http(&target);
    let ssl_future = ssl::scan_ssl(&target);
    let sub_future = subdomains::scan_subdomains(&target);
    let whois_future = whois::scan_whois(&target);

    // Initial parallel scan
    let (dns_res, http_res, ssl_res, sub_res, whois_res) = tokio::join!(
        dns_future,
        http_future,
        ssl_future,
        sub_future,
        whois_future
    );

    let mut info = TargetInfo {
        domain: target.clone(),
        dns: dns_res.unwrap_or_else(|e| {
            eprintln!("[!] DNS scan failed: {}", e);
            Default::default()
        }),
        http: http_res.ok(),
        ssl: ssl_res.ok(),
        subdomains: sub_res.unwrap_or_else(|e| {
            eprintln!("[!] Subdomain scan failed: {}", e);
            vec![]
        }),
        whois: whois_res.ok(),
        shodan: None,
    };

    // Sequential Scan: Shodan (Needs IP from DNS)
    if let Some(geo) = &info.dns.geo_ip {
        eprintln!("[*] Querying InternetDB (Shodan) for IP: {}", geo.ip);
        if let Ok(shodan_data) = shodan::scan_internetdb(&geo.ip).await {
            info.shodan = shodan_data;
        }
    }

    // Analyze Intelligence
    eprintln!("[*] Analyzing intelligence data...");
    let intel = intelligence::analyze_target(&info);

    let json_output = serde_json::to_string_pretty(&info)?;
    println!("{}", json_output);

    if let Some(html_path) = args.html {
        eprintln!("[*] Generating HTML report: {}", html_path);
        report::generate_html_report(&info, &intel, &html_path)?;
    }

    eprintln!("[*] Scan complete. Risk Level: {}", intel.risk_level);
    Ok(())
}
