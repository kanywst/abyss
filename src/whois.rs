use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn scan_whois(domain: &str) -> Result<String> {
    // 1. Query IANA to find the TLD whois server
    let iana_response = query_server("whois.iana.org", domain).await?;
    
    // 2. Find referral
    let referral = iana_response.lines()
        .find(|l| l.to_lowercase().starts_with("refer:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string());

    if let Some(server) = referral {
        if !server.is_empty() {
            // 3. Query the actual registrar
            return query_server(&server, domain).await;
        }
    }

    // Default fallback for some common TLDs if IANA fails or no referral
    if domain.ends_with(".com") || domain.ends_with(".net") {
        return query_server("whois.verisign-grs.com", domain).await;
    }
    if domain.ends_with(".org") {
        return query_server("whois.pir.org", domain).await;
    }
    if domain.ends_with(".jp") {
        return query_server("whois.jprs.jp", &format!("{}/e", domain)).await; // /e for English
    }

    Ok(iana_response)
}

async fn query_server(server: &str, query: &str) -> Result<String> {
    let addr = format!("{}:43", server);
    
    let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok("Whois connection timed out".to_string()),
    };

    let request = format!("{}\r\n", query);
    stream.write_all(request.as_bytes()).await?;

    let mut response = String::new();
    match timeout(Duration::from_secs(5), stream.read_to_string(&mut response)).await {
        Ok(_) => {},
        Err(_) => response.push_str("\n[Timeout reading response]"),
    }

    Ok(response)
}
