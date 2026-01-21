use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

// Connect to Mail Servers to grab banners (postfix version, internal hostnames)
pub async fn grab_mx_banners(mx_records: &[String]) -> Vec<String> {
    let mut banners = Vec::new();
    
    for mx in mx_records {
        // MX record usually comes as "10 mail.example.com", split it
        let host = mx.split_whitespace().last().unwrap_or(mx);
        
        // Try port 25 (SMTP) and 587 (Submission)
        for port in [25, 587] {
            let addr = format!("{}:{}", host, port);
            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                Duration::from_secs(3),
                TcpStream::connect(&addr)
            ).await {
                // Wait for greeting
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = tokio::time::timeout(
                    Duration::from_secs(3),
                    stream.read(&mut buffer)
                ).await
                    && n > 0
                {
                    let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                        // Only keep relevant SMTP banners
                        if banner.starts_with("220") {
                            banners.push(format!("{}:{} -> {}", host, port, banner));
                            // Be polite and send QUIT
                            let _ = stream.write_all(b"QUIT\r\n").await;
                            break; // Found one, move to next MX
                        }
                }
            }
        }
    }
    banners
}
