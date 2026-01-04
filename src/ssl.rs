use anyhow::{Result, Context};
use crate::models::SslInfo;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

pub async fn scan_ssl(domain: &str) -> Result<SslInfo> {
    let mut root_store = RootCertStore::empty();
    // Using default webpki roots
    root_store.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    
    // Connect to port 443
    let addr = format!("{}:443", domain);
    let stream = TcpStream::connect(&addr).await
        .context("Failed to connect to TCP 443")?;

    let server_name = ServerName::try_from(domain)
        .context("Invalid DNS name for SSL")?;

    let stream = connector.connect(server_name, stream).await
        .context("TLS handshake failed")?;

    let (_, session) = stream.get_ref();
    
    if let Some(certs) = session.peer_certificates() {
        if let Some(cert) = certs.first() {
            return parse_cert(&cert.0);
        }
    }

    Err(anyhow::anyhow!("No certificates found"))
}

fn parse_cert(der_data: &[u8]) -> Result<SslInfo> {
    let (_, x509) = X509Certificate::from_der(der_data)?;
    
    let subject = x509.subject();
    let issuer = x509.issuer();
    
    let cn = subject.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();

    let issuer_str = issuer.to_string();
    
    let valid_from = x509.validity().not_before.to_string();
    let valid_to = x509.validity().not_after.to_string();

    let mut sans = Vec::new();
    if let Some(ext) = x509.extensions().iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .map(|ext| ext.parsed_extension())
    {
        if let ParsedExtension::SubjectAlternativeName(san_ext) = ext {
            for name in &san_ext.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                    GeneralName::IPAddress(ip) => sans.push(format!("{:?}", ip)),
                    _ => {}
                }
            }
        }
    }

    Ok(SslInfo {
        issuer: issuer_str,
        subject_cn: cn,
        sans,
        valid_from,
        valid_to,
    })
}