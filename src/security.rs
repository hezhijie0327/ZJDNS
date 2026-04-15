use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rcgen::generate_simple_self_signed;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::types::TLSSettings;

pub fn load_tls_config(settings: &TLSSettings) -> Result<Arc<ServerConfig>> {
    if settings.self_signed {
        let cert = generate_simple_self_signed(vec!["zjdns.local".to_string()])?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        let certs = vec![Certificate(cert_der)];
        let key = PrivateKey(key_der);
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("create self-signed TLS config")?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        return Ok(Arc::new(config));
    }

    let cert_file = &settings.cert_file;
    let key_file = &settings.key_file;
    if cert_file.is_empty() || key_file.is_empty() {
        return Err(anyhow!("TLS certificate and key files must be configured"));
    }

    let certs = load_certs(cert_file).context("load TLS certificate")?;
    let key = load_private_key(key_file).context("load TLS private key")?;

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("create TLS config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn build_tls_client_config(skip_tls_verify: bool) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints.map(|x| x.to_vec()),
        )
    }));

    let builder = ClientConfig::builder().with_safe_defaults();
    let config = if skip_tls_verify {
        builder
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(root_store).with_no_client_auth()
    };

    Ok(config)
}

struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let file = File::open(path).context("open cert file")?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader).context("decode cert PEM")?;
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &str) -> Result<PrivateKey> {
    let file = File::open(path).context("open key file")?;
    let mut reader = BufReader::new(file);
    let keys = pkcs8_private_keys(&mut reader).context("decode pkcs8 key")?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    let file = File::open(path).context("open key file fallback")?;
    let mut reader = BufReader::new(file);
    let keys = rsa_private_keys(&mut reader).context("decode rsa key")?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    Err(anyhow!("no private keys found in {}", path))
}
