use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country_code: String,
    pub country: String,
    pub city: String,
}

impl Default for GeoInfo {
    fn default() -> Self {
        Self {
            country_code: "XX".into(),
            country: "N/A".into(),
            city: "N/A".into(),
        }
    }
}

/// Resolve a public IP to a country code and city using the free ip-api.com
/// lookup. Returns None if the lookup fails or times out (the caller should
/// fall back to `GeoInfo::default()`).
pub async fn lookup(ip: &str) -> Option<GeoInfo> {
    let host = ip.split(':').next().unwrap_or(ip);
    if host.is_empty() || host == "0.0.0.0" || host == "255.255.255.255" {
        return None;
    }
    let path = format!("/json/{}?fields=status,country,countryCode,city", host);
    let resp = http_get("ip-api.com", 80, &path).await?;
    let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
    if v.get("status").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }
    let country = v
        .get("countryCode")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let country_name = sanitize(v.get("country").and_then(|c| c.as_str()).unwrap_or(""));
    let city = sanitize(v.get("city").and_then(|c| c.as_str()).unwrap_or(""));
    Some(GeoInfo {
        country_code: country,
        country: country_name,
        city,
    })
}

/// Keep the city safe for the `_`-separated ok-file line: spaces and other
/// non-alphanumeric characters become `-` so the field count stays fixed.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    if cleaned.is_empty() {
        "N/A".into()
    } else {
        cleaned
    }
}

async fn http_get(host: &str, port: u16, path: &str) -> Option<String> {
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let mut sock = TcpStream::connect(format!("{}:{}", host, port))
            .await
            .ok()?;
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             User-Agent: dahua-dhip-adduser/0.1\r\nAccept: application/json\r\n\r\n",
            path, host
        );
        sock.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        Some(body.trim().to_string())
    })
    .await;
    match result {
        Ok(r) => r,
        Err(_) => None,
    }
}
