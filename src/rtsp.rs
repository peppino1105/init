use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RTSP_PORTS: &[u16] = &[554, 854];

pub async fn capture_snapshot(
    host: &str,
    port: u16,
    channel: u16,
    user: &str,
    password: &str,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let mut ports_to_try = vec![port];
    for &p in RTSP_PORTS {
        if p != port {
            ports_to_try.push(p);
        }
    }
    for &try_port in &ports_to_try {
        if let Some(jpeg) =
            try_capture_on_port(host, try_port, channel, user, password, timeout).await
        {
            return Some(jpeg);
        }
    }
    None
}

async fn try_capture_on_port(
    host: &str,
    port: u16,
    channel: u16,
    user: &str,
    password: &str,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let addr = format!("{}:{}", host, port);
    eprintln!("  [debug] rtsp: connecting to {} ch={}...", addr, channel);

    // Use a short connect timeout (3s) — if port is closed/NAT'd, fail fast.
    let connect_timeout = Duration::from_secs(3);
    let mut stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("  [debug] rtsp: TCP connect to {} failed: {}", addr, e);
            return None;
        }
        Err(_) => {
            eprintln!("  [debug] rtsp: TCP connect to {} timed out (3s)", addr);
            return None;
        }
    };
    stream.set_nodelay(true).ok();

    let base_url = format!(
        "rtsp://{}:{}/cam/realmonitor?channel={}",
        host, port, channel
    );

    // -- OPTIONS (cseq=1) --
    eprintln!("  [debug] rtsp: OPTIONS {} ...", base_url);
    let opts_raw = send_and_read(&mut stream, "OPTIONS", &base_url, "", 1, None, timeout).await;
    let opts_resp = match opts_raw {
        Some(r) => r,
        None => {
            eprintln!("  [debug] rtsp: OPTIONS no response from {}", addr);
            return None;
        }
    };
    let opts_first = opts_resp.lines().next().unwrap_or("");
    eprintln!("  [debug] rtsp: OPTIONS -> {}", opts_first);

    // Handle 401: compute Digest auth for all subsequent requests.
    let mut digest_auth = String::new();
    if opts_resp.contains("401") {
        if let Some(ch) = parse_digest_challenge(&opts_resp) {
            let resp = compute_digest(&ch, user, password, "OPTIONS", &base_url);
            digest_auth = format!(
                "Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"\r\n",
                user, ch.realm, ch.nonce, base_url, resp
            );
            // Retry OPTIONS with Digest.
            eprintln!("  [debug] rtsp: OPTIONS retry with Digest auth...");
            let retry = send_and_read(
                &mut stream,
                "OPTIONS",
                &base_url,
                &digest_auth,
                2,
                None,
                timeout,
            )
            .await;
            if let Some(r) = retry {
                eprintln!(
                    "  [debug] rtsp: OPTIONS retry -> {}",
                    r.lines().next().unwrap_or("")
                );
                // Some Dahua RTSP servers keep answering 401 to OPTIONS even
                // with a correct Digest (they only honor it on DESCRIBE/SETUP).
                // Fail only on a hard error, not on a repeat 401 — the
                // challenge from the first response is still good.
                if !r.contains("200") && !r.contains("401") {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            eprintln!("  [debug] rtsp: no Digest challenge in 401");
            return None;
        }
    }

    // -- DESCRIBE --
    eprintln!("  [debug] rtsp: DESCRIBE {} ...", base_url);
    let desc_resp = send_and_read(
        &mut stream,
        "DESCRIBE",
        &base_url,
        &digest_auth,
        3,
        None,
        timeout,
    )
    .await;
    let desc_raw = match desc_resp {
        Some(r) => r,
        None => {
            eprintln!("  [debug] rtsp: DESCRIBE failed");
            return None;
        }
    };
    eprintln!(
        "  [debug] rtsp: DESCRIBE -> {}",
        desc_raw.lines().next().unwrap_or("")
    );
    if !desc_raw.contains("200") {
        return None;
    }

    // -- SETUP --
    let setup_url = format!("{}/trackID=0", base_url);
    let transport = "RTP/AVP/TCP;interleaved=0-1";
    eprintln!("  [debug] rtsp: SETUP {} ...", setup_url);
    let setup_resp = send_and_read_with_transport(
        &mut stream,
        "SETUP",
        &setup_url,
        &digest_auth,
        4,
        transport,
        timeout,
    )
    .await;
    let setup_raw = match setup_resp {
        Some(r) => r,
        None => {
            eprintln!("  [debug] rtsp: SETUP failed");
            return None;
        }
    };
    eprintln!(
        "  [debug] rtsp: SETUP -> {}",
        setup_raw.lines().next().unwrap_or("")
    );
    if !setup_raw.contains("200") {
        return None;
    }

    // Extract Session header for subsequent requests.
    let session_id = extract_header(&setup_raw, "Session");

    // -- PLAY --
    eprintln!("  [debug] rtsp: PLAY {} ...", base_url);
    let session_hdr = session_id
        .as_ref()
        .map(|s| format!("Session: {}\r\n", s))
        .unwrap_or_default();
    let play_resp = send_and_read_with_session(
        &mut stream,
        "PLAY",
        &base_url,
        &digest_auth,
        &session_hdr,
        5,
        timeout,
    )
    .await;
    if let Some(r) = play_resp {
        eprintln!("  [debug] rtsp: PLAY -> {}", r.lines().next().unwrap_or(""));
        if !r.contains("200") {
            return None;
        }
    } else {
        eprintln!("  [debug] rtsp: PLAY failed");
        return None;
    }

    // -- Receive RTP packets and extract MJPEG frame --
    eprintln!("  [debug] rtsp: receiving RTP stream...");
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = Vec::with_capacity(256 * 1024);
    let mut frame_buf = Vec::new();
    let mut got_rtp = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            eprintln!(
                "  [debug] rtsp: receive timed out after {}ms",
                timeout.as_millis()
            );
            break;
        }

        let mut chunk = [0u8; 4096];
        let n = match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                eprintln!("  [debug] rtsp: stream EOF");
                break;
            }
            Ok(Ok(n)) => n,
            Err(_) => {
                eprintln!("  [debug] rtsp: read timed out");
                break;
            }
            _ => break,
        };
        buf.extend_from_slice(&chunk[..n]);

        // Parse interleaved RTP frames: '$' + channel(1) + length(2) + data.
        while buf.len() >= 4 {
            if buf[0] == b'$' {
                let rtsp_channel = buf[1] as u16;
                let rtp_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                if buf.len() < 4 + rtp_len {
                    break;
                }
                let rtp_data = buf[4..4 + rtp_len].to_vec();
                buf.drain(..4 + rtp_len);

                if rtsp_channel == 0 && rtp_data.len() >= 12 {
                    got_rtp = true;
                    let header_len = 12;
                    let padding = if rtp_data.len() > 1 && (rtp_data[0] & 0x20) != 0 {
                        *rtp_data.last().unwrap_or(&0) as usize
                    } else {
                        0
                    };
                    let payload_end = rtp_data.len().saturating_sub(padding);
                    if payload_end > header_len {
                        let payload = &rtp_data[header_len..payload_end];
                        frame_buf.extend_from_slice(payload);
                    }
                }
            } else {
                if !frame_buf.is_empty() {
                    break;
                }
                buf.remove(0);
            }
        }

        // Check for complete JPEG (FFD8...FFD9).
        if frame_buf.len() >= 4 && frame_buf[0] == 0xFF && frame_buf[1] == 0xD8 {
            let last_two = &frame_buf[frame_buf.len() - 2..];
            if last_two[0] == 0xFF && last_two[1] == 0xD9 {
                eprintln!(
                    "  [debug] rtsp: got complete JPEG frame ({} bytes)",
                    frame_buf.len()
                );
                let _ = teardown(&mut stream, &base_url, &digest_auth, &session_hdr, timeout).await;
                return Some(frame_buf);
            }
        }

        // H.264/H.265 detection: give up.
        if got_rtp && frame_buf.len() > 512 * 1024 {
            eprintln!(
                "  [debug] rtsp: buffer too large ({} bytes) - likely H.264/H.265, not MJPEG",
                frame_buf.len()
            );
            let _ = teardown(&mut stream, &base_url, &digest_auth, &session_hdr, timeout).await;
            return None;
        }
        if got_rtp && !frame_buf.is_empty() && frame_buf.len() >= 2 && frame_buf[0] != 0xFF {
            eprintln!(
                "  [debug] rtsp: first payload byte=0x{:02X} - likely H.264/H.265",
                frame_buf[0]
            );
            let _ = teardown(&mut stream, &base_url, &digest_auth, &session_hdr, timeout).await;
            return None;
        }

        if got_rtp {
            eprintln!(
                "  [debug] rtsp: RTP frames received, buffer={} bytes, waiting for JPEG EOI...",
                frame_buf.len()
            );
        }
    }

    let _ = teardown(&mut stream, &base_url, &digest_auth, &session_hdr, timeout).await;
    None
}

// --- Low-level RTSP helpers ---

async fn send_and_read(
    stream: &mut TcpStream,
    method: &str,
    url: &str,
    extra_headers: &str,
    cseq: u32,
    transport: Option<&str>,
    timeout: Duration,
) -> Option<String> {
    let transport_hdr = match transport {
        Some(t) => format!("Transport: {}\r\n", t),
        None => String::new(),
    };
    let request = format!(
        "{method} {url} RTSP/1.0\r\n\
         CSeq: {cseq}\r\n\
         {extra_headers}\
         {transport_hdr}\
         User-Agent: DahuaDhipAdduser\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    read_rtsp_response(stream, timeout).await
}

async fn send_and_read_with_transport(
    stream: &mut TcpStream,
    method: &str,
    url: &str,
    extra_headers: &str,
    cseq: u32,
    transport: &str,
    timeout: Duration,
) -> Option<String> {
    let request = format!(
        "{method} {url} RTSP/1.0\r\n\
         CSeq: {cseq}\r\n\
         {extra_headers}\
         Transport: {transport}\r\n\
         User-Agent: DahuaDhipAdduser\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    read_rtsp_response(stream, timeout).await
}

async fn send_and_read_with_session(
    stream: &mut TcpStream,
    method: &str,
    url: &str,
    extra_headers: &str,
    session_hdr: &str,
    cseq: u32,
    timeout: Duration,
) -> Option<String> {
    let request = format!(
        "{method} {url} RTSP/1.0\r\n\
         CSeq: {cseq}\r\n\
         {extra_headers}\
         {session_hdr}\
         User-Agent: DahuaDhipAdduser\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    read_rtsp_response(stream, timeout).await
}

async fn teardown(
    stream: &mut TcpStream,
    url: &str,
    extra_headers: &str,
    session_hdr: &str,
    timeout: Duration,
) -> Option<String> {
    send_and_read_with_session(
        stream,
        "TEARDOWN",
        url,
        extra_headers,
        session_hdr,
        99,
        timeout,
    )
    .await
}

async fn read_rtsp_response(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut resp_buf = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                resp_buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_header_end(&resp_buf) {
                    let headers_str = String::from_utf8_lossy(&resp_buf[..pos]).to_string();
                    let content_len = headers_str
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|s| s.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = pos + 4;
                    let body_available = resp_buf.len().saturating_sub(body_start);
                    if body_available < content_len {
                        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                        let mut body = vec![0u8; content_len - body_available];
                        let _ = tokio::time::timeout(rem, stream.read_exact(&mut body)).await;
                    }
                    return Some(headers_str);
                }
            }
            _ => break,
        }
    }
    None
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn extract_header(response: &str, name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        if line
            .to_lowercase()
            .starts_with(&format!("{}:", name.to_lowercase()))
        {
            line.split(':').nth(1).map(|s| s.trim().to_string())
        } else {
            None
        }
    })
}

// --- Digest Auth ---

struct DigestChallenge {
    realm: String,
    nonce: String,
    #[allow(dead_code)]
    opaque: String,
    qop: String,
}

fn parse_digest_challenge(response: &str) -> Option<DigestChallenge> {
    let www_auth = response
        .lines()
        .find(|l| l.to_lowercase().starts_with("www-authenticate:"))?;
    let challenge = www_auth
        .trim_start_matches("WWW-Authenticate:")
        .trim_start_matches("www-authenticate:")
        .trim();

    if !challenge.to_lowercase().starts_with("digest ") {
        return None;
    }
    let params = &challenge[7..];

    let realm = extract_quoted(params, "realm").unwrap_or_default();
    let nonce = extract_quoted(params, "nonce").unwrap_or_default();
    let opaque = extract_quoted(params, "opaque").unwrap_or_default();
    let qop = extract_quoted(params, "qop").unwrap_or_else(|| "auth".to_string());

    Some(DigestChallenge {
        realm,
        nonce,
        opaque,
        qop,
    })
}

fn extract_quoted(params: &str, key: &str) -> Option<String> {
    let idx = params.find(&format!("{}=", key))?;
    let after_eq = &params[idx + key.len() + 1..];
    let trimmed = after_eq.trim_start();
    if trimmed.starts_with('"') {
        let end = trimmed[1..].find('"')?;
        Some(trimmed[1..end + 1].to_string())
    } else {
        let end = trimmed
            .find(|c: char| c == ',' || c == ' ')
            .unwrap_or(trimmed.len());
        Some(trimmed[..end].to_string())
    }
}

fn compute_digest(
    ch: &DigestChallenge,
    user: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> String {
    let ha1 = hex::encode(md5::compute(format!("{}:{}:{}", user, ch.realm, password)).as_ref());
    let ha2 = hex::encode(md5::compute(format!("{}:{}", method, uri)).as_ref());
    let nc = "00000001";
    let cnonce = "dahua_rtsp_cnonce";

    if ch.qop.is_empty() || ch.qop == "none" {
        hex::encode(md5::compute(format!("{}:{}:{}", ha1, ch.nonce, ha2)).as_ref())
    } else {
        hex::encode(
            md5::compute(format!(
                "{}:{}:{}:{}:{}:{}",
                ha1, ch.nonce, nc, cnonce, ch.qop, ha2
            ))
            .as_ref(),
        )
    }
}
