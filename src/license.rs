use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use sha2::{Digest, Sha256};

pub const MASTER_LICENSE: &str =
    "A7fK3mP9xQ2Lz8WcR5TnV6bY1HjU4eD0sGkM7aZpX9oCqF2rB8lN5tJ3uE6vIh4yO1wS2dQ8PzX7cL3mK5nR9T0H";

const LICENSE_FILE: &str = "licence.lic";

#[derive(Debug)]
pub enum LicenseStatus {
    Valid,
    Missing,
    Empty,
    Invalid(String),
}

/// Validate a license string against the current machine.
/// A license is valid if it equals the MASTER_LICENSE key, or if it decrypts
/// to a payload whose machine_id matches the current computer.
pub fn validate_content(content: &str) -> Result<(), String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("la licenza è vuota".into());
    }
    if trimmed == MASTER_LICENSE {
        return Ok(());
    }
    match decrypt_license(trimmed) {
        Some(payload) => match parse_machine_id(&payload) {
            Some(mid) if mid == machine_id() => Ok(()),
            Some(_) => Err("la licenza non è valida per questo computer".into()),
            None => Err("licenza non valida".into()),
        },
        None => Err("formato di licenza non valido".into()),
    }
}

/// Read licence.lic (next to the executable, falling back to the current dir)
/// and validate it against the current machine.
pub fn check_license() -> LicenseStatus {
    let content = match read_license_file() {
        Ok(c) => c,
        Err(_) => return LicenseStatus::Missing,
    };
    if content.trim().is_empty() {
        return LicenseStatus::Empty;
    }
    match validate_content(&content) {
        Ok(()) => LicenseStatus::Valid,
        Err(r) => LicenseStatus::Invalid(r),
    }
}

pub fn license_file_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(LICENSE_FILE);
        }
    }
    PathBuf::from(LICENSE_FILE)
}

fn license_file_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join(LICENSE_FILE));
        }
    }
    v.push(PathBuf::from(LICENSE_FILE));
    v
}

pub fn read_license_file() -> Result<String, IoError> {
    for p in license_file_candidates() {
        if p.exists() {
            return std::fs::read_to_string(p);
        }
    }
    Err(IoError::new(ErrorKind::NotFound, "licence.lic non trovato"))
}

pub fn write_license_file(content: &str) -> std::io::Result<()> {
    std::fs::write(license_file_path(), content.trim())
}

// ---- License generation ----

pub fn make_payload(machine_id: &str) -> String {
    serde_json::json!({
        "machine_id": machine_id,
        "created": chrono::Utc::now().to_rfc3339(),
    })
    .to_string()
}

pub fn encrypt_license(payload: &str) -> String {
    hex::encode_upper(aes_ecb_encrypt(&secret_key(), payload.as_bytes()))
}

fn decrypt_license(s: &str) -> Option<String> {
    let bytes = hex::decode(s.trim()).ok()?;
    let plain = aes_ecb_decrypt(&secret_key(), &bytes)?;
    String::from_utf8(plain).ok()
}

fn parse_machine_id(payload: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    v.get("machine_id")?.as_str().map(|s| s.to_string())
}

fn secret_key() -> [u8; 32] {
    let d = Sha256::digest(b"dahua-p2p-adduser-license-v1");
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

fn aes_ecb_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let block_len = 16usize;
    let pad = block_len - (data.len() % block_len);
    let total = data.len() + pad;
    let mut buf = vec![0u8; total];
    buf[..data.len()].copy_from_slice(data);
    for b in &mut buf[data.len()..] {
        *b = pad as u8;
    }
    let mut out = Vec::with_capacity(total);
    for chunk in buf.chunks_exact(block_len) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

fn aes_ecb_decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    let pad = *out.last()? as usize;
    if pad == 0 || pad > 16 || out.len() < pad {
        return None;
    }
    if !out[out.len() - pad..].iter().all(|&b| b as usize == pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

// ---- Machine fingerprint (unique per computer) ----

pub fn machine_id() -> String {
    let raw = machine_id_raw();
    let digest = Sha256::digest(raw.as_bytes());
    let hex = hex::encode(digest);
    let mut out = String::new();
    for (i, c) in hex.chars().take(24).enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    out
}

fn machine_id_raw() -> String {
    if let Some(uuid) = platform_uuid() {
        return format!("uuid:{}\nos:{}", uuid, std::env::consts::OS);
    }
    format!(
        "host:{}\nmac:{}\nos:{}",
        hostname(),
        primary_mac().unwrap_or_default(),
        std::env::consts::OS
    )
}

#[cfg(target_os = "linux")]
fn platform_uuid() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn platform_uuid() -> Option<String> {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    extract_quoted_after(&text, "IOPlatformUUID")
}

#[cfg(target_os = "windows")]
fn platform_uuid() -> Option<String> {
    let out = std::process::Command::new("reg")
        .args([
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains("MachineGuid"))
        .and_then(|l| l.split_whitespace().last().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_uuid() -> Option<String> {
    None
}

fn extract_quoted_after(text: &str, key: &str) -> Option<String> {
    let idx = text.find(key)?;
    let rest = &text[idx + key.len()..];
    let eq = rest.find('=')?;
    let after_eq = &rest[eq + 1..];
    let q1 = after_eq.find('"')?;
    let inner = &after_eq[q1 + 1..];
    let q2 = inner.find('"')?;
    Some(inner[..q2].to_string())
}

fn hostname() -> String {
    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(h) = std::env::var(key) {
            if !h.trim().is_empty() {
                return h;
            }
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[allow(dead_code)]
fn prefer_score(name: &str) -> u8 {
    if name.starts_with("en") || name.starts_with("eth") || name.starts_with("wlan") {
        2
    } else if name.starts_with("wl") {
        1
    } else {
        0
    }
}

fn primary_mac() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let dirs = std::fs::read_dir("/sys/class/net").ok()?;
        let mut candidates = Vec::new();
        for e in dirs.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            if let Ok(addr) = std::fs::read_to_string(e.path().join("address")) {
                let a = addr.trim().to_string();
                if !a.is_empty() && a != "00:00:00:00:00:00" {
                    candidates.push((prefer_score(&name), a));
                }
            }
        }
        candidates.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
        return candidates.into_iter().next().map(|(_, a)| a);
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ifconfig").arg("-l").output().ok()?;
        let list = String::from_utf8_lossy(&out.stdout);
        for iface in list.split_whitespace() {
            if !(iface.starts_with("en") || iface.starts_with("eth")) {
                continue;
            }
            let o = std::process::Command::new("ifconfig").arg(iface).output().ok()?;
            let txt = String::from_utf8_lossy(&o.stdout);
            if let Some(line) = txt.lines().find(|l| l.contains("ether")) {
                let mac = line.split_whitespace().nth(1)?.to_string();
                if mac != "00:00:00:00:00:00" {
                    return Some(mac);
                }
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("getmac")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let mac = line
                .split(',')
                .next()
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_default();
            if !mac.is_empty() && mac != "00-00-00-00-00-00" {
                return Some(mac);
            }
        }
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}
