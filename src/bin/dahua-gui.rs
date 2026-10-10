use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use chrono::Datelike;
use chrono::Timelike;
use dahua_dhip_adduser::license;
use eframe::egui;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    AddUser,
    List,
    Delete,
    Reboot,
    CheckP2p,
}

struct GuiApp {
    serial: String,
    serial_file: String,
    user: String,
    delete_name: String,
    delete_by_id: bool,
    delete_all: bool,
    password: String,
    memo: String,
    admin_user: String,
    admin_pass: String,
    op: Op,
    group_admin: bool,
    ok_file: String,
    nok_file: String,
    verbose: bool,
    try_defaults: bool,
    timeout: String,
    snapshot: bool,
    direct_http: bool,
    rtsp: bool,
    log: Arc<Mutex<String>>,
    running: Arc<AtomicBool>,
    child: Arc<Mutex<Option<std::process::Child>>>,
    worker: Option<JoinHandle<()>>,
    status: String,
    licensed: bool,
    license_reason: String,
    license_input: String,
    license_msg: String,
    machine_id: String,
    progress_start: usize,
    dark_mode: bool,
    generate_smartpss: bool,
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let dark_mode = true;
        apply_theme(&cc.egui_ctx, dark_mode);
        let machine_id = license::machine_id();
        let (licensed, license_reason) = match license::check_license() {
            license::LicenseStatus::Valid => (true, String::new()),
            license::LicenseStatus::Missing => (
                false,
                "licence.lic not found: activate the license to continue.".into(),
            ),
            license::LicenseStatus::Empty => (
                false,
                "licence.lic is empty: activate the license to continue.".into(),
            ),
            license::LicenseStatus::Invalid(r) => (false, format!("Invalid license file: {}.", r)),
        };
        Self {
            serial: String::new(),
            serial_file: String::new(),
            user: String::new(),
            delete_name: String::new(),
            delete_by_id: false,
            delete_all: false,
            password: String::new(),
            memo: String::new(),
            admin_user: String::new(),
            admin_pass: String::new(),
            op: Op::AddUser,
            group_admin: true,
            ok_file: String::new(),
            nok_file: String::new(),
            verbose: false,
            try_defaults: false,
            timeout: "0".into(),
            snapshot: false,
            direct_http: false,
            rtsp: false,
            log: Arc::new(Mutex::new(String::new())),
            running: Arc::new(AtomicBool::new(false)),
            child: Arc::new(Mutex::new(None)),
            worker: None,
            status: "Ready".into(),
            licensed,
            license_reason,
            license_input: String::new(),
            license_msg: String::new(),
            machine_id,
            progress_start: 0,
            dark_mode,
            generate_smartpss: false,
        }
    }

    fn log_line(&self, line: &str) {
        if let Ok(mut log) = self.log.lock() {
            log.push_str(line);
            log.push('\n');
        }
    }

    fn browse(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            self.serial_file = path.to_string_lossy().to_string();
            self.log_line(&format!(
                "[GUI] Serials file selected: {}",
                self.serial_file
            ));
        }
    }

    fn show_license_dialog(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Dahua P2P — License required");
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60), &self.license_reason);
            ui.add_space(12.0);
            ui.label(
                "This computer is not enabled. To get a license, send this machine \
                 code (unique for each computer):",
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&self.machine_id)
                            .monospace()
                            .size(16.0)
                            .strong(),
                    )
                    .selectable(true),
                );
                if ui.button("Copy").clicked() {
                    ctx.copy_text(self.machine_id.clone());
                }
            });
            ui.add_space(12.0);
            ui.label("Paste here the license generated with 'license-gen':");
            ui.add(
                egui::TextEdit::singleline(&mut self.license_input)
                    .hint_text("license string")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(640.0),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let save = ui.button("Save license").clicked();
                if save {
                    let content = self.license_input.trim().to_string();
                    if content.is_empty() {
                        self.license_msg = "Paste a license first.".into();
                    } else {
                        match license::validate_content(&content) {
                            Ok(()) => match license::write_license_file(&content) {
                                Ok(()) => {
                                    self.licensed = true;
                                    self.status = "License saved".into();
                                }
                                Err(e) => {
                                    self.license_msg = format!("Error writing licence.lic: {}", e)
                                }
                            },
                            Err(reason) => {
                                self.license_msg = format!("Invalid license: {}", reason)
                            }
                        }
                    }
                }
                if ui.button("Exit").clicked() {
                    self.exit(ctx);
                }
            });
            if !self.license_msg.is_empty() {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::from_rgb(200, 60, 60), &self.license_msg);
            }
        });
    }

    fn start(&mut self) {
        let serial = self.serial.trim().replace(',', " ").replace(';', " ");
        let typed: Vec<String> = serial
            .split_whitespace()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let serial_file = self.serial_file.trim().to_string();
        // Nomi originali SmartPSS (serial -> name) quando l'input è un file XML.
        let mut original_names: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let (raw, use_file): (Vec<String>, bool) = if !serial_file.is_empty() {
            match dahua_dhip_adduser::serials::parse_serials_file_with_names(&serial_file) {
                Ok(p) => {
                    for (serial, nm) in p.serials.iter().zip(p.names.iter()) {
                        if !nm.is_empty() {
                            original_names.insert(serial.clone(), nm.clone());
                        }
                    }
                    (p.serials, true)
                }
                Err(e) => {
                    self.log_line(&format!(
                        "[GUI] ERROR reading serials file '{}': {}",
                        serial_file, e
                    ));
                    return;
                }
            }
        } else {
            (typed, false)
        };

        let mut serials: Vec<String> = Vec::with_capacity(raw.len());
        for entry in &raw {
            let (serial_clean, _) = parse_serial_entry(entry);
            serials.push(serial_clean);
        }

        if serials.is_empty() {
            self.log_line("[GUI] ERROR: no serial number entered (empty field or file)");
            return;
        }

        let user = self.user.trim().to_string();
        let password = self.password.clone();
        let memo = self.memo.trim().to_string();
        let delete_name = self.delete_name.trim().to_string();

        match self.op {
            Op::AddUser => {
                if user.is_empty() || password.is_empty() {
                    self.log_line("[GUI] ERROR: add_user requires user and password");
                    return;
                }
            }
            Op::List => {}
            Op::Delete => {
                if !self.delete_all {
                    if delete_name.is_empty() {
                        self.log_line(
                            "[GUI] ERROR: for delete, write the username (or numeric Id) to delete",
                        );
                        return;
                    }
                    if self.delete_by_id && delete_name.parse::<u32>().is_err() {
                        self.log_line("[GUI] ERROR: delete by Id requires a numeric Id");
                        return;
                    }
                }
            }
            Op::Reboot => {}
            Op::CheckP2p => {}
        }

        if self.snapshot
            && user.is_empty()
            && password.is_empty()
            && !matches!(self.op, Op::CheckP2p)
        {
            self.log_line(
                "[GUI] ERROR: snapshot requires user and password (camera stream credentials) for add_user; for check_p2p the admin credentials are tried automatically",
            );
            return;
        }

        let cli = cli_binary_path();
        if !cli.exists() {
            self.log_line(&format!(
                "[GUI] ERROR: CLI binary not found: {}",
                cli.display()
            ));
            return;
        }

        let mut args: Vec<String> = vec!["--relay".into()];
        if self.verbose {
            args.push("-v".into());
        }
        if self.try_defaults {
            args.push("--try-defaults".into());
        }
        let timeout = self.timeout.trim();
        if !timeout.is_empty() && timeout != "0" {
            match timeout.parse::<u64>() {
                Ok(0) | Err(_) => {
                    self.log_line(&format!(
                        "[GUI] ERROR: invalid timeout '{}' (seconds, 0 = default)",
                        timeout
                    ));
                    return;
                }
                Ok(secs) => {
                    args.push("--timeout".into());
                    args.push(secs.to_string());
                }
            }
        }
        let admin_user = self.admin_user.trim().to_string();
        if !admin_user.is_empty() {
            args.push("--admin-user".into());
            args.push(admin_user);
        }
        if !self.admin_pass.is_empty() {
            args.push("-p".into());
            args.push(self.admin_pass.clone());
        }

        match self.op {
            Op::AddUser => {
                args.push("-u".into());
                args.push(user.clone());
                args.push("-w".into());
                args.push(password.clone());
                if !memo.is_empty() {
                    args.push("--memo".into());
                    args.push(memo);
                }
                if !self.group_admin {
                    args.push("--group".into());
                    args.push("user".into());
                }
                if self.snapshot {
                    args.push("--snapshot".into());
                    if self.direct_http {
                        args.push("--direct-http".into());
                    }
                    if self.rtsp {
                        args.push("--rtsp".into());
                    }
                }
            }
            Op::List => {
                args.push("--list-users".into());
            }
            Op::Delete => {
                if self.delete_all {
                    args.push("--delete-all".into());
                } else if self.delete_by_id {
                    args.push("--delete-user".into());
                    args.push(delete_name);
                } else {
                    args.push("--delete-user-name".into());
                    args.push(delete_name);
                }
            }
            Op::Reboot => {
                args.push("--reboot".into());
            }
            Op::CheckP2p => {
                args.push("--check-p2p".into());
                if self.snapshot {
                    args.push("--snapshot".into());
                    if self.direct_http {
                        args.push("--direct-http".into());
                    }
                    if self.rtsp {
                        args.push("--rtsp".into());
                    }
                    if !user.is_empty() || !password.is_empty() {
                        args.push("-u".into());
                        args.push(user.clone());
                        args.push("-w".into());
                        args.push(password.clone());
                    }
                }
            }
        }

        if !self.generate_smartpss {
            args.push("--no-xml".into());
        }

        let serials_source = if use_file {
            serial_file.clone()
        } else {
            let tmp_file = std::env::temp_dir().join("dahua_gui_serials.txt");
            if let Err(e) = std::fs::write(&tmp_file, serials.join("\n")) {
                self.log_line(&format!("[GUI] ERROR writing serials file: {}", e));
                return;
            }
            tmp_file.to_string_lossy().to_string()
        };
        args.push("-f".into());
        args.push(serials_source.clone());

        // Both sides derive the same names from the serials file, so the CLI
        // is only told about them when the user has overridden them.
        let (derived_ok, derived_nok) =
            dahua_dhip_adduser::paths::log_files(Some(&serials_source), None);
        let ok_path = if self.ok_file.trim().is_empty() {
            derived_ok.clone()
        } else {
            self.ok_file.clone()
        };
        let nok_path = if self.nok_file.trim().is_empty() {
            derived_nok.clone()
        } else {
            self.nok_file.clone()
        };

        if matches!(self.op, Op::AddUser | Op::Delete | Op::Reboot)
            && (ok_path != derived_ok || nok_path != derived_nok)
        {
            args.push("--ok-file".into());
            args.push(ok_path.clone());
            args.push("--nok-file".into());
            args.push(nok_path.clone());
        }

        // Only the stem: a full path would land the XML outside the working
        // directory, or produce a nonsense name once prefixed with xml/.
        let xml_base = if use_file {
            dahua_dhip_adduser::paths::run_stem(Some(&serials_source), None)
        } else {
            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
            format!(
                "{:04}{:02}{:02}-{:02}{:02}{:02}",
                now.year(),
                now.month(),
                now.day(),
                now.hour(),
                now.minute(),
                now.second()
            )
        };

        self.log_line(&format!(
            "[GUI] Running: {} {}",
            cli.display(),
            args.join(" ")
        ));

        if let Ok(log) = self.log.lock() {
            self.progress_start = log.len();
        }

        let log = Arc::clone(&self.log);
        let running = Arc::clone(&self.running);
        let child_slot = Arc::clone(&self.child);
        let gen_smartpss = self.generate_smartpss;
        let is_add = self.op == Op::AddUser;
        let ok_file = ok_path.clone();
        self.running.store(true, Ordering::SeqCst);
        self.status = "Running...".into();

        self.worker = Some(std::thread::spawn(move || {
            let mut cmd = Command::new(&cli);
            cmd.args(&args);
            // The CLI writes snapshots/, ok/nok files and the failure log relative
            // to its CWD. Launched from Finder the inherited CWD is "/", where
            // creating those folders fails, so pin it to the binary's own folder.
            if let Some(dir) = cli.parent() {
                cmd.current_dir(dir);
            }
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    if let Ok(mut l) = log.lock() {
                        l.push_str(&format!("[GUI] ERROR starting process: {}\n", e));
                    }
                    running.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            {
                let mut slot = child_slot.lock().unwrap();
                *slot = Some(child);
            }

            if let Some(out) = stdout {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    for line in BufReader::new(out).lines() {
                        if let Ok(l) = line {
                            if let Ok(mut log) = log.lock() {
                                log.push_str(&l);
                                log.push('\n');
                            }
                        }
                    }
                });
            }
            if let Some(err) = stderr {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    for line in BufReader::new(err).lines() {
                        if let Ok(l) = line {
                            if let Ok(mut log) = log.lock() {
                                log.push_str(&format!("[stderr] {}", l));
                                log.push('\n');
                            }
                        }
                    }
                });
            }

            let status = child_slot.lock().unwrap().as_mut().map(|c| c.wait());
            if let Ok(mut l) = log.lock() {
                match status {
                    Some(Ok(s)) => {
                        l.push_str(&format!("\n[GUI] Process finished (exit {:?})\n", s.code()))
                    }
                    _ => l.push_str("\n[GUI] Process finished\n"),
                }
            }
            running.store(false, Ordering::SeqCst);

            if gen_smartpss && is_add {
                let entries = load_ok_entries(&ok_file);
                let paths = smartpss_paths(&xml_base, entries.len());
                for (ci, chunk) in entries.chunks(22).enumerate() {
                    let mut countries = std::collections::HashMap::new();
                    let mut serials = Vec::with_capacity(chunk.len());
                    for (country, serial, _, _) in chunk {
                        countries.insert(serial.clone(), country.clone());
                        serials.push(serial.clone());
                    }
                    let user = chunk[0].2.clone();
                    let password = chunk[0].3.clone();
                    let xml_path = &paths[ci];
                    match generate_smartpss_file(
                        xml_path,
                        &serials,
                        &user,
                        &password,
                        &countries,
                        &original_names,
                    ) {
                        Ok(()) => {
                            if let Ok(mut l) = log.lock() {
                                l.push_str(&format!(
                                    "[GUI] SmartPSS file generated: {}\n",
                                    xml_path
                                ));
                            }
                        }
                        Err(e) => {
                            if let Ok(mut l) = log.lock() {
                                l.push_str(&format!(
                                    "[GUI] ERROR generating SmartPSS file: {}\n",
                                    e
                                ));
                            }
                        }
                    }
                }
            }
        }));
    }

    fn exit(&mut self, ctx: &egui::Context) {
        if let Ok(mut slot) = self.child.lock() {
            if let Some(c) = slot.as_mut() {
                let _ = c.kill();
            }
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn progress(&self) -> (usize, usize, usize, usize) {
        let log = self.log.lock().unwrap();
        let from = self.progress_start.min(log.len());
        parse_progress(&log[from..])
    }
}

/// Parse CLI progress lines into `(processed, total, ok, nok)`.
///
/// Recognised patterns (see `main.rs`):
/// - `[i/N] <serial>` — per-serial header (processed/total)
/// - `[+] <serial> → OK` — add_user success (also covers "already exists": the
///   CLI prints the `[!] ... already exists ...` note AND the `→ OK` line)
/// - `[-] <serial> → FAIL: ...` / `  [-] P2P handshake failed: ...` — NOK
/// - `  [+] user ... deleted via ...` — delete success (delete has no `→ OK`)
/// - `[*] DONE — X OK, Y FAIL out of Z` — authoritative final summary
fn parse_progress(s: &str) -> (usize, usize, usize, usize) {
    let mut processed = 0;
    let mut total = 0;
    let mut ok = 0;
    let mut nok = 0;
    let mut done: Option<(usize, usize, usize)> = None;

    for line in s.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('[') {
            if let Some(slash) = rest.find('/') {
                if let Some(bracket) = rest.find(']') {
                    if bracket > slash {
                        let num = rest[..slash].trim().parse::<usize>().unwrap_or(0);
                        let den = rest[slash + 1..bracket]
                            .trim()
                            .parse::<usize>()
                            .unwrap_or(0);
                        if num >= 1 && num <= den && den > 0 {
                            processed = num;
                            total = den;
                        }
                    }
                }
            }
        }
        if t.contains("\u{2192} OK") {
            ok += 1;
        } else if t.contains("\u{2192} FAIL")
            || t.contains("P2P handshake failed")
            || t.contains("Failed to delete user")
        {
            nok += 1;
        } else if t.contains("deleted via") {
            // Delete flow only: success is reported here, with no `→ OK` line.
            // Do NOT also count the add flow's `already exists` note — it is
            // always followed by a `→ OK` line and would double-count.
            ok += 1;
        }
        if t.starts_with("[*] DONE") {
            let tokens: Vec<&str> = t.split_whitespace().collect();
            if tokens.len() >= 10 {
                if let (Ok(o), Ok(f), Ok(tot)) = (
                    tokens[3].parse::<usize>(),
                    tokens[5].parse::<usize>(),
                    tokens[9].parse::<usize>(),
                ) {
                    done = Some((o, f, tot));
                }
            }
        }
    }

    if let Some((o, f, tot)) = done {
        ok = o;
        nok = f;
        total = tot;
        processed = tot;
    }

    (processed, total, ok, nok)
}

fn generate_smartpss_file(
    path: &str,
    serials: &[String],
    user: &str,
    password: &str,
    countries: &std::collections::HashMap<String, String>,
    original_names: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    use base64::Engine;

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    xml.push_str("<DeviceManager version=\"1.0\">\n");
    for (i, serial) in serials.iter().enumerate() {
        // Preserva il `name` dell'XML SmartPSS di origine quando disponibile,
        // altrimenti genera un name progressivo con la country (come prima).
        let name = match original_names.get(serial) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => match countries.get(serial) {
                Some(c) => format!("{:02}_{}_{}", i + 1, c, serial),
                None => format!("{:02}_{}", i + 1, serial),
            },
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(password.as_bytes());
        xml.push_str(&format!(
            "\n<Device connect=\"19\" domain=\"{}\" name=\"{}\" password=\"{}\" port=\"37777\" protocol=\"1\" username=\"{}\"/>",
            xml_escape(serial),
            xml_escape(&name),
            b64,
            xml_escape(user)
        ));
    }
    xml.push_str("\n\n</DeviceManager>\n");

    dahua_dhip_adduser::paths::ensure_parent_dir(path).map_err(|e| e.to_string())?;
    std::fs::write(path, xml).map_err(|e| e.to_string())
}

fn parse_serial_entry(raw: &str) -> (String, Option<String>) {
    let t = raw.trim();
    if let Some(idx) = t.find('_') {
        let head = &t[..idx];
        if head.len() == 2 {
            let rest = &t[idx + 1..];
            let serial = match rest.find('_') {
                Some(i) => &rest[..i],
                None => rest,
            };
            let serial = serial.trim().to_string();
            if !serial.is_empty() {
                return (serial, Some(head.to_string()));
            }
        }
    }
    (t.to_string(), None)
}

/// SmartPSS XML files live in their own folder, so a run does not litter the
/// working directory. Splits every 22 entries, which is what SmartPSS imports
/// per file.
fn smartpss_paths(base: &str, n: usize) -> Vec<String> {
    if n <= 22 {
        vec![dahua_dhip_adduser::paths::xml_file(&format!("{base}.xml"))]
    } else {
        (1..=n.div_ceil(22))
            .map(|i| dahua_dhip_adduser::paths::xml_file(&format!("{base} ({i}).xml")))
            .collect()
    }
}

fn load_ok_entries(path: &str) -> Vec<(String, String, String, String)> {
    let mut entries = Vec::new();
    if path.trim().is_empty() {
        return entries;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let parts: Vec<&str> = t.split('_').collect();
            if parts.len() >= 4 && parts[0].len() == 2 {
                entries.push((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts[2].to_string(),
                    parts[3].to_string(),
                ));
            }
        }
    }
    entries
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn cli_binary_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    if let Some(dir) = exe.parent() {
        let native = dir.join(format!(
            "dahua-dhip-adduser{}",
            std::env::consts::EXE_SUFFIX
        ));
        if native.exists() {
            native
        } else {
            dir.join("dahua-dhip-adduser")
        }
    } else {
        PathBuf::from("dahua-dhip-adduser")
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.running.load(Ordering::SeqCst) {
            ctx.request_repaint();
        }

        if !self.licensed {
            self.show_license_dialog(ctx);
            return;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Dahua P2P — User Management v1");
                let prev_dark = self.dark_mode;
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.radio_value(&mut self.dark_mode, false, "Light");
                    ui.radio_value(&mut self.dark_mode, true, "Dark");
                    ui.label("Theme:");
                });
                if prev_dark != self.dark_mode {
                    apply_theme(ctx, self.dark_mode);
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Serial number:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.serial).hint_text(
                        "e.g. 6M06DDXXXXXXXX (multiple serials separated by space/comma)",
                    ),
                );
                ui.label("Group:");
                ui.radio_value(&mut self.group_admin, true, "admin (all permissions)");
                ui.radio_value(&mut self.group_admin, false, "user (monitor+playback)");
            });

            ui.horizontal(|ui| {
                ui.label("or serials file (-f):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.serial_file)
                        .hint_text("path to a .txt file with one serial per line"),
                );
                if ui.button("Browse...").clicked() {
                    self.browse();
                }
                if !self.serial_file.trim().is_empty() && ui.button("X").clicked() {
                    self.serial_file.clear();
                }
                ui.checkbox(&mut self.generate_smartpss, "Generate SmartPSS file");
            });

            ui.horizontal(|ui| {
                ui.label("Admin user:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_user)
                        .hint_text("device admin (default: admin)"),
                );
                ui.label("Admin pass:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_pass)
                        .password(true)
                        .hint_text("device admin password (required on hardened firmware)"),
                );
            });

            match self.op {
                Op::AddUser => {
                    ui.horizontal(|ui| {
                        ui.label("User:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.user)
                                .hint_text("username to create"),
                        );
                        ui.label("Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .hint_text("plaintext password (add_user only)"),
                        );
                    });
                }
                Op::Delete => {
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(!self.delete_all, |ui| {
                            ui.label("User to delete:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.delete_name)
                                    .hint_text("username to delete"),
                            );
                            ui.radio_value(&mut self.delete_by_id, false, "Name");
                            ui.radio_value(&mut self.delete_by_id, true, "Id");
                        });
                        ui.radio_value(&mut self.delete_all, false, "single");
                        ui.radio_value(&mut self.delete_all, true, "delete all (keep admin)");
                    });
                }
                Op::List => {}
                Op::Reboot => {
                    ui.label("Reboot each device (magicBox.reboot). No fields required.");
                }
                Op::CheckP2p => {
                    ui.label("Check P2P/cloud state of each device (account, status, public IP).");
                    if self.snapshot {
                        ui.horizontal(|ui| {
                            ui.label("User (opt):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.user)
                                    .hint_text("camera user (admin credentials tried first)"),
                            );
                            ui.label("Password (opt):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password)
                                    .hint_text("camera password (admin credentials tried first)"),
                            );
                        });
                    }
                }
            }

            ui.horizontal(|ui| {
                ui.label("Operation:");
                ui.radio_value(&mut self.op, Op::AddUser, "add_user");
                ui.radio_value(&mut self.op, Op::List, "list");
                ui.radio_value(&mut self.op, Op::Delete, "delete");
                ui.radio_value(&mut self.op, Op::Reboot, "reboot");
                ui.radio_value(&mut self.op, Op::CheckP2p, "check_p2p");
            });

            ui.horizontal(|ui| {
                let can_snapshot = matches!(self.op, Op::AddUser | Op::CheckP2p);
                ui.add_enabled(
                    can_snapshot,
                    egui::Checkbox::new(&mut self.snapshot, "Snapshot"),
                );
                if self.snapshot && can_snapshot {
                    ui.add_enabled(
                        true,
                        egui::Checkbox::new(&mut self.direct_http, "Direct HTTP"),
                    );
                    ui.add_enabled(true, egui::Checkbox::new(&mut self.rtsp, "RTSP"));
                    ui.label("(fallback: P2P → SDK 37777 → direct IP → RTSP)");
                } else if can_snapshot {
                    ui.label("(capture a live JPG per active camera channel)");
                } else {
                    ui.label("(only with add_user or check_p2p)");
                }
            });

            ui.horizontal(|ui| {
                ui.label("OK file:");
                ui.add(egui::TextEdit::singleline(&mut self.ok_file));
                ui.label("NOK file:");
                ui.add(egui::TextEdit::singleline(&mut self.nok_file));
            });

            ui.horizontal(|ui| {
                ui.label("Timeout (s):");
                ui.add(egui::TextEdit::singleline(&mut self.timeout).hint_text("0 = default"));
                ui.label(
                    "network timeout for PTCP/DHIP/HTTP calls (raise it on 'challenge timeout')",
                );
                ui.checkbox(&mut self.verbose, "Verbose");
                ui.checkbox(&mut self.try_defaults, "Try default passwords");
            });

            if self.op == Op::AddUser {
                ui.horizontal(|ui| {
                    ui.label("Memo:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.memo)
                            .hint_text("note for the user (add_user only)"),
                    );
                });
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let run = ui
                    .add_enabled(
                        !self.running.load(Ordering::SeqCst),
                        egui::Button::new(egui::RichText::new("Run").size(16.0))
                            .fill(egui::Color32::from_rgb(30, 110, 200)),
                    )
                    .clicked();
                if run {
                    self.start();
                }
                let clear = ui.button("Clear log").clicked();
                if clear {
                    if let Ok(mut log) = self.log.lock() {
                        log.clear();
                    }
                    self.progress_start = 0;
                }
                if ui.button("Exit").clicked() {
                    self.exit(ctx);
                }
                ui.label(&self.status);
                let (processed, total, ok, nok) = self.progress();
                if total > 0 {
                    let pct = (processed as f64 / total as f64 * 100.0).round() as usize;
                    let counter = format!(
                        "    [{}/{}]  {}%  OK: {}  NOK: {}",
                        processed, total, pct, ok, nok
                    );
                    ui.add(egui::Label::new(
                        egui::RichText::new(counter).monospace().strong(),
                    ));
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.label("Log:");
            egui::ScrollArea::vertical()
                .id_salt("log_scroll")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    let mut log = self.log.lock().unwrap();
                    ui.add(
                        egui::TextEdit::multiline(&mut *log)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(24)
                            .desired_width(f32::INFINITY),
                    );
                });

            if !self.running.load(Ordering::SeqCst) && self.status == "Running..." {
                self.status = "Finished".into();
            }
        });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 680.0])
            .with_min_inner_size([1000.0, 500.0])
            .with_title("Dahua P2P — User Management"),
        ..Default::default()
    };
    eframe::run_native(
        "Dahua P2P — User Management",
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        generate_smartpss_file, load_ok_entries, parse_progress, parse_serial_entry, smartpss_paths,
    };

    #[test]
    fn parses_live_add_user_progress() {
        let log = "\
[*] 3 serial(s) to process

========================================
[1/3] SERIALAAA
========================================
  [+] user added via HTTP/RPC2 (Type=Normal)
[+] SERIALAAA \u{2192} OK

========================================
[2/3] SERIALBBB
========================================
  [-] P2P handshake failed: Timeout waiting for PTCP Sync from agent

========================================
[3/3] SERIALCCC
========================================
  [+] user added via DHIP (Type=Admin)
[+] SERIALCCC \u{2192} OK

[*] DONE \u{2014} 2 OK, 1 FAIL out of 3
";
        assert_eq!(parse_progress(log), (3, 3, 2, 1));
    }

    #[test]
    fn counts_delete_outcomes() {
        let log = "\
[1/2] SERIALAAA
========================================
  [+] user Id=19 (camuser1) deleted via HTTP/RPC2

[2/2] SERIALBBB
========================================
  [-] Failed to delete user 'camuser2'
";
        assert_eq!(parse_progress(log), (2, 2, 1, 1));
    }

    #[test]
    fn counts_existing_user_as_ok() {
        let log = "\
[1/1] SERIALAAA
========================================
  [!] user 'camuser1' already exists on device, skipping
[+] SERIALAAA \u{2192} OK

[*] DONE \u{2014} 1 OK, 0 FAIL out of 1
";
        assert_eq!(parse_progress(log), (1, 1, 1, 0));
    }

    #[test]
    fn existing_users_do_not_double_count_live() {
        // Mid-run the authoritative `[*] DONE` line has not appeared yet, so the
        // live counters must not count both the `already exists` note and the
        // `→ OK` line for the same serial.
        let log = "\
[1/3] SERIALAAA
  [!] user 'camuser1' already exists on device, skipping
[+] SERIALAAA \u{2192} OK

[2/3] SERIALBBB
  [!] user 'camuser2' already exists on device, skipping
[+] SERIALBBB \u{2192} OK

[3/3] SERIALCCC
  [+] user added via DHIP (Type=Admin)
[+] SERIALCCC \u{2192} OK

";
        assert_eq!(parse_progress(log), (3, 3, 3, 0));
    }

    #[test]
    fn empty_log() {
        assert_eq!(parse_progress(""), (0, 0, 0, 0));
    }

    #[test]
    fn generates_smartpss_file() {
        use base64::Engine;

        let path = std::env::temp_dir().join("dahua_smartpss_test.xml");
        let serials = vec!["7H09D4DPAZ7495F".to_string(), "2K02033PAE00089".to_string()];
        let mut countries = std::collections::HashMap::new();
        countries.insert("7H09D4DPAZ7495F".to_string(), "IT".to_string());
        let empty_names = std::collections::HashMap::new();
        let res = generate_smartpss_file(
            path.to_str().unwrap(),
            &serials,
            "camuser02251",
            "Cam@2026",
            &countries,
            &empty_names,
        );
        assert!(res.is_ok());
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        let b64 = base64::engine::general_purpose::STANDARD.encode("Cam@2026".as_bytes());
        assert!(
            content.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n")
        );
        assert!(content.contains("<DeviceManager version=\"1.0\">"));
        assert!(content.contains(
            "<Device connect=\"19\" domain=\"7H09D4DPAZ7495F\" name=\"01_IT_7H09D4DPAZ7495F\""
        ));
        assert!(content.contains(
            "<Device connect=\"19\" domain=\"2K02033PAE00089\" name=\"02_2K02033PAE00089\""
        ));
        assert!(content.contains(&format!(
            "password=\"{}\" port=\"37777\" protocol=\"1\" username=\"camuser02251\"",
            b64
        )));
        assert!(content.contains("</DeviceManager>"));

        // Con i nomi originali SmartPSS (da XML di input) il `name` resta invariato.
        let mut names = std::collections::HashMap::new();
        names.insert(
            "7H09D4DPAZ7495F".to_string(),
            "01) 7H09D4DPAZ7495F".to_string(),
        );
        let res2 = generate_smartpss_file(
            path.to_str().unwrap(),
            &serials,
            "camuser02251",
            "Cam@2026",
            &countries,
            &names,
        );
        assert!(res2.is_ok());
        let content2 = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(content2.contains(
            "<Device connect=\"19\" domain=\"7H09D4DPAZ7495F\" name=\"01) 7H09D4DPAZ7495F\""
        ));
        assert!(content2.contains(
            "<Device connect=\"19\" domain=\"2K02033PAE00089\" name=\"02_2K02033PAE00089\""
        ));
    }

    #[test]
    fn parses_country_prefix_from_serial_entry() {
        assert_eq!(
            parse_serial_entry("IT_7H09D4DPAZ7495F_camuser1_Pwd123_Rome"),
            ("7H09D4DPAZ7495F".to_string(), Some("IT".to_string()))
        );
        assert_eq!(
            parse_serial_entry("IT_7H09D4DPAZ7495F"),
            ("7H09D4DPAZ7495F".to_string(), Some("IT".to_string()))
        );
        assert_eq!(
            parse_serial_entry(" 7H09D4DPAZ7495F "),
            ("7H09D4DPAZ7495F".to_string(), None)
        );
    }

    #[test]
    fn loads_ok_entries() {
        let path = std::env::temp_dir().join("dahua_ok_test.txt");
        std::fs::write(
            &path,
            "IT_7H09D4DPAZ7495F_camuser1_Pwd123_Rome\nXX_2K02033PAE00089_camuser2_Pwd456_N/A\n",
        )
        .unwrap();
        let entries = load_ok_entries(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            (
                "IT".to_string(),
                "7H09D4DPAZ7495F".to_string(),
                "camuser1".to_string(),
                "Pwd123".to_string()
            )
        );
        assert_eq!(entries[1].0, "XX");
        assert_eq!(entries[1].1, "2K02033PAE00089");
    }

    #[test]
    fn splits_smartpss_files_by_22_and_keeps_them_in_the_xml_folder() {
        let b = "serials";
        assert_eq!(smartpss_paths(b, 1), vec!["xml/serials.xml"]);
        assert_eq!(smartpss_paths(b, 22), vec!["xml/serials.xml"]);
        assert_eq!(
            smartpss_paths(b, 23),
            vec!["xml/serials (1).xml", "xml/serials (2).xml"]
        );
        assert_eq!(
            smartpss_paths(b, 45),
            vec![
                "xml/serials (1).xml",
                "xml/serials (2).xml",
                "xml/serials (3).xml"
            ]
        );
    }
}

fn apply_theme(ctx: &egui::Context, dark: bool) {
    if dark {
        let mut visuals = egui::Visuals::dark();
        let panel = egui::Color32::from_rgb(38, 40, 44);
        let field = egui::Color32::from_rgb(50, 52, 57);
        let btn = egui::Color32::from_rgb(56, 58, 63);
        visuals.panel_fill = panel;
        visuals.window_fill = panel;
        visuals.extreme_bg_color = field;
        visuals.faint_bg_color = egui::Color32::from_rgb(28, 30, 33);
        visuals.widgets.noninteractive.bg_fill = panel;
        visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 74, 80));
        visuals.widgets.inactive.bg_fill = btn;
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(66, 70, 76);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(74, 78, 85);
        visuals.selection.bg_fill = egui::Color32::from_rgb(30, 110, 200);
        visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(120, 160, 210));
        ctx.set_visuals(visuals);
    } else {
        let mut visuals = egui::Visuals::light();
        let panel = egui::Color32::from_rgb(228, 230, 233);
        let field = egui::Color32::WHITE;
        visuals.panel_fill = panel;
        visuals.window_fill = panel;
        visuals.extreme_bg_color = field;
        visuals.widgets.noninteractive.bg_fill = panel;
        visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(176, 180, 186));
        visuals.selection.bg_fill = egui::Color32::from_rgb(30, 110, 200);
        visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(200, 220, 255));
        ctx.set_visuals(visuals);
    }
    ctx.set_zoom_factor(1.15);
}
