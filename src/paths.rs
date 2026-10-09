//! Where run artefacts land on disk.
//!
//! Shared by the CLI and the GUI so both agree on the names without the GUI
//! having to hard-code them.
//!
//! Rules:
//! - logs go under `log/`, named `ok<stem>.log` and `nok<stem>.log`, where
//!   `<stem>` comes from the serials file that drove the run;
//! - a run against a bare `--serial` uses the serial itself as `<stem>`;
//! - SmartPSS XML files go under `xml/`.

use std::path::Path;

/// Folder that receives the ok/nok logs.
pub const LOG_DIR: &str = "log";

/// Folder that receives the generated SmartPSS XML files.
pub const XML_DIR: &str = "xml";

/// Stem for a run, either the serials file name or the single serial.
pub fn run_stem(serials_file: Option<&str>, serial: Option<&str>) -> String {
    if let Some(path) = serials_file {
        let stem = Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !stem.trim().is_empty() {
            return stem.to_string();
        }
    }
    if let Some(s) = serial {
        let s = s.trim();
        if !s.is_empty() {
            // A comma-separated list would make a poor file name.
            return s.split(',').next().unwrap_or(s).trim().to_string();
        }
    }
    "serials".to_string()
}

/// `(ok, nok)` log paths for this run.
pub fn log_files(serials_file: Option<&str>, serial: Option<&str>) -> (String, String) {
    let stem = run_stem(serials_file, serial);
    (
        format!("{LOG_DIR}/ok{stem}.log"),
        format!("{LOG_DIR}/nok{stem}.log"),
    )
}

/// Full path for a SmartPSS XML file with the given timestamped file name.
pub fn xml_file(file_name: &str) -> String {
    format!("{XML_DIR}/{file_name}")
}

/// `fs::create_dir_all` on the parent of `path`, tolerating a bare file name.
pub fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    match Path::new(path).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => std::fs::create_dir_all(dir),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_serials_file_names_the_logs_after_its_stem() {
        let (ok, nok) = log_files(Some("/tmp/serials.txt"), None);
        assert_eq!(ok, "log/okserials.log");
        assert_eq!(nok, "log/nokserials.log");
    }

    #[test]
    fn the_extension_is_stripped_but_dots_inside_the_name_are_kept() {
        let (ok, _) = log_files(Some("/tmp/NVR.HIKVISION.xml"), None);
        assert_eq!(ok, "log/okNVR.HIKVISION.log");
        let (ok2, _) = log_files(Some("cams ok.txt"), None);
        assert_eq!(ok2, "log/okcams ok.log");
    }

    #[test]
    fn a_single_serial_names_the_logs_after_that_serial() {
        let (ok, nok) = log_files(None, Some("7C03FF7PAZ93E44"));
        assert_eq!(ok, "log/ok7C03FF7PAZ93E44.log");
        assert_eq!(nok, "log/nok7C03FF7PAZ93E44.log");
    }

    #[test]
    fn a_comma_separated_serial_list_uses_only_the_first() {
        let (ok, _) = log_files(None, Some("AAA111,BBB222"));
        assert_eq!(ok, "log/okAAA111.log");
    }

    #[test]
    fn the_serials_file_wins_over_the_serial() {
        let (ok, _) = log_files(Some("/tmp/lista.txt"), Some("7C03FF7PAZ93E44"));
        assert_eq!(ok, "log/oklista.log");
    }

    #[test]
    fn a_dotfile_keeps_its_leading_dot_because_rust_sees_no_extension() {
        // Path::file_stem treats a leading dot as part of the name, not as an
        // extension separator, so ".hidden" is a stem rather than a stem-less name.
        assert_eq!(run_stem(Some("/tmp/.hidden"), None), ".hidden");
    }

    #[test]
    fn input_with_no_usable_name_falls_back_to_serials() {
        assert_eq!(run_stem(Some(""), None), "serials");
        assert_eq!(run_stem(None, None), "serials");
        assert_eq!(run_stem(Some("   "), Some("  ")), "serials");
    }

    #[test]
    fn xml_files_land_in_their_own_folder() {
        assert_eq!(xml_file("20261005-201530.xml"), "xml/20261005-201530.xml");
    }

    #[test]
    fn ensure_parent_dir_is_a_no_op_for_a_bare_file_name() {
        assert!(ensure_parent_dir("okserials.log").is_ok());
    }

    #[test]
    fn ensure_parent_dir_actually_creates_the_folder() {
        let root = std::env::temp_dir().join("dahua_paths_test");
        let target = root.join("xml").join("20261005-201530.xml");
        let _ = std::fs::remove_dir_all(&root);

        ensure_parent_dir(&target.to_string_lossy()).expect("creating xml/");
        assert!(root.join("xml").is_dir());
        assert!(!target.exists(), "only the folder should be created");

        // Idempotent: a second run must not fail.
        ensure_parent_dir(&target.to_string_lossy()).expect("second call");
        let _ = std::fs::remove_dir_all(&root);
    }
}
