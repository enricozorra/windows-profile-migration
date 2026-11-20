//! Catalog of applications whose per-user data needs attention when a
//! profile moves to a new account and folder.
//!
//! Each entry detects the application from files in the profile and from the
//! registry inspection, then states what the copy carries over on its own
//! and what needs an action. Detection is read-only. Adding an application
//! means adding one `detect_*` function to `detect_all`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hive_scan::contains_path;
use crate::model::{KnownPaths, RegistryInspection};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppReport {
    /// Preflight check id, e.g. `APP_CHROME`.
    pub id: &'static str,
    pub name: &'static str,
    /// What moves with the copied profile without intervention.
    pub carried: Vec<String>,
    /// What the operator or the user has to do; empty means nothing.
    pub actions: Vec<String>,
}

pub struct AppContext<'a> {
    pub profile: &'a Path,
    pub source_sid: &'a str,
    pub known: &'a KnownPaths,
    pub registry: Option<&'a RegistryInspection>,
    /// Final folder of the migrated profile, when known.
    pub target_profile: Option<&'a Path>,
}

pub fn detect_all(ctx: &AppContext) -> Vec<AppReport> {
    let mut reports = Vec::new();
    for browser in CHROMIUM_BROWSERS {
        reports.extend(detect_chromium(ctx, browser));
    }
    reports.extend(detect_firefox(ctx));
    reports.extend(detect_outlook(ctx));
    reports.extend(detect_network_drives(ctx));
    reports.extend(detect_printers(ctx));
    reports.extend(detect_certificates(ctx));
    reports.extend(detect_onedrive(ctx));
    reports.extend(detect_teams(ctx));
    reports
}

struct Chromium {
    id: &'static str,
    name: &'static str,
    /// User Data folder, relative to the profile.
    user_data: &'static [&'static str],
}

const CHROMIUM_BROWSERS: &[Chromium] = &[
    Chromium {
        id: "APP_CHROME",
        name: "Google Chrome",
        user_data: &["AppData", "Local", "Google", "Chrome", "User Data"],
    },
    Chromium {
        id: "APP_EDGE",
        name: "Microsoft Edge",
        user_data: &["AppData", "Local", "Microsoft", "Edge", "User Data"],
    },
    Chromium {
        id: "APP_BRAVE",
        name: "Brave",
        user_data: &[
            "AppData",
            "Local",
            "BraveSoftware",
            "Brave-Browser",
            "User Data",
        ],
    },
];

fn detect_chromium(ctx: &AppContext, browser: &Chromium) -> Option<AppReport> {
    let user_data = join_all(ctx.profile, browser.user_data);
    let local_state = user_data.join("Local State");
    if !local_state.is_file() {
        return None;
    }
    let mut report = AppReport {
        id: browser.id,
        name: browser.name,
        carried: Vec::new(),
        actions: Vec::new(),
    };
    let profiles = match chromium_profiles(&user_data) {
        Ok(profiles) => profiles,
        Err(err) => {
            report
                .actions
                .push(format!("could not list browser profiles: {err}"));
            Vec::new()
        }
    };
    report.carried.push(format!(
        "{} browser profile(s): bookmarks, history, extensions and settings are copied as files",
        profiles.len()
    ));
    let with_passwords: Vec<&str> = profiles
        .iter()
        .filter(|p| user_data.join(p).join("Login Data").is_file())
        .map(String::as_str)
        .collect();
    if !with_passwords.is_empty() {
        // Chromium encrypts saved passwords with a key that DPAPI protects
        // for the Windows account; recent versions add an app-bound layer.
        let app_bound = match fs::read_to_string(&local_state) {
            Ok(text) => text.contains("app_bound_encrypted_key"),
            Err(err) => {
                report
                    .actions
                    .push(format!("could not read {}: {err}", local_state.display()));
                false
            }
        };
        report.actions.push(format!(
            "saved passwords ({}) are encrypted for the source Windows account{}; \
             turn on browser sync or export them before migrating, otherwise they will not open for the target",
            with_passwords.join(", "),
            if app_bound {
                " and with app-bound encryption"
            } else {
                ""
            }
        ));
    }
    Some(report)
}

fn chromium_profiles(user_data: &Path) -> io::Result<Vec<String>> {
    let mut profiles = Vec::new();
    for entry in fs::read_dir(user_data)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if (name == "Default" || name.starts_with("Profile ")) && entry.file_type()?.is_dir() {
            profiles.push(name);
        }
    }
    profiles.sort();
    Ok(profiles)
}

fn detect_firefox(ctx: &AppContext) -> Option<AppReport> {
    let firefox = join_all(ctx.profile, &["AppData", "Roaming", "Mozilla", "Firefox"]);
    let ini = firefox.join("profiles.ini");
    let mut report = AppReport {
        id: "APP_FIREFOX",
        name: "Mozilla Firefox",
        carried: Vec::new(),
        actions: Vec::new(),
    };
    let text = match fs::read_to_string(&ini) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => {
            report
                .actions
                .push(format!("could not read {}: {err}", ini.display()));
            return Some(report);
        }
    };
    let profiles = firefox_profile_paths(&text);
    report.carried.push(format!(
        "{} Firefox profile(s): bookmarks, history and saved passwords (Firefox encrypts them with its own key4.db, not with the Windows account)",
        profiles.len()
    ));
    let old_root = ctx.profile.to_string_lossy();
    for (path, is_relative) in &profiles {
        if !is_relative && contains_path(path, &old_root) {
            report.actions.push(format!(
                "profiles.ini uses the absolute path {path}; it will be rewritten to the new folder"
            ));
        }
    }
    Some(report)
}

/// `(Path, IsRelative)` of every profile section in profiles.ini.
pub fn firefox_profile_paths(ini: &str) -> Vec<(String, bool)> {
    let mut profiles = Vec::new();
    let mut in_profile = false;
    let mut path: Option<String> = None;
    let mut relative = true;
    let mut flush = |path: &mut Option<String>, relative: bool| {
        if let Some(p) = path.take() {
            profiles.push((p, relative));
        }
    };
    for line in ini.lines().map(str::trim) {
        if line.starts_with('[') {
            flush(&mut path, relative);
            in_profile = line.to_ascii_lowercase().starts_with("[profile");
            relative = true;
        } else if in_profile {
            if let Some(value) = line.strip_prefix("Path=") {
                path = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("IsRelative=") {
                relative = value.trim() != "0";
            }
        }
    }
    flush(&mut path, relative);
    profiles
}

fn detect_outlook(ctx: &AppContext) -> Option<AppReport> {
    let registry_profiles = ctx
        .registry
        .map(|r| r.outlook_profiles.as_slice())
        .unwrap_or_default();
    let local = join_all(ctx.profile, &["AppData", "Local", "Microsoft", "Outlook"]);
    if registry_profiles.is_empty() && !local.is_dir() {
        return None;
    }
    let mut report = AppReport {
        id: "APP_OUTLOOK",
        name: "Microsoft Outlook",
        carried: Vec::new(),
        actions: Vec::new(),
    };
    if !registry_profiles.is_empty() {
        report
            .carried
            .push(format!("mail profiles: {}", registry_profiles.join(", ")));
    }
    let signatures = join_all(
        ctx.profile,
        &["AppData", "Roaming", "Microsoft", "Signatures"],
    );
    match count_files(&signatures) {
        Ok(0) => {}
        Ok(count) => report.carried.push(format!("{count} signature file(s)")),
        Err(err) => report.actions.push(err),
    }
    let old_root = ctx.profile.to_string_lossy();
    for file in ctx
        .registry
        .map(|r| r.outlook_data_files.as_slice())
        .unwrap_or_default()
    {
        let is_cache = file.to_ascii_lowercase().ends_with(".ost");
        if contains_path(file, &old_root) {
            report.actions.push(format!(
                "{file}: inside the profile, repointed to the new folder{}",
                if is_cache {
                    " (.ost is a cache and can also be rebuilt)"
                } else {
                    ""
                }
            ));
        } else {
            report
                .carried
                .push(format!("{file}: outside the profile, path unchanged"));
        }
    }
    report.actions.push(
        "sign in to Exchange/Microsoft 365 again as the target (cached tokens are tied to the source account)"
            .into(),
    );
    Some(report)
}

fn detect_network_drives(ctx: &AppContext) -> Option<AppReport> {
    let drives = &ctx.registry?.network_drives;
    if drives.is_empty() {
        return None;
    }
    Some(AppReport {
        id: "APP_NETWORK_DRIVES",
        name: "Mapped network drives",
        carried: drives.clone(),
        actions: vec![
            "passwords saved for these shares are not carried; the domain account normally connects with single sign-on"
                .into(),
        ],
    })
}

fn detect_printers(ctx: &AppContext) -> Option<AppReport> {
    let printers = &ctx.registry?.printer_connections;
    if printers.is_empty() {
        return None;
    }
    Some(AppReport {
        id: "APP_PRINTERS",
        name: "Network printer connections",
        carried: printers.clone(),
        actions: Vec::new(),
    })
}

fn detect_certificates(ctx: &AppContext) -> Option<AppReport> {
    let microsoft = join_all(ctx.profile, &["AppData", "Roaming", "Microsoft"]);
    let mut errors = Vec::new();
    let mut count = |dir: PathBuf| {
        count_files(&dir).unwrap_or_else(|err| {
            errors.push(err);
            0
        })
    };
    let certificates = count(join_all(
        &microsoft,
        &["SystemCertificates", "My", "Certificates"],
    ));
    let private_keys = count(join_all(&microsoft, &["Crypto", "RSA", ctx.source_sid]))
        + count(join_all(&microsoft, &["Crypto", "Keys"]));
    if certificates == 0 && private_keys == 0 && errors.is_empty() {
        return None;
    }
    let mut report = AppReport {
        id: "APP_CERTIFICATES",
        name: "Personal certificates",
        carried: vec![format!(
            "{certificates} certificate(s) in the personal store (public part)"
        )],
        actions: errors,
    };
    if private_keys > 0 && certificates > 0 {
        report.actions.push(format!(
            "{private_keys} private key(s) are protected for the source account: export the certificates with their private key (.pfx) as the source user and import them as the target"
        ));
    } else if private_keys > 0 {
        report.actions.push(format!(
            "{private_keys} private key(s) without a personal certificate (usually created by an application) are protected for the source account; the application may need to create new ones for the target"
        ));
    }
    Some(report)
}

fn detect_onedrive(ctx: &AppContext) -> Option<AppReport> {
    let accounts = ctx
        .registry
        .map(|r| r.onedrive_accounts.as_slice())
        .unwrap_or_default();
    if ctx.known.onedrive_folders.is_empty()
        && !ctx.known.onedrive_client_state
        && accounts.is_empty()
    {
        return None;
    }
    let mut report = AppReport {
        id: "APP_ONEDRIVE",
        name: "OneDrive",
        carried: ctx
            .known
            .onedrive_folders
            .iter()
            .map(|f| format!("folder {f} is copied with its local files"))
            .collect(),
        actions: Vec::new(),
    };
    match ctx.registry {
        Some(_) if accounts.is_empty() => report
            .carried
            .push("no OneDrive account is signed in: nothing to reconnect".into()),
        _ => {
            let new_folder = ctx
                .target_profile
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "the new profile folder".into());
            for account in accounts {
                report.actions.push(format!("signed in: {account}"));
            }
            report.actions.push(format!(
                "sign in to OneDrive again as the target and, when asked, choose the existing folder under {new_folder}"
            ));
            report.actions.push(
                "files that are only online (placeholders) are not copied; they reappear after sign-in".into(),
            );
        }
    }
    Some(report)
}

fn detect_teams(ctx: &AppContext) -> Option<AppReport> {
    let new_teams = join_all(
        ctx.profile,
        &["AppData", "Local", "Packages", "MSTeams_8wekyb3d8bbwe"],
    );
    let classic = join_all(ctx.profile, &["AppData", "Roaming", "Microsoft", "Teams"]);
    if !new_teams.is_dir() && !classic.is_dir() {
        return None;
    }
    Some(AppReport {
        id: "APP_TEAMS",
        name: "Microsoft Teams",
        carried: vec!["local cache and settings are copied".into()],
        actions: vec!["sign in to Teams again as the target".into()],
    })
}

fn join_all(root: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// Files directly inside `dir`. A missing folder counts as none; any other
/// failure is returned as report text so it is never silently zero.
fn count_files(dir: &Path) -> Result<usize, String> {
    let describe = |err: io::Error| format!("could not read {}: {err}", dir.display());
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(describe(err)),
    };
    let mut count = 0;
    for entry in entries {
        if entry
            .and_then(|e| e.file_type())
            .map_err(describe)?
            .is_file()
        {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "S-1-5-21-1-2-3-1001";

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(name: &str) -> TempTree {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "windows-profile-migration-apps-{name}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempTree(dir)
        }

        fn file(&self, relative: &str, content: &str) {
            let path = relative
                .split('/')
                .fold(self.0.clone(), |path, part| path.join(part));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn detect(tree: &TempTree, registry: Option<&RegistryInspection>) -> Vec<AppReport> {
        let known = KnownPaths::default();
        detect_all(&AppContext {
            profile: &tree.0,
            source_sid: SRC,
            known: &known,
            registry,
            target_profile: Some(Path::new(r"C:\Users\new")),
        })
    }

    fn report<'a>(reports: &'a [AppReport], id: &str) -> &'a AppReport {
        reports
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} not detected in {reports:#?}"))
    }

    #[test]
    fn empty_profile_detects_nothing() {
        let tree = TempTree::new("empty");
        assert!(detect(&tree, Some(&RegistryInspection::default())).is_empty());
    }

    #[test]
    fn chromium_browsers_with_saved_passwords_need_action() {
        let tree = TempTree::new("chromium");
        let brave = "AppData/Local/BraveSoftware/Brave-Browser/User Data";
        tree.file(
            &format!("{brave}/Local State"),
            r#"{"os_crypt":{"app_bound_encrypted_key":"x"}}"#,
        );
        tree.file(&format!("{brave}/Default/Bookmarks"), "{}");
        tree.file(&format!("{brave}/Default/Login Data"), "sqlite");
        tree.file(&format!("{brave}/Profile 1/Bookmarks"), "{}");
        let edge = "AppData/Local/Microsoft/Edge/User Data";
        tree.file(&format!("{edge}/Local State"), "{}");
        tree.file(&format!("{edge}/Default/Bookmarks"), "{}");

        let reports = detect(&tree, None);
        let brave = report(&reports, "APP_BRAVE");
        assert!(brave.carried[0].starts_with("2 browser profile(s)"));
        assert_eq!(brave.actions.len(), 1);
        assert!(brave.actions[0].contains("(Default)"));
        assert!(brave.actions[0].contains("app-bound"));
        let edge = report(&reports, "APP_EDGE");
        assert!(edge.actions.is_empty());
        assert!(!reports.iter().any(|r| r.id == "APP_CHROME"));
    }

    #[test]
    fn firefox_profiles_ini_is_parsed() {
        let ini = "[General]\nStartWithLastProfile=1\n\n[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n\n[Profile1]\nIsRelative=0\nPath=C:\\Users\\Test\\ff\n\n[Install123]\nDefault=Profiles/abc.default\n";
        assert_eq!(
            firefox_profile_paths(ini),
            vec![
                ("Profiles/abc.default".to_string(), true),
                (r"C:\Users\Test\ff".to_string(), false)
            ]
        );
    }

    #[test]
    fn firefox_absolute_profile_path_inside_old_profile_needs_rewrite() {
        let tree = TempTree::new("firefox");
        let inside = tree.0.join("ff").display().to_string();
        tree.file(
            "AppData/Roaming/Mozilla/Firefox/profiles.ini",
            &format!("[Profile0]\nIsRelative=1\nPath=Profiles/a\n[Profile1]\nIsRelative=0\nPath={inside}\n"),
        );
        let reports = detect(&tree, None);
        let firefox = report(&reports, "APP_FIREFOX");
        assert!(firefox.carried[0].starts_with("2 Firefox profile(s)"));
        assert_eq!(firefox.actions.len(), 1);
        assert!(firefox.actions[0].contains(&inside));
    }

    #[test]
    fn outlook_data_files_are_split_by_location() {
        let tree = TempTree::new("outlook");
        let inside = tree
            .0
            .join("Documents")
            .join("mail.pst")
            .display()
            .to_string();
        let registry = RegistryInspection {
            outlook_profiles: vec!["Outlook".into()],
            outlook_data_files: vec![inside.clone(), r"D:\Archive\old.pst".into()],
            ..RegistryInspection::default()
        };
        let reports = detect(&tree, Some(&registry));
        let outlook = report(&reports, "APP_OUTLOOK");
        assert!(outlook
            .carried
            .iter()
            .any(|c| c.contains(r"D:\Archive\old.pst")));
        assert!(outlook.actions.iter().any(|a| a.starts_with(&inside)));
        assert!(outlook.actions.iter().any(|a| a.contains("sign in")));
    }

    #[test]
    fn registry_settings_drive_network_and_printer_reports() {
        let tree = TempTree::new("registry");
        let registry = RegistryInspection {
            network_drives: vec![r"Z: -> \\srv\share".into()],
            printer_connections: vec![r"\\printsrv\HP".into()],
            ..RegistryInspection::default()
        };
        let reports = detect(&tree, Some(&registry));
        assert_eq!(report(&reports, "APP_NETWORK_DRIVES").carried.len(), 1);
        assert!(report(&reports, "APP_PRINTERS").actions.is_empty());
    }

    #[test]
    fn certificates_with_private_keys_need_export() {
        let tree = TempTree::new("certs");
        tree.file(
            "AppData/Roaming/Microsoft/SystemCertificates/My/Certificates/AB12",
            "c",
        );
        tree.file(
            &format!("AppData/Roaming/Microsoft/Crypto/RSA/{SRC}/key1"),
            "k",
        );
        let reports = detect(&tree, None);
        let certs = report(&reports, "APP_CERTIFICATES");
        assert!(certs.carried[0].starts_with("1 certificate"));
        assert!(certs.actions[0].starts_with("1 private key"));
    }

    #[test]
    fn keys_without_certificates_are_described_as_application_keys() {
        let tree = TempTree::new("keys");
        tree.file(
            &format!("AppData/Roaming/Microsoft/Crypto/RSA/{SRC}/key1"),
            "k",
        );
        let reports = detect(&tree, None);
        let certs = report(&reports, "APP_CERTIFICATES");
        assert!(certs.actions[0].contains("without a personal certificate"));
    }

    #[test]
    fn onedrive_without_signed_in_account_needs_nothing() {
        let tree = TempTree::new("onedrive");
        let known = KnownPaths {
            onedrive_folders: vec!["OneDrive".into()],
            onedrive_client_state: true,
            ..KnownPaths::default()
        };
        let idle = RegistryInspection::default();
        let ctx = AppContext {
            profile: &tree.0,
            source_sid: SRC,
            known: &known,
            registry: Some(&idle),
            target_profile: Some(Path::new(r"C:\Users\new")),
        };
        let reports = detect_all(&ctx);
        assert!(report(&reports, "APP_ONEDRIVE").actions.is_empty());

        let signed_in = RegistryInspection {
            onedrive_accounts: vec![r"Business1 -> C:\Users\Test\OneDrive - Contoso".into()],
            ..RegistryInspection::default()
        };
        let reports = detect_all(&AppContext {
            registry: Some(&signed_in),
            ..ctx
        });
        let onedrive = report(&reports, "APP_ONEDRIVE");
        assert!(onedrive.actions.iter().any(|a| a.contains(r"C:\Users\new")));
    }

    #[test]
    fn teams_is_detected_from_the_new_client_package() {
        let tree = TempTree::new("teams");
        tree.file(
            "AppData/Local/Packages/MSTeams_8wekyb3d8bbwe/Settings/x",
            "x",
        );
        let reports = detect(&tree, None);
        assert_eq!(report(&reports, "APP_TEAMS").actions.len(), 1);
    }
}
