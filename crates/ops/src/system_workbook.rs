use crate::health::{collect_health_report, collect_system_info, format_uptime, HealthStatus};
use crate::tasks::parse_snapper_list_output;
use chamrisk_core::models::{BtrfsSnapshotRow, PackageLock, PackageRow, RepositoryRow};
use chamrisk_core::zypper::{parse_package_locks, parse_packages_xml, parse_repositories_xml};
use chrono::Utc;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemWorkbook {
    pub sheets: Vec<SystemWorkbookSheet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemWorkbookSheet {
    pub name: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatpakRow {
    pub application: String,
    pub name: String,
    pub branch: String,
    pub origin: String,
    pub installation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitRow {
    pub unit: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemInfoEntry {
    property: String,
    value: String,
    note: String,
}

pub fn collect_system_workbook<F>(
    sudo_password: Option<String>,
    mut progress: F,
) -> Result<SystemWorkbook, String>
where
    F: FnMut(&str),
{
    if sudo_password.is_none() {
        return Err("System workbook export requires sudo authentication.".to_string());
    }

    progress("Collecting health checks");
    let health_report = collect_health_report();

    progress("Collecting system info");
    let system_info = collect_workbook_system_info();

    progress("Collecting snapshots");
    let snapshots = collect_snapshots(sudo_password.clone());

    progress("Collecting packages");
    let packages = collect_installed_packages(sudo_password.clone());

    progress("Collecting locks");
    let locks = collect_package_locks(sudo_password);

    progress("Collecting repositories");
    let repositories = collect_repositories();

    progress("Collecting flatpaks");
    let flatpaks = collect_flatpaks();

    progress("Collecting systemd units");
    let systemd_units = collect_active_systemd_units();

    let mut sheets = vec![
        build_system_info_sheet(system_info),
        build_health_sheet(&health_report),
        build_snapshots_sheet(snapshots),
        build_packages_sheet(packages),
        build_locks_sheet(locks),
        build_repositories_sheet(repositories),
    ];

    if let Some(flatpaks) = flatpaks {
        sheets.push(build_flatpaks_sheet(flatpaks));
    }

    sheets.push(build_systemd_sheet(systemd_units));

    Ok(SystemWorkbook { sheets })
}

pub fn write_system_workbook(path: &Path, workbook: &SystemWorkbook) -> Result<(), String> {
    if workbook.sheets.is_empty() {
        return Err("system workbook contains no sheets".to_string());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create output dir {}: {err}", parent.display()))?;
    }

    let file = fs::File::create(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    let mut zip = ZipWriter::new(file);
    let stored = FileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = FileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file("[Content_Types].xml", deflated)
        .map_err(|err| format!("failed to write [Content_Types].xml: {err}"))?;
    zip.write_all(content_types_xml(workbook).as_bytes())
        .map_err(|err| format!("failed to write content types: {err}"))?;

    zip.add_directory("_rels/", deflated)
        .map_err(|err| format!("failed to add _rels/: {err}"))?;
    zip.start_file("_rels/.rels", deflated)
        .map_err(|err| format!("failed to write .rels: {err}"))?;
    zip.write_all(root_rels_xml().as_bytes())
        .map_err(|err| format!("failed to write root rels: {err}"))?;

    zip.add_directory("docProps/", deflated)
        .map_err(|err| format!("failed to add docProps/: {err}"))?;
    zip.start_file("docProps/app.xml", deflated)
        .map_err(|err| format!("failed to write app.xml: {err}"))?;
    zip.write_all(app_props_xml(workbook).as_bytes())
        .map_err(|err| format!("failed to write app props: {err}"))?;
    zip.start_file("docProps/core.xml", deflated)
        .map_err(|err| format!("failed to write core.xml: {err}"))?;
    zip.write_all(core_props_xml().as_bytes())
        .map_err(|err| format!("failed to write core props: {err}"))?;

    zip.add_directory("xl/", deflated)
        .map_err(|err| format!("failed to add xl/: {err}"))?;
    zip.start_file("xl/workbook.xml", deflated)
        .map_err(|err| format!("failed to write workbook.xml: {err}"))?;
    zip.write_all(workbook_xml(workbook).as_bytes())
        .map_err(|err| format!("failed to write workbook xml: {err}"))?;

    zip.add_directory("xl/_rels/", deflated)
        .map_err(|err| format!("failed to add xl/_rels/: {err}"))?;
    zip.start_file("xl/_rels/workbook.xml.rels", deflated)
        .map_err(|err| format!("failed to write workbook.xml.rels: {err}"))?;
    zip.write_all(workbook_rels_xml(workbook).as_bytes())
        .map_err(|err| format!("failed to write workbook rels: {err}"))?;

    zip.start_file("xl/styles.xml", deflated)
        .map_err(|err| format!("failed to write styles.xml: {err}"))?;
    zip.write_all(styles_xml().as_bytes())
        .map_err(|err| format!("failed to write styles xml: {err}"))?;

    zip.add_directory("xl/worksheets/", deflated)
        .map_err(|err| format!("failed to add xl/worksheets/: {err}"))?;
    for (index, sheet) in workbook.sheets.iter().enumerate() {
        let name = format!("xl/worksheets/sheet{}.xml", index + 1);
        zip.start_file(name, stored)
            .map_err(|err| format!("failed to start worksheet entry: {err}"))?;
        zip.write_all(worksheet_xml(sheet).as_bytes())
            .map_err(|err| format!("failed to write worksheet xml: {err}"))?;
    }

    zip.finish()
        .map_err(|err| format!("failed to finish workbook {}: {err}", path.display()))?;
    Ok(())
}

pub fn default_workbook_path(base_dir: Option<&Path>) -> PathBuf {
    let file_name = format!(
        "system-workbook-{}.xlsx",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    match base_dir {
        Some(dir) => dir.join(file_name),
        None => PathBuf::from(file_name),
    }
}

fn build_health_sheet(report: &crate::health::HealthReport) -> SystemWorkbookSheet {
    let mut rows = Vec::with_capacity(report.checks.len());
    for check in &report.checks {
        rows.push(vec![
            health_status_label(check.status).to_string(),
            check.name.clone(),
            check.message.clone(),
            check.recommendation.clone().unwrap_or_default(),
        ]);
    }

    if rows.is_empty() {
        rows.push(vec![
            "Unavailable".to_string(),
            "Health checks".to_string(),
            "No health checks were returned.".to_string(),
            String::new(),
        ]);
    }

    SystemWorkbookSheet {
        name: "Health".to_string(),
        headers: vec![
            "Status".to_string(),
            "Check".to_string(),
            "Message".to_string(),
            "Recommendation".to_string(),
        ],
        rows,
    }
}

fn build_system_info_sheet(entries: Vec<SystemInfoEntry>) -> SystemWorkbookSheet {
    let headers = vec![
        "Property".to_string(),
        "Value".to_string(),
        "Note".to_string(),
    ];

    let rows = if entries.is_empty() {
        vec![empty_row(
            headers.len(),
            "No system information was returned.",
        )]
    } else {
        entries
            .into_iter()
            .map(|entry| vec![entry.property, entry.value, entry.note])
            .collect()
    };

    SystemWorkbookSheet {
        name: "SystemInfo".to_string(),
        headers,
        rows,
    }
}

fn build_snapshots_sheet(result: Result<Vec<BtrfsSnapshotRow>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "Snapshot #".to_string(),
        "Current".to_string(),
        "Type".to_string(),
        "Pre #".to_string(),
        "Date".to_string(),
        "User".to_string(),
        "Used Space".to_string(),
        "Cleanup".to_string(),
        "Description".to_string(),
        "Userdata".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => {
            vec![empty_row(headers.len(), "No snapshots were returned.")]
        }
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                vec![
                    row.snapshot_id,
                    yes_no(row.is_current).to_string(),
                    row.snapshot_type,
                    row.pre_number.unwrap_or_default(),
                    row.date,
                    row.user,
                    row.used_space,
                    row.cleanup,
                    row.description,
                    row.userdata,
                ]
            })
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Snapshots".to_string(),
        headers,
        rows,
    }
}

fn build_packages_sheet(result: Result<Vec<PackageRow>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "Package".to_string(),
        "Installed Version".to_string(),
        "Available Version".to_string(),
        "Repository".to_string(),
        "Architecture".to_string(),
        "Summary".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => vec![empty_row(
            headers.len(),
            "No installed packages were returned.",
        )],
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                vec![
                    row.name,
                    row.installed_version.unwrap_or_default(),
                    row.available_version.unwrap_or_default(),
                    row.repository.unwrap_or_default(),
                    row.arch.unwrap_or_default(),
                    row.summary.unwrap_or_default(),
                ]
            })
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Packages".to_string(),
        headers,
        rows,
    }
}

fn build_flatpaks_sheet(result: Result<Vec<FlatpakRow>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "Application".to_string(),
        "Name".to_string(),
        "Branch".to_string(),
        "Origin".to_string(),
        "Installation".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => vec![empty_row(headers.len(), "No flatpaks installed.")],
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                vec![
                    row.application,
                    row.name,
                    row.branch,
                    row.origin,
                    row.installation,
                ]
            })
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Flatpaks".to_string(),
        headers,
        rows,
    }
}

fn build_locks_sheet(result: Result<Vec<PackageLock>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "ID".to_string(),
        "Name".to_string(),
        "Type".to_string(),
        "Repository".to_string(),
        "Comment".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => {
            vec![empty_row(headers.len(), "No package locks were returned.")]
        }
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                vec![
                    row.lock_id.unwrap_or_default(),
                    row.name,
                    row.match_type.unwrap_or_default(),
                    row.repository.unwrap_or_default(),
                    row.comment.unwrap_or_default(),
                ]
            })
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Locks".to_string(),
        headers,
        rows,
    }
}

fn build_repositories_sheet(result: Result<Vec<RepositoryRow>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "Alias".to_string(),
        "Name".to_string(),
        "Enabled".to_string(),
        "GPG Check".to_string(),
        "Refresh".to_string(),
        "Priority".to_string(),
        "URI".to_string(),
        "Type".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => {
            vec![empty_row(headers.len(), "No repositories were returned.")]
        }
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                vec![
                    row.alias,
                    row.name,
                    bool_cell(row.enabled),
                    bool_cell(row.gpg_check),
                    bool_cell(row.refresh),
                    row.priority.unwrap_or_default(),
                    row.uri.unwrap_or_default(),
                    row.repo_type.unwrap_or_default(),
                ]
            })
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Repositories".to_string(),
        headers,
        rows,
    }
}

fn build_systemd_sheet(result: Result<Vec<SystemdUnitRow>, String>) -> SystemWorkbookSheet {
    let headers = vec![
        "Unit".to_string(),
        "Load".to_string(),
        "Active".to_string(),
        "Sub".to_string(),
        "Description".to_string(),
    ];

    let rows = match result {
        Ok(rows) if rows.is_empty() => vec![empty_row(
            headers.len(),
            "No active systemd units were returned.",
        )],
        Ok(rows) => rows
            .into_iter()
            .map(|row| vec![row.unit, row.load, row.active, row.sub, row.description])
            .collect(),
        Err(err) => vec![empty_row(headers.len(), &format!("Unavailable: {err}"))],
    };

    SystemWorkbookSheet {
        name: "Systemd".to_string(),
        headers,
        rows,
    }
}

fn collect_workbook_system_info() -> Vec<SystemInfoEntry> {
    let info = collect_system_info();
    let export_timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    vec![
        system_info_entry("Hostname", read_hostname(), ""),
        system_info_entry("Operating System", non_unknown(&info.os_name), ""),
        system_info_entry("Version", non_unknown(&info.os_version), ""),
        system_info_entry("Kernel", non_unknown(&info.kernel), ""),
        system_info_entry("Architecture", non_unknown(&info.architecture), ""),
        system_info_entry(
            "Machine ID",
            read_machine_id(),
            "May be sensitive in shared reports.",
        ),
        system_info_entry("Boot Mode", detect_boot_mode(), ""),
        system_info_entry("Root Filesystem", read_root_filesystem(), ""),
        system_info_entry("Desktop Session", read_desktop_session(), ""),
        system_info_entry(
            "Uptime",
            if info.uptime_seconds > 0 {
                Some(format_uptime(info.uptime_seconds))
            } else {
                None
            },
            "",
        ),
        system_info_entry("Export Timestamp", Some(export_timestamp), ""),
    ]
}

fn collect_snapshots(sudo_password: Option<String>) -> Result<Vec<BtrfsSnapshotRow>, String> {
    let output = run_capture_with_sudo(sudo_password, "snapper", &["list"])?;
    if output.0 != 0 {
        return Err(command_failure("snapper list", output.0, &output.2));
    }
    parse_snapper_list_output(&output.1)
}

fn collect_installed_packages(sudo_password: Option<String>) -> Result<Vec<PackageRow>, String> {
    let primary_args = [
        "--non-interactive",
        "--xmlout",
        "search",
        "-s",
        "--details",
        "-t",
        "package",
        "--installed-only",
        "",
    ];
    let fallback_args = [
        "--non-interactive",
        "--xmlout",
        "search",
        "-s",
        "-t",
        "package",
        "--installed-only",
        "",
    ];
    let broad_fallback_args = [
        "--non-interactive",
        "--xmlout",
        "search",
        "-s",
        "-t",
        "package",
        "",
    ];

    let mut output = run_capture_with_sudo(sudo_password.clone(), "zypper", &primary_args)?;
    if output.0 != 0 {
        let stderr_lc = output.2.to_ascii_lowercase();
        if stderr_lc.contains("unknown option") && stderr_lc.contains("details") {
            output = run_capture_with_sudo(sudo_password.clone(), "zypper", &fallback_args)?;
        }
    }
    if output.0 != 0 {
        let stderr_lc = output.2.to_ascii_lowercase();
        if stderr_lc.contains("unknown option") && stderr_lc.contains("installed-only") {
            output = run_capture_with_sudo(sudo_password, "zypper", &broad_fallback_args)?;
        }
    }
    if output.0 != 0 {
        return Err(command_failure("zypper search", output.0, &output.2));
    }

    let rows =
        parse_packages_xml(&output.1).map_err(|err| format!("packages parse failed: {err}"))?;
    Ok(rows
        .into_iter()
        .filter(|row| row.installed_version.is_some())
        .collect())
}

fn collect_package_locks(sudo_password: Option<String>) -> Result<Vec<PackageLock>, String> {
    let output = run_capture_with_sudo(sudo_password, "zypper", &["--non-interactive", "locks"])?;
    if output.0 != 0 {
        return Err(command_failure("zypper locks", output.0, &output.2));
    }

    Ok(parse_package_locks(&output.1)
        .into_iter()
        .filter(is_real_package_lock)
        .collect())
}

fn collect_repositories() -> Result<Vec<RepositoryRow>, String> {
    let output = run_capture("zypper", &["--xmlout", "lr", "-d"])?;
    if output.0 != 0 {
        return Err(command_failure("zypper lr -d", output.0, &output.2));
    }

    parse_repositories_xml(&output.1).map_err(|err| format!("repository parse failed: {err}"))
}

fn collect_flatpaks() -> Option<Result<Vec<FlatpakRow>, String>> {
    if !command_exists("flatpak") {
        return None;
    }

    Some(
        run_capture(
            "flatpak",
            &[
                "list",
                "--system",
                "--columns=application,name,branch,origin,installation",
            ],
        )
        .and_then(|output| {
            if output.0 != 0 {
                return Err(command_failure("flatpak list", output.0, &output.2));
            }
            Ok(parse_flatpak_list(&output.1))
        }),
    )
}

fn collect_active_systemd_units() -> Result<Vec<SystemdUnitRow>, String> {
    let output = run_capture(
        "systemctl",
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-pager",
            "--no-legend",
            "--type=service",
            "--type=mount",
            "--type=timer",
            "--state=active",
        ],
    )?;
    if output.0 != 0 {
        return Err(command_failure("systemctl list-units", output.0, &output.2));
    }
    Ok(parse_systemd_units(&output.1))
}

fn run_capture(cmd: &str, args: &[&str]) -> Result<(i32, String, String), String> {
    let output = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to execute {cmd}: {err}"))?;

    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

fn run_capture_with_sudo(
    sudo_password: Option<String>,
    cmd: &str,
    args: &[&str],
) -> Result<(i32, String, String), String> {
    let Some(password) = sudo_password else {
        return Err(format!("sudo password unavailable for {cmd}"));
    };

    let mut child = Command::new("sudo")
        .args(["-S", "-p", ""])
        .arg(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to start sudo {cmd}: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{password}\n").as_bytes())
            .map_err(|err| format!("failed to write sudo password: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting for sudo {cmd}: {err}"))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

fn parse_flatpak_list(output: &str) -> Vec<FlatpakRow> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut parts = trimmed.split('\t');
            Some(FlatpakRow {
                application: parts.next().unwrap_or_default().trim().to_string(),
                name: parts.next().unwrap_or_default().trim().to_string(),
                branch: parts.next().unwrap_or_default().trim().to_string(),
                origin: parts.next().unwrap_or_default().trim().to_string(),
                installation: parts.next().unwrap_or_default().trim().to_string(),
            })
        })
        .collect()
}

fn parse_systemd_units(output: &str) -> Vec<SystemdUnitRow> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let unit = parts.next()?.to_string();
            let load = parts.next().unwrap_or_default().to_string();
            let active = parts.next().unwrap_or_default().to_string();
            let sub = parts.next().unwrap_or_default().to_string();
            let description = parts.collect::<Vec<_>>().join(" ");
            Some(SystemdUnitRow {
                unit,
                load,
                active,
                sub,
                description,
            })
        })
        .collect()
}

fn system_info_entry(property: &str, value: Option<String>, note: &str) -> SystemInfoEntry {
    SystemInfoEntry {
        property: property.to_string(),
        value: value.unwrap_or_default(),
        note: note.to_string(),
    }
}

fn non_unknown(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_hostname() -> Option<String> {
    run_capture("hostname", &[])
        .ok()
        .and_then(|output| if output.0 == 0 { Some(output.1) } else { None })
        .and_then(|stdout| first_non_empty_line(&stdout))
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(|contents| first_non_empty_line(&contents))
        })
}

fn read_machine_id() -> Option<String> {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .and_then(|contents| first_non_empty_line(&contents))
}

fn detect_boot_mode() -> Option<String> {
    if Path::new("/sys/firmware/efi").exists() {
        Some("UEFI".to_string())
    } else {
        Some("BIOS/Legacy".to_string())
    }
}

fn read_root_filesystem() -> Option<String> {
    run_capture("findmnt", &["-no", "FSTYPE", "/"])
        .ok()
        .and_then(|output| if output.0 == 0 { Some(output.1) } else { None })
        .and_then(|stdout| first_non_empty_line(&stdout))
}

fn read_desktop_session() -> Option<String> {
    [
        env::var("XDG_CURRENT_DESKTOP").ok(),
        env::var("DESKTOP_SESSION").ok(),
        env::var("XDG_SESSION_DESKTOP").ok(),
    ]
    .into_iter()
    .flatten()
    .find_map(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn first_non_empty_line(contents: &str) -> Option<String> {
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.to_string())
}

fn command_exists(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_failure(command: &str, exit_code: i32, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        format!("{command} failed with exit code {exit_code}")
    } else {
        format!("{command} failed with exit code {exit_code}: {stderr}")
    }
}

fn health_status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Ok => "OK",
        HealthStatus::Warn => "Warn",
        HealthStatus::Error => "Error",
        HealthStatus::Unknown => "Unknown",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn bool_cell(value: Option<bool>) -> String {
    match value {
        Some(true) => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None => String::new(),
    }
}

fn empty_row(width: usize, message: &str) -> Vec<String> {
    let mut row = vec![String::new(); width.max(1)];
    row[0] = message.to_string();
    row
}

fn is_real_package_lock(lock: &PackageLock) -> bool {
    lock.lock_id
        .as_deref()
        .map(str::trim)
        .map(|id| !id.is_empty())
        .unwrap_or(false)
        && !lock.name.trim().is_empty()
}

fn content_types_xml(workbook: &SystemWorkbook) -> String {
    let mut overrides = vec![
        r#"<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>"#.to_string(),
        r#"<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>"#.to_string(),
        r#"<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>"#.to_string(),
        r#"<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>"#.to_string(),
    ];

    for index in 0..workbook.sheets.len() {
        overrides.push(format!(
            r#"<Override PartName="/xl/worksheets/sheet{}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#,
            index + 1
        ));
    }

    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"#,
            r#"<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>"#,
            r#"<Default Extension="xml" ContentType="application/xml"/>"#,
            "{}",
            r#"</Types>"#
        ),
        overrides.join("")
    )
}

fn root_rels_xml() -> &'static str {
    concat!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
        r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
        r#"<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>"#,
        r#"<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>"#,
        r#"<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>"#,
        r#"</Relationships>"#
    )
}

fn app_props_xml(workbook: &SystemWorkbook) -> String {
    let titles = workbook
        .sheets
        .iter()
        .map(|sheet| format!("<vt:lpstr>{}</vt:lpstr>", xml_escape(&sheet.name)))
        .collect::<Vec<_>>()
        .join("");

    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">"#,
            r#"<Application>ChamRisk</Application>"#,
            r#"<HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>{}</vt:i4></vt:variant></vt:vector></HeadingPairs>"#,
            r#"<TitlesOfParts><vt:vector size="{}" baseType="lpstr">{}</vt:vector></TitlesOfParts>"#,
            r#"</Properties>"#
        ),
        workbook.sheets.len(),
        workbook.sheets.len(),
        titles
    )
}

fn core_props_xml() -> String {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#,
            r#"<dc:creator>ChamRisk</dc:creator>"#,
            r#"<cp:lastModifiedBy>ChamRisk</cp:lastModifiedBy>"#,
            r#"<dcterms:created xsi:type="dcterms:W3CDTF">{}</dcterms:created>"#,
            r#"<dcterms:modified xsi:type="dcterms:W3CDTF">{}</dcterms:modified>"#,
            r#"</cp:coreProperties>"#
        ),
        now, now
    )
}

fn workbook_xml(workbook: &SystemWorkbook) -> String {
    let sheets = workbook
        .sheets
        .iter()
        .enumerate()
        .map(|(index, sheet)| {
            format!(
                r#"<sheet name="{}" sheetId="{}" r:id="rId{}"/>"#,
                xml_escape(&sanitize_sheet_name(&sheet.name)),
                index + 1,
                index + 1
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">"#,
            r#"<sheets>{}</sheets>"#,
            r#"</workbook>"#
        ),
        sheets
    )
}

fn workbook_rels_xml(workbook: &SystemWorkbook) -> String {
    let mut relationships = workbook
        .sheets
        .iter()
        .enumerate()
        .map(|(index, _)| {
            format!(
                r#"<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{}.xml"/>"#,
                index + 1,
                index + 1
            )
        })
        .collect::<Vec<_>>();
    relationships.push(
        format!(
            r#"<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>"#,
            workbook.sheets.len() + 1
        ),
    );

    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
            "{}",
            r#"</Relationships>"#
        ),
        relationships.join("")
    )
}

fn styles_xml() -> &'static str {
    concat!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
        r#"<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">"#,
        r#"<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>"#,
        r#"<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>"#,
        r#"<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>"#,
        r#"<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>"#,
        r#"<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>"#,
        r#"<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>"#,
        r#"</styleSheet>"#
    )
}

fn worksheet_xml(sheet: &SystemWorkbookSheet) -> String {
    let mut rows = Vec::with_capacity(sheet.rows.len() + 1);
    rows.push(row_xml(1, &sheet.headers));
    for (index, row) in sheet.rows.iter().enumerate() {
        rows.push(row_xml((index + 2) as u32, row));
    }

    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
            r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">"#,
            r#"<sheetData>{}</sheetData>"#,
            r#"</worksheet>"#
        ),
        rows.join("")
    )
}

fn row_xml(row_index: u32, values: &[String]) -> String {
    let cells = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            format!(
                r#"<c r="{}{}" t="inlineStr"><is><t xml:space="preserve">{}</t></is></c>"#,
                column_name(index),
                row_index,
                xml_escape(&sanitize_cell_value(value))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(r#"<row r="{row_index}">{cells}</row>"#)
}

fn column_name(mut index: usize) -> String {
    let mut name = String::new();
    loop {
        let remainder = index % 26;
        name.insert(0, (b'A' + remainder as u8) as char);
        if index < 26 {
            break;
        }
        index = (index / 26) - 1;
    }
    name
}

fn sanitize_sheet_name(name: &str) -> String {
    let filtered = name
        .chars()
        .filter(|ch| !matches!(ch, ':' | '\\' | '/' | '?' | '*' | '[' | ']'))
        .collect::<String>();
    let trimmed = filtered.trim();
    let fallback = if trimmed.is_empty() { "Sheet" } else { trimmed };
    fallback.chars().take(31).collect()
}

fn sanitize_cell_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}'))
        .collect()
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::{
        bool_cell, build_locks_sheet, build_repositories_sheet, build_system_info_sheet,
        first_non_empty_line, is_real_package_lock, non_unknown, system_info_entry,
        write_system_workbook, SystemInfoEntry, SystemWorkbook, SystemWorkbookSheet,
    };
    use chamrisk_core::models::{PackageLock, RepositoryRow};
    use std::fs::File;
    use tempfile::tempdir;
    use zip::ZipArchive;

    #[test]
    fn workbook_writer_preserves_sheet_order() {
        let workbook = SystemWorkbook {
            sheets: vec![
                SystemWorkbookSheet {
                    name: "SystemInfo".to_string(),
                    headers: vec!["Property".to_string()],
                    rows: vec![vec!["Hostname".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Health".to_string(),
                    headers: vec!["Status".to_string(), "Check".to_string()],
                    rows: vec![vec!["OK".to_string(), "Repositories".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Snapshots".to_string(),
                    headers: vec!["Snapshot #".to_string()],
                    rows: vec![vec!["123".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Packages".to_string(),
                    headers: vec!["Package".to_string()],
                    rows: vec![vec!["systemd".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Locks".to_string(),
                    headers: vec!["ID".to_string()],
                    rows: vec![vec!["1".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Repositories".to_string(),
                    headers: vec!["Alias".to_string()],
                    rows: vec![vec!["repo-oss".to_string()]],
                },
                SystemWorkbookSheet {
                    name: "Systemd".to_string(),
                    headers: vec!["Unit".to_string()],
                    rows: vec![vec!["sshd.service".to_string()]],
                },
            ],
        };
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("system.xlsx");

        write_system_workbook(&path, &workbook).expect("write workbook");

        let file = File::open(&path).expect("open workbook");
        let mut zip = ZipArchive::new(file).expect("zip");
        let workbook_xml = {
            let mut entry = zip.by_name("xl/workbook.xml").expect("workbook.xml");
            let mut content = String::new();
            use std::io::Read;
            entry
                .read_to_string(&mut content)
                .expect("read workbook xml");
            content
        };

        let health = workbook_xml.find(r#"sheet name="Health""#).expect("health");
        let system_info = workbook_xml
            .find(r#"sheet name="SystemInfo""#)
            .expect("system info");
        let snapshots = workbook_xml
            .find(r#"sheet name="Snapshots""#)
            .expect("snapshots");
        let packages = workbook_xml
            .find(r#"sheet name="Packages""#)
            .expect("packages");
        let locks = workbook_xml.find(r#"sheet name="Locks""#).expect("locks");
        let repositories = workbook_xml
            .find(r#"sheet name="Repositories""#)
            .expect("repositories");
        let systemd = workbook_xml
            .find(r#"sheet name="Systemd""#)
            .expect("systemd");
        assert!(
            system_info < health
                && health < snapshots
                && snapshots < packages
                && packages < locks
                && locks < repositories
                && repositories < systemd
        );
    }

    #[test]
    fn workbook_writer_emits_headers_and_rows() {
        let workbook = SystemWorkbook {
            sheets: vec![SystemWorkbookSheet {
                name: "Health".to_string(),
                headers: vec![
                    "Status".to_string(),
                    "Check".to_string(),
                    "Message".to_string(),
                ],
                rows: vec![vec![
                    "Warn".to_string(),
                    "Boot Partition".to_string(),
                    "82% used".to_string(),
                ]],
            }],
        };
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("system.xlsx");

        write_system_workbook(&path, &workbook).expect("write workbook");

        let file = File::open(&path).expect("open workbook");
        let mut zip = ZipArchive::new(file).expect("zip");
        let sheet_xml = {
            let mut entry = zip.by_name("xl/worksheets/sheet1.xml").expect("sheet1.xml");
            let mut content = String::new();
            use std::io::Read;
            entry.read_to_string(&mut content).expect("read sheet xml");
            content
        };

        assert!(sheet_xml.contains("Status"));
        assert!(sheet_xml.contains("Boot Partition"));
        assert!(sheet_xml.contains("82% used"));
    }

    #[test]
    fn workbook_writer_serializes_system_info_sheet_content() {
        let workbook = SystemWorkbook {
            sheets: vec![build_system_info_sheet(vec![
                system_info_entry("Hostname", Some("workstation".to_string()), ""),
                system_info_entry(
                    "Export Timestamp",
                    Some("2026-03-12T10:00:00Z".to_string()),
                    "",
                ),
            ])],
        };
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("system.xlsx");

        write_system_workbook(&path, &workbook).expect("write workbook");

        let file = File::open(&path).expect("open workbook");
        let mut zip = ZipArchive::new(file).expect("zip");
        let sheet_xml = {
            let mut entry = zip.by_name("xl/worksheets/sheet1.xml").expect("sheet1.xml");
            let mut content = String::new();
            use std::io::Read;
            entry.read_to_string(&mut content).expect("read sheet xml");
            content
        };

        assert!(sheet_xml.contains("Property"));
        assert!(sheet_xml.contains("Hostname"));
        assert!(sheet_xml.contains("workstation"));
        assert!(sheet_xml.contains("Export Timestamp"));
        assert!(sheet_xml.contains("2026-03-12T10:00:00Z"));
    }

    #[test]
    fn workbook_writer_serializes_locks_sheet_content() {
        let workbook = SystemWorkbook {
            sheets: vec![build_locks_sheet(Ok(vec![PackageLock {
                lock_id: Some("7".to_string()),
                name: "kernel-default".to_string(),
                match_type: Some("package".to_string()),
                repository: Some("repo-oss".to_string()),
                comment: Some("pin kernel".to_string()),
                raw_entry: "| 7 | kernel-default | package | repo-oss | pin kernel |".to_string(),
            }]))],
        };
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("system.xlsx");

        write_system_workbook(&path, &workbook).expect("write workbook");

        let file = File::open(&path).expect("open workbook");
        let mut zip = ZipArchive::new(file).expect("zip");
        let sheet_xml = {
            let mut entry = zip.by_name("xl/worksheets/sheet1.xml").expect("sheet1.xml");
            let mut content = String::new();
            use std::io::Read;
            entry.read_to_string(&mut content).expect("read sheet xml");
            content
        };

        assert!(sheet_xml.contains("ID"));
        assert!(sheet_xml.contains("Repository"));
        assert!(sheet_xml.contains("kernel-default"));
        assert!(sheet_xml.contains("repo-oss"));
        assert!(sheet_xml.contains("pin kernel"));
    }

    #[test]
    fn workbook_writer_serializes_repositories_sheet_content() {
        let workbook = SystemWorkbook {
            sheets: vec![build_repositories_sheet(Ok(vec![RepositoryRow {
                alias: "repo-oss".to_string(),
                name: "Main Repository (OSS)".to_string(),
                enabled: Some(true),
                gpg_check: Some(true),
                refresh: Some(false),
                priority: Some("99".to_string()),
                uri: Some("http://example.invalid/oss".to_string()),
                repo_type: Some("rpm-md".to_string()),
            }]))],
        };
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("system.xlsx");

        write_system_workbook(&path, &workbook).expect("write workbook");

        let file = File::open(&path).expect("open workbook");
        let mut zip = ZipArchive::new(file).expect("zip");
        let sheet_xml = {
            let mut entry = zip.by_name("xl/worksheets/sheet1.xml").expect("sheet1.xml");
            let mut content = String::new();
            use std::io::Read;
            entry.read_to_string(&mut content).expect("read sheet xml");
            content
        };

        assert!(sheet_xml.contains("Alias"));
        assert!(sheet_xml.contains("GPG Check"));
        assert!(sheet_xml.contains("repo-oss"));
        assert!(sheet_xml.contains("Main Repository (OSS)"));
        assert!(sheet_xml.contains("http://example.invalid/oss"));
        assert!(sheet_xml.contains("rpm-md"));
    }

    #[test]
    fn locks_sheet_includes_real_lock_rows() {
        let sheet = build_locks_sheet(Ok(vec![PackageLock {
            lock_id: Some("1".to_string()),
            name: "MozillaFirefox".to_string(),
            match_type: Some("package".to_string()),
            repository: Some("repo-oss".to_string()),
            comment: Some("browser hold".to_string()),
            raw_entry: "| 1 | MozillaFirefox | package | repo-oss | browser hold |".to_string(),
        }]));

        assert_eq!(sheet.name, "Locks");
        assert_eq!(
            sheet.headers,
            vec![
                "ID".to_string(),
                "Name".to_string(),
                "Type".to_string(),
                "Repository".to_string(),
                "Comment".to_string()
            ]
        );
        assert_eq!(
            sheet.rows,
            vec![vec![
                "1".to_string(),
                "MozillaFirefox".to_string(),
                "package".to_string(),
                "repo-oss".to_string(),
                "browser hold".to_string()
            ]]
        );
    }

    #[test]
    fn locks_sheet_uses_no_data_convention_for_zero_locks() {
        let sheet = build_locks_sheet(Ok(Vec::new()));

        assert_eq!(sheet.name, "Locks");
        assert_eq!(
            sheet.headers,
            vec![
                "ID".to_string(),
                "Name".to_string(),
                "Type".to_string(),
                "Repository".to_string(),
                "Comment".to_string()
            ]
        );
        assert_eq!(sheet.rows.len(), 1);
        assert_eq!(sheet.rows[0][0], "No package locks were returned.");
        assert!(sheet.rows[0][1..].iter().all(|cell| cell.is_empty()));
    }

    #[test]
    fn workbook_lock_filter_excludes_informational_rows() {
        let info = PackageLock {
            lock_id: None,
            name: "No locks defined.".to_string(),
            match_type: None,
            repository: None,
            comment: None,
            raw_entry: "No locks defined.".to_string(),
        };
        let blank_id = PackageLock {
            lock_id: Some("   ".to_string()),
            name: "Try zypper addlock <name>.".to_string(),
            match_type: None,
            repository: None,
            comment: None,
            raw_entry: "Try zypper addlock <name>.".to_string(),
        };
        let real = PackageLock {
            lock_id: Some("4".to_string()),
            name: "kernel-default".to_string(),
            match_type: Some("package".to_string()),
            repository: Some("repo-oss".to_string()),
            comment: None,
            raw_entry: "| 4 | kernel-default | package | repo-oss |".to_string(),
        };

        assert!(!is_real_package_lock(&info));
        assert!(!is_real_package_lock(&blank_id));
        assert!(is_real_package_lock(&real));
    }

    #[test]
    fn repositories_sheet_includes_structured_rows() {
        let sheet = build_repositories_sheet(Ok(vec![RepositoryRow {
            alias: "repo-oss".to_string(),
            name: "Main Repository (OSS)".to_string(),
            enabled: Some(true),
            gpg_check: Some(true),
            refresh: Some(false),
            priority: Some("99".to_string()),
            uri: Some("http://example.invalid/oss".to_string()),
            repo_type: Some("rpm-md".to_string()),
        }]));

        assert_eq!(sheet.name, "Repositories");
        assert_eq!(
            sheet.headers,
            vec![
                "Alias".to_string(),
                "Name".to_string(),
                "Enabled".to_string(),
                "GPG Check".to_string(),
                "Refresh".to_string(),
                "Priority".to_string(),
                "URI".to_string(),
                "Type".to_string(),
            ]
        );
        assert_eq!(
            sheet.rows,
            vec![vec![
                "repo-oss".to_string(),
                "Main Repository (OSS)".to_string(),
                "Yes".to_string(),
                "Yes".to_string(),
                "No".to_string(),
                "99".to_string(),
                "http://example.invalid/oss".to_string(),
                "rpm-md".to_string(),
            ]]
        );
    }

    #[test]
    fn repositories_sheet_handles_blank_optional_fields() {
        let sheet = build_repositories_sheet(Ok(vec![RepositoryRow {
            alias: "custom".to_string(),
            name: "Custom Repo".to_string(),
            enabled: None,
            gpg_check: None,
            refresh: None,
            priority: None,
            uri: None,
            repo_type: None,
        }]));

        assert_eq!(
            sheet.rows,
            vec![vec![
                "custom".to_string(),
                "Custom Repo".to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]]
        );
    }

    #[test]
    fn repositories_sheet_uses_no_data_convention_for_zero_repositories() {
        let sheet = build_repositories_sheet(Ok(Vec::new()));

        assert_eq!(sheet.name, "Repositories");
        assert_eq!(sheet.rows.len(), 1);
        assert_eq!(sheet.rows[0][0], "No repositories were returned.");
        assert!(sheet.rows[0][1..].iter().all(|cell| cell.is_empty()));
    }

    #[test]
    fn repository_bool_cells_are_human_readable() {
        assert_eq!(bool_cell(Some(true)), "Yes");
        assert_eq!(bool_cell(Some(false)), "No");
        assert_eq!(bool_cell(None), "");
    }

    #[test]
    fn system_info_sheet_includes_property_value_rows() {
        let sheet = build_system_info_sheet(vec![
            SystemInfoEntry {
                property: "Hostname".to_string(),
                value: "workstation".to_string(),
                note: String::new(),
            },
            SystemInfoEntry {
                property: "Export Timestamp".to_string(),
                value: "2026-03-12T10:00:00Z".to_string(),
                note: String::new(),
            },
        ]);

        assert_eq!(sheet.name, "SystemInfo");
        assert_eq!(
            sheet.headers,
            vec![
                "Property".to_string(),
                "Value".to_string(),
                "Note".to_string(),
            ]
        );
        assert_eq!(
            sheet.rows,
            vec![
                vec![
                    "Hostname".to_string(),
                    "workstation".to_string(),
                    String::new(),
                ],
                vec![
                    "Export Timestamp".to_string(),
                    "2026-03-12T10:00:00Z".to_string(),
                    String::new(),
                ],
            ]
        );
    }

    #[test]
    fn system_info_sheet_uses_no_data_convention_when_empty() {
        let sheet = build_system_info_sheet(Vec::new());

        assert_eq!(sheet.name, "SystemInfo");
        assert_eq!(sheet.rows.len(), 1);
        assert_eq!(sheet.rows[0][0], "No system information was returned.");
        assert!(sheet.rows[0][1..].iter().all(|cell| cell.is_empty()));
    }

    #[test]
    fn system_info_helpers_tolerate_missing_optional_fields() {
        assert_eq!(non_unknown("Unknown"), None);
        assert_eq!(non_unknown(" x86_64 "), Some("x86_64".to_string()));
        assert_eq!(
            first_non_empty_line("\n\nvalue\n"),
            Some("value".to_string())
        );
        assert_eq!(first_non_empty_line("   \n"), None);
    }
}
