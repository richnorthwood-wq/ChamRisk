use crate::events::{OpsEvent as StructuredOpsEvent, OpsEventKind};
use crate::report_store::{PackageEvidenceRow, ReportStore};
use crate::runner::{
    normalize_zypper_log_line, run_streaming, run_streaming_blocking_with_input,
    run_streaming_with_input, zypp_lock, LogStream, OperationKind, OpsEvent, RunSummary, Runner,
};
use crate::system_workbook::{collect_system_workbook, write_system_workbook};
use chamrisk_core::models::{
    BtrfsSnapshotRow, CommandResult, PackageAction, PackageChange, ProcessRun, ReconcileResult,
    UpdateAction, UpdatePlan,
};
use chamrisk_core::risk::{assess_package_risk, report_risk_label};
use chamrisk_core::services::reconciler::reconcile_triage_against_run;
use chamrisk_core::zypper::{
    build_preview_dup_xml_args, parse_package_locks, parse_packages_xml, parse_preview_xml,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct UpdateRunSelection {
    pub snapshot_before_update: bool,
    pub zypper_dup: bool,
    pub prefer_packman: bool,
    pub flatpak: bool,
    pub journal_vacuum: bool,
    pub mode: String,
    pub risk_filter: String,
    pub repos: Vec<String>,
}

impl UpdateRunSelection {
    pub fn from_flags(
        snapshot_before_update: bool,
        zypper_dup: bool,
        prefer_packman: bool,
        flatpak: bool,
        journal_vacuum: bool,
    ) -> Self {
        Self {
            snapshot_before_update,
            zypper_dup,
            prefer_packman,
            flatpak,
            journal_vacuum,
            mode: "apply".to_string(),
            risk_filter: "all".to_string(),
            repos: Vec::new(),
        }
    }

    pub fn preview() -> Self {
        Self {
            snapshot_before_update: false,
            zypper_dup: true,
            prefer_packman: false,
            flatpak: false,
            journal_vacuum: false,
            mode: "preview".to_string(),
            risk_filter: "all".to_string(),
            repos: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct PersistedRun {
    store: ReportStore,
    run_id: String,
}

#[derive(Debug)]
struct RunFinalizeGuard {
    run: Option<PersistedRun>,
    finished: bool,
}

impl RunFinalizeGuard {
    fn new(run: Option<PersistedRun>) -> Self {
        Self {
            run,
            finished: false,
        }
    }

    fn as_mut(&mut self) -> Option<&mut PersistedRun> {
        self.run.as_mut()
    }

    fn finish(
        &mut self,
        verdict: &str,
        attempted: i64,
        installed: i64,
        failed: i64,
        unaccounted: i64,
    ) {
        if self.finished {
            return;
        }

        if let Some(run) = self.run.as_mut() {
            let _ = run.store.finish_run(
                &run.run_id,
                now_ms(),
                verdict,
                attempted,
                installed,
                failed,
                unaccounted,
            );
        }

        self.finished = true;
    }
}

impl Drop for RunFinalizeGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }

        if let Some(run) = self.run.as_mut() {
            let _ = run
                .store
                .finish_run(&run.run_id, now_ms(), "FAIL", 0, 0, 0, 0);
        }
        self.finished = true;
    }
}

#[derive(Debug, Default)]
struct RunState {
    master_run_id: Option<String>,
    verdict_override: Option<String>,
    had_blocked_task: bool,
    had_skipped_task: bool,
    zypper_requested: bool,
    zypper_plan: Option<UpdatePlan>,
    zypper_apply_exit_code: Option<i32>,
    apply_active: bool,
    flatpak_active: bool,
    flatpak_exit_code: Option<i32>,
    flatpak_updated_apps: BTreeSet<String>,
    summary_emitted: bool,
    had_error: bool,
}

fn structured(kind: OpsEventKind) -> OpsEvent {
    OpsEvent::Structured(StructuredOpsEvent::from_kind(kind))
}

fn run_capture(cmd: &str, args: &[&str]) -> Result<(i32, String, String), String> {
    let output = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("Failed to execute {cmd}: {e}"))?;

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((code, stdout, stderr))
}

fn run_capture_with_sudo(
    sudo_password: Option<String>,
    cmd: &str,
    args: &[&str],
) -> Result<(i32, String, String), String> {
    if let Some(pw) = sudo_password {
        // sudo -S reads password from stdin
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
            .map_err(|e| format!("Failed to spawn sudo {cmd}: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(format!("{pw}\n").as_bytes())
                .map_err(|e| format!("Failed writing sudo password: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed waiting for sudo {cmd}: {e}"))?;

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok((code, stdout, stderr))
    } else {
        run_capture(cmd, args)
    }
}

pub fn validate_sudo_password(password: &str) -> Result<(), String> {
    let mut child = Command::new("sudo")
        .args(["-S", "-k", "-p", "", "-v"])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("Failed to start sudo validation: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{password}\n").as_bytes())
            .map_err(|err| format!("Failed writing sudo password: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("Failed waiting for sudo validation: {err}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let _stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err("Authentication failed. Please try again.".to_string())
    }
}

pub fn preview_dup(tx: Sender<OpsEvent>, sudo_password: Option<String>) {
    preview_dup_with_persisted(tx, sudo_password, None);
}

fn preview_dup_with_persisted(
    tx: Sender<OpsEvent>,
    sudo_password: Option<String>,
    persisted_run: Option<PersistedRun>,
) {
    match zypp_lock_check(Path::new("/var/run/zypp.pid"), Path::new("/proc")) {
        ZyppLockCheck::Blocked(msg) => {
            if let Some(run) = persisted_run {
                let _ = run
                    .store
                    .finish_run(&run.run_id, now_ms(), "FAIL", 0, 0, 0, 0);
            }
            let _ = tx.send(OpsEvent::Error(msg));
            return;
        }

        ZyppLockCheck::Clear => {}
    }
    emit_update_phase(&tx, "Preview");
    let _ = tx.send(OpsEvent::Progress("Running zypper preview".to_string()));
    let args = build_preview_dup_xml_args(true);
    run_preview_plan(tx, args, sudo_password, false, persisted_run);
}

pub fn list_available_packages(
    runner: &Runner,
) -> Result<Vec<chamrisk_core::models::PackageRow>, String> {
    let primary_args = [
        "--non-interactive",
        "--xmlout",
        "search",
        "-s",
        "--details",
        "-t",
        "package",
        "",
    ];
    let fallback_args = [
        "--non-interactive",
        "--xmlout",
        "search",
        "-s",
        "-t",
        "package",
        "",
    ];

    let mut result = runner.run("zypper", &primary_args)?;
    if result.exit_code != 0 {
        let stderr_lc = result.stderr.to_ascii_lowercase();
        if stderr_lc.contains("unknown option") && stderr_lc.contains("details") {
            result = runner.run("zypper", &fallback_args)?;
        }
    }
    if result.exit_code != 0 {
        let stderr = result.stderr.trim();
        let msg = if stderr.is_empty() {
            format!("zypper failed with exit code {}", result.exit_code)
        } else {
            format!("zypper failed: {}", stderr)
        };
        return Err(msg);
    }
    parse_packages_xml(&result.stdout).map_err(|err| format!("packages parse failed: {err}"))
}

pub fn list_package_locks(tx: Sender<OpsEvent>, runner: &Runner) {
    let cmd = vec!["--non-interactive", "locks"];
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: "INFO: Running zypper locks".to_string(),
    });
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: "$ zypper --non-interactive locks".to_string(),
    });

    let result = runner.run("zypper", &cmd);
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            let message = format!("PKG_LOCKS: {err}");
            let _ = tx.send(OpsEvent::Log {
                stream: LogStream::PackageManager,
                line: format!("ERROR: {message}"),
            });
            let _ = tx.send(OpsEvent::Error(message.clone()));
            let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
                action: "list".to_string(),
                name: String::new(),
                success: false,
                message,
            });
            return;
        }
    };

    emit_package_lock_output_logs(&tx, &result.stdout, &result.stderr);

    if result.exit_code != 0 {
        let message = command_failure_message("PKG_LOCKS", "zypper locks", &result);
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("ERROR: {message}"),
        });
        let _ = tx.send(OpsEvent::Error(message.clone()));
        let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
            action: "list".to_string(),
            name: String::new(),
            success: false,
            message,
        });
        let _ = tx.send(OpsEvent::CommandResult {
            operation: OperationKind::PackageManager,
            result,
        });
        return;
    }

    let (locks, fallback_rows) = parse_package_locks_defensive(&result.stdout);
    if fallback_rows > 0 {
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!(
                "WARN: Parsed package locks with {} fallback row(s); raw rows preserved",
                fallback_rows
            ),
        });
    }
    let _ = tx.send(OpsEvent::PackageLocks(locks.clone()));
    let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
        action: "list".to_string(),
        name: String::new(),
        success: true,
        message: format!("Loaded {} package lock(s)", locks.len()),
    });
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: format!("INFO: zypper locks completed with {} row(s)", locks.len()),
    });
    let _ = tx.send(OpsEvent::CommandResult {
        operation: OperationKind::PackageManager,
        result,
    });
}

pub fn add_package_lock(tx: Sender<OpsEvent>, package: &str, sudo_password: Option<String>) {
    let package = package.trim();
    if package.is_empty() {
        let message = "PKG_LOCK_ADD: package name is required".to_string();
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("ERROR: {message}"),
        });
        let _ = tx.send(OpsEvent::Error(message.clone()));
        let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
            action: "add".to_string(),
            name: String::new(),
            success: false,
            message,
        });
        return;
    }

    let args = vec!["--non-interactive", "addlock", package];
    run_package_lock_operation(
        tx,
        "add",
        package,
        &args,
        sudo_password,
        Some("package-name locks only"),
    );
}

pub fn remove_package_lock(tx: Sender<OpsEvent>, lock_ref: &str, sudo_password: Option<String>) {
    let lock_ref = lock_ref.trim();
    if lock_ref.is_empty() {
        let message = "PKG_LOCK_REMOVE: lock id or package name is required".to_string();
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("ERROR: {message}"),
        });
        let _ = tx.send(OpsEvent::Error(message.clone()));
        let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
            action: "remove".to_string(),
            name: String::new(),
            success: false,
            message,
        });
        return;
    }

    let args = vec!["--non-interactive", "removelock", lock_ref];
    run_package_lock_operation(tx, "remove", lock_ref, &args, sudo_password, None);
}

pub fn clean_package_locks(tx: Sender<OpsEvent>, sudo_password: Option<String>) {
    let args = vec!["--non-interactive", "cleanlocks"];
    run_package_lock_operation(
        tx,
        "clean",
        "useless",
        &args,
        sudo_password,
        Some("clean useless locks"),
    );
}

pub fn export_system_workbook(
    tx: Sender<OpsEvent>,
    output_path: PathBuf,
    sudo_password: Option<String>,
) {
    let _ = tx.send(OpsEvent::SystemWorkbookExportProgress(
        "Preparing system workbook export".to_string(),
    ));

    let workbook = match collect_system_workbook(sudo_password, |message| {
        let _ = tx.send(OpsEvent::SystemWorkbookExportProgress(message.to_string()));
    }) {
        Ok(workbook) => workbook,
        Err(err) => {
            let _ = tx.send(OpsEvent::SystemWorkbookExportFailed(err));
            return;
        }
    };

    let _ = tx.send(OpsEvent::SystemWorkbookExportProgress(
        "Writing workbook".to_string(),
    ));
    match write_system_workbook(&output_path, &workbook) {
        Ok(()) => {
            let _ = tx.send(OpsEvent::SystemWorkbookExportCompleted { path: output_path });
        }
        Err(err) => {
            let _ = tx.send(OpsEvent::SystemWorkbookExportFailed(err));
        }
    }
}

fn run_package_lock_operation(
    tx: Sender<OpsEvent>,
    action: &str,
    name: &str,
    args: &[&str],
    sudo_password: Option<String>,
    context_note: Option<&str>,
) {
    let (error_prefix, command_name) = match action {
        "add" => ("PKG_LOCK_ADD", "zypper addlock"),
        "remove" => ("PKG_LOCK_REMOVE", "zypper removelock"),
        "clean" => ("PKG_LOCK_CLEAN", "zypper cleanlocks"),
        _ => ("PKG_LOCK_OP", "zypper lock operation"),
    };

    if sudo_password.is_none() {
        let message = format!("{error_prefix}: sudo password required for lock operation");
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("ERROR: {message}"),
        });
        let _ = tx.send(OpsEvent::Error(message.clone()));
        let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
            action: action.to_string(),
            name: name.to_string(),
            success: false,
            message,
        });
        return;
    }

    let cmd_line = format!("$ sudo zypper {}", args.join(" "));
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: format!("INFO: Starting lock operation ({action}) for {name}"),
    });
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: cmd_line,
    });
    if let Some(note) = context_note {
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("INFO: {note}"),
        });
    }

    let result = run_capture_with_sudo(sudo_password, "zypper", args);
    let result = match result {
        Ok((exit_code, stdout, stderr)) => CommandResult {
            stdout,
            stderr,
            exit_code,
        },
        Err(err) => {
            let message = format!("{error_prefix}: {err}");
            let _ = tx.send(OpsEvent::Log {
                stream: LogStream::PackageManager,
                line: format!("ERROR: {message}"),
            });
            let _ = tx.send(OpsEvent::Error(message.clone()));
            let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
                action: action.to_string(),
                name: name.to_string(),
                success: false,
                message,
            });
            return;
        }
    };

    emit_package_lock_output_logs(&tx, &result.stdout, &result.stderr);

    if result.exit_code != 0 {
        let message = command_failure_message(error_prefix, command_name, &result);
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: format!("ERROR: {message}"),
        });
        let _ = tx.send(OpsEvent::Error(message.clone()));
        let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
            action: action.to_string(),
            name: name.to_string(),
            success: false,
            message,
        });
        let _ = tx.send(OpsEvent::CommandResult {
            operation: OperationKind::PackageManager,
            result,
        });
        return;
    }

    let success_message = format!("Lock operation '{action}' completed for {name}");
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: format!("INFO: {success_message}"),
    });
    let _ = tx.send(OpsEvent::PackageLockOperationCompleted {
        action: action.to_string(),
        name: name.to_string(),
        success: true,
        message: success_message,
    });
    let _ = tx.send(OpsEvent::CommandResult {
        operation: OperationKind::PackageManager,
        result,
    });

    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: format!("INFO: Refreshing package locks after '{action}'"),
    });
    let runner = Runner::new();
    list_package_locks(tx, &runner);
}

fn parse_package_locks_defensive(output: &str) -> (Vec<chamrisk_core::models::PackageLock>, usize) {
    let mut locks = parse_package_locks(output);
    let mut fallback_rows = 0usize;
    let mut seen_raw: HashSet<String> = locks.iter().map(|lock| lock.raw_entry.clone()).collect();

    for line in output.lines() {
        let raw = line.trim();
        if raw.is_empty() || !raw.contains('|') {
            continue;
        }
        if is_locks_header_or_divider(raw) || seen_raw.contains(raw) {
            continue;
        }
        // Preserve unparsed rows for troubleshooting instead of dropping them.
        let name = raw
            .split('|')
            .map(str::trim)
            .find(|cell| !cell.is_empty() && !cell.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(raw)
            .to_string();
        locks.push(chamrisk_core::models::PackageLock {
            lock_id: None,
            name,
            match_type: None,
            repository: None,
            comment: None,
            raw_entry: raw.to_string(),
        });
        seen_raw.insert(raw.to_string());
        fallback_rows += 1;
    }

    if locks.is_empty() && !output.trim().is_empty() {
        for raw in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if raw.starts_with("Loading repository data")
                || raw.starts_with("Reading installed packages")
            {
                continue;
            }
            locks.push(chamrisk_core::models::PackageLock {
                lock_id: None,
                name: raw.to_string(),
                match_type: None,
                repository: None,
                comment: None,
                raw_entry: raw.to_string(),
            });
            fallback_rows += 1;
        }
    }

    (locks, fallback_rows)
}

fn is_locks_header_or_divider(line: &str) -> bool {
    let normalized = line
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }
    if normalized
        .chars()
        .all(|ch| ch == '|' || ch == '-' || ch == '+' || ch == '#')
    {
        return true;
    }
    normalized.contains("name") && (normalized.contains("type") || normalized.contains("match"))
}

fn emit_package_lock_output_logs(tx: &Sender<OpsEvent>, stdout: &str, stderr: &str) {
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(normalized) = normalize_zypper_log_line(line) {
            if is_low_value_lock_log_line(&normalized) {
                continue;
            }
            let _ = tx.send(OpsEvent::Log {
                stream: LogStream::PackageManager,
                line: normalized,
            });
        }
    }
}

fn is_low_value_lock_log_line(line: &str) -> bool {
    let normalized = line.to_ascii_lowercase();
    if normalized == "info: loading repository data..."
        || normalized == "info: reading installed packages..."
    {
        return true;
    }
    // Skip table rows from `zypper locks`; list completion is logged separately.
    normalized.starts_with("info: |")
}

fn command_failure_message(prefix: &str, command: &str, result: &CommandResult) -> String {
    let stderr = result.stderr.trim();
    if stderr.is_empty() {
        format!(
            "{prefix}: {command} failed with exit code {}",
            result.exit_code
        )
    } else {
        format!(
            "{prefix}: {command} failed with exit code {}: {}",
            result.exit_code, stderr
        )
    }
}

pub fn search_packages(
    runner: &Runner,
    term: &str,
    installed_only: bool,
) -> Result<Vec<chamrisk_core::models::PackageRow>, String> {
    let mut args = vec![
        "--non-interactive".to_string(),
        "--xmlout".to_string(),
        "search".to_string(),
        "-s".to_string(),
        "--details".to_string(),
        "-t".to_string(),
        "package".to_string(),
    ];
    if installed_only {
        args.push("--installed-only".to_string());
    }
    args.push(term.to_string());

    let mut result = {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        runner.run("zypper", &refs)?
    };

    if result.exit_code != 0 {
        let stderr_lc = result.stderr.to_ascii_lowercase();
        if stderr_lc.contains("unknown option") && stderr_lc.contains("details") {
            let mut fallback_args = vec![
                "--non-interactive".to_string(),
                "--xmlout".to_string(),
                "search".to_string(),
                "-s".to_string(),
                "-t".to_string(),
                "package".to_string(),
            ];
            if installed_only {
                fallback_args.push("--installed-only".to_string());
            }
            fallback_args.push(term.to_string());
            let refs: Vec<&str> = fallback_args.iter().map(|s| s.as_str()).collect();
            result = runner.run("zypper", &refs)?;
        }
    }

    if installed_only && result.exit_code != 0 {
        let stderr_lc = result.stderr.to_ascii_lowercase();
        if stderr_lc.contains("unknown option") && stderr_lc.contains("installed-only") {
            let fallback_args = vec![
                "--non-interactive".to_string(),
                "--xmlout".to_string(),
                "search".to_string(),
                "-s".to_string(),
                "-t".to_string(),
                "package".to_string(),
                term.to_string(),
            ];
            let refs: Vec<&str> = fallback_args.iter().map(|s| s.as_str()).collect();
            result = runner.run("zypper", &refs)?;
        }
    }

    if result.exit_code != 0 {
        let stderr = result.stderr.trim();
        let msg = if stderr.is_empty() {
            format!("zypper failed (exit code {})", result.exit_code)
        } else {
            format!("zypper failed (exit code {}): {}", result.exit_code, stderr)
        };
        return Err(msg);
    }

    parse_packages_xml(&result.stdout).map_err(|err| format!("packages parse failed: {err}"))
}

fn get_installed_versions(runner: &Runner) -> Result<HashMap<String, String>, String> {
    let result = runner.run("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])?;
    if result.exit_code != 0 {
        let stderr = result.stderr.trim();
        let msg = if stderr.is_empty() {
            format!("rpm failed with exit code {}", result.exit_code)
        } else {
            format!("rpm failed: {}", stderr)
        };
        return Err(msg);
    }

    let mut map = HashMap::new();
    for line in result.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let name = parts.next().unwrap_or("").trim();
        let version = parts.next().unwrap_or("").trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        map.insert(name.to_string(), version.to_string());
    }

    Ok(map)
}

pub fn build_package_index(
    runner: &Runner,
) -> Result<Vec<chamrisk_core::models::PackageRow>, String> {
    let mut rows = list_available_packages(runner)?;
    let installed = get_installed_versions(runner)?;
    for row in &mut rows {
        if let Some(version) = installed.get(&row.name) {
            row.installed_version = Some(version.to_string());
        }
    }
    Ok(rows)
}

pub fn preview_transaction(
    runner: &Runner,
    marks: &std::collections::HashMap<String, chamrisk_core::models::PackageAction>,
) -> Result<chamrisk_core::models::UpdatePlan, String> {
    let mut installs: Vec<String> = Vec::new();
    let mut removes: Vec<String> = Vec::new();

    for (name, action) in marks {
        match action {
            PackageAction::Install | PackageAction::Upgrade => installs.push(name.clone()),
            PackageAction::Remove => removes.push(name.clone()),
        }
    }

    if installs.is_empty() && removes.is_empty() {
        return Err("No packages marked".to_string());
    }

    let mut all_changes = Vec::new();
    let mut command_vec: Vec<String> = Vec::new();
    let mut stdout_all = String::new();
    let mut stderr_all = String::new();
    let mut exit_code_all = 0;

    // helper: run a single zypper dry-run command and merge results
    let mut run_group = |subcommand: &str, pkgs: &[String]| -> Result<(), String> {
        if pkgs.is_empty() {
            return Ok(());
        }

        // Keep args minimal and portable across zypper variants:
        // --non-interactive + --xmlout + <subcommand> + --dry-run + pkgs...
        let mut args: Vec<String> = vec![
            "--non-interactive".to_string(),
            "--xmlout".to_string(),
            subcommand.to_string(),
            "--dry-run".to_string(),
        ];
        args.extend(pkgs.iter().cloned());

        // Capture the "command" for display/debug in the plan
        if command_vec.is_empty() {
            command_vec = std::iter::once("zypper".to_string())
                .chain(args.iter().cloned())
                .collect();
        } else {
            command_vec.push(";".to_string());
            command_vec.extend(std::iter::once("zypper".to_string()).chain(args.iter().cloned()));
        }

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = runner.run("zypper", &args_refs)?;

        stdout_all.push_str(&result.stdout);
        if !stdout_all.ends_with('\n') {
            stdout_all.push('\n');
        }

        if !result.stderr.is_empty() {
            stderr_all.push_str(&result.stderr);
            if !stderr_all.ends_with('\n') {
                stderr_all.push('\n');
            }
        }

        if result.exit_code != 0 && exit_code_all == 0 {
            exit_code_all = result.exit_code;
        }

        // Parse the XML preview into changes
        let mut changes = parse_preview_changes_or_noop(&result.stdout, &result.stderr)
            .map_err(|err| format!("preview parse failed: {err}"))?;
        all_changes.append(&mut changes);

        Ok(())
    };

    // Preview installs/upgrades first, then removals.
    run_group("install", &installs)?;
    run_group("remove", &removes)?;

    let result = CommandResult {
        stdout: stdout_all,
        stderr: stderr_all,
        exit_code: exit_code_all,
    };

    Ok(UpdatePlan {
        changes: all_changes,
        command: command_vec,
        result,
    })
}
pub fn apply_transaction(
    tx: Sender<OpsEvent>,
    marks: &std::collections::HashMap<String, chamrisk_core::models::PackageAction>,
    dry_run: bool,
    sudo_password: Option<String>,
) {
    if marks.is_empty() {
        let _ = tx.send(OpsEvent::Error("PKG_APPLY: no packages marked".to_string()));
        return;
    }

    // Transactions require root. For dry-run, zypper can still require root depending on system
    // config; keep it simple and require sudo either way.
    let Some(password) = sudo_password else {
        let _ = tx.send(OpsEvent::Error(
            "PKG_APPLY: sudo password required for install/remove".to_string(),
        ));
        return;
    };

    let mut installs: Vec<String> = Vec::new();
    let mut removes: Vec<String> = Vec::new();
    for (name, action) in marks {
        match action {
            PackageAction::Install | PackageAction::Upgrade => installs.push(name.clone()),
            PackageAction::Remove => removes.push(name.clone()),
        }
    }

    let run_group = |subcommand: &str, pkgs: &[String]| -> Result<CommandResult, String> {
        if pkgs.is_empty() {
            return Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            });
        }

        // Build a sudo -> zypper invocation.
        // Keep options portable across zypper variants.
        let mut args: Vec<String> = Vec::new();

        // sudo reads password from stdin
        args.push("-S".to_string());
        args.push("-p".to_string());
        args.push("".to_string());

        // command
        args.push("zypper".to_string());

        // global options first
        args.push("--xmlout".to_string());
        args.push("--non-interactive".to_string());

        // subcommand
        args.push(subcommand.to_string());

        // IMPORTANT: -y is NOT a global option. It must come immediately after the subcommand.
        if !dry_run {
            args.push("-y".to_string());
        }

        if dry_run {
            args.push("--dry-run".to_string());
        }

        // packages last
        args.extend(pkgs.iter().cloned());

        // Log exactly what we run (minus sudo's -S/-p plumbing)
        let printable = format!(
            "$ sudo zypper --xmlout --non-interactive {}{}{}{}",
            subcommand,
            if !dry_run { " -y" } else { "" },
            if dry_run { " --dry-run" } else { "" },
            format!(" {}", pkgs.join(" "))
        );
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::PackageManager,
            line: printable,
        });

        let _guard = zypp_lock().lock().unwrap();

        let mut child = Command::new("sudo")
            .args(&args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("spawn failed: {err}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{password}\n").as_bytes());
        }

        let output = child
            .wait_with_output()
            .map_err(|err| format!("wait failed: {err}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        emit_package_manager_transaction_logs(&tx, subcommand, pkgs, &stdout, &stderr, exit_code);

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
        })
    };

    // Install/upgrade first, then removals.
    let mut last = CommandResult {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };

    for (cmd, pkgs) in [("install", installs), ("remove", removes)] {
        match run_group(cmd, &pkgs) {
            Ok(result) => {
                last = result;
                if last.exit_code != 0 {
                    let _ = tx.send(OpsEvent::Error(format!(
                        "PKG_APPLY: zypper {} failed (exit code {})",
                        cmd, last.exit_code
                    )));
                    let _ = tx.send(OpsEvent::CommandResult {
                        operation: OperationKind::PackageManager,
                        result: last,
                    });
                    return;
                }
            }
            Err(err) => {
                let _ = tx.send(OpsEvent::Error(format!("PKG_APPLY: {err}")));
                return;
            }
        }
    }

    let _ = tx.send(OpsEvent::CommandResult {
        operation: OperationKind::PackageManager,
        result: last,
    });
}

fn emit_package_manager_transaction_logs(
    tx: &Sender<OpsEvent>,
    subcommand: &str,
    pkgs: &[String],
    stdout: &str,
    stderr: &str,
    exit_code: i32,
) {
    let mut emitted = HashSet::new();
    let mut success_pkgs = HashSet::new();
    let mut failed_pkgs = HashSet::new();

    if subcommand == "install" {
        for pkg in pkgs {
            emit_package_manager_log_once(tx, &mut emitted, format!("INFO: Installing: {pkg}"));
        }
    } else if subcommand == "remove" {
        for pkg in pkgs {
            emit_package_manager_log_once(tx, &mut emitted, format!("INFO: Removing: {pkg}"));
        }
    }

    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(normalized) = normalize_zypper_log_line(line) {
            track_package_outcome(&normalized, &mut success_pkgs, &mut failed_pkgs);
            emit_package_manager_log_once(tx, &mut emitted, normalized);
        }

        if let Some(event_line) = parse_package_transaction_xml_event(subcommand, line) {
            track_package_outcome(&event_line, &mut success_pkgs, &mut failed_pkgs);
            emit_package_manager_log_once(tx, &mut emitted, event_line);
        }
    }

    if subcommand == "install" {
        if exit_code == 0 {
            if pkgs.is_empty() {
                return;
            }
            for pkg in pkgs {
                if !success_pkgs.contains(pkg) {
                    emit_package_manager_log_once(
                        tx,
                        &mut emitted,
                        format!("INFO: Installed successfully: {pkg}"),
                    );
                }
            }
        } else {
            if !failed_pkgs.is_empty() {
                return;
            }
            for pkg in pkgs {
                emit_package_manager_log_once(
                    tx,
                    &mut emitted,
                    format!("ERROR: Install failed: {pkg}"),
                );
            }
        }
    } else if subcommand == "remove" {
        if exit_code == 0 {
            if pkgs.is_empty() {
                return;
            }
            for pkg in pkgs {
                if !success_pkgs.contains(pkg) {
                    emit_package_manager_log_once(
                        tx,
                        &mut emitted,
                        format!("INFO: Removed successfully: {pkg}"),
                    );
                }
            }
        } else {
            if !failed_pkgs.is_empty() {
                return;
            }
            for pkg in pkgs {
                emit_package_manager_log_once(
                    tx,
                    &mut emitted,
                    format!("ERROR: Remove failed: {pkg}"),
                );
            }
        }
    }
}

fn emit_package_manager_log_once(
    tx: &Sender<OpsEvent>,
    emitted: &mut HashSet<String>,
    line: String,
) {
    if !emitted.insert(line.clone()) {
        return;
    }
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line,
    });
}

fn track_package_outcome(
    line: &str,
    success_pkgs: &mut HashSet<String>,
    failed_pkgs: &mut HashSet<String>,
) {
    if let Some(pkg) = parse_package_from_prefixed_line(line, "INFO: Installed successfully:") {
        success_pkgs.insert(pkg);
        return;
    }
    if let Some(pkg) = parse_package_from_prefixed_line(line, "INFO: Removed successfully:") {
        success_pkgs.insert(pkg);
        return;
    }

    if let Some(pkg) = parse_package_from_prefixed_line(line, "ERROR: Install failed:") {
        failed_pkgs.insert(pkg);
        return;
    }
    if let Some(pkg) = parse_package_from_prefixed_line(line, "ERROR: Remove failed:") {
        failed_pkgs.insert(pkg);
    }
}

fn parse_package_from_prefixed_line(line: &str, prefix: &str) -> Option<String> {
    let rest = line.strip_prefix(prefix)?.trim();
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

fn parse_package_transaction_xml_event(subcommand: &str, line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.starts_with('<') {
        return None;
    }

    if trimmed.contains("<progress") {
        let id = extract_xml_attr(trimmed, "id")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let pkg = extract_xml_attr(trimmed, "name")
            .or_else(|| extract_xml_attr(trimmed, "value"))
            .map(|value| value.trim().trim_matches('"').to_string())
            .filter(|value| !value.is_empty())?;

        if id.contains("install") {
            return Some(format!("INFO: Installing: {pkg}"));
        }
        if id.contains("remove") || id.contains("delete") || id.contains("erase") {
            return Some(format!("INFO: Removing: {pkg}"));
        }
    }

    if trimmed.contains("<solvable") {
        let status = extract_xml_attr(trimmed, "status")?.to_ascii_lowercase();
        let name = extract_xml_attr(trimmed, "name")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;

        return match status.as_str() {
            "installed" => Some(format!("INFO: Installed successfully: {name}")),
            "removed" | "deleted" | "erased" => Some(format!("INFO: Removed successfully: {name}")),
            "failed" | "error" | "broken" => Some(format!(
                "ERROR: {} failed: {name}",
                if subcommand == "remove" {
                    "Remove"
                } else {
                    "Install"
                }
            )),
            _ => None,
        };
    }

    None
}

fn extract_xml_attr(line: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=\"");
    let start = line.find(&marker)? + marker.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}

fn run_preview_plan(
    tx: Sender<OpsEvent>,
    args: Vec<String>,
    sudo_password: Option<String>,
    emit_preview_logs: bool,
    mut persisted_run: Option<PersistedRun>,
) {
    let (cmd, cmd_args, stdin_input, command_vec) = if let Some(password) = sudo_password {
        let mut sudo_args = vec![
            "-S".to_string(),
            "-p".to_string(),
            "".to_string(),
            "zypper".to_string(),
        ];
        sudo_args.extend(args.clone());
        let mut command_vec = vec!["sudo".to_string()];
        command_vec.extend(sudo_args.clone());
        (
            "sudo".to_string(),
            sudo_args,
            Some(format!("{password}\n")),
            command_vec,
        )
    } else {
        let mut command_vec = vec!["zypper".to_string()];
        command_vec.extend(args.clone());
        ("zypper".to_string(), args, None, command_vec)
    };

    let _guard = zypp_lock().lock().unwrap();
    let mut child = match Command::new(&cmd)
        .args(&cmd_args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            if let Some(run) = persisted_run.take() {
                let _ = run
                    .store
                    .finish_run(&run.run_id, now_ms(), "FAIL", 0, 0, 0, 0);
            }
            let _ = tx.send(OpsEvent::Error(format!("spawn failed: {err}")));
            return;
        }
    };

    if let Some(input) = stdin_input {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.as_bytes());
        }
    }

    let out = child.stdout.take();
    let err = child.stderr.take();

    let stdout_handle = out.map(|stdout| {
        let tx2 = tx.clone();
        thread::spawn(move || {
            let mut local_raw = String::new();
            for line in BufReader::new(stdout).lines().flatten() {
                local_raw.push_str(&line);
                local_raw.push('\n');
                if emit_preview_logs {
                    if let Some(normalized) = normalize_preview_log_line_for_ui(&line) {
                        let _ = tx2.send(OpsEvent::Log {
                            stream: LogStream::Updates,
                            line: normalized,
                        });
                    }
                }
            }
            local_raw
        })
    });

    let stderr_handle = err.map(|stderr| {
        let tx2 = tx.clone();
        thread::spawn(move || {
            let mut local_raw = String::new();
            for line in BufReader::new(stderr).lines().flatten() {
                local_raw.push_str(&line);
                local_raw.push('\n');
                if emit_preview_logs {
                    if let Some(normalized) = normalize_preview_log_line_for_ui(&line) {
                        let _ = tx2.send(OpsEvent::Log {
                            stream: LogStream::Updates,
                            line: normalized,
                        });
                    }
                }
            }
            local_raw
        })
    });

    let status = match child.wait() {
        Ok(status) => status,
        Err(err) => {
            if let Some(run) = persisted_run.take() {
                let _ = run
                    .store
                    .finish_run(&run.run_id, now_ms(), "FAIL", 0, 0, 0, 0);
            }
            let _ = tx.send(OpsEvent::Error(format!("wait failed: {err}")));
            return;
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let result = CommandResult {
        stdout: stdout.clone(),
        stderr,
        exit_code: status.code().unwrap_or(-1),
    };

    match parse_preview_changes_or_noop(&stdout, &result.stderr) {
        Ok(changes) => {
            let package_count = changes.len();
            let plan = UpdatePlan {
                changes,
                command: command_vec,
                result,
            };
            let preview_result = structured(OpsEventKind::PreviewResult {
                packages: package_count,
            });
            if let Some(run) = persisted_run.as_mut() {
                persist_event(Some(run), &preview_result);
                persist_event(Some(run), &OpsEvent::UpdatePlan(plan.clone()));
                let package_rows = package_evidence_rows_for_plan(&run.run_id, &plan);
                let _ = run.store.replace_packages(&run.run_id, &package_rows);
            }
            let _ = tx.send(preview_result);
            let _ = tx.send(OpsEvent::UpdatePlan(plan));
        }
        Err(err) => {
            if let Some(run) = persisted_run.take() {
                let _ = run
                    .store
                    .finish_run(&run.run_id, now_ms(), "FAIL", 0, 0, 0, 0);
            }
            let _ = tx.send(OpsEvent::Error(format!("preview parse failed: {err}")));
            let _ = tx.send(OpsEvent::CommandResult {
                operation: OperationKind::UpdatesZypperPreview,
                result,
            });
        }
    }
    emit_update_phase(&tx, "Idle");
}

fn normalize_preview_log_line_for_ui(line: &str) -> Option<String> {
    let normalized = normalize_zypper_log_line(line)?;
    if normalized.starts_with("WARN:") || normalized.starts_with("ERROR:") {
        return Some(normalized);
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("warning:") || lower.starts_with("warn:") {
        let body = trimmed
            .trim_start_matches("warning:")
            .trim_start_matches("Warning:")
            .trim_start_matches("warn:")
            .trim_start_matches("Warn:")
            .trim();
        return Some(format!("WARN: {body}"));
    }
    if lower.starts_with("error:")
        || lower.starts_with("failed:")
        || lower.contains("permission denied")
        || lower.contains("command not found")
        || lower.contains("not found")
    {
        let body = trimmed
            .trim_start_matches("error:")
            .trim_start_matches("Error:")
            .trim();
        return Some(format!("ERROR: {body}"));
    }

    None
}

fn parse_preview_changes_or_noop(stdout: &str, stderr: &str) -> Result<Vec<PackageChange>, String> {
    match parse_preview_xml(stdout) {
        Ok(changes) if !changes.is_empty() => Ok(changes),
        Ok(changes) if preview_output_indicates_noop(stdout, stderr) => Ok(changes),
        Ok(_) => {
            Err("preview output contained no actionable changes and no no-op marker".to_string())
        }
        Err(err) if preview_output_indicates_noop(stdout, stderr) => Ok(Vec::new()),
        Err(err) => Err(err.to_string()),
    }
}

fn preview_output_indicates_noop(stdout: &str, stderr: &str) -> bool {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    combined.contains("nothing to do")
        || combined.contains("up to date")
        || combined.contains("no updates are available")
}

pub fn btrfs_manual_snapshot(tx: Sender<OpsEvent>, sudo_password: Option<String>) {
    let _ = tx.send(OpsEvent::Progress(
        "Please wait: creating manual snapshot".into(),
    ));
    run_privileged(
        "snapper",
        &["create", "-d", "manual snapshot"],
        LogStream::Btrfs,
        tx,
        sudo_password,
    );
}

pub fn btrfs_scrub(tx: Sender<OpsEvent>, sudo_password: Option<String>) {
    let _ = tx.send(OpsEvent::Progress(
        "Please wait: running btrfs scrub".into(),
    ));
    run_privileged(
        "btrfs",
        &["scrub", "start", "-B", "/"],
        LogStream::Btrfs,
        tx,
        sudo_password,
    );
}

pub fn btrfs_list_snapshots(tx: Sender<OpsEvent>, sudo_password: Option<String>) {
    let _ = tx.send(OpsEvent::Progress("Please wait: listing snapshots".into()));
    thread::spawn(move || {
        let result = if let Some(password) = sudo_password {
            run_capture_with_sudo(Some(password), "snapper", &["list"]).map(
                |(exit_code, stdout, stderr)| CommandResult {
                    stdout,
                    stderr,
                    exit_code,
                },
            )
        } else {
            run_capture("snapper", &["list"]).map(|(exit_code, stdout, stderr)| CommandResult {
                stdout,
                stderr,
                exit_code,
            })
        };

        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let _ = tx.send(OpsEvent::Error(err));
                return;
            }
        };

        if result.exit_code == 0 {
            match parse_snapper_list_output(&result.stdout) {
                Ok(rows) => {
                    let count = rows.len();
                    let _ = tx.send(OpsEvent::BtrfsSnapshots(rows));
                    let _ = tx.send(OpsEvent::Log {
                        stream: LogStream::Btrfs,
                        line: format!("INFO: Loaded {count} snapshot(s)"),
                    });
                }
                Err(err) => {
                    let _ = tx.send(OpsEvent::Error(format!("BTRFS_SNAPSHOT_LIST_PARSE: {err}")));
                    emit_btrfs_list_raw_logs(&tx, &result.stdout, &result.stderr);
                }
            }
        } else {
            let stderr = result.stderr.trim();
            let message = if stderr.is_empty() {
                format!("snapper list failed with exit code {}", result.exit_code)
            } else {
                format!(
                    "snapper list failed with exit code {}: {}",
                    result.exit_code, stderr
                )
            };
            let _ = tx.send(OpsEvent::Error(message));
            emit_btrfs_list_raw_logs(&tx, &result.stdout, &result.stderr);
        }

        let _ = tx.send(OpsEvent::CommandResult {
            operation: OperationKind::Btrfs,
            result,
        });
    });
}

pub fn run_updates_plan(
    tx: Sender<OpsEvent>,
    snapshot_before_update: bool,
    include_zypper_dup: bool,
    prefer_packman: bool,
    include_flatpak: bool,
    include_journal_vacuum: bool,
    sudo_password: Option<String>,
) {
    let selection = UpdateRunSelection::from_flags(
        snapshot_before_update,
        include_zypper_dup,
        prefer_packman,
        include_flatpak,
        include_journal_vacuum,
    );
    run_updates_plan_with_selection(tx, selection, sudo_password);
}

pub fn run_updates_plan_with_selection(
    tx: Sender<OpsEvent>,
    selection: UpdateRunSelection,
    sudo_password: Option<String>,
) {
    thread::spawn(move || {
        run_updates_plan_sync(tx, selection, sudo_password, None);
    });
}

pub fn run_updates_plan_with_selection_and_return_run_id(
    tx: Sender<OpsEvent>,
    selection: UpdateRunSelection,
    existing_run_id: Option<String>,
    sudo_password: Option<String>,
) -> Option<String> {
    let persisted_run =
        attach_or_create_persisted_run(None, existing_run_id.as_deref(), &selection)?;
    let run_id = persisted_run.run_id.clone();
    thread::spawn(move || {
        run_updates_plan_sync_with_persisted(tx, selection, sudo_password, Some(persisted_run));
    });
    Some(run_id)
}

pub fn run_updates_plan_sync(
    tx: Sender<OpsEvent>,
    selection: UpdateRunSelection,
    sudo_password: Option<String>,
    store: Option<ReportStore>,
) {
    let persisted_run = create_persisted_run(store, &selection);
    run_updates_plan_sync_with_persisted(tx, selection, sudo_password, persisted_run);
}

fn run_updates_plan_sync_with_persisted(
    tx: Sender<OpsEvent>,
    selection: UpdateRunSelection,
    sudo_password: Option<String>,
    persisted_run: Option<PersistedRun>,
) {
    let execution_plan = normalize_execution_selection(selection);
    let selection = execution_plan.effective_selection;
    let (internal_tx, internal_rx) = channel();
    let mut state = RunState {
        master_run_id: persisted_run.as_ref().map(|run| run.run_id.clone()),
        had_blocked_task: false,
        had_skipped_task: false,
        zypper_requested: selection.zypper_dup || selection.prefer_packman,
        ..RunState::default()
    };
    let mut finalize_guard = RunFinalizeGuard::new(persisted_run);

    let _ = tx.send(OpsEvent::Progress("Executing updates plan".into()));
    emit_event(
        &tx,
        &mut finalize_guard,
        &mut state,
        structured(OpsEventKind::RunStart),
    );

    for notice in execution_plan.notices {
        match notice.kind {
            ExecutionNoticeKind::Skipped => {
                state.had_skipped_task = true;
                emit_event(
                    &tx,
                    &mut finalize_guard,
                    &mut state,
                    OpsEvent::Progress(format!("Task skipped: {}", notice.message)),
                );
            }
            ExecutionNoticeKind::Blocked => {
                state.had_blocked_task = true;
                emit_event(
                    &tx,
                    &mut finalize_guard,
                    &mut state,
                    OpsEvent::Progress(format!("Task blocked: {}", notice.message)),
                );
            }
        }
    }

    if !selection_has_any_requested_task(&selection) {
        state.verdict_override = Some(if state.had_blocked_task {
            "BLOCKED".to_string()
        } else {
            "SKIP".to_string()
        });
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::Progress("No selected tasks to execute; run skipped.".to_string()),
        );
        finish_persisted_run(&mut finalize_guard, &state);
        emit_update_phase(&tx, "Idle");
        return;
    }

    if selection.snapshot_before_update {
        match create_pre_update_snapshot(internal_tx.clone(), sudo_password.clone()) {
            Ok(SnapshotAttempt::Completed) | Ok(SnapshotAttempt::Skipped) => {
                drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);
            }
            Err(err) => {
                emit_event(&tx, &mut finalize_guard, &mut state, OpsEvent::Error(err));
                drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);
                return;
            }
        }
    }

    if state.zypper_requested {
        emit_update_phase(&tx, "Preview");
        let _ = tx.send(OpsEvent::Progress("Running zypper preview".to_string()));
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            structured(OpsEventKind::PreviewStart),
        );
        let args = build_preview_dup_xml_args(true);
        run_preview_plan(internal_tx.clone(), args, sudo_password.clone(), true, None);
        drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);

        emit_update_phase(&tx, "Updating");
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            structured(OpsEventKind::ApplyStart),
        );
        run_zypper_dup_blocking(
            internal_tx.clone(),
            sudo_password.clone(),
            selection.prefer_packman,
        );
        drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);

        emit_summary_if_ready(&tx, &mut finalize_guard, &mut state);
        emit_update_phase(&tx, "Idle");
    }

    if selection.flatpak {
        state.flatpak_active = true;
        if let Some(pw) = sudo_password.as_deref() {
            run_streaming_blocking_with_input(
                "sudo",
                &[
                    "-S",
                    "-p",
                    "",
                    "env",
                    "XDG_DATA_DIRS=/var/lib/flatpak/exports/share:/usr/local/share:/usr/share",
                    "flatpak",
                    "update",
                    "-y",
                    "--system",
                ],
                LogStream::Updates,
                internal_tx.clone(),
                Some(format!("{pw}\n")),
            );
        } else {
            state.flatpak_active = false;
            emit_event(
                &tx,
                &mut finalize_guard,
                &mut state,
                OpsEvent::Error("Flatpak update blocked: requires sudo password".to_string()),
            );
            if !selection.journal_vacuum {
                finalize_guard.finish("FAIL", 0, 0, 0, 0);
                emit_update_phase(&tx, "Idle");
                return;
            }
        }
        drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);
        emit_summary_if_ready(&tx, &mut finalize_guard, &mut state);
    }

    if selection.journal_vacuum {
        if let Some(pw) = sudo_password.as_deref() {
            run_streaming_blocking_with_input(
                "sudo",
                &[
                    "-S",
                    "-p",
                    "",
                    "journalctl",
                    "--system",
                    "-q",
                    "--vacuum-time=14d",
                ],
                LogStream::Updates,
                internal_tx,
                Some(format!("{pw}\n")),
            );
        } else {
            emit_event(
                &tx,
                &mut finalize_guard,
                &mut state,
                OpsEvent::Error("Journal vacuum blocked: requires sudo password".to_string()),
            );
            finalize_guard.finish("FAIL", 0, 0, 0, 0);
            emit_update_phase(&tx, "Idle");
            return;
        }
        drain_events(&internal_rx, &tx, &mut finalize_guard, &mut state);
    }

    finish_persisted_run(&mut finalize_guard, &state);
    emit_update_phase(&tx, "Idle");
}

fn create_persisted_run(
    store: Option<ReportStore>,
    selection: &UpdateRunSelection,
) -> Option<PersistedRun> {
    let store = match store {
        Some(store) => store,
        None => match ReportStore::new() {
            Ok(store) => store,
            Err(err) => {
                eprintln!("ERROR: workflow.run.create run_id=- status=failed error={err}");
                return None;
            }
        },
    };
    let selection_json = match serde_json::to_string(selection) {
        Ok(selection_json) => selection_json,
        Err(err) => {
            eprintln!("ERROR: workflow.run.create run_id=- status=failed error={err}");
            return None;
        }
    };
    let app_version = env!("CARGO_PKG_VERSION");
    let run_id = match store.start_run(&selection_json, app_version) {
        Ok(run_id) => run_id,
        Err(err) => {
            eprintln!("ERROR: workflow.run.create run_id=- status=failed error={err}");
            return None;
        }
    };
    eprintln!("INFO: workflow.run.create run_id={run_id} status=created");
    Some(PersistedRun { store, run_id })
}

pub fn create_master_run_with_optional_plan(
    selection: &UpdateRunSelection,
    plan: Option<&UpdatePlan>,
) -> Option<String> {
    let store = ReportStore::new().ok()?;
    create_master_run_with_optional_plan_in_store(&store, selection, plan).ok()
}

pub fn create_master_run_with_optional_plan_in_store(
    store: &ReportStore,
    selection: &UpdateRunSelection,
    plan: Option<&UpdatePlan>,
) -> Result<String, String> {
    let selection_json = serde_json::to_string(selection)
        .map_err(|err| format!("failed to serialize run selection: {err}"))?;
    let run_id = store.start_run(&selection_json, env!("CARGO_PKG_VERSION"))?;
    if let Some(plan) = plan {
        persist_canonical_payload_snapshot(store, &run_id, plan)?;
    }
    eprintln!("INFO: workflow.master_run.create run_id={run_id} status=created");
    Ok(run_id)
}

fn attach_or_create_persisted_run(
    store: Option<ReportStore>,
    existing_run_id: Option<&str>,
    selection: &UpdateRunSelection,
) -> Option<PersistedRun> {
    let store = match store {
        Some(store) => store,
        None => match ReportStore::new() {
            Ok(store) => store,
            Err(err) => {
                eprintln!("ERROR: workflow.run.attach run_id=- status=failed error={err}");
                return None;
            }
        },
    };

    let selection_json = match serde_json::to_string(selection) {
        Ok(selection_json) => selection_json,
        Err(err) => {
            eprintln!("ERROR: workflow.run.attach run_id=- status=failed error={err}");
            return None;
        }
    };

    if let Some(run_id) = existing_run_id {
        match store.ai_persistence_eligibility(run_id) {
            Ok(crate::report_store::AiPersistenceEligibility::EligibleOpenRun) => {
                if let Err(err) = store.update_run_selection(run_id, &selection_json) {
                    eprintln!(
                        "ERROR: workflow.run.attach run_id={run_id} status=failed error={err}"
                    );
                    return None;
                }
                eprintln!("INFO: workflow.run.attach run_id={run_id} status=reused");
                return Some(PersistedRun {
                    store,
                    run_id: run_id.to_string(),
                });
            }
            Ok(_) => {
                eprintln!(
                    "WARN: workflow.run.attach run_id={run_id} status=unavailable reason=not_open"
                );
            }
            Err(err) => {
                eprintln!("ERROR: workflow.run.attach run_id={run_id} status=failed error={err}");
                return None;
            }
        }
    }

    let app_version = env!("CARGO_PKG_VERSION");
    let run_id = match store.start_run(&selection_json, app_version) {
        Ok(run_id) => run_id,
        Err(err) => {
            eprintln!("ERROR: workflow.run.create run_id=- status=failed error={err}");
            return None;
        }
    };
    eprintln!("INFO: workflow.run.create run_id={run_id} status=created");
    Some(PersistedRun { store, run_id })
}

pub fn persist_canonical_payload_snapshot(
    store: &ReportStore,
    run_id: &str,
    plan: &UpdatePlan,
) -> Result<(), String> {
    let preview_result = structured(OpsEventKind::PreviewResult {
        packages: plan.changes.len(),
    });
    persist_event_to_store(
        store,
        run_id,
        &preview_result,
        Some(package_evidence_rows_for_plan(run_id, plan)),
    )?;
    persist_event_to_store(store, run_id, &OpsEvent::UpdatePlan(plan.clone()), None)?;
    Ok(())
}

fn drain_events(
    internal_rx: &Receiver<OpsEvent>,
    tx: &Sender<OpsEvent>,
    finalize_guard: &mut RunFinalizeGuard,
    state: &mut RunState,
) {
    while let Ok(event) = internal_rx.try_recv() {
        emit_event(tx, finalize_guard, state, event);
    }
}

fn selection_has_any_requested_task(selection: &UpdateRunSelection) -> bool {
    selection.snapshot_before_update
        || selection.zypper_dup
        || selection.prefer_packman
        || selection.flatpak
        || selection.journal_vacuum
}

fn normalize_execution_selection(selection: UpdateRunSelection) -> ExecutionSelectionPlan {
    let mut effective_selection = selection;
    let mut notices = Vec::new();

    if effective_selection.prefer_packman && !effective_selection.zypper_dup {
        effective_selection.prefer_packman = false;
        notices.push(ExecutionNotice {
            kind: ExecutionNoticeKind::Blocked,
            message: "Prefer Packman requires zypper dup to be selected.".to_string(),
        });
    }

    if effective_selection.snapshot_before_update
        && !(effective_selection.zypper_dup || effective_selection.prefer_packman)
    {
        effective_selection.snapshot_before_update = false;
        notices.push(ExecutionNotice {
            kind: ExecutionNoticeKind::Skipped,
            message: "Snapshot before update requires a zypper dup task.".to_string(),
        });
    }

    ExecutionSelectionPlan {
        effective_selection,
        notices,
    }
}

enum SnapshotAttempt {
    Completed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutionNoticeKind {
    Skipped,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionNotice {
    kind: ExecutionNoticeKind,
    message: String,
}

#[derive(Debug, Clone)]
struct ExecutionSelectionPlan {
    effective_selection: UpdateRunSelection,
    notices: Vec<ExecutionNotice>,
}

fn create_pre_update_snapshot(
    tx: Sender<OpsEvent>,
    sudo_password: Option<String>,
) -> Result<SnapshotAttempt, String> {
    let fs_type = root_filesystem_type(sudo_password.clone())?;
    if snapshot_action_for_filesystem(&fs_type) == SnapshotAction::Skip {
        let _ = tx.send(structured(OpsEventKind::SnapshotFailure {
            reason: "filesystem not btrfs".to_string(),
        }));
        return Ok(SnapshotAttempt::Skipped);
    }

    let _ = tx.send(OpsEvent::Progress(
        "Please wait: creating pre-update snapshot".to_string(),
    ));
    let _ = tx.send(structured(OpsEventKind::SnapshotStart));

    let (exit_code, stdout, stderr) = run_capture_with_sudo(
        sudo_password.clone(),
        "snapper",
        &[
            "create",
            "--type",
            "pre",
            "--description",
            "chamrisk pre-update",
        ],
    )?;
    emit_btrfs_command_result(&tx, stdout, stderr, exit_code);
    if exit_code == 0 {
        let _ = tx.send(structured(OpsEventKind::SnapshotSuccess {
            snapshot_id: None,
        }));
        Ok(SnapshotAttempt::Completed)
    } else {
        let reason = "snapshot creation failed".to_string();
        let _ = tx.send(structured(OpsEventKind::SnapshotFailure {
            reason: reason.clone(),
        }));
        Err(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotAction {
    Attempt,
    Skip,
}

fn snapshot_action_for_filesystem(fs_type: &str) -> SnapshotAction {
    if fs_type.eq_ignore_ascii_case("btrfs") {
        SnapshotAction::Attempt
    } else {
        SnapshotAction::Skip
    }
}

fn root_filesystem_type(sudo_password: Option<String>) -> Result<String, String> {
    let (exit_code, stdout, stderr) =
        run_capture_with_sudo(sudo_password, "findmnt", &["-no", "FSTYPE", "/"])?;
    if exit_code != 0 {
        let stderr = stderr.trim();
        if stderr.is_empty() {
            return Err(format!(
                "Failed to detect root filesystem type (exit code {exit_code})."
            ));
        }
        return Err(format!("Failed to detect root filesystem type: {stderr}"));
    }

    let fs_type = stdout.trim().to_ascii_lowercase();
    if fs_type.is_empty() {
        Err("Failed to detect root filesystem type: empty output from findmnt.".to_string())
    } else {
        Ok(fs_type)
    }
}

fn emit_btrfs_command_result(
    tx: &Sender<OpsEvent>,
    stdout: String,
    stderr: String,
    exit_code: i32,
) {
    for line in stdout.lines() {
        let line = line.trim();
        if !line.is_empty() {
            let _ = tx.send(OpsEvent::Log {
                stream: LogStream::Btrfs,
                line: line.to_string(),
            });
        }
    }
    for line in stderr.lines() {
        let line = line.trim();
        if !line.is_empty() {
            let _ = tx.send(OpsEvent::Log {
                stream: LogStream::Btrfs,
                line: format!("ERR: {line}"),
            });
        }
    }
    let _ = tx.send(OpsEvent::CommandResult {
        operation: OperationKind::Btrfs,
        result: CommandResult {
            stdout,
            stderr,
            exit_code,
        },
    });
}

fn emit_event(
    tx: &Sender<OpsEvent>,
    finalize_guard: &mut RunFinalizeGuard,
    state: &mut RunState,
    event: OpsEvent,
) {
    let derived_events = derived_events_from_event(state, &event);
    track_event(state, &event);
    persist_event(finalize_guard.as_mut(), &event);
    let _ = tx.send(event);
    for derived in derived_events {
        emit_event(tx, finalize_guard, state, structured(derived));
    }
}

fn emit_update_phase(tx: &Sender<OpsEvent>, phase: &str) {
    let _ = tx.send(OpsEvent::UpdatePhase(phase.to_string()));
}

fn track_event(state: &mut RunState, event: &OpsEvent) {
    match event {
        OpsEvent::Structured(event) => match &event.kind {
            OpsEventKind::Error { .. } | OpsEventKind::SnapshotFailure { .. } => {
                state.had_error = true;
            }
            OpsEventKind::ApplyStart => {
                state.apply_active = true;
            }
            OpsEventKind::ApplyResult { .. } => {
                state.apply_active = false;
            }
            OpsEventKind::FlatpakUpdated { app_id } => {
                state.flatpak_updated_apps.insert(app_id.clone());
            }
            _ => {}
        },
        OpsEvent::UpdatePlan(plan) => state.zypper_plan = Some(plan.clone()),
        OpsEvent::CommandResult { operation, result } => {
            if *operation == OperationKind::UpdatesZypperApply {
                state.zypper_apply_exit_code = Some(result.exit_code);
            }
            if *operation == OperationKind::UpdatesFlatpak {
                state.flatpak_exit_code = Some(result.exit_code);
                state.flatpak_active = false;
            }
            if result.exit_code != 0 {
                state.had_error = true;
            }
        }
        OpsEvent::Error(_) => state.had_error = true,
        _ => {}
    }
}

fn derived_events_from_event(state: &RunState, event: &OpsEvent) -> Vec<OpsEventKind> {
    match event {
        OpsEvent::CommandResult { operation, result }
            if *operation == OperationKind::UpdatesZypperApply =>
        {
            vec![OpsEventKind::ApplyResult {
                exit_code: result.exit_code,
            }]
        }
        OpsEvent::Log {
            stream: LogStream::Updates,
            line,
        } if state.apply_active => parse_apply_package_event(line).into_iter().collect(),
        OpsEvent::Log {
            stream: LogStream::Updates,
            line,
        } if state.flatpak_active => parse_flatpak_update_event(line)
            .filter(|app_id| !state.flatpak_updated_apps.contains(app_id))
            .map(|app_id| OpsEventKind::FlatpakUpdated { app_id })
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_apply_package_event(line: &str) -> Option<OpsEventKind> {
    let trimmed = line.trim();
    let message = trimmed
        .strip_prefix("INFO:")
        .or_else(|| trimmed.strip_prefix("WARN:"))
        .or_else(|| trimmed.strip_prefix("ERROR:"))
        .unwrap_or(trimmed)
        .trim();

    let markers = [
        ("Installing:", "installed"),
        ("Removing:", "removed"),
        ("Upgrading:", "upgraded"),
        ("Updating:", "upgraded"),
    ];

    let (package_raw, status) = markers
        .iter()
        .find_map(|(marker, status)| message.strip_prefix(marker).map(|rest| (rest, *status)))?;

    let package = package_raw
        .split(" [")
        .next()
        .unwrap_or(package_raw)
        .trim()
        .trim_matches('"');
    if package.is_empty() {
        return None;
    }

    match status {
        "installed" => Some(OpsEventKind::PackageInstalled {
            name: package.to_string(),
            from: None,
            to: None,
            repo: None,
            arch: None,
        }),
        "removed" => Some(OpsEventKind::PackageRemoved {
            name: package.to_string(),
            from: None,
            to: None,
            repo: None,
            arch: None,
        }),
        "upgraded" => Some(OpsEventKind::PackageUpgraded {
            name: package.to_string(),
            from: None,
            to: None,
            repo: None,
            arch: None,
        }),
        _ => None,
    }
}

fn parse_flatpak_update_event(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    parse_flatpak_table_row(trimmed).or_else(|| parse_flatpak_completion_line(trimmed))
}

fn parse_flatpak_table_row(line: &str) -> Option<String> {
    let (index, rest) = line.split_once('.')?;
    if index.trim().is_empty() || !index.trim().chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let mut columns = rest.split_whitespace();
    let candidate = columns.next()?.trim();
    normalize_flatpak_ref(candidate)
}

fn parse_flatpak_completion_line(line: &str) -> Option<String> {
    let reference = line.strip_prefix("Updating ")?.split_whitespace().next()?;
    normalize_flatpak_ref(reference)
}

fn normalize_flatpak_ref(reference: &str) -> Option<String> {
    let trimmed = reference.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    if let Some(stripped) = trimmed
        .strip_prefix("app/")
        .or_else(|| trimmed.strip_prefix("runtime/"))
    {
        let app_id = stripped.split('/').next()?.trim();
        return (!app_id.is_empty()).then(|| app_id.to_string());
    }

    if trimmed.contains('/') {
        return None;
    }

    let valid = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    if !valid || !trimmed.contains('.') {
        return None;
    }

    Some(trimmed.to_string())
}

fn persist_event(run: Option<&mut PersistedRun>, event: &OpsEvent) {
    let Some(run) = run else {
        return;
    };

    if !should_persist_event(event) {
        return;
    }

    if let OpsEvent::RunSummary(summary) = event {
        let package_rows = package_evidence_rows_for_summary(&run.run_id, summary);
        let _ = run.store.replace_packages(&run.run_id, &package_rows);
        return;
    }

    if let OpsEvent::UpdatePlan(plan) = event {
        let package_rows = package_evidence_rows_for_plan(&run.run_id, plan);
        let _ = run.store.replace_packages(&run.run_id, &package_rows);
    }

    if let Some((risk, recommendations)) = ai_assessment_for_persistence(event) {
        let recommendations_json = json!(recommendations).to_string();
        let _ =
            run.store
                .upsert_ai_assessment(&run.run_id, Some(risk.as_str()), &recommendations_json);
    }

    let (phase, severity, event_type, payload_json, message) = event_persistence_fields(event);
    let _ = run.store.append_event(
        &run.run_id,
        &phase,
        &severity,
        &event_type,
        &payload_json,
        &message,
    );
}

fn persist_event_to_store(
    store: &ReportStore,
    run_id: &str,
    event: &OpsEvent,
    package_rows: Option<Vec<PackageEvidenceRow>>,
) -> Result<(), String> {
    if !should_persist_event(event) {
        return Ok(());
    }

    if let Some(package_rows) = package_rows {
        store.replace_packages(run_id, &package_rows)?;
    } else if let OpsEvent::RunSummary(summary) = event {
        let package_rows = package_evidence_rows_for_summary(run_id, summary);
        store.replace_packages(run_id, &package_rows)?;
        return Ok(());
    }

    if let Some((risk, recommendations)) = ai_assessment_for_persistence(event) {
        let recommendations_json = json!(recommendations).to_string();
        store.upsert_ai_assessment(run_id, Some(risk.as_str()), &recommendations_json)?;
    }

    let (phase, severity, event_type, payload_json, message) = event_persistence_fields(event);
    store.append_event(
        run_id,
        &phase,
        &severity,
        &event_type,
        &payload_json,
        &message,
    )
}

fn should_persist_event(event: &OpsEvent) -> bool {
    !matches!(
        event,
        OpsEvent::CommandResult {
            operation: OperationKind::UpdatesZypperPreview | OperationKind::UpdatesZypperApply,
            ..
        }
    )
}

fn ai_assessment_for_persistence(event: &OpsEvent) -> Option<(String, Vec<String>)> {
    match event {
        OpsEvent::Structured(StructuredOpsEvent {
            kind:
                OpsEventKind::AIAnalysis {
                    risk,
                    recommendations,
                    ..
                },
            ..
        }) => Some((risk.clone(), recommendations.clone())),
        _ => None,
    }
}

fn event_persistence_fields(event: &OpsEvent) -> (String, String, String, String, String) {
    match event {
        OpsEvent::Structured(event) => structured_event_persistence_fields(event),
        OpsEvent::Log { stream, line } => {
            if let Some((risk, recommendations)) = parse_ai_assessment_line(line) {
                (
                    "run".to_string(),
                    "info".to_string(),
                    "ai.assessment".to_string(),
                    json!({
                        "risk": risk,
                        "recommendations": recommendations,
                    })
                    .to_string(),
                    line.clone(),
                )
            } else {
                (
                    phase_for_stream(*stream).to_string(),
                    "info".to_string(),
                    "log".to_string(),
                    json!({
                        "stream": format!("{stream:?}"),
                    })
                    .to_string(),
                    line.clone(),
                )
            }
        }
        OpsEvent::Progress(line) => {
            if let Some((risk, recommendations)) = parse_ai_assessment_line(line) {
                (
                    "run".to_string(),
                    "info".to_string(),
                    "ai.assessment".to_string(),
                    json!({
                        "risk": risk,
                        "recommendations": recommendations,
                    })
                    .to_string(),
                    line.clone(),
                )
            } else {
                (
                    progress_phase(line).to_string(),
                    "info".to_string(),
                    "progress".to_string(),
                    json!({}).to_string(),
                    line.clone(),
                )
            }
        }
        OpsEvent::Error(line) => (
            "run".to_string(),
            "error".to_string(),
            "error".to_string(),
            json!({}).to_string(),
            line.clone(),
        ),
        OpsEvent::CommandResult { operation, result } => (
            phase_for_operation(*operation).to_string(),
            if result.exit_code == 0 {
                "info".to_string()
            } else {
                "error".to_string()
            },
            event_type_for_operation(*operation).to_string(),
            json!({
                "operation": format!("{operation:?}"),
                "exit_code": result.exit_code,
            })
            .to_string(),
            format!("Completed with exit code {}", result.exit_code),
        ),
        OpsEvent::UpdatePlan(plan) => (
            "zypper".to_string(),
            "info".to_string(),
            "zypper.preview.plan".to_string(),
            json!({
                "changes": plan.changes.len(),
                "command": plan.command.clone(),
                "exit_code": plan.result.exit_code,
            })
            .to_string(),
            format!("Preview plan with {} change(s)", plan.changes.len()),
        ),
        OpsEvent::RunSummary(summary) => (
            "reconcile".to_string(),
            if summary.verdict == "PASS" {
                "info".to_string()
            } else {
                "warn".to_string()
            },
            "reconcile.summary".to_string(),
            json!({
                "verdict": summary.verdict.clone(),
                "attempted": summary.attempted,
                "installed": summary.installed,
                "failed": summary.failed,
                "unaccounted": summary.unaccounted,
                "package_rows": package_rows_json(summary.process_run.as_ref()),
            })
            .to_string(),
            format!(
                "Attempted={} Installed={} Failed={} Unaccounted={} Verdict={}",
                summary.attempted,
                summary.installed,
                summary.failed,
                summary.unaccounted,
                summary.verdict
            ),
        ),
        OpsEvent::PackageIndex(rows) => (
            "package_manager".to_string(),
            "info".to_string(),
            "package.index".to_string(),
            json!({ "rows": rows.len() }).to_string(),
            format!("Loaded {} package row(s)", rows.len()),
        ),
        OpsEvent::BtrfsSnapshots(rows) => (
            "btrfs".to_string(),
            "info".to_string(),
            "btrfs.snapshots".to_string(),
            json!({ "rows": rows.len() }).to_string(),
            format!("Loaded {} Btrfs snapshot row(s)", rows.len()),
        ),
        OpsEvent::PackageLocks(locks) => (
            "package_manager".to_string(),
            "info".to_string(),
            "package.locks".to_string(),
            json!({ "locks": locks.len() }).to_string(),
            format!("Loaded {} package lock(s)", locks.len()),
        ),
        OpsEvent::PackageLockOperationCompleted {
            action,
            name,
            success,
            message,
        } => (
            "package_manager".to_string(),
            if *success {
                "info".to_string()
            } else {
                "error".to_string()
            },
            "package.lock.operation".to_string(),
            json!({
                "action": action,
                "name": name,
                "success": success,
            })
            .to_string(),
            message.clone(),
        ),
        OpsEvent::HealthReport(report) => (
            "health".to_string(),
            "info".to_string(),
            "health.report".to_string(),
            json!({
                "checks": report.checks.len(),
            })
            .to_string(),
            format!("Health report with {} check(s)", report.checks.len()),
        ),
        OpsEvent::SystemPulse(pulse) => (
            "health".to_string(),
            "info".to_string(),
            "health.pulse".to_string(),
            json!({
                "cpu_load": pulse.cpu_load,
                "mem_ratio": pulse.mem_ratio,
                "root_disk_ratio": pulse.root_disk_ratio,
            })
            .to_string(),
            "System pulse updated".to_string(),
        ),
        OpsEvent::TelemetryUpdate(telemetry) => (
            "health".to_string(),
            "info".to_string(),
            "health.telemetry".to_string(),
            json!({
                "cpu_percent": telemetry.cpu_percent,
                "mem_used_gb": telemetry.mem_used_gb,
                "mem_total_gb": telemetry.mem_total_gb,
                "root_fs_percent": telemetry.root_fs_percent,
            })
            .to_string(),
            "Telemetry updated".to_string(),
        ),
        OpsEvent::UpdateProgress {
            package,
            processed,
            total,
        } => (
            "update".to_string(),
            "info".to_string(),
            "update.progress".to_string(),
            json!({
                "package": package,
                "processed": processed,
                "total": total,
            })
            .to_string(),
            format!("Update progress {processed}/{total}: {package}"),
        ),
        OpsEvent::UpdatePhase(phase) => (
            "update".to_string(),
            "info".to_string(),
            "update.phase".to_string(),
            json!({
                "phase": phase,
            })
            .to_string(),
            format!("Update phase: {phase}"),
        ),
        OpsEvent::SystemWorkbookExportProgress(message) => (
            "system_workbook".to_string(),
            "info".to_string(),
            "system_workbook.progress".to_string(),
            json!({}).to_string(),
            message.clone(),
        ),
        OpsEvent::SystemWorkbookExportCompleted { path } => (
            "system_workbook".to_string(),
            "info".to_string(),
            "system_workbook.completed".to_string(),
            json!({
                "path": path,
            })
            .to_string(),
            format!("System workbook exported to {}", path.display()),
        ),
        OpsEvent::SystemWorkbookExportFailed(message) => (
            "system_workbook".to_string(),
            "error".to_string(),
            "system_workbook.failed".to_string(),
            json!({}).to_string(),
            message.clone(),
        ),
    }
}

fn structured_event_persistence_fields(
    event: &StructuredOpsEvent,
) -> (String, String, String, String, String) {
    match &event.kind {
        OpsEventKind::RunStart => (
            event.phase.clone(),
            event.severity.clone(),
            "run.start".to_string(),
            json!({}).to_string(),
            "Executing updates plan".to_string(),
        ),
        OpsEventKind::RunEnd => (
            event.phase.clone(),
            event.severity.clone(),
            "run.end".to_string(),
            json!({}).to_string(),
            "Run completed".to_string(),
        ),
        OpsEventKind::SnapshotStart => (
            event.phase.clone(),
            event.severity.clone(),
            "snapshot.start".to_string(),
            json!({}).to_string(),
            "Starting pre-update snapshot".to_string(),
        ),
        OpsEventKind::SnapshotSuccess { snapshot_id } => (
            "btrfs".to_string(),
            "info".to_string(),
            "btrfs.result".to_string(),
            json!({
                "exit_code": 0,
                "snapshot_id": snapshot_id,
            })
            .to_string(),
            "Created pre-update snapshot".to_string(),
        ),
        OpsEventKind::SnapshotFailure { reason } => (
            "btrfs".to_string(),
            "error".to_string(),
            "btrfs.result".to_string(),
            json!({
                "exit_code": 1,
                "reason": reason,
            })
            .to_string(),
            reason.clone(),
        ),
        OpsEventKind::PreviewStart => (
            "zypper".to_string(),
            "info".to_string(),
            "preview.start".to_string(),
            json!({}).to_string(),
            "Running zypper preview".to_string(),
        ),
        OpsEventKind::PreviewResult { packages } => (
            "zypper".to_string(),
            "info".to_string(),
            "preview.result".to_string(),
            json!({ "packages": packages }).to_string(),
            format!("Preview result with {packages} package(s)"),
        ),
        OpsEventKind::AIAnalysis {
            risk,
            rationale,
            recommendations,
        } => (
            "run".to_string(),
            "info".to_string(),
            "ai.assessment".to_string(),
            json!({
                "risk": risk,
                "rationale": rationale,
                "recommendations": recommendations,
            })
            .to_string(),
            format!("AI_ASSESSMENT:{}|{}", risk, recommendations.join("|")),
        ),
        OpsEventKind::ApplyStart => (
            "zypper".to_string(),
            "info".to_string(),
            "apply.start".to_string(),
            json!({}).to_string(),
            "Applying updates".to_string(),
        ),
        OpsEventKind::ApplyResult { exit_code } => (
            "zypper".to_string(),
            if *exit_code == 0 {
                "info".to_string()
            } else {
                "error".to_string()
            },
            "zypper.apply.result".to_string(),
            json!({ "exit_code": exit_code }).to_string(),
            format!("Apply completed with exit code {exit_code}"),
        ),
        OpsEventKind::PackageInstalled {
            name,
            from,
            to,
            repo,
            arch,
        } => (
            "zypper".to_string(),
            "info".to_string(),
            "PackageResult".to_string(),
            json!({
                "name": name,
                "status": "installed",
                "from_version": from,
                "to_version": to,
                "repo": repo,
                "arch": arch,
            })
            .to_string(),
            format!("{name} installed"),
        ),
        OpsEventKind::PackageRemoved {
            name,
            from,
            to,
            repo,
            arch,
        } => (
            "zypper".to_string(),
            "info".to_string(),
            "PackageResult".to_string(),
            json!({
                "name": name,
                "status": "removed",
                "from_version": from,
                "to_version": to,
                "repo": repo,
                "arch": arch,
            })
            .to_string(),
            format!("{name} removed"),
        ),
        OpsEventKind::PackageUpgraded {
            name,
            from,
            to,
            repo,
            arch,
        } => (
            "zypper".to_string(),
            "info".to_string(),
            "PackageResult".to_string(),
            json!({
                "name": name,
                "status": "upgraded",
                "from_version": from,
                "to_version": to,
                "repo": repo,
                "arch": arch,
            })
            .to_string(),
            format!("{name} upgraded"),
        ),
        OpsEventKind::FlatpakUpdated { app_id } => (
            "flatpak".to_string(),
            "info".to_string(),
            "flatpak.package".to_string(),
            json!({ "app_id": app_id }).to_string(),
            format!("Updated {app_id}"),
        ),
        OpsEventKind::ReconcileSummary {
            attempted,
            installed,
            failed,
            unaccounted,
            verdict,
        } => (
            "reconcile".to_string(),
            if verdict == "PASS" {
                "info".to_string()
            } else {
                "warn".to_string()
            },
            "reconcile.summary".to_string(),
            json!({
                "verdict": verdict,
                "attempted": attempted,
                "installed": installed,
                "failed": failed,
                "unaccounted": unaccounted,
            })
            .to_string(),
            format!(
                "Attempted={} Installed={} Failed={} Unaccounted={} Verdict={}",
                attempted, installed, failed, unaccounted, verdict
            ),
        ),
        OpsEventKind::Error { message } => (
            "run".to_string(),
            "error".to_string(),
            "error".to_string(),
            json!({}).to_string(),
            message.clone(),
        ),
    }
}

fn package_rows_json(process_run: Option<&ProcessRun>) -> Vec<serde_json::Value> {
    use chamrisk_core::models::PackageEventKind;

    let Some(process_run) = process_run else {
        return Vec::new();
    };

    process_run
        .events
        .iter()
        .map(|event| {
            let status = match event.kind {
                PackageEventKind::InstallSucceeded => "installed",
                PackageEventKind::UpdateSucceeded | PackageEventKind::UpgradeSucceeded => {
                    "upgraded"
                }
                PackageEventKind::DowngradeSucceeded => "downgraded",
                PackageEventKind::RemoveSucceeded => "removed",
                PackageEventKind::InstallFailed
                | PackageEventKind::UpdateFailed
                | PackageEventKind::UpgradeFailed
                | PackageEventKind::DowngradeFailed
                | PackageEventKind::RemoveFailed => "failed",
                PackageEventKind::Skipped => "skipped",
                PackageEventKind::Planned => "planned",
            };

            json!({
                "name": event.package_name,
                "status": status,
                "from_version": event.from_version,
                "to_version": event.to_version,
                "repo": event.repo,
                "arch": event.arch,
                "message": package_row_message_from_event(status, event),
            })
        })
        .collect()
}

fn package_evidence_rows_for_summary(
    run_id: &str,
    summary: &RunSummary,
) -> Vec<PackageEvidenceRow> {
    use chamrisk_core::models::{
        PackageUpdate, PlannedAction, ReconcileStatus, UpdateAction, VendorGroup,
    };

    let (Some(process_run), Some(reconcile)) =
        (summary.process_run.as_ref(), summary.reconcile.as_ref())
    else {
        return Vec::new();
    };

    reconcile
        .items
        .iter()
        .map(|item| {
            let matched_event = item
                .matched_event_index
                .and_then(|index| process_run.events.get(index));

            let repository = matched_event
                .and_then(|event| event.repo.clone())
                .or_else(|| {
                    process_run
                        .events
                        .iter()
                        .find(|event| {
                            event.package_name_norm == item.planned_package_name_norm
                                && (item.planned_arch.is_none() || event.arch == item.planned_arch)
                        })
                        .and_then(|event| event.repo.clone())
                });

            let action = match item.planned_action {
                PlannedAction::Install => "install",
                PlannedAction::Remove => "remove",
                PlannedAction::Update => "update",
                PlannedAction::Upgrade => "upgrade",
                PlannedAction::Downgrade => "downgrade",
            };

            let result = match item.status {
                ReconcileStatus::Succeeded => "succeeded",
                ReconcileStatus::Failed => "failed",
                ReconcileStatus::Skipped => "skipped",
                ReconcileStatus::NotAttempted => "not_attempted",
                ReconcileStatus::Ambiguous => "ambiguous",
            };

            let update_action = match item.planned_action {
                PlannedAction::Install => UpdateAction::Install,
                PlannedAction::Remove => UpdateAction::Remove,
                PlannedAction::Update | PlannedAction::Upgrade => UpdateAction::Upgrade,
                PlannedAction::Downgrade => UpdateAction::Downgrade,
            };
            let risk = Some(
                report_risk_label(assess_package_risk(&PackageUpdate {
                    name: item.planned_package_name.clone(),
                    action: update_action,
                    current_version: item
                        .actual_from_version
                        .clone()
                        .or_else(|| item.planned_from_version.clone()),
                    new_version: item
                        .actual_to_version
                        .clone()
                        .or_else(|| item.planned_to_version.clone()),
                    arch: item
                        .actual_arch
                        .clone()
                        .or_else(|| item.planned_arch.clone()),
                    repository: repository.clone(),
                    vendor: None,
                    vendor_group: VendorGroup::Unknown,
                    vendor_change: false,
                    repo_change: false,
                }))
                .to_string(),
            );

            PackageEvidenceRow {
                run_id: run_id.to_string(),
                package_name: item.planned_package_name.clone(),
                from_version: item
                    .actual_from_version
                    .clone()
                    .or_else(|| item.planned_from_version.clone()),
                to_version: item
                    .actual_to_version
                    .clone()
                    .or_else(|| item.planned_to_version.clone()),
                arch: item
                    .actual_arch
                    .clone()
                    .or_else(|| item.planned_arch.clone()),
                repository,
                action: Some(action.to_string()),
                result: Some(result.to_string()),
                risk,
            }
        })
        .collect()
}

fn package_evidence_rows_for_plan(run_id: &str, plan: &UpdatePlan) -> Vec<PackageEvidenceRow> {
    use chamrisk_core::models::{PackageUpdate, VendorGroup};

    plan.changes
        .iter()
        .map(|change| {
            let action = match change.action {
                UpdateAction::Install => "install",
                UpdateAction::Remove => "remove",
                UpdateAction::Upgrade => "upgrade",
                UpdateAction::Downgrade => "downgrade",
                UpdateAction::VendorChange => "vendor_change",
                UpdateAction::RepoChange => "repo_change",
                UpdateAction::Unknown => "unknown",
            };

            let risk = Some(
                report_risk_label(assess_package_risk(&PackageUpdate {
                    name: change.name.clone(),
                    action: change.action.clone(),
                    current_version: change.from.clone(),
                    new_version: change.to.clone(),
                    arch: change.arch.clone(),
                    repository: change.repo.clone(),
                    vendor: change.vendor.clone(),
                    vendor_group: VendorGroup::Unknown,
                    vendor_change: change
                        .vendor
                        .as_deref()
                        .map(|value| value.contains("->"))
                        .unwrap_or(false),
                    repo_change: change
                        .repo
                        .as_deref()
                        .map(|value| value.contains("->"))
                        .unwrap_or(false),
                }))
                .to_string(),
            );

            PackageEvidenceRow {
                run_id: run_id.to_string(),
                package_name: change.name.clone(),
                from_version: change.from.clone(),
                to_version: change.to.clone(),
                arch: change.arch.clone(),
                repository: change.repo.clone(),
                action: Some(action.to_string()),
                result: Some("planned".to_string()),
                risk,
            }
        })
        .collect()
}

fn package_row_message_from_event(
    status: &str,
    event: &chamrisk_core::models::PackageEvent,
) -> String {
    let mut parts = vec![format!("{} {}", event.package_name, status)];

    match (event.from_version.as_deref(), event.to_version.as_deref()) {
        (Some(from), Some(to)) if from != to => parts.push(format!("{from} -> {to}")),
        (None, Some(to)) => parts.push(format!("-> {to}")),
        (Some(from), None) => parts.push(from.to_string()),
        _ => {}
    }

    if let Some(repo) = event.repo.as_deref() {
        parts.push(format!("repo={repo}"));
    }
    if let Some(arch) = event.arch.as_deref() {
        parts.push(format!("arch={arch}"));
    }
    if let Some(reason) = event.reason.as_deref() {
        parts.push(reason.to_string());
    }

    parts.join(" ")
}

fn parse_ai_assessment_line(line: &str) -> Option<(String, Vec<String>)> {
    let marker_index = line.find("AI_ASSESSMENT:")?;
    let assessment = line.get(marker_index + "AI_ASSESSMENT:".len()..)?.trim();
    let mut tokens = assessment
        .split('|')
        .map(str::trim)
        .filter(|token| !token.is_empty());

    let risk = tokens.next()?.to_string();
    let recommendations = tokens.map(|token| token.to_string()).collect::<Vec<_>>();

    Some((risk, recommendations))
}

fn progress_phase(line: &str) -> &'static str {
    if line.to_ascii_lowercase().contains("zypper") {
        "zypper"
    } else if line.to_ascii_lowercase().contains("flatpak") {
        "flatpak"
    } else if line.to_ascii_lowercase().contains("journal") {
        "journal"
    } else if line.to_ascii_lowercase().contains("snapshot") {
        "btrfs"
    } else {
        "run"
    }
}

fn phase_for_stream(stream: LogStream) -> &'static str {
    match stream {
        LogStream::Updates => "updates",
        LogStream::Btrfs => "btrfs",
        LogStream::PackageManager => "package_manager",
    }
}

fn phase_for_operation(operation: OperationKind) -> &'static str {
    match operation {
        OperationKind::UpdatesZypperPreview | OperationKind::UpdatesZypperApply => "zypper",
        OperationKind::UpdatesFlatpak => "flatpak",
        OperationKind::UpdatesJournalVacuum => "journal",
        OperationKind::Btrfs => "btrfs",
        OperationKind::PackageManager => "package_manager",
        OperationKind::UpdatesOther => "run",
    }
}

fn event_type_for_operation(operation: OperationKind) -> &'static str {
    match operation {
        OperationKind::UpdatesZypperPreview => "zypper.preview.result",
        OperationKind::UpdatesZypperApply => "zypper.apply.result",
        OperationKind::UpdatesFlatpak => "flatpak.update.result",
        OperationKind::UpdatesJournalVacuum => "journal.vacuum.result",
        OperationKind::Btrfs => "btrfs.result",
        OperationKind::PackageManager => "package_manager.result",
        OperationKind::UpdatesOther => "run.result",
    }
}

fn build_run_summary(state: &RunState) -> Option<RunSummary> {
    if let Some(exit_code) = state.zypper_apply_exit_code {
        let Some(plan) = state.zypper_plan.as_ref() else {
            return Some(RunSummary {
                verdict: "SKIP".to_string(),
                attempted: 0,
                installed: 0,
                failed: 0,
                unaccounted: 0,
                process_run: None,
                reconcile: None,
            });
        };
        let (process_run, reconcile) =
            make_run_and_reconcile_from_plan(plan, exit_code, state.master_run_id.as_deref())?;

        let attempted = reconcile.total_planned as i64;
        let installed = reconcile.matched_success as i64;
        let failed = reconcile.matched_failed as i64;
        let skipped = reconcile.skipped as i64;
        let ambiguous = reconcile.ambiguous as i64;
        let accounted = installed + failed + skipped + ambiguous;
        let unaccounted = attempted.saturating_sub(accounted);
        let verdict = if failed == 0 && exit_code == 0 {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        return Some(RunSummary {
            verdict,
            attempted,
            installed,
            failed,
            unaccounted,
            process_run: Some(process_run),
            reconcile: Some(reconcile),
        });
    }

    let exit_code = state.flatpak_exit_code?;
    let installed = state.flatpak_updated_apps.len() as i64;
    Some(RunSummary {
        verdict: if exit_code == 0 { "PASS" } else { "FAIL" }.to_string(),
        attempted: installed,
        installed,
        failed: 0,
        unaccounted: 0,
        process_run: None,
        reconcile: None,
    })
}

fn finish_persisted_run(finalize_guard: &mut RunFinalizeGuard, state: &RunState) {
    if let Some(verdict) = state.verdict_override.as_deref() {
        finalize_guard.finish(verdict, 0, 0, 0, 0);
        return;
    }

    let (attempted, installed, failed, unaccounted, verdict) =
        if let Some(summary) = build_run_summary(state) {
            let verdict = if state.had_blocked_task && summary.verdict == "PASS" {
                "BLOCKED".to_string()
            } else {
                summary.verdict.clone()
            };
            (
                summary.attempted,
                summary.installed,
                summary.failed,
                summary.unaccounted,
                verdict,
            )
        } else {
            (
                0,
                0,
                0,
                0,
                if state.had_error {
                    "FAIL".to_string()
                } else if state.had_blocked_task {
                    "BLOCKED".to_string()
                } else if state.had_skipped_task {
                    "SKIP".to_string()
                } else {
                    "PASS".to_string()
                },
            )
        };

    finalize_guard.finish(&verdict, attempted, installed, failed, unaccounted);
}

fn emit_summary_if_ready(
    tx: &Sender<OpsEvent>,
    finalize_guard: &mut RunFinalizeGuard,
    state: &mut RunState,
) {
    if state.summary_emitted {
        return;
    }
    let Some(summary) = build_run_summary(state) else {
        return;
    };
    state.summary_emitted = true;
    if let Some(run) = finalize_guard.as_mut() {
        let package_rows = package_evidence_rows_for_summary(&run.run_id, &summary);
        let _ = run.store.replace_packages(&run.run_id, &package_rows);
    }
    emit_event(
        tx,
        finalize_guard,
        state,
        structured(OpsEventKind::ReconcileSummary {
            attempted: summary.attempted.max(0) as u32,
            installed: summary.installed.max(0) as u32,
            failed: summary.failed.max(0) as u32,
            unaccounted: summary.unaccounted.max(0) as u32,
            verdict: summary.verdict.clone(),
        }),
    );
    emit_event(tx, finalize_guard, state, OpsEvent::RunSummary(summary));
}

fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().try_into().unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn make_run_and_reconcile_from_plan(
    plan: &UpdatePlan,
    exit_code: i32,
    master_run_id: Option<&str>,
) -> Option<(ProcessRun, ReconcileResult)> {
    use chamrisk_core::models::{
        Confidence, EventLevel, PackageBackend, PackageEvent, PackageEventKind, PlannedAction,
        ProcessStatus, ProcessSummary, TriagePackage,
    };

    let status = if exit_code == 0 {
        ProcessStatus::Success
    } else {
        ProcessStatus::Failed
    };

    let mut triage: Vec<TriagePackage> = Vec::with_capacity(plan.changes.len());
    let mut events: Vec<PackageEvent> = Vec::with_capacity(plan.changes.len());

    for (i, c) in plan.changes.iter().enumerate() {
        let planned_action = match c.action {
            UpdateAction::Install => PlannedAction::Install,
            UpdateAction::Remove => PlannedAction::Remove,
            UpdateAction::Downgrade => PlannedAction::Downgrade,
            _ => PlannedAction::Update,
        };

        let triage_id = format!("plan-{i}");
        let norm = c.name.trim().to_ascii_lowercase();

        triage.push(TriagePackage {
            triage_id: triage_id.clone(),
            backend: PackageBackend::Zypper,
            package_name: c.name.clone(),
            package_name_norm: norm.clone(),
            arch: c.arch.clone(),
            planned_action,
            planned_from_version: c.from.clone(),
            planned_to_version: c.to.clone(),
            selected: true,
            source_repo: c.repo.clone(),
        });

        let kind = if exit_code == 0 {
            match c.action {
                UpdateAction::Install => PackageEventKind::InstallSucceeded,
                UpdateAction::Remove => PackageEventKind::RemoveSucceeded,
                UpdateAction::Downgrade => PackageEventKind::DowngradeSucceeded,
                _ => PackageEventKind::UpgradeSucceeded,
            }
        } else {
            PackageEventKind::Planned
        };

        events.push(PackageEvent {
            ts_ms: Some(i as u64),
            backend: PackageBackend::Zypper,
            kind,
            package_name: c.name.clone(),
            package_name_norm: norm,
            arch: c.arch.clone(),
            from_version: c.from.clone(),
            to_version: c.to.clone(),
            repo: c.repo.clone(),
            level: if exit_code == 0 {
                EventLevel::Info
            } else {
                EventLevel::Warning
            },
            raw_line: None,
            reason: if exit_code == 0 {
                Some("Assumed success (exit 0)".to_string())
            } else {
                Some("Run failed; results unknown (no log parse yet)".to_string())
            },
        });
    }

    let run = ProcessRun {
        run_id: master_run_id
            .map(|run_id| run_id.to_string())
            .unwrap_or_else(|| format!("run-{}", now_ms())),
        backend: PackageBackend::Zypper,
        command: "zypper".to_string(),
        args: vec![],
        started_at_utc: now_ms().to_string(),
        ended_at_utc: None,
        duration_ms: None,
        events,
        summary: ProcessSummary {
            process_name: "zypper".to_string(),
            process_type: "update".to_string(),
            status,
            reboot_recommended: false,
            test_required: false,
            summary_line: format!("Completed with exit code {exit_code}"),
            exit_code: Some(exit_code),
            confidence: if exit_code == 0 {
                Confidence::Medium
            } else {
                Confidence::Low
            },
            error_category: None,
        },
    };

    let reconcile = reconcile_triage_against_run(&triage, &run);
    Some((run, reconcile))
}

fn run_privileged(
    cmd: &str,
    args: &[&str],
    stream: LogStream,
    tx: Sender<OpsEvent>,
    sudo_password: Option<String>,
) {
    if let Some(password) = sudo_password {
        let mut sudo_args = vec!["-S", "-p", "", cmd];
        sudo_args.extend(args);
        run_streaming_with_input(
            "sudo",
            &sudo_args,
            stream,
            tx,
            Some(format!("{password}\n")),
        );
    } else {
        run_streaming(cmd, args, stream, tx);
    }
}

fn emit_btrfs_list_raw_logs(tx: &Sender<OpsEvent>, stdout: &str, stderr: &str) {
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = tx.send(OpsEvent::Log {
            stream: LogStream::Btrfs,
            line: trimmed.to_string(),
        });
    }
}

pub fn parse_snapper_list_output(output: &str) -> Result<Vec<BtrfsSnapshotRow>, String> {
    let mut rows = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_snapper_table_separator(trimmed) {
            continue;
        }

        let cells = trimmed
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect::<Vec<_>>();

        if cells.len() < 9 {
            continue;
        }

        if cells[0] == "#" && cells[1].eq_ignore_ascii_case("type") {
            continue;
        }

        rows.push(parse_snapper_snapshot_row(&cells)?);
    }

    if rows.is_empty() {
        return Err("snapper list returned no parseable snapshot rows".to_string());
    }

    Ok(rows)
}

fn parse_snapper_snapshot_row(cells: &[String]) -> Result<BtrfsSnapshotRow, String> {
    let raw_id = cells
        .first()
        .map(String::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if raw_id.is_empty() {
        return Err("snapshot row missing snapshot id".to_string());
    }

    let is_current = raw_id.ends_with('*');
    let snapshot_id = raw_id.trim_end_matches('*').trim().to_string();
    if snapshot_id.is_empty() {
        return Err(format!("snapshot row has invalid snapshot id: {raw_id}"));
    }

    Ok(BtrfsSnapshotRow {
        snapshot_id,
        is_current,
        snapshot_type: cells.get(1).cloned().unwrap_or_default(),
        pre_number: cells
            .get(2)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        date: cells.get(3).cloned().unwrap_or_default(),
        user: cells.get(4).cloned().unwrap_or_default(),
        used_space: cells.get(5).cloned().unwrap_or_default(),
        cleanup: cells.get(6).cloned().unwrap_or_default(),
        description: cells.get(7).cloned().unwrap_or_default(),
        userdata: cells.get(8).cloned().unwrap_or_default(),
    })
}

fn is_snapper_table_separator(line: &str) -> bool {
    let compact = line
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    !compact.is_empty()
        && compact
            .chars()
            .all(|ch| ch == '-' || ch == '+' || ch == '|' || ch == '#')
}

fn run_zypper_dup_blocking(
    tx: Sender<OpsEvent>,
    sudo_password: Option<String>,
    prefer_packman: bool,
) {
    let mut args = vec![
        "zypper".to_string(),
        "--xmlout".to_string(),
        "--non-interactive".to_string(),
        "dup".to_string(),
    ];
    if prefer_packman {
        args.push("--allow-vendor-change".to_string());
    }
    args.push("--no-confirm".to_string());

    let command_string = format!("sudo {}", args.join(" "));
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::Updates,
        line: format!("Running command: {command_string}"),
    });
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::Updates,
        line: "Update process started.".to_string(),
    });

    if let Some(password) = sudo_password {
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_streaming_blocking_with_input(
            "sudo",
            &arg_refs,
            LogStream::Updates,
            tx,
            Some(format!("{password}\n")),
        );
    } else {
        let arg_refs = args.iter().skip(1).map(String::as_str).collect::<Vec<_>>();
        crate::runner::run_streaming_blocking("zypper", &arg_refs, LogStream::Updates, tx);
    }
}

enum ZyppLockCheck {
    Clear,
    Blocked(String),
}

fn zypp_lock_check(pid_file: &Path, proc_root: &Path) -> ZyppLockCheck {
    if !pid_file.exists() {
        return ZyppLockCheck::Clear;
    }

    let raw_pid = match fs::read_to_string(pid_file) {
        Ok(v) => v,
        Err(err) => {
            return match fs::remove_file(pid_file) {
                Ok(_) => ZyppLockCheck::Clear,
                Err(_) => ZyppLockCheck::Blocked(format!(
                    "Warning: zypp lock file could not be read and could not be removed (/var/run/zypp.pid): {err}"
                )),
            }
        }
    };

    let trimmed = raw_pid.trim();
    if trimmed.is_empty() {
        return ZyppLockCheck::Clear;
    }

    let pid = match trimmed.parse::<u32>() {
        Ok(v) => v,
        Err(_) => {
            return match fs::remove_file(pid_file) {
                Ok(_) => ZyppLockCheck::Clear,
                Err(err) => ZyppLockCheck::Blocked(format!(
                    "Warning: zypp lock file is invalid and could not be removed (/var/run/zypp.pid): {err}"
                )),
            }
        }
    };

    let mut proc_path = PathBuf::from(proc_root);
    proc_path.push(pid.to_string());

    if proc_path.exists() {
        ZyppLockCheck::Blocked(format!(
            "Cannot preview updates: zypp is locked (/var/run/zypp.pid pid {pid} is active)."
        ))
    } else {
        match fs::remove_file(pid_file) {
            Ok(_) => ZyppLockCheck::Clear,
            Err(err) => ZyppLockCheck::Blocked(format!(
                "Warning: stale zypp lock file could not be removed (/var/run/zypp.pid): {err}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attach_or_create_persisted_run, build_run_summary,
        create_master_run_with_optional_plan_in_store, create_persisted_run, emit_event,
        finish_persisted_run, normalize_execution_selection, normalize_preview_log_line_for_ui,
        package_evidence_rows_for_summary, parse_flatpak_update_event,
        parse_package_locks_defensive, parse_package_transaction_xml_event,
        parse_snapper_list_output, selection_has_any_requested_task,
        snapshot_action_for_filesystem, structured, zypp_lock_check, RunFinalizeGuard, RunState,
        SnapshotAction, UpdateRunSelection, ZyppLockCheck,
    };
    use crate::events::OpsEventKind;
    use crate::report_store::ReportStore;
    use crate::runner::{OperationKind, OpsEvent, RunSummary};
    use chamrisk_core::models::{
        CommandResult, Confidence, EventLevel, MatchConfidence, PackageBackend, PackageChange,
        PackageEvent, PackageEventKind, PlannedAction, ProcessRun, ProcessStatus, ProcessSummary,
        ReconcileMatch, ReconcileResult, ReconcileStatus, UpdateAction, UpdatePlan,
    };
    use std::fs;
    use std::sync::mpsc::channel;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn uniq(name: &str) -> String {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        format!("{name}-{n}")
    }

    #[test]
    fn allows_preview_when_pid_file_missing() {
        let base = std::env::temp_dir().join(uniq("ops-lock-missing"));
        fs::create_dir_all(&base).expect("mkdir");
        let pid = base.join("zypp.pid");
        let proc_root = base.join("proc");
        fs::create_dir_all(&proc_root).expect("mkdir proc");

        assert!(matches!(
            zypp_lock_check(&pid, &proc_root),
            ZyppLockCheck::Clear
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn allows_preview_when_pid_file_stale() {
        let base = std::env::temp_dir().join(uniq("ops-lock-stale"));
        fs::create_dir_all(&base).expect("mkdir");
        let pid = base.join("zypp.pid");
        let proc_root = base.join("proc");
        fs::create_dir_all(&proc_root).expect("mkdir proc");
        fs::write(&pid, "424242\n").expect("write pid");

        assert!(matches!(
            zypp_lock_check(&pid, &proc_root),
            ZyppLockCheck::Clear
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn allows_preview_when_pid_file_invalid() {
        let base = std::env::temp_dir().join(uniq("ops-lock-invalid"));
        fs::create_dir_all(&base).expect("mkdir");
        let pid = base.join("zypp.pid");
        let proc_root = base.join("proc");
        fs::create_dir_all(&proc_root).expect("mkdir proc");
        fs::write(&pid, "not-a-pid\n").expect("write pid");

        assert!(matches!(
            zypp_lock_check(&pid, &proc_root),
            ZyppLockCheck::Clear
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn allows_preview_when_pid_file_empty() {
        let base = std::env::temp_dir().join(uniq("ops-lock-empty"));
        fs::create_dir_all(&base).expect("mkdir");
        let pid = base.join("zypp.pid");
        let proc_root = base.join("proc");
        fs::create_dir_all(&proc_root).expect("mkdir proc");
        fs::write(&pid, "\n").expect("write pid");

        assert!(matches!(
            zypp_lock_check(&pid, &proc_root),
            ZyppLockCheck::Clear
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn blocks_preview_when_pid_is_active() {
        let base = std::env::temp_dir().join(uniq("ops-lock-active"));
        fs::create_dir_all(&base).expect("mkdir");
        let pid = base.join("zypp.pid");
        let proc_root = base.join("proc");
        let active_pid = 1234u32;

        fs::create_dir_all(proc_root.join(active_pid.to_string())).expect("mkdir active pid");
        fs::write(&pid, format!("{active_pid}\n")).expect("write pid");

        assert!(matches!(
            zypp_lock_check(&pid, &proc_root),
            ZyppLockCheck::Blocked(_)
        ));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn snapshot_is_skipped_for_non_btrfs_filesystems() {
        assert_eq!(snapshot_action_for_filesystem("ext4"), SnapshotAction::Skip);
        assert_eq!(snapshot_action_for_filesystem("xfs"), SnapshotAction::Skip);
    }

    #[test]
    fn snapshot_is_attempted_for_btrfs_filesystem() {
        assert_eq!(
            snapshot_action_for_filesystem("btrfs"),
            SnapshotAction::Attempt
        );
        assert_eq!(
            snapshot_action_for_filesystem("BTRFS"),
            SnapshotAction::Attempt
        );
    }

    #[test]
    fn preview_ui_filter_drops_info_noise() {
        assert_eq!(
            normalize_preview_log_line_for_ui("For basic pattern searching, try this utility..."),
            None
        );
        assert_eq!(
            normalize_preview_log_line_for_ui(
                r#"<message type="info">Loading repository data...</message>"#
            ),
            None
        );
    }

    #[test]
    fn preview_ui_filter_keeps_warnings_and_errors() {
        assert_eq!(
            normalize_preview_log_line_for_ui(
                r#"<message type="warning">Repository metadata is stale.</message>"#
            ),
            Some("WARN: Repository metadata is stale.".to_string())
        );
        assert_eq!(
            normalize_preview_log_line_for_ui("warning: refresh delayed"),
            Some("WARN: refresh delayed".to_string())
        );
        assert_eq!(
            normalize_preview_log_line_for_ui("error: temporary network failure"),
            Some("ERROR: temporary network failure".to_string())
        );
    }

    #[test]
    fn package_manager_xml_parser_emits_install_and_success() {
        assert_eq!(
            parse_package_transaction_xml_event(
                "install",
                r#"<progress id="install" name="nano"/>"#
            ),
            Some("INFO: Installing: nano".to_string())
        );
        assert_eq!(
            parse_package_transaction_xml_event(
                "install",
                r#"<solvable status="installed" name="nano" kind="package"/>"#
            ),
            Some("INFO: Installed successfully: nano".to_string())
        );
    }

    #[test]
    fn package_manager_xml_parser_emits_install_failure() {
        assert_eq!(
            parse_package_transaction_xml_event(
                "install",
                r#"<solvable status="failed" name="nano" kind="package"/>"#
            ),
            Some("ERROR: Install failed: nano".to_string())
        );
    }

    #[test]
    fn package_manager_xml_parser_emits_remove_and_success() {
        assert_eq!(
            parse_package_transaction_xml_event("remove", r#"<progress id="remove" name="nano"/>"#),
            Some("INFO: Removing: nano".to_string())
        );
        assert_eq!(
            parse_package_transaction_xml_event(
                "remove",
                r#"<solvable status="removed" name="nano" kind="package"/>"#
            ),
            Some("INFO: Removed successfully: nano".to_string())
        );
    }

    #[test]
    fn package_manager_xml_parser_emits_remove_failure() {
        assert_eq!(
            parse_package_transaction_xml_event(
                "remove",
                r#"<solvable status="failed" name="nano" kind="package"/>"#
            ),
            Some("ERROR: Remove failed: nano".to_string())
        );
    }

    #[test]
    fn flatpak_parser_recognizes_numbered_update_row() {
        assert_eq!(
            parse_flatpak_update_event(
                " 1.	   	com.cherry_ai.CherryStudio	stable	u	flathub	< 173.5 MB"
            ),
            Some("com.cherry_ai.CherryStudio".to_string())
        );
        assert_eq!(
            parse_flatpak_update_event("Updating app/dev.zed.Zed/x86_64/stable flathub ...done"),
            Some("dev.zed.Zed".to_string())
        );
    }

    #[test]
    fn flatpak_parser_ignores_no_update_lines() {
        for line in [
            "Looking for updates...",
            "Nothing to do.",
            "Updates complete.",
            "Updating... ████████████████████ 100%  16.8 MB/s  00:00",
            "",
        ] {
            assert_eq!(parse_flatpak_update_event(line), None, "line: {line}");
        }
    }

    #[test]
    fn flatpak_only_summary_uses_parsed_rows_after_successful_completion() {
        let (tx, _rx) = channel();
        let mut finalize_guard = RunFinalizeGuard::new(None);
        let mut state = RunState {
            flatpak_active: true,
            ..RunState::default()
        };

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::Log {
                stream: crate::runner::LogStream::Updates,
                line: " 1.	   	com.cherry_ai.CherryStudio	stable	u	flathub	< 173.5 MB".to_string(),
            },
        );
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::CommandResult {
                operation: OperationKind::UpdatesFlatpak,
                result: CommandResult {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            },
        );

        let summary = build_run_summary(&state).expect("flatpak summary");
        assert_eq!(summary.verdict, "PASS");
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.installed, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.unaccounted, 0);
        assert!(state
            .flatpak_updated_apps
            .contains("com.cherry_ai.CherryStudio"));
        assert!(!state.flatpak_active);
    }

    #[test]
    fn parses_snapper_list_rows_and_detects_current_snapshot() {
        let output = "\
# | Type   | Pre # | Date                     | User | Used Space | Cleanup | Description                | Userdata
--+--------+-------+--------------------------+------+------------+---------+----------------------------+---------
0 | single |       |                          | root |            |         | current                    |
1081* | single | | Mon Mar 9 18:38:31 2026 | root | 656.00 KiB | | writable copy of #1077 |
";

        let rows = parse_snapper_list_output(output).expect("parse snapper list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].snapshot_id, "0");
        assert!(!rows[0].is_current);
        assert_eq!(rows[1].snapshot_id, "1081");
        assert!(rows[1].is_current);
        assert_eq!(rows[1].description, "writable copy of #1077");
        assert_eq!(rows[1].pre_number, None);
    }

    #[test]
    fn parses_snapper_list_empty_fields_and_skips_header_separator_rows() {
        let output = "\
# | Type | Pre # | Date | User | Used Space | Cleanup | Description | Userdata
--+------+-------+------+------|------------+---------+-------------+---------
42 | pre | | Tue Mar 10 10:00:00 2026 | root | | timeline | before update |
";

        let rows = parse_snapper_list_output(output).expect("parse snapper list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].snapshot_id, "42");
        assert_eq!(rows[0].snapshot_type, "pre");
        assert_eq!(rows[0].pre_number, None);
        assert_eq!(rows[0].used_space, "");
        assert_eq!(rows[0].userdata, "");
    }

    #[test]
    fn snapper_list_parser_rejects_unrelated_output() {
        let output = "snapper command failed unexpectedly";
        assert!(parse_snapper_list_output(output).is_err());
    }

    #[test]
    fn parse_package_locks_defensive_preserves_unparsed_rows() {
        let output = "\
| # | Name | Type |
|---+------+------|
| 1 | MozillaFirefox | package |
| broken row without expected columns |
";

        let (locks, fallback_rows) = parse_package_locks_defensive(output);
        assert_eq!(locks.len(), 2);
        assert_eq!(fallback_rows, 1);
        assert!(locks
            .iter()
            .any(|lock| lock.raw_entry == "| broken row without expected columns |"));
    }

    #[test]
    fn parse_package_locks_defensive_soft_fallback_for_non_table_output() {
        let output = "\
No locks defined.
Try zypper addlock <name>.
";

        let (locks, fallback_rows) = parse_package_locks_defensive(output);
        assert_eq!(locks.len(), 2);
        assert_eq!(fallback_rows, 2);
        assert_eq!(locks[0].raw_entry, "No locks defined.");
        assert_eq!(locks[1].raw_entry, "Try zypper addlock <name>.");
    }

    #[test]
    fn run_summary_is_not_persisted_when_structured_reconcile_summary_exists() {
        let base = std::env::temp_dir().join(uniq("ops-reconcile-persist"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, true, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let mut state = RunState::default();
        let (tx, _rx) = channel();

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            structured(OpsEventKind::ReconcileSummary {
                attempted: 1,
                installed: 1,
                failed: 0,
                unaccounted: 0,
                verdict: "PASS".to_string(),
            }),
        );
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::RunSummary(RunSummary {
                verdict: "PASS".to_string(),
                attempted: 1,
                installed: 1,
                failed: 0,
                unaccounted: 0,
                process_run: Some(ProcessRun {
                    run_id: run_id.clone(),
                    backend: PackageBackend::Zypper,
                    command: "zypper".to_string(),
                    args: Vec::new(),
                    started_at_utc: "0".to_string(),
                    ended_at_utc: Some("1".to_string()),
                    duration_ms: Some(1),
                    events: vec![PackageEvent {
                        ts_ms: Some(0),
                        backend: PackageBackend::Zypper,
                        kind: PackageEventKind::UpgradeSucceeded,
                        package_name: "mesa".to_string(),
                        package_name_norm: "mesa".to_string(),
                        arch: Some("x86_64".to_string()),
                        from_version: Some("24.0".to_string()),
                        to_version: Some("24.1".to_string()),
                        repo: Some("repo-oss".to_string()),
                        level: EventLevel::Info,
                        raw_line: None,
                        reason: None,
                    }],
                    summary: ProcessSummary {
                        process_name: "zypper".to_string(),
                        process_type: "update".to_string(),
                        status: ProcessStatus::Success,
                        reboot_recommended: false,
                        test_required: false,
                        summary_line: "done".to_string(),
                        exit_code: Some(0),
                        confidence: Confidence::Medium,
                        error_category: None,
                    },
                }),
                reconcile: Some(ReconcileResult {
                    run_id: run_id.clone(),
                    total_planned: 1,
                    matched_success: 1,
                    matched_failed: 0,
                    skipped: 0,
                    not_attempted: 0,
                    ambiguous: 0,
                    items: vec![ReconcileMatch {
                        status: ReconcileStatus::Succeeded,
                        match_confidence: MatchConfidence::Exact,
                        triage_id: "plan-0".to_string(),
                        planned_action: PlannedAction::Upgrade,
                        planned_package_name: "mesa".to_string(),
                        planned_package_name_norm: "mesa".to_string(),
                        planned_arch: Some("x86_64".to_string()),
                        planned_from_version: Some("24.0".to_string()),
                        planned_to_version: Some("24.1".to_string()),
                        matched_event_index: Some(0),
                        actual_event_kind: Some(PackageEventKind::UpgradeSucceeded),
                        actual_package_name: Some("mesa".to_string()),
                        actual_arch: Some("x86_64".to_string()),
                        actual_from_version: Some("24.0".to_string()),
                        actual_to_version: Some("24.1".to_string()),
                        reason: None,
                        note: "exact match".to_string(),
                    }],
                }),
            }),
        );

        let stored = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_events(&run_id)
            .expect("load events");

        assert_eq!(
            stored
                .iter()
                .filter(|event| event.event_type == "reconcile.summary")
                .count(),
            1
        );
        assert_eq!(
            stored
                .iter()
                .filter(|event| {
                    event.message == "Attempted=1 Installed=1 Failed=0 Unaccounted=0 Verdict=PASS"
                })
                .count(),
            1
        );
        let packages = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_packages(&run_id)
            .expect("load packages");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].run_id, run_id);
        assert_eq!(packages[0].package_name, "mesa");
        assert_eq!(packages[0].from_version.as_deref(), Some("24.0"));
        assert_eq!(packages[0].to_version.as_deref(), Some("24.1"));
        assert_eq!(packages[0].arch.as_deref(), Some("x86_64"));
        assert_eq!(packages[0].repository.as_deref(), Some("repo-oss"));
        assert_eq!(packages[0].action.as_deref(), Some("upgrade"));
        assert_eq!(packages[0].result.as_deref(), Some("succeeded"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn structured_ai_analysis_is_persisted_to_ai_assessments() {
        let base = std::env::temp_dir().join(uniq("ops-ai-assessment-persist"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, true, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let mut state = RunState::default();
        let (tx, _rx) = channel();

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            structured(OpsEventKind::AIAnalysis {
                risk: "Amber".to_string(),
                rationale: Some("legacy rationale ignored by reports".to_string()),
                recommendations: vec![
                    "1) Snapshot first.".to_string(),
                    "2) Reboot after update.".to_string(),
                ],
            }),
        );

        let assessment = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_ai_assessment(&run_id)
            .expect("load ai assessment")
            .expect("ai assessment row");

        assert_eq!(assessment.run_id, run_id);
        assert_eq!(assessment.risk_level.as_deref(), Some("Amber"));
        assert_eq!(
            assessment.recommendations_json,
            r#"["1) Snapshot first.","2) Reboot after update."]"#
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn package_evidence_risk_covers_kernel_release_remove_and_downgrade() {
        let summary = RunSummary {
            verdict: "PASS".to_string(),
            attempted: 4,
            installed: 4,
            failed: 0,
            unaccounted: 0,
            process_run: Some(ProcessRun {
                run_id: "run-1".to_string(),
                backend: PackageBackend::Zypper,
                command: "zypper".to_string(),
                args: Vec::new(),
                started_at_utc: "0".to_string(),
                ended_at_utc: Some("1".to_string()),
                duration_ms: Some(1),
                events: vec![
                    PackageEvent {
                        ts_ms: Some(0),
                        backend: PackageBackend::Zypper,
                        kind: PackageEventKind::UpgradeSucceeded,
                        package_name: "kernel-default".to_string(),
                        package_name_norm: "kernel-default".to_string(),
                        arch: Some("x86_64".to_string()),
                        from_version: Some("6.8.0".to_string()),
                        to_version: Some("6.9.0".to_string()),
                        repo: Some("repo-oss".to_string()),
                        level: EventLevel::Info,
                        raw_line: None,
                        reason: None,
                    },
                    PackageEvent {
                        ts_ms: Some(1),
                        backend: PackageBackend::Zypper,
                        kind: PackageEventKind::UpgradeSucceeded,
                        package_name: "openSUSE-release".to_string(),
                        package_name_norm: "opensuse-release".to_string(),
                        arch: Some("x86_64".to_string()),
                        from_version: Some("20260310".to_string()),
                        to_version: Some("20260312".to_string()),
                        repo: Some("repo-oss".to_string()),
                        level: EventLevel::Info,
                        raw_line: None,
                        reason: None,
                    },
                    PackageEvent {
                        ts_ms: Some(2),
                        backend: PackageBackend::Zypper,
                        kind: PackageEventKind::RemoveSucceeded,
                        package_name: "ffmpeg".to_string(),
                        package_name_norm: "ffmpeg".to_string(),
                        arch: Some("x86_64".to_string()),
                        from_version: Some("8.0".to_string()),
                        to_version: None,
                        repo: Some("packman".to_string()),
                        level: EventLevel::Info,
                        raw_line: None,
                        reason: None,
                    },
                    PackageEvent {
                        ts_ms: Some(3),
                        backend: PackageBackend::Zypper,
                        kind: PackageEventKind::DowngradeSucceeded,
                        package_name: "mesa".to_string(),
                        package_name_norm: "mesa".to_string(),
                        arch: Some("x86_64".to_string()),
                        from_version: Some("24.1".to_string()),
                        to_version: Some("24.0".to_string()),
                        repo: Some("repo-oss".to_string()),
                        level: EventLevel::Info,
                        raw_line: None,
                        reason: None,
                    },
                ],
                summary: ProcessSummary {
                    process_name: "zypper".to_string(),
                    process_type: "update".to_string(),
                    status: ProcessStatus::Success,
                    reboot_recommended: false,
                    test_required: false,
                    summary_line: "done".to_string(),
                    exit_code: Some(0),
                    confidence: Confidence::Medium,
                    error_category: None,
                },
            }),
            reconcile: Some(ReconcileResult {
                run_id: "run-1".to_string(),
                total_planned: 4,
                matched_success: 4,
                matched_failed: 0,
                skipped: 0,
                not_attempted: 0,
                ambiguous: 0,
                items: vec![
                    ReconcileMatch {
                        status: ReconcileStatus::Succeeded,
                        match_confidence: MatchConfidence::Exact,
                        triage_id: "plan-0".to_string(),
                        planned_action: PlannedAction::Upgrade,
                        planned_package_name: "kernel-default".to_string(),
                        planned_package_name_norm: "kernel-default".to_string(),
                        planned_arch: Some("x86_64".to_string()),
                        planned_from_version: Some("6.8.0".to_string()),
                        planned_to_version: Some("6.9.0".to_string()),
                        matched_event_index: Some(0),
                        actual_event_kind: Some(PackageEventKind::UpgradeSucceeded),
                        actual_package_name: Some("kernel-default".to_string()),
                        actual_arch: Some("x86_64".to_string()),
                        actual_from_version: Some("6.8.0".to_string()),
                        actual_to_version: Some("6.9.0".to_string()),
                        reason: None,
                        note: "kernel upgraded".to_string(),
                    },
                    ReconcileMatch {
                        status: ReconcileStatus::Succeeded,
                        match_confidence: MatchConfidence::Exact,
                        triage_id: "plan-1".to_string(),
                        planned_action: PlannedAction::Upgrade,
                        planned_package_name: "openSUSE-release".to_string(),
                        planned_package_name_norm: "opensuse-release".to_string(),
                        planned_arch: Some("x86_64".to_string()),
                        planned_from_version: Some("20260310".to_string()),
                        planned_to_version: Some("20260312".to_string()),
                        matched_event_index: Some(1),
                        actual_event_kind: Some(PackageEventKind::UpgradeSucceeded),
                        actual_package_name: Some("openSUSE-release".to_string()),
                        actual_arch: Some("x86_64".to_string()),
                        actual_from_version: Some("20260310".to_string()),
                        actual_to_version: Some("20260312".to_string()),
                        reason: None,
                        note: "release upgraded".to_string(),
                    },
                    ReconcileMatch {
                        status: ReconcileStatus::Succeeded,
                        match_confidence: MatchConfidence::Exact,
                        triage_id: "plan-2".to_string(),
                        planned_action: PlannedAction::Remove,
                        planned_package_name: "ffmpeg".to_string(),
                        planned_package_name_norm: "ffmpeg".to_string(),
                        planned_arch: Some("x86_64".to_string()),
                        planned_from_version: Some("8.0".to_string()),
                        planned_to_version: None,
                        matched_event_index: Some(2),
                        actual_event_kind: Some(PackageEventKind::RemoveSucceeded),
                        actual_package_name: Some("ffmpeg".to_string()),
                        actual_arch: Some("x86_64".to_string()),
                        actual_from_version: Some("8.0".to_string()),
                        actual_to_version: None,
                        reason: None,
                        note: "ffmpeg removed".to_string(),
                    },
                    ReconcileMatch {
                        status: ReconcileStatus::Succeeded,
                        match_confidence: MatchConfidence::Exact,
                        triage_id: "plan-3".to_string(),
                        planned_action: PlannedAction::Downgrade,
                        planned_package_name: "mesa".to_string(),
                        planned_package_name_norm: "mesa".to_string(),
                        planned_arch: Some("x86_64".to_string()),
                        planned_from_version: Some("24.1".to_string()),
                        planned_to_version: Some("24.0".to_string()),
                        matched_event_index: Some(3),
                        actual_event_kind: Some(PackageEventKind::DowngradeSucceeded),
                        actual_package_name: Some("mesa".to_string()),
                        actual_arch: Some("x86_64".to_string()),
                        actual_from_version: Some("24.1".to_string()),
                        actual_to_version: Some("24.0".to_string()),
                        reason: None,
                        note: "mesa downgraded".to_string(),
                    },
                ],
            }),
        };

        let rows = package_evidence_rows_for_summary("run-1", &summary);
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.iter()
                .find(|row| row.package_name == "kernel-default")
                .and_then(|row| row.risk.as_deref()),
            Some("amber")
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.package_name == "openSUSE-release")
                .and_then(|row| row.risk.as_deref()),
            Some("amber")
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.package_name == "ffmpeg")
                .and_then(|row| row.risk.as_deref()),
            Some("amber")
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.package_name == "mesa")
                .and_then(|row| row.risk.as_deref()),
            Some("amber")
        );
    }

    #[test]
    fn zypper_apply_command_result_updates_state_without_persisting_duplicate_row() {
        let base = std::env::temp_dir().join(uniq("ops-apply-command-result"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, true, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let mut state = RunState::default();
        let (tx, rx) = channel();

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            structured(OpsEventKind::ApplyStart),
        );
        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::CommandResult {
                operation: OperationKind::UpdatesZypperApply,
                result: CommandResult {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
            },
        );

        assert_eq!(state.zypper_apply_exit_code, Some(0));
        assert!(!state.apply_active);

        let emitted: Vec<_> = rx.try_iter().collect();
        assert!(emitted.iter().any(|event| {
            matches!(
                event,
                OpsEvent::CommandResult {
                    operation: OperationKind::UpdatesZypperApply,
                    result
                } if result.exit_code == 0
            )
        }));
        assert!(emitted.iter().any(|event| {
            matches!(
                event,
                OpsEvent::Structured(event)
                    if matches!(event.kind, OpsEventKind::ApplyResult { exit_code: 0 })
            )
        }));

        let stored = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_events(&run_id)
            .expect("load events");

        assert_eq!(
            stored
                .iter()
                .filter(|event| event.event_type == "zypper.apply.result")
                .count(),
            1
        );
        assert_eq!(
            stored
                .iter()
                .filter(|event| event.message == "Apply completed with exit code 0")
                .count(),
            1
        );
        assert!(!stored
            .iter()
            .any(|event| event.message == "Completed with exit code 0"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn zypper_preview_command_result_is_not_persisted() {
        let base = std::env::temp_dir().join(uniq("ops-preview-command-result"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, true, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let mut state = RunState::default();
        let (tx, rx) = channel();

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::CommandResult {
                operation: OperationKind::UpdatesZypperPreview,
                result: CommandResult {
                    stdout: String::new(),
                    stderr: "preview parse failed".to_string(),
                    exit_code: 1,
                },
            },
        );

        let emitted: Vec<_> = rx.try_iter().collect();
        assert!(emitted.iter().any(|event| {
            matches!(
                event,
                OpsEvent::CommandResult {
                    operation: OperationKind::UpdatesZypperPreview,
                    result
                } if result.exit_code == 1
            )
        }));

        let stored = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_events(&run_id)
            .expect("load events");
        assert!(stored.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn attach_or_create_persisted_run_reuses_existing_open_master_run() {
        let base = std::env::temp_dir().join(uniq("ops-attach-master-run"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");

        let preview_selection = UpdateRunSelection::preview();
        let preview_run =
            create_persisted_run(Some(store), &preview_selection).expect("preview run");
        let run_id = preview_run.run_id.clone();
        let preview_selection_json =
            serde_json::to_string(&preview_selection).expect("serialize preview selection");
        assert_eq!(
            preview_run
                .store
                .list_runs(10)
                .expect("list runs")
                .first()
                .map(|row| row.selection_json.as_str()),
            Some(preview_selection_json.as_str())
        );

        let apply_selection = UpdateRunSelection::from_flags(true, true, false, false, false);
        let apply_selection_json =
            serde_json::to_string(&apply_selection).expect("serialize apply selection");
        let attached = attach_or_create_persisted_run(
            Some(preview_run.store),
            Some(&run_id),
            &apply_selection,
        )
        .expect("attach existing master run");

        assert_eq!(attached.run_id, run_id);
        let runs = attached.store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].selection_json, apply_selection_json);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn create_master_run_with_optional_plan_persists_canonical_snapshot() {
        let base = std::env::temp_dir().join(uniq("ops-master-run-preview"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(true, true, false, false, false);
        let plan = UpdatePlan {
            changes: vec![PackageChange {
                name: "mesa".to_string(),
                arch: Some("x86_64".to_string()),
                action: UpdateAction::Upgrade,
                from: Some("24.0".to_string()),
                to: Some("24.1".to_string()),
                repo: Some("repo-oss".to_string()),
                vendor: Some("openSUSE".to_string()),
                kind: None,
            }],
            command: vec![
                "zypper".to_string(),
                "dup".to_string(),
                "--dry-run".to_string(),
            ],
            result: CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        };

        let run_id = create_master_run_with_optional_plan_in_store(&store, &selection, Some(&plan))
            .expect("create master run");

        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        let events = store.load_events(&run_id).expect("load events");
        assert!(events
            .iter()
            .any(|event| event.event_type == "preview.result"));
        assert!(events
            .iter()
            .any(|event| event.event_type == "zypper.preview.plan"));
        let packages = store.load_packages(&run_id).expect("load packages");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_name, "mesa");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn selection_has_any_requested_task_detects_empty_and_non_empty_runs() {
        let empty = UpdateRunSelection::from_flags(false, false, false, false, false);
        assert!(!selection_has_any_requested_task(&empty));

        let flatpak_only = UpdateRunSelection::from_flags(false, false, false, true, false);
        assert!(selection_has_any_requested_task(&flatpak_only));

        let journal_only = UpdateRunSelection::from_flags(false, false, false, false, true);
        assert!(selection_has_any_requested_task(&journal_only));

        let packman_only = UpdateRunSelection::from_flags(false, false, true, false, false);
        assert!(selection_has_any_requested_task(&packman_only));
    }

    #[test]
    fn normalize_execution_selection_blocks_packman_without_zypper_and_skips_snapshot_without_zypper(
    ) {
        let selection = UpdateRunSelection::from_flags(true, false, true, false, false);
        let plan = normalize_execution_selection(selection);

        assert!(!plan.effective_selection.snapshot_before_update);
        assert!(!plan.effective_selection.prefer_packman);
        assert_eq!(plan.notices.len(), 2);
        assert!(plan
            .notices
            .iter()
            .any(|notice| notice.message == "Prefer Packman requires zypper dup to be selected."));
        assert!(plan
            .notices
            .iter()
            .any(|notice| notice.message == "Snapshot before update requires a zypper dup task."));
    }

    #[test]
    fn normalize_execution_selection_keeps_valid_mixed_selection_unchanged() {
        let selection = UpdateRunSelection::from_flags(true, true, true, true, true);
        let plan = normalize_execution_selection(selection.clone());

        assert_eq!(
            plan.effective_selection.snapshot_before_update,
            selection.snapshot_before_update
        );
        assert_eq!(plan.effective_selection.zypper_dup, selection.zypper_dup);
        assert_eq!(
            plan.effective_selection.prefer_packman,
            selection.prefer_packman
        );
        assert_eq!(plan.effective_selection.flatpak, selection.flatpak);
        assert_eq!(
            plan.effective_selection.journal_vacuum,
            selection.journal_vacuum
        );
        assert!(plan.notices.is_empty());
    }

    #[test]
    fn update_plan_persistence_replaces_package_rows_for_master_run() {
        let base = std::env::temp_dir().join(uniq("ops-update-plan-persist"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, true, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let mut state = RunState::default();
        let (tx, _rx) = channel();
        let plan = UpdatePlan {
            changes: vec![PackageChange {
                name: "mesa".to_string(),
                arch: Some("x86_64".to_string()),
                action: UpdateAction::Upgrade,
                from: Some("24.0".to_string()),
                to: Some("24.1".to_string()),
                repo: Some("repo-oss".to_string()),
                vendor: Some("openSUSE".to_string()),
                kind: None,
            }],
            command: vec![
                "zypper".to_string(),
                "dup".to_string(),
                "--dry-run".to_string(),
            ],
            result: CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        };

        emit_event(
            &tx,
            &mut finalize_guard,
            &mut state,
            OpsEvent::UpdatePlan(plan),
        );

        let packages = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .load_packages(&run_id)
            .expect("load packages");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_name, "mesa");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn finish_persisted_run_uses_skip_verdict_override_for_empty_selection() {
        let base = std::env::temp_dir().join(uniq("ops-empty-selection-skip"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, false, false, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let state = RunState {
            verdict_override: Some("SKIP".to_string()),
            ..RunState::default()
        };

        finish_persisted_run(&mut finalize_guard, &state);

        let runs = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .list_runs(10)
            .expect("list runs");
        let row = runs
            .into_iter()
            .find(|row| row.run_id == run_id)
            .expect("run row");
        assert_eq!(row.verdict.as_deref(), Some("SKIP"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn finish_persisted_run_uses_blocked_verdict_when_only_blocked_tasks_remain() {
        let base = std::env::temp_dir().join(uniq("ops-blocked-selection"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, false, true, false, false);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let state = RunState {
            had_blocked_task: true,
            ..RunState::default()
        };

        finish_persisted_run(&mut finalize_guard, &state);

        let runs = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .list_runs(10)
            .expect("list runs");
        let row = runs
            .into_iter()
            .find(|row| row.run_id == run_id)
            .expect("run row");
        assert_eq!(row.verdict.as_deref(), Some("BLOCKED"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn finish_persisted_run_prefers_fail_over_blocked_and_skip_states() {
        let base = std::env::temp_dir().join(uniq("ops-fail-precedence"));
        fs::create_dir_all(&base).expect("mkdir");
        let db_path = base.join("report-store.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(false, false, false, true, true);
        let persisted = create_persisted_run(Some(store), &selection).expect("persisted run");
        let run_id = persisted.run_id.clone();
        let mut finalize_guard = RunFinalizeGuard::new(Some(persisted));
        let state = RunState {
            had_error: true,
            had_blocked_task: true,
            had_skipped_task: true,
            ..RunState::default()
        };

        finish_persisted_run(&mut finalize_guard, &state);

        let runs = finalize_guard
            .run
            .as_ref()
            .expect("persisted run available")
            .store
            .list_runs(10)
            .expect("list runs");
        let row = runs
            .into_iter()
            .find(|row| row.run_id == run_id)
            .expect("run row");
        assert_eq!(row.verdict.as_deref(), Some("FAIL"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn run_summary_uses_persisted_master_run_id_as_report_anchor() {
        let plan = UpdatePlan {
            changes: vec![PackageChange {
                name: "mesa".to_string(),
                arch: Some("x86_64".to_string()),
                action: UpdateAction::Upgrade,
                from: Some("24.0".to_string()),
                to: Some("24.1".to_string()),
                repo: Some("repo-oss".to_string()),
                vendor: Some("openSUSE".to_string()),
                kind: None,
            }],
            command: vec!["zypper".to_string(), "dup".to_string()],
            result: CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        };
        let state = RunState {
            master_run_id: Some("master-run-1".to_string()),
            zypper_plan: Some(plan),
            zypper_apply_exit_code: Some(0),
            ..RunState::default()
        };

        let summary = build_run_summary(&state).expect("build run summary");
        assert_eq!(
            summary.process_run.as_ref().map(|run| run.run_id.as_str()),
            Some("master-run-1")
        );
        assert_eq!(
            summary.reconcile.as_ref().map(|run| run.run_id.as_str()),
            Some("master-run-1")
        );
    }

    #[test]
    fn preview_noop_output_is_treated_as_zero_updates_not_failure() {
        let stdout = r#"<stream><message type="info">Nothing to do.</message></stream>"#;

        let changes = super::parse_preview_changes_or_noop(stdout, "").expect("parse noop preview");

        assert!(changes.is_empty());
    }

    #[test]
    fn invalid_preview_output_still_errors() {
        let err = super::parse_preview_changes_or_noop("<stream><message>", "")
            .expect_err("invalid output");

        assert!(!err.is_empty());
        assert!(!super::preview_output_indicates_noop(
            "<stream><message>",
            ""
        ));
    }
}
