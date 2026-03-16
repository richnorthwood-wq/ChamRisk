use crate::health::HealthReport;
use crate::health::SystemPulse;
use crate::health::SystemTelemetry;
use chamrisk_core::models::{
    BtrfsSnapshotRow, CommandResult, PackageLock, ProcessRun, ReconcileResult, UpdatePlan,
};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc::Sender, Arc, Mutex, OnceLock};
use std::thread;

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub verdict: String,
    pub attempted: i64,
    pub installed: i64,
    pub failed: i64,
    pub unaccounted: i64,
    pub process_run: Option<ProcessRun>,
    pub reconcile: Option<ReconcileResult>,
}

impl PartialEq for RunSummary {
    fn eq(&self, other: &Self) -> bool {
        self.verdict == other.verdict
            && self.attempted == other.attempted
            && self.installed == other.installed
            && self.failed == other.failed
            && self.unaccounted == other.unaccounted
            && self.process_run.as_ref().map(|run| run.run_id.as_str())
                == other.process_run.as_ref().map(|run| run.run_id.as_str())
            && self.reconcile.as_ref().map(|recon| {
                (
                    recon.run_id.as_str(),
                    recon.total_planned,
                    recon.matched_success,
                    recon.matched_failed,
                    recon.skipped,
                    recon.not_attempted,
                    recon.ambiguous,
                )
            }) == other.reconcile.as_ref().map(|recon| {
                (
                    recon.run_id.as_str(),
                    recon.total_planned,
                    recon.matched_success,
                    recon.matched_failed,
                    recon.skipped,
                    recon.not_attempted,
                    recon.ambiguous,
                )
            })
    }
}

impl Eq for RunSummary {}

#[derive(Debug, Clone, PartialEq)]
pub enum OpsEvent {
    Structured(crate::events::OpsEvent),
    Log {
        stream: LogStream,
        line: String,
    },
    Progress(String),
    Error(String),
    CommandResult {
        operation: OperationKind,
        result: CommandResult,
    },
    UpdatePlan(UpdatePlan),
    RunSummary(RunSummary),
    PackageIndex(Vec<chamrisk_core::models::PackageRow>),
    BtrfsSnapshots(Vec<BtrfsSnapshotRow>),
    PackageLocks(Vec<PackageLock>),
    PackageLockOperationCompleted {
        action: String,
        name: String,
        success: bool,
        message: String,
    },
    HealthReport(HealthReport),
    SystemPulse(SystemPulse),
    TelemetryUpdate(SystemTelemetry),
    UpdateProgress {
        package: String,
        processed: u32,
        total: u32,
    },
    UpdatePhase(String),
    SystemWorkbookExportProgress(String),
    SystemWorkbookExportCompleted {
        path: PathBuf,
    },
    SystemWorkbookExportFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Updates,
    Btrfs,
    PackageManager,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    UpdatesZypperPreview,
    UpdatesZypperApply,
    UpdatesFlatpak,
    UpdatesJournalVacuum,
    UpdatesOther,
    Btrfs,
    PackageManager,
}

static ZYPP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn zypp_lock() -> &'static Mutex<()> {
    ZYPP_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Default)]
pub struct Runner;

impl Runner {
    pub fn new() -> Self {
        Self
    }

    pub fn run(&self, cmd: &str, args: &[&str]) -> Result<CommandResult, String> {
        let output = Command::new(cmd)
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("spawn failed: {err}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok(CommandResult {
            stdout,
            stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

pub fn run_streaming(cmd: &str, args: &[&str], stream: LogStream, tx: Sender<OpsEvent>) {
    run_streaming_with_input(cmd, args, stream, tx, None);
}

pub(crate) fn normalize_zypper_log_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(message_xml) = extract_message_tag(trimmed) {
        let level = extract_message_type(message_xml)
            .map(|kind| kind.to_ascii_lowercase())
            .unwrap_or_else(|| "info".to_string());
        let level = match level.as_str() {
            "warning" | "warn" => "WARN",
            "error" => "ERROR",
            _ => "INFO",
        };
        let text = xml_unescape(&extract_message_text(message_xml));
        if text.is_empty() {
            return None;
        }
        return Some(format!("{level}: {text}"));
    }

    if trimmed.starts_with('<') {
        return None;
    }

    // Non-XML output is treated as informational.
    if trimmed.contains('<') && trimmed.contains('>') {
        return None;
    }

    Some(format!("INFO: {trimmed}"))
}

fn extract_message_tag(line: &str) -> Option<&str> {
    let start = line.find("<message")?;
    let tail = &line[start..];
    let close = tail.find("</message>")?;
    Some(&tail[..close + "</message>".len()])
}

fn xml_unescape(s: &str) -> String {
    s.replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn extract_message_type(line: &str) -> Option<String> {
    let marker = "type=\"";
    let start = line.find(marker)? + marker.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}

fn extract_message_text(line: &str) -> String {
    let Some(start) = line.find('>') else {
        return String::new();
    };
    let tail = &line[start + 1..];
    let Some(end) = tail.rfind("</message>") else {
        return tail.trim().to_string();
    };
    tail[..end].trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::{normalize_zypper_log_line, parse_zypper_progress, should_emit_progress};
    use std::sync::{Arc, Mutex};

    #[test]
    fn normalizes_message_line() {
        let line = r#"<message type="info">Loading repository data...</message>"#;
        assert_eq!(
            normalize_zypper_log_line(line),
            Some("INFO: Loading repository data...".to_string())
        );
    }

    #[test]
    fn normalizes_warning_and_unescapes_entities() {
        let line = r#"<message type="warning">See &apos;man zypper&apos;.</message>"#;
        assert_eq!(
            normalize_zypper_log_line(line),
            Some("WARN: See 'man zypper'.".to_string())
        );
    }

    #[test]
    fn drops_non_message_xml_lines() {
        assert_eq!(normalize_zypper_log_line("<?xml version='1.0'?>"), None);
        assert_eq!(normalize_zypper_log_line("<stream>"), None);
        assert_eq!(normalize_zypper_log_line("</stream>"), None);
        assert_eq!(
            normalize_zypper_log_line("<install-summary packages-to-change=\"0\">"),
            None
        );
    }

    #[test]
    fn handles_message_embedded_in_xml() {
        let line = "<stream><message type=\"info\">Nothing to do.</message></stream>";
        assert_eq!(
            normalize_zypper_log_line(line),
            Some("INFO: Nothing to do.".to_string())
        );
    }

    #[test]
    fn normalizes_plain_text_lines() {
        assert_eq!(
            normalize_zypper_log_line("Running command: sudo zypper dup"),
            Some("INFO: Running command: sudo zypper dup".to_string())
        );
    }

    #[test]
    fn parses_plain_text_install_progress() {
        assert_eq!(
            parse_zypper_progress("Installing: mesa-32bit-1.2.3.x86_64 [3/42]"),
            Some(("mesa-32bit-1.2.3.x86_64".to_string(), 3, 42))
        );
    }

    #[test]
    fn parses_normalized_xml_install_progress() {
        assert_eq!(
            parse_zypper_progress("INFO: Installing: MozillaFirefox-1.0.x86_64 [7/9]"),
            Some(("MozillaFirefox-1.0.x86_64".to_string(), 7, 9))
        );
    }

    #[test]
    fn ignores_unrelated_lines_for_progress() {
        assert_eq!(
            parse_zypper_progress("INFO: Installing patches is enabled"),
            None
        );
        assert_eq!(parse_zypper_progress("Retrieving: pkg [3%]"), None);
        assert_eq!(parse_zypper_progress("INFO: Done."), None);
    }

    #[test]
    fn dedupes_identical_progress_events() {
        let last_progress = Arc::new(Mutex::new(None));
        let progress = ("mesa".to_string(), 1, 4);

        assert!(should_emit_progress(&last_progress, &progress));
        assert!(!should_emit_progress(&last_progress, &progress));
        assert!(should_emit_progress(
            &last_progress,
            &("mesa".to_string(), 2, 4)
        ));
    }
}

fn should_check_zypp_lock(cmd: &str, args: &[String]) -> bool {
    invokes_zypper(cmd, args)
}

fn invokes_zypper(cmd: &str, args: &[String]) -> bool {
    if cmd == "zypper" {
        return true;
    }
    if cmd == "sudo" {
        return args.iter().any(|arg| arg == "zypper");
    }
    false
}

fn infer_operation_kind(cmd: &str, args: &[String], stream: LogStream) -> OperationKind {
    match stream {
        LogStream::Btrfs => OperationKind::Btrfs,
        LogStream::PackageManager => OperationKind::PackageManager,
        LogStream::Updates => {
            let invokes = |needle: &str| {
                cmd == needle || (cmd == "sudo" && args.iter().any(|arg| arg == needle))
            };

            if invokes("flatpak") {
                OperationKind::UpdatesFlatpak
            } else if invokes("journalctl") {
                OperationKind::UpdatesJournalVacuum
            } else if invokes("zypper") {
                let is_preview = args.iter().any(|arg| arg == "--dry-run");
                if is_preview {
                    OperationKind::UpdatesZypperPreview
                } else {
                    OperationKind::UpdatesZypperApply
                }
            } else {
                OperationKind::UpdatesOther
            }
        }
    }
}

fn handle_zypp_lock() -> Result<(), String> {
    let pid_file = Path::new("/var/run/zypp.pid");
    if !pid_file.exists() {
        return Ok(());
    }

    let raw_pid = fs::read_to_string(pid_file)
        .map_err(|e| format!("zypper lock file present but unreadable (/var/run/zypp.pid): {e}"))?;

    let pid: u32 = match raw_pid.trim().parse() {
        Ok(pid) => pid,
        Err(_) => {
            let _ = fs::remove_file(pid_file);
            return Ok(());
        }
    };

    let proc_path = Path::new("/proc").join(pid.to_string());
    if proc_path.exists() {
        return Err(format!("zypper already running (pid {pid})"));
    }

    fs::remove_file(pid_file)
        .map_err(|e| format!("failed to remove stale zypper lock file (/var/run/zypp.pid): {e}"))?;

    Ok(())
}

fn run_streaming_inner(
    cmd: String,
    args: Vec<String>,
    stream: LogStream,
    tx: Sender<OpsEvent>,
    stdin_input: Option<String>,
) {
    let operation = infer_operation_kind(&cmd, &args, stream);
    let should_lock = should_check_zypp_lock(&cmd, &args);
    let is_zypper = invokes_zypper(&cmd, &args);
    let _guard = if should_lock {
        Some(zypp_lock().lock().unwrap())
    } else {
        None
    };
    if should_lock {
        if let Err(msg) = handle_zypp_lock() {
            let _ = tx.send(OpsEvent::Error(msg));
            return;
        }
    }

    let mut child = match Command::new(&cmd)
        .args(&args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(OpsEvent::Error(format!("spawn failed: {e}")));
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
    let last_progress = Arc::new(Mutex::new(None::<(String, u32, u32)>));

    let stdout_handle = out.map(|stdout| {
        let tx2 = tx.clone();
        let stream2 = stream;
        let last_progress2 = Arc::clone(&last_progress);
        thread::spawn(move || {
            let mut local_raw = String::new();
            for line in BufReader::new(stdout).lines().flatten() {
                local_raw.push_str(&line);
                local_raw.push('\n');
                if is_zypper {
                    if let Some(normalized) = normalize_zypper_log_line(&line) {
                        emit_zypper_progress_once(&tx2, &last_progress2, &line, Some(&normalized));
                        let _ = tx2.send(OpsEvent::Log {
                            stream: stream2,
                            line: normalized,
                        });
                    } else {
                        emit_zypper_progress_once(&tx2, &last_progress2, &line, None);
                    }
                } else {
                    let _ = tx2.send(OpsEvent::Log {
                        stream: stream2,
                        line,
                    });
                }
            }
            local_raw
        })
    });

    let stderr_handle = err.map(|stderr| {
        let tx2 = tx.clone();
        let stream2 = stream;
        let last_progress2 = Arc::clone(&last_progress);
        thread::spawn(move || {
            let mut local_raw = String::new();
            for line in BufReader::new(stderr).lines().flatten() {
                local_raw.push_str(&line);
                local_raw.push('\n');
                if is_zypper {
                    if let Some(normalized) = normalize_zypper_log_line(&line) {
                        emit_zypper_progress_once(&tx2, &last_progress2, &line, Some(&normalized));
                        let _ = tx2.send(OpsEvent::Log {
                            stream: stream2,
                            line: normalized,
                        });
                    } else {
                        emit_zypper_progress_once(&tx2, &last_progress2, &line, None);
                    }
                } else {
                    let _ = tx2.send(OpsEvent::Log {
                        stream: stream2,
                        line,
                    });
                }
            }
            local_raw
        })
    });

    match child.wait() {
        Ok(status) => {
            let stdout = stdout_handle
                .and_then(|h| h.join().ok())
                .unwrap_or_default();
            let stderr = stderr_handle
                .and_then(|h| h.join().ok())
                .unwrap_or_default();

            let result = CommandResult {
                stdout,
                stderr,
                exit_code: status.code().unwrap_or(-1),
            };
            if result.exit_code != 0 {
                let stderr = result.stderr.trim_end();
                let message = if stderr.is_empty() {
                    format!("{cmd} {args:?} failed with exit code {}", result.exit_code)
                } else {
                    format!(
                        "{cmd} {args:?} failed with exit code {}\n{stderr}",
                        result.exit_code
                    )
                };
                let _ = tx.send(OpsEvent::Error(message));
            }
            let _ = tx.send(OpsEvent::CommandResult { operation, result });
        }
        Err(e) => {
            let _ = tx.send(OpsEvent::Error(format!("wait failed: {e}")));
        }
    }
}

pub fn run_streaming_with_input(
    cmd: &str,
    args: &[&str],
    stream: LogStream,
    tx: Sender<OpsEvent>,
    stdin_input: Option<String>,
) {
    let cmd = cmd.to_string();
    let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    thread::spawn(move || {
        run_streaming_inner(cmd, args, stream, tx, stdin_input);
    });
}

/// Blocking variant for sequential pipelines (zypper then flatpak, etc.)
pub fn run_streaming_blocking_with_input(
    cmd: &str,
    args: &[&str],
    stream: LogStream,
    tx: Sender<OpsEvent>,
    stdin_input: Option<String>,
) {
    let cmd = cmd.to_string();
    let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    run_streaming_inner(cmd, args, stream, tx, stdin_input);
}

fn parse_zypper_progress(line: &str) -> Option<(String, u32, u32)> {
    let stripped = line
        .trim()
        .strip_prefix("INFO: ")
        .unwrap_or(line.trim())
        .strip_prefix("Installing:")?
        .trim();
    let open = stripped.rfind('[')?;
    let close = stripped.rfind(']')?;
    if close <= open {
        return None;
    }

    let package = stripped[..open].trim();
    if package.is_empty() {
        return None;
    }

    let counters = &stripped[open + 1..close];
    let (processed, total) = counters.split_once('/')?;
    let processed = processed.trim().parse::<u32>().ok()?;
    let total = total.trim().parse::<u32>().ok()?;

    Some((package.to_string(), processed, total))
}

fn emit_zypper_progress_once(
    tx: &Sender<OpsEvent>,
    last_progress: &Arc<Mutex<Option<(String, u32, u32)>>>,
    raw_line: &str,
    normalized_line: Option<&str>,
) {
    let progress =
        parse_zypper_progress(raw_line).or_else(|| normalized_line.and_then(parse_zypper_progress));

    if let Some((package, processed, total)) = progress {
        let key = (package.clone(), processed, total);
        if should_emit_progress(last_progress, &key) {
            let _ = tx.send(OpsEvent::UpdateProgress {
                package,
                processed,
                total,
            });
        }
    }
}

fn should_emit_progress(
    last_progress: &Arc<Mutex<Option<(String, u32, u32)>>>,
    next: &(String, u32, u32),
) -> bool {
    let mut guard = last_progress.lock().unwrap();
    if guard.as_ref() == Some(next) {
        return false;
    }
    *guard = Some(next.clone());
    true
}

pub fn run_streaming_blocking(cmd: &str, args: &[&str], stream: LogStream, tx: Sender<OpsEvent>) {
    run_streaming_blocking_with_input(cmd, args, stream, tx, None);
}
