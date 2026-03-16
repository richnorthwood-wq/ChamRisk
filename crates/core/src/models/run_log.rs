// models/run_log.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageBackend {
    Zypper,
    Dnf,
    Pacman,
    Btrfs, // keep if you're logging snapshots/rollback actions too
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageEventKind {
    Planned, // optional if parser emits detected intents
    InstallSucceeded,
    UpdateSucceeded,
    UpgradeSucceeded,
    DowngradeSucceeded,
    RemoveSucceeded,
    InstallFailed,
    UpdateFailed,
    UpgradeFailed,
    DowngradeFailed,
    RemoveFailed,
    Skipped,
}

#[derive(Debug, Clone)]
pub struct PackageEvent {
    pub ts_ms: Option<u64>, // optional timestamp/order marker
    pub backend: PackageBackend,
    pub kind: PackageEventKind,
    pub package_name: String,
    pub package_name_norm: String,
    pub arch: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub repo: Option<String>,
    pub level: EventLevel,
    pub raw_line: Option<String>, // useful for diagnostics
    pub reason: Option<String>,   // conflict, missing key, lock, etc
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessStatus {
    Success,
    Partial,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCategory {
    DependencyConflict,
    RepoUnavailable,
    GpgKey,
    LockHeld,
    DiskSpace,
    Network,
    ScriptletFailure,
    Permission,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProcessSummary {
    pub process_name: String, // "zypper", "dnf", "pacman", "btrfs"
    pub process_type: String, // update/install/remove/...
    pub status: ProcessStatus,
    pub reboot_recommended: bool,
    pub test_required: bool,
    pub summary_line: String,

    // completion-level fields (your point exactly)
    pub exit_code: Option<i32>,
    pub confidence: Confidence,
    pub error_category: Option<ErrorCategory>,
}

#[derive(Debug, Clone)]
pub struct ProcessRun {
    pub run_id: String,
    pub backend: PackageBackend,
    pub command: String,
    pub args: Vec<String>,
    pub started_at_utc: String,
    pub ended_at_utc: Option<String>,
    pub duration_ms: Option<u64>,

    pub events: Vec<PackageEvent>,
    pub summary: ProcessSummary,
}
