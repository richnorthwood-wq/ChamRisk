use std::sync::mpsc::Sender;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpsEventKind {
    RunStart,
    RunEnd,
    SnapshotStart,
    SnapshotSuccess {
        snapshot_id: Option<u64>,
    },
    SnapshotFailure {
        reason: String,
    },
    PreviewStart,
    PreviewResult {
        packages: usize,
    },
    AIAnalysis {
        risk: String,
        rationale: Option<String>,
        recommendations: Vec<String>,
    },
    ApplyStart,
    ApplyResult {
        exit_code: i32,
    },
    PackageInstalled {
        name: String,
        from: Option<String>,
        to: Option<String>,
        repo: Option<String>,
        arch: Option<String>,
    },
    PackageRemoved {
        name: String,
        from: Option<String>,
        to: Option<String>,
        repo: Option<String>,
        arch: Option<String>,
    },
    PackageUpgraded {
        name: String,
        from: Option<String>,
        to: Option<String>,
        repo: Option<String>,
        arch: Option<String>,
    },
    FlatpakUpdated {
        app_id: String,
    },
    ReconcileSummary {
        attempted: u32,
        installed: u32,
        failed: u32,
        unaccounted: u32,
        verdict: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsEvent {
    pub ts_ms: i64,
    pub phase: String,
    pub severity: String,
    pub kind: OpsEventKind,
}

impl OpsEvent {
    pub fn from_kind(kind: OpsEventKind) -> Self {
        let (phase, severity) = phase_and_severity(&kind);
        Self {
            ts_ms: now_ms(),
            phase: phase.to_string(),
            severity: severity.to_string(),
            kind,
        }
    }
}

pub fn emit(tx: &Sender<OpsEvent>, kind: OpsEventKind) {
    let _ = tx.send(OpsEvent::from_kind(kind));
}

fn phase_and_severity(kind: &OpsEventKind) -> (&'static str, &'static str) {
    match kind {
        OpsEventKind::RunStart | OpsEventKind::RunEnd => ("run", "info"),
        OpsEventKind::SnapshotStart | OpsEventKind::SnapshotSuccess { .. } => ("btrfs", "info"),
        OpsEventKind::SnapshotFailure { .. } => ("btrfs", "error"),
        OpsEventKind::PreviewStart | OpsEventKind::PreviewResult { .. } => ("zypper", "info"),
        OpsEventKind::AIAnalysis { .. } => ("run", "info"),
        OpsEventKind::ApplyStart | OpsEventKind::ApplyResult { .. } => ("zypper", "info"),
        OpsEventKind::PackageInstalled { .. }
        | OpsEventKind::PackageRemoved { .. }
        | OpsEventKind::PackageUpgraded { .. } => ("zypper", "info"),
        OpsEventKind::FlatpakUpdated { .. } => ("flatpak", "info"),
        OpsEventKind::ReconcileSummary { verdict, .. } => {
            if verdict == "PASS" {
                ("reconcile", "info")
            } else {
                ("reconcile", "warn")
            }
        }
        OpsEventKind::Error { .. } => ("run", "error"),
    }
}

fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().try_into().unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
