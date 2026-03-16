use chamrisk_core::models::{
    BtrfsSnapshotRow, CommandResult, PackageAction, PackageChange, PackageLock, PackageRow,
    PackageUpdate, ProcessRun, ReconcileResult, UpdateAction, UpdatePlan, VendorGroup,
};
use chamrisk_core::risk::{assess_risk, RiskLevel};
use chamrisk_ops::events::OpsEventKind;
use chamrisk_ops::runner::{LogStream, OperationKind, OpsEvent};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tab {
    Health,
    TriageAi,
    Reports,
    Btrfs,
    PackageManager,
    Configuration,
    About,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskFilter {
    All,
    Red,
    Amber,
    Green,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCol {
    Risk,
    Result,
    Name,
    Action,
    From,
    To,
    Repo,
    Vendor,
    Arch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortState {
    pub col: SortCol,
    pub asc: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            col: SortCol::Risk,
            asc: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct TriageCounts {
    pub all: usize,
    pub red: usize,
    pub amber: usize,
    pub green: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriagePreviewStatus {
    Empty,
    Updating,
    Complete,
}

impl Default for TriagePreviewStatus {
    fn default() -> Self {
        Self::Empty
    }
}

impl TriagePreviewStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Updating => "Updating",
            Self::Complete => "Complete",
        }
    }
}

#[derive(Debug, Clone)]
pub enum AppEvent {
    Refresh,
    RefreshUpdates,
    RefreshPackages,
    Quit,
    DemoUpdates,
    SimulateSuccess,
}

#[derive(Debug, Default)]
pub struct FilterCounts {
    pub all: usize,
    pub vendor_changes: usize,
    pub repo_changes: usize,
}

#[derive(Debug, Default)]
pub struct BtrfsStatus {
    pub please_wait: bool,
    pub completed: bool,
}

#[derive(Debug, Default)]
pub struct RunContext {
    pub run_id: Option<String>,
    pub zypper_requested: bool,
    pub zypper_plan: Option<UpdatePlan>,
    pub zypper_reconciled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    pub active: bool,
    pub phase: String,
    pub current_package: String,
    pub processed: u32,
    pub total: u32,
    pub exact_progress: bool,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            active: false,
            phase: "Idle".to_string(),
            current_package: String::new(),
            processed: 0,
            total: 0,
            exact_progress: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ExecutionSelectionState {
    pub snapshot_before_update: bool,
    pub zypper_dup: bool,
    pub packman_preference: bool,
    pub flatpaks: bool,
    pub journal_vacuum: bool,
}

#[derive(Debug, Default)]
pub struct PackageManagerTabState {
    pub rows: Vec<PackageRow>,
    pub locks: Vec<PackageLock>,
    pub filtered: Vec<usize>,
    pub search: String,
    pub last_search: String,
    pub selected: Option<usize>,
    pub selected_lock: Option<usize>,
    pub marks: std::collections::HashMap<String, PackageAction>,
    pub selected_row: Option<usize>,
    pub installed_mode: bool,
    pub dry_run: bool,
    pub last_error: Option<String>,
    pub preview_plan: Option<UpdatePlan>,
    pub preview_error: Option<String>,
    pub busy_preview: bool,
    pub busy_apply: bool,
    pub busy: bool,
    pub locks_busy: bool,
    pub apply_error: Option<String>,
    pub locks_error: Option<String>,
}

impl PackageManagerTabState {
    pub fn lock_name_index(&self) -> std::collections::HashSet<String> {
        self.locks.iter().map(|lock| lock.name.clone()).collect()
    }

    pub fn active_lock_count(&self) -> usize {
        self.locks
            .iter()
            .filter(|lock| {
                lock.lock_id
                    .as_deref()
                    .map(|id| !id.trim().is_empty())
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn rebuild_filtered(&mut self) {
        if self.search != self.last_search {
            let needle = self.search.trim().to_ascii_lowercase();
            self.filtered.clear();

            if needle.is_empty() {
                self.filtered.extend(0..self.rows.len());
            } else {
                for (i, pkg) in self.rows.iter().enumerate() {
                    let mut hit = pkg.name.to_ascii_lowercase().contains(&needle);

                    if !hit {
                        if let Some(r) = pkg.repository.as_deref() {
                            let r: &str = r;
                            hit = r.to_ascii_lowercase().contains(&needle);
                        }
                    }
                    if let Some(s) = pkg.summary.as_deref() {
                        let s: &str = s;
                        hit = hit || s.to_ascii_lowercase().contains(&needle);
                    }

                    if hit {
                        self.filtered.push(i);
                    }
                }
            }

            if let Some(sel) = self.selected {
                if !self.filtered.iter().any(|&x| x == sel) {
                    self.selected = None;
                }
            }

            self.last_search = self.search.clone();
        }
    }
}

#[allow(dead_code)]
fn can_mark_install(row: &PackageRow) -> bool {
    row.installed_version.is_none()
}

#[derive(Debug, Default)]
pub struct AiState {
    pub enabled: bool,
    pub preflight_ok: bool,
    pub last_error: Option<String>,
    pub assessment_risk: Option<String>,
    pub assessment_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStage {
    Preview,
    Apply,
    Locks,
    Install,
    Reconciliation,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub stage: LogStage,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoDialogState {
    pub title: String,
    pub message: String,
}

#[derive(Debug)]
pub struct MaintenanceApp {
    pub logs: Vec<LogEntry>,
    pub btrfs_available: bool,
    pub active_tab: Tab,
    pub updates_log: Vec<String>,
    pub btrfs_log: Vec<String>,
    pub btrfs_snapshots: Vec<BtrfsSnapshotRow>,
    pub btrfs_snapshots_error: Option<String>,
    pub info_dialog: Option<InfoDialogState>,
    pub changes: Vec<PackageChange>,
    pub selected: Option<usize>,
    pub update_plan: Option<UpdatePlan>,
    pub last_preview_result: Option<CommandResult>,
    pub last_preview_packages: Option<usize>,
    pub preview_running: bool,
    pub counts: FilterCounts,
    pub btrfs_status: BtrfsStatus,
    pub execution_selection: ExecutionSelectionState,
    pub ai_state: AiState,
    pub risk_filter: RiskFilter,
    pub sort_state: SortState,
    pub triage_counts: TriageCounts,
    pub triage_repos: Vec<String>,
    pub triage_preview_status: TriagePreviewStatus,
    pub filter_text: String,
    pub package_manager: PackageManagerTabState,
    pub last_run: Option<ProcessRun>,
    pub last_reconcile: Option<ReconcileResult>,
    pub active_execution: bool,
    pub current_run: Option<RunContext>,
    pub loaded_canonical_run_id: Option<String>,
}

impl Default for MaintenanceApp {
    fn default() -> Self {
        Self {
            logs: Vec::new(),
            btrfs_available: false,
            active_tab: Tab::Health,
            updates_log: Vec::new(),
            btrfs_log: Vec::new(),
            btrfs_snapshots: Vec::new(),
            btrfs_snapshots_error: None,
            info_dialog: None,
            changes: Vec::new(),
            last_run: None,
            last_reconcile: None,
            selected: None,
            update_plan: None,
            last_preview_result: None,
            last_preview_packages: None,
            preview_running: false,
            counts: FilterCounts::default(),
            btrfs_status: BtrfsStatus::default(),
            execution_selection: ExecutionSelectionState {
                snapshot_before_update: true,
                zypper_dup: true,
                packman_preference: true,
                flatpaks: true,
                journal_vacuum: true,
            },
            ai_state: AiState {
                enabled: true,
                preflight_ok: false,
                last_error: None,
                assessment_risk: None,
                assessment_summary: None,
            },
            risk_filter: RiskFilter::All,
            sort_state: SortState::default(),
            triage_counts: TriageCounts::default(),
            triage_repos: Vec::new(),
            triage_preview_status: TriagePreviewStatus::default(),
            filter_text: String::new(),
            package_manager: PackageManagerTabState::default(),
            active_execution: false,
            current_run: None,
            loaded_canonical_run_id: None,
        }
    }
}

impl MaintenanceApp {
    pub fn show_info_dialog(&mut self, title: impl Into<String>, message: impl Into<String>) {
        self.info_dialog = Some(InfoDialogState {
            title: title.into(),
            message: message.into(),
        });
    }

    pub fn dismiss_info_dialog(&mut self) {
        self.info_dialog = None;
    }

    pub fn request_btrfs_snapshot_export(&mut self) -> bool {
        if self.btrfs_snapshots.is_empty() {
            self.show_info_dialog("Snapshot export", "Please list snapshots first");
            return false;
        }
        true
    }

    fn log_level_for_message(message: &str) -> LogLevel {
        let normalized = message.trim_start();
        if normalized.starts_with("ERROR:") {
            LogLevel::Error
        } else if normalized.starts_with("WARN:") || normalized.starts_with("WARNING:") {
            LogLevel::Warn
        } else {
            LogLevel::Info
        }
    }

    fn log_stage_for_stream(stream: LogStream, message: &str) -> LogStage {
        match stream {
            LogStream::Btrfs => LogStage::System,
            LogStream::PackageManager => {
                let normalized = message.to_ascii_lowercase();
                if normalized.contains("preview") {
                    LogStage::Preview
                } else if normalized.contains("lock")
                    || normalized.contains("pkg_locks:")
                    || normalized.contains("pkg_lock_add:")
                    || normalized.contains("pkg_lock_remove:")
                    || normalized.contains("pkg_lock_clean:")
                {
                    LogStage::Locks
                } else {
                    LogStage::Apply
                }
            }
            LogStream::Updates => {
                let normalized = message.to_ascii_lowercase();
                if normalized.contains("preview") {
                    LogStage::Preview
                } else if normalized.contains("reconciliation")
                    || normalized.contains("verdict=")
                    || normalized.contains("attempted=")
                {
                    LogStage::Reconciliation
                } else if normalized.contains("installing:")
                    || normalized.contains("removing:")
                    || normalized.contains("upgrading:")
                    || normalized.contains("installed ")
                    || normalized.contains("removed ")
                    || normalized.contains("upgraded ")
                {
                    LogStage::Install
                } else if normalized.contains("apply")
                    || normalized.contains("installed")
                    || normalized.contains("updated")
                {
                    LogStage::Apply
                } else {
                    LogStage::System
                }
            }
        }
    }

    fn build_log_entry(stream: LogStream, message: &str) -> LogEntry {
        LogEntry {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            level: Self::log_level_for_message(message),
            stage: Self::log_stage_for_stream(stream, message),
            message: message.to_string(),
        }
    }

    fn build_log_entry_with(stage: LogStage, level: LogLevel, message: String) -> LogEntry {
        LogEntry {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            level,
            stage,
            message,
        }
    }

    fn push_log_entry(&mut self, entry: LogEntry) {
        // Defensive dedupe: skip exact same log fingerprint in the same second bucket.
        if self.logs.last().map_or(false, |last| {
            last.timestamp == entry.timestamp
                && last.stage == entry.stage
                && last.level == entry.level
                && last.message == entry.message
        }) {
            return;
        }
        self.logs.push(entry);
        if self.logs.len() > 5000 {
            self.logs.remove(0);
        }
    }

    fn is_updates_progress_duplicate(line: &str) -> bool {
        matches!(line, "Executing updates plan" | "Running zypper preview")
    }

    pub fn begin_updates_run(&mut self, zypper_requested: bool) {
        self.last_run = None;
        self.last_reconcile = None;
        self.loaded_canonical_run_id = None;
        self.current_run = Some(RunContext {
            run_id: None,
            zypper_requested,
            zypper_plan: None,
            zypper_reconciled: false,
        });
    }

    pub fn begin_updates_run_with_existing_master_run(
        &mut self,
        run_id: String,
        zypper_requested: bool,
    ) {
        self.last_run = None;
        self.last_reconcile = None;
        self.loaded_canonical_run_id = None;
        self.current_run = Some(RunContext {
            run_id: Some(run_id),
            zypper_requested,
            zypper_plan: None,
            zypper_reconciled: false,
        });
    }

    pub fn try_begin_execution(&mut self) -> bool {
        if self.active_execution {
            return false;
        }

        self.active_execution = true;
        true
    }

    pub fn finish_execution(&mut self) {
        self.active_execution = false;
        self.current_run = None;
    }

    pub fn handle_shortcut(&self, ctrl: bool, shift: bool, key: char) -> Option<AppEvent> {
        match (ctrl, shift, key.to_ascii_uppercase()) {
            (true, false, 'Q') => Some(AppEvent::Quit),
            (true, false, 'R') => Some(AppEvent::Refresh),
            (true, true, 'T') => Some(AppEvent::DemoUpdates),
            (true, true, 'Y') => Some(AppEvent::SimulateSuccess),
            _ => None,
        }
    }
    //commented out code build_triage_from_plan

    pub fn apply_ops_event(&mut self, event: OpsEvent) -> bool {
        match event {
            OpsEvent::Structured(event) => {
                match event.kind {
                    OpsEventKind::RunStart => {
                        self.updates_log
                            .push("INFO: Executing updates plan".to_string());
                    }
                    OpsEventKind::RunEnd => {
                        self.updates_log.push("INFO: Run completed".to_string());
                    }
                    OpsEventKind::SnapshotStart => {
                        self.btrfs_status.please_wait = true;
                        self.btrfs_status.completed = false;
                        self.btrfs_log
                            .push("INFO: Starting pre-update snapshot".to_string());
                    }
                    OpsEventKind::SnapshotSuccess { .. } => {
                        self.btrfs_status.please_wait = false;
                        self.btrfs_status.completed = true;
                        self.btrfs_log
                            .push("INFO: Created pre-update snapshot".to_string());
                    }
                    OpsEventKind::SnapshotFailure { reason } => {
                        self.btrfs_status.please_wait = false;
                        self.btrfs_status.completed = false;
                        self.btrfs_log.push(format!("ERROR: {reason}"));
                    }
                    OpsEventKind::PreviewStart => {
                        self.preview_running = true;
                    }
                    OpsEventKind::PreviewResult { packages } => {
                        self.preview_running = false;
                        self.last_preview_packages = Some(packages);
                    }
                    OpsEventKind::AIAnalysis {
                        risk,
                        recommendations,
                        ..
                    } => {
                        self.ai_state.assessment_risk = Some(risk.clone());
                        self.ai_state.assessment_summary = Some(recommendations.join("\n"));
                        self.updates_log
                            .push(format!("INFO: AI analysis complete ({risk})"));
                    }
                    OpsEventKind::ApplyStart => {
                        self.updates_log.push("INFO: Applying updates".to_string());
                    }
                    OpsEventKind::ApplyResult { exit_code } => {
                        self.updates_log
                            .push(format!("INFO: Apply completed with exit code {exit_code}"));
                    }
                    OpsEventKind::PackageInstalled { name, .. } => {
                        let line = format!("INFO: Installed {name}");
                        self.updates_log.push(line.clone());
                        self.push_log_entry(Self::build_log_entry_with(
                            LogStage::Install,
                            LogLevel::Info,
                            line,
                        ));
                    }
                    OpsEventKind::PackageRemoved { name, .. } => {
                        let line = format!("INFO: Removed {name}");
                        self.updates_log.push(line.clone());
                        self.push_log_entry(Self::build_log_entry_with(
                            LogStage::Install,
                            LogLevel::Info,
                            line,
                        ));
                    }
                    OpsEventKind::PackageUpgraded { name, .. } => {
                        let line = format!("INFO: Upgraded {name}");
                        self.updates_log.push(line.clone());
                        self.push_log_entry(Self::build_log_entry_with(
                            LogStage::Install,
                            LogLevel::Info,
                            line,
                        ));
                    }
                    OpsEventKind::FlatpakUpdated { app_id } => {
                        self.updates_log.push(format!("INFO: Updated {app_id}"));
                    }
                    OpsEventKind::ReconcileSummary {
                        attempted: _,
                        installed: _,
                        failed: _,
                        unaccounted: _,
                        verdict: _,
                    } => {
                        // Canonical reconciliation row is written from OpsEvent::RunSummary.
                    }
                    OpsEventKind::Error { message } => match self.active_tab {
                        Tab::Btrfs => self.btrfs_log.push(format!("ERROR: {message}")),
                        _ => self.updates_log.push(format!("ERROR: {message}")),
                    },
                }
                true
            }
            OpsEvent::Log { stream, line } => {
                self.push_log_entry(Self::build_log_entry(stream, &line));
                match stream {
                    LogStream::Updates => {
                        let canonical_updates_active = self
                            .current_run
                            .as_ref()
                            .map_or(false, |run| run.zypper_requested);
                        // During zypper runs, structured events are canonical for updates_log.
                        if !canonical_updates_active {
                            self.updates_log.push(line);
                        }
                    }
                    LogStream::Btrfs => self.btrfs_log.push(line),
                    LogStream::PackageManager => {}
                }
                true
            }
            OpsEvent::UpdatePlan(plan) => {
                // Preview plans belong to the package manager *operation*, not the visible tab.
                if self.package_manager.busy_preview {
                    self.package_manager.preview_plan = Some(plan);
                    self.package_manager.preview_error = None;
                    self.package_manager.busy_preview = false;
                } else {
                    if let Some(run) = self.current_run.as_mut() {
                        if run.zypper_requested {
                            run.zypper_plan = Some(plan.clone());
                        }
                    }
                    self.apply_update_plan(plan);
                    self.triage_preview_status = TriagePreviewStatus::Complete;
                }
                true
            }
            OpsEvent::CommandResult { operation, result } => {
                self.last_preview_result = Some(result.clone());
                self.triage_preview_status = TriagePreviewStatus::Complete;
                let line = format!("Completed with exit code {}", result.exit_code);

                if self.active_tab == Tab::Btrfs {
                    self.btrfs_status.please_wait = false;
                    self.btrfs_status.completed = true;
                }

                if self.package_manager.busy_apply {
                    self.package_manager.busy_apply = false;
                    return true;
                }

                if operation == OperationKind::PackageManager {
                    return true;
                }

                if operation == OperationKind::UpdatesZypperApply {
                    // Canonical apply completion row comes from structured ApplyResult.
                    return true;
                }

                match self.active_tab {
                    Tab::Btrfs => self.btrfs_log.push(line),
                    _ => self.updates_log.push(line),
                }

                true
            }

            OpsEvent::Error(line) => {
                self.triage_preview_status = TriagePreviewStatus::Complete;
                self.preview_running = false;
                if line.starts_with("BTRFS_SNAPSHOT_LIST_PARSE:") {
                    self.btrfs_snapshots.clear();
                    self.btrfs_snapshots_error = Some(
                        line.trim_start_matches("BTRFS_SNAPSHOT_LIST_PARSE:")
                            .trim()
                            .to_string(),
                    );
                }
                if line.starts_with("AI") {
                    self.ai_state.last_error = Some(line.clone());
                }
                if line.starts_with("PKG_PREVIEW:") {
                    self.package_manager.preview_error = Some(line.clone());
                    self.package_manager.busy_preview = false;
                }
                if line.starts_with("PKG_SEARCH:") {
                    self.package_manager.last_error = Some(line.clone());
                    self.package_manager.busy = false;
                }
                if line.starts_with("PKG_APPLY:") {
                    self.package_manager.apply_error = Some(line.clone());
                    self.package_manager.busy_apply = false;
                    return true;
                }
                if line.starts_with("PKG_LOCKS:") {
                    self.package_manager.locks_error = Some(line.clone());
                    self.package_manager.locks_busy = false;
                    return true;
                }
                if line.starts_with("PKG_LOCK_ADD:") {
                    self.package_manager.locks_error = Some(line.clone());
                    self.package_manager.locks_busy = false;
                    return true;
                }
                if line.starts_with("PKG_LOCK_REMOVE:") {
                    self.package_manager.locks_error = Some(line.clone());
                    self.package_manager.locks_busy = false;
                    return true;
                }
                if line.starts_with("PKG_LOCK_CLEAN:") {
                    self.package_manager.locks_error = Some(line.clone());
                    self.package_manager.locks_busy = false;
                    return true;
                }
                if line.starts_with("PKG_LOCK_OP:") {
                    self.package_manager.locks_error = Some(line.clone());
                    self.package_manager.locks_busy = false;
                    return true;
                }
                match self.active_tab {
                    Tab::Btrfs => self.btrfs_log.push(format!("ERROR: {line}")),
                    _ => self.updates_log.push(format!("ERROR: {line}")),
                }
                true
            }
            OpsEvent::PackageIndex(rows) => {
                self.package_manager.rows = rows;
                self.package_manager.filtered = (0..self.package_manager.rows.len()).collect();
                self.package_manager.selected = None;
                self.package_manager.marks.clear();
                self.package_manager.busy = false;
                self.package_manager.last_error = None;
                true
            }
            OpsEvent::BtrfsSnapshots(rows) => {
                self.btrfs_snapshots = rows;
                self.btrfs_snapshots_error = None;
                true
            }
            OpsEvent::PackageLocks(locks) => {
                self.package_manager.locks = locks;
                if let Some(sel) = self.package_manager.selected_lock {
                    if sel >= self.package_manager.locks.len() {
                        self.package_manager.selected_lock = None;
                    }
                }
                self.package_manager.locks_busy = false;
                self.package_manager.locks_error = None;
                true
            }
            OpsEvent::PackageLockOperationCompleted {
                action,
                name: _,
                success,
                message,
            } => {
                if success {
                    self.package_manager.locks_error = None;
                    // add/remove/clean auto-refresh locks; keep busy until PackageLocks/list completion.
                    self.package_manager.locks_busy =
                        matches!(action.as_str(), "add" | "remove" | "clean");
                } else {
                    self.package_manager.locks_busy = false;
                    self.package_manager.locks_error = Some(message.clone());
                }
                true
            }
            OpsEvent::RunSummary(summary) => {
                self.finish_execution();
                self.last_run = summary.process_run;
                self.last_reconcile = summary.reconcile;
                let summary_line = "Reconciliation summary".to_string();
                let stats_line = format!(
                    "Attempted={} Installed={} Failed={} Unaccounted={} Verdict={}",
                    summary.attempted,
                    summary.installed,
                    summary.failed,
                    summary.unaccounted,
                    summary.verdict
                );
                self.updates_log.push(summary_line.clone());
                self.updates_log.push(stats_line.clone());
                self.push_log_entry(Self::build_log_entry_with(
                    LogStage::Reconciliation,
                    LogLevel::Info,
                    summary_line,
                ));
                self.push_log_entry(Self::build_log_entry_with(
                    LogStage::Reconciliation,
                    LogLevel::Info,
                    stats_line,
                ));
                true
            }
            OpsEvent::Progress(line) => {
                if line.starts_with("AI_ASSESSMENT:") {
                    if let Some((risk, summary)) =
                        line.trim_start_matches("AI_ASSESSMENT:").split_once("|")
                    {
                        self.ai_state.assessment_risk = Some(risk.to_string());
                        self.ai_state.assessment_summary = Some(summary.to_string());
                    }
                }
                if line.starts_with("AI triage completed") {
                    self.ai_state.preflight_ok = true;
                }
                if line.starts_with("Please wait") {
                    self.btrfs_status.please_wait = true;
                    self.btrfs_status.completed = false;
                    if line == "Please wait: listing snapshots" {
                        self.btrfs_snapshots_error = None;
                    }
                }
                match self.active_tab {
                    Tab::Btrfs => self.btrfs_log.push(format!("INFO: {line}")),
                    _ => {
                        if !Self::is_updates_progress_duplicate(&line) {
                            self.updates_log.push(format!("INFO: {line}"));
                        }
                    }
                }
                true
            }
            OpsEvent::HealthReport(_) => false,
            OpsEvent::SystemPulse(_) => false,
            OpsEvent::TelemetryUpdate(_) => false,
            OpsEvent::UpdateProgress { .. } => false,
            OpsEvent::UpdatePhase(_) => false,
            OpsEvent::SystemWorkbookExportProgress(_) => false,
            OpsEvent::SystemWorkbookExportCompleted { .. } => false,
            OpsEvent::SystemWorkbookExportFailed(_) => false,
        }
    }

    pub fn apply_update_plan(&mut self, plan: UpdatePlan) {
        let changes = plan.changes.clone();
        self.update_plan = Some(plan);
        self.set_changes(changes);
    }

    pub fn set_changes(&mut self, changes: Vec<PackageChange>) {
        // Generic row updates do not imply that the visible data came from a retained canonical
        // run; explicit retained-run load flow restores that id separately.
        self.loaded_canonical_run_id = None;
        self.counts.all = changes.len();
        self.counts.vendor_changes = changes
            .iter()
            .filter(|u| {
                u.vendor
                    .as_deref()
                    .map(|v| v.contains("->"))
                    .unwrap_or(false)
            })
            .count();
        self.counts.repo_changes = changes
            .iter()
            .filter(|u| u.repo.as_deref().map(|r| r.contains("->")).unwrap_or(false))
            .count();

        self.triage_counts.all = changes.len();
        self.triage_counts.red = changes
            .iter()
            .filter(|u| Self::package_risk_category(u) == RiskFilter::Red)
            .count();
        self.triage_counts.amber = changes
            .iter()
            .filter(|u| Self::package_risk_category(u) == RiskFilter::Amber)
            .count();
        self.triage_counts.green = changes
            .iter()
            .filter(|u| Self::package_risk_category(u) == RiskFilter::Green)
            .count();

        let mut repos = BTreeSet::new();
        for update in &changes {
            if let Some(repo) = &update.repo {
                repos.insert(repo.to_string());
            }
        }
        self.triage_repos = repos.into_iter().collect();
        self.changes = changes;
    }

    pub fn restore_loaded_canonical_run_id(&mut self, run_id: String) {
        self.loaded_canonical_run_id = Some(run_id);
    }

    pub fn clear_loaded_canonical_run_id_if_matching(&mut self, run_id: &str) {
        if self.loaded_canonical_run_id.as_deref() == Some(run_id) {
            self.loaded_canonical_run_id = None;
        }
    }

    pub fn selected_details(&self) -> Option<&PackageChange> {
        self.selected.and_then(|idx| self.changes.get(idx))
    }

    pub fn filtered_updates(&self) -> Vec<(usize, &PackageChange)> {
        self.changes
            .iter()
            .enumerate()
            .filter(|(_, pkg)| match self.risk_filter {
                RiskFilter::All => true,
                RiskFilter::Red => Self::package_risk_category(pkg) == RiskFilter::Red,
                RiskFilter::Amber => Self::package_risk_category(pkg) == RiskFilter::Amber,
                RiskFilter::Green => Self::package_risk_category(pkg) == RiskFilter::Green,
            })
            .collect()
    }

    pub fn package_risk_category(pkg: &PackageChange) -> RiskFilter {
        let update = Self::package_change_as_update(pkg);
        match assess_risk(std::slice::from_ref(&update)).level {
            RiskLevel::High => RiskFilter::Red,
            RiskLevel::Medium => RiskFilter::Amber,
            RiskLevel::Low => RiskFilter::Green,
        }
    }

    fn package_change_as_update(pkg: &PackageChange) -> PackageUpdate {
        // UI package triage uses the core risk engine, so normalize the preview row into the
        // engine's transaction model instead of maintaining a second heuristic.
        PackageUpdate {
            name: pkg.name.clone(),
            action: pkg.action.clone(),
            current_version: pkg.from.clone(),
            new_version: pkg.to.clone(),
            arch: pkg.arch.clone(),
            repository: pkg.repo.clone(),
            vendor: pkg.vendor.clone(),
            vendor_group: VendorGroup::Unknown,
            vendor_change: change_field_has_transition(pkg.vendor.as_deref())
                || pkg.action == UpdateAction::VendorChange,
            repo_change: change_field_has_transition(pkg.repo.as_deref())
                || pkg.action == UpdateAction::RepoChange,
        }
    }
}

fn change_field_has_transition(value: Option<&str>) -> bool {
    value.map(|s| s.contains("->")).unwrap_or(false)
}
