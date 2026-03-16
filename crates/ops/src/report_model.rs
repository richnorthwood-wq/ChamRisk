use crate::events::{OpsEvent, OpsEventKind};
use crate::health::{format_uptime, SystemInfo};
use crate::report_store::{AiAssessmentRow, EventRow, PackageEvidenceRow, ReportStore, RunRow};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportHeader {
    pub run_id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub verdict: String,
    pub app_version: String,
    pub repos_requested: Vec<String>,
    pub repos_effective: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTableRow {
    pub name: String,
    pub status: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub repo: Option<String>,
    pub arch: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPackageRow {
    pub package_name: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub arch: Option<String>,
    pub repository: Option<String>,
    pub action: Option<String>,
    pub result: Option<String>,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatpakRow {
    pub app_id: String,
    pub name: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub origin: Option<String>,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLogEntry {
    pub ts_ms: i64,
    pub severity: String,
    pub message: String,
    pub phase: String,
    pub event_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationSummary {
    pub verdict: String,
    pub attempted: i64,
    pub installed: i64,
    pub failed: i64,
    pub unaccounted: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRow {
    pub name: String,
    pub requested: bool,
    pub effective: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFactRow {
    pub label: String,
    pub value: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountMetric {
    pub label: String,
    pub count: usize,
}

impl CountMetric {
    pub(crate) fn summary_text(items: &[Self]) -> Option<String> {
        if items.is_empty() {
            None
        } else {
            Some(
                items
                    .iter()
                    .map(|item| format!("{} {}", item.label, item.count))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RiskItemCounts {
    pub red: Option<usize>,
    pub amber: Option<usize>,
    pub green: Option<usize>,
}

impl RiskItemCounts {
    fn has_any(&self) -> bool {
        self.red.is_some() || self.amber.is_some() || self.green.is_some()
    }

    pub(crate) fn summary_text(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(red) = self.red {
            parts.push(format!("Red: {red}"));
        }
        if let Some(amber) = self.amber {
            parts.push(format!("Amber: {amber}"));
        }
        if let Some(green) = self.green {
            parts.push(format!("Green: {green}"));
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSummaryMetrics {
    pub total_count: usize,
    pub risk_counts: RiskItemCounts,
    pub action_counts: Vec<CountMetric>,
    pub result_counts: Vec<CountMetric>,
    pub high_risk_packages: Vec<String>,
}

impl PackageSummaryMetrics {
    fn from_rows(rows: &[ReportPackageRow]) -> Option<Self> {
        if rows.is_empty() {
            return None;
        }

        let mut risk_counts = RiskItemCounts::default();
        let mut action_counts = BTreeMap::new();
        let mut result_counts = BTreeMap::new();
        let mut red_packages = Vec::new();
        let mut amber_packages = Vec::new();

        for row in rows {
            match canonical_risk(row.risk.as_deref()) {
                Some("red") => {
                    risk_counts.red = Some(risk_counts.red.unwrap_or(0) + 1);
                    push_unique_name(&mut red_packages, &row.package_name);
                }
                Some("amber") => {
                    risk_counts.amber = Some(risk_counts.amber.unwrap_or(0) + 1);
                    push_unique_name(&mut amber_packages, &row.package_name);
                }
                Some("green") => {
                    risk_counts.green = Some(risk_counts.green.unwrap_or(0) + 1);
                }
                _ => {}
            }

            if let Some(action) = canonical_text_metric(row.action.as_deref()) {
                *action_counts.entry(action).or_insert(0usize) += 1;
            }

            if let Some(result) = canonical_text_metric(row.result.as_deref()) {
                *result_counts.entry(result).or_insert(0usize) += 1;
            }
        }

        Some(Self {
            total_count: rows.len(),
            risk_counts,
            action_counts: count_metrics_from_map(action_counts),
            result_counts: count_metrics_from_map(result_counts),
            high_risk_packages: if red_packages.is_empty() {
                amber_packages
            } else {
                red_packages
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeSummary {
    pub total_package_count: Option<usize>,
    pub risk_item_counts: Option<RiskItemCounts>,
    pub action_counts: Vec<CountMetric>,
    pub result_counts: Vec<CountMetric>,
    pub notable_high_risk_packages: Vec<String>,
    pub notable_red_items: Vec<String>,
    pub repo_vendor_anomalies: Vec<String>,
    pub package_lock_count: Option<usize>,
    pub snapshot_status: Option<String>,
    pub flatpak_count: Option<usize>,
    pub update_type: Option<String>,
}

impl ChangeSummary {
    pub fn rows(&self) -> Vec<ReportFactRow> {
        let mut rows = Vec::new();

        if let Some(total_package_count) = self.total_package_count {
            rows.push(ReportFactRow {
                label: "Total Package Count Affected".to_string(),
                value: total_package_count.to_string(),
                note: "Structured package scope for this run.".to_string(),
            });
        }

        if let Some(risk_counts) = self.risk_item_counts.as_ref() {
            if let Some(summary) = risk_counts.summary_text() {
                rows.push(ReportFactRow {
                    label: "Risk Counts".to_string(),
                    value: summary,
                    note: "Structured per-risk counts when available.".to_string(),
                });
            }
        }

        if let Some(summary) = CountMetric::summary_text(&self.action_counts) {
            rows.push(ReportFactRow {
                label: "Actions".to_string(),
                value: summary,
                note: "Counts derived from persisted package evidence when available.".to_string(),
            });
        }

        if let Some(summary) = CountMetric::summary_text(&self.result_counts) {
            rows.push(ReportFactRow {
                label: "Results".to_string(),
                value: summary,
                note: "Structured package outcome counts when recorded.".to_string(),
            });
        }

        if !self.notable_high_risk_packages.is_empty() {
            rows.push(ReportFactRow {
                label: "High-Risk Packages".to_string(),
                value: self.notable_high_risk_packages.join(", "),
                note: "Highest-risk package names from persisted package evidence.".to_string(),
            });
        }

        if !self.notable_red_items.is_empty() {
            rows.push(ReportFactRow {
                label: "Notable Red Items".to_string(),
                value: self.notable_red_items.join("; "),
                note: "Highest-risk items or reasons carried by structured assessment data."
                    .to_string(),
            });
        }

        if !self.repo_vendor_anomalies.is_empty() {
            rows.push(ReportFactRow {
                label: "Repository/Vendor Anomalies".to_string(),
                value: self.repo_vendor_anomalies.join("; "),
                note: "Structured repo/vendor drift or mixing signals.".to_string(),
            });
        }

        if let Some(package_lock_count) = self.package_lock_count {
            rows.push(ReportFactRow {
                label: "Package Locks".to_string(),
                value: package_lock_count.to_string(),
                note: "Count of package locks reported during the run.".to_string(),
            });
        }

        if let Some(snapshot_status) = self.snapshot_status.as_deref() {
            rows.push(ReportFactRow {
                label: "Snapshot Status".to_string(),
                value: snapshot_status.to_string(),
                note: String::new(),
            });
        }

        if let Some(flatpak_count) = self.flatpak_count.filter(|count| *count > 0) {
            rows.push(ReportFactRow {
                label: "Flatpak Impact".to_string(),
                value: flatpak_count.to_string(),
                note: "Flatpak updates recorded.".to_string(),
            });
        }

        if let Some(update_type) = self.update_type.as_deref() {
            rows.push(ReportFactRow {
                label: "Update Type".to_string(),
                value: update_type.to_string(),
                note: "Structured mode/type derived from run selection and events.".to_string(),
            });
        }

        rows
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendationRow {
    pub step: String,
    pub recommendation: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSystemInfo {
    pub os: String,
    pub kernel: String,
    pub architecture: String,
    pub cpu: String,
    pub memory: String,
    pub uptime: String,
}

impl ReportSystemInfo {
    pub fn unknown() -> Self {
        Self {
            os: "Unknown".to_string(),
            kernel: "Unknown".to_string(),
            architecture: "Unknown".to_string(),
            cpu: "Unknown".to_string(),
            memory: "Unknown".to_string(),
            uptime: "Unknown".to_string(),
        }
    }

    pub fn from_system_info(system_info: Option<&SystemInfo>) -> Self {
        let Some(info) = system_info else {
            return Self::unknown();
        };

        let os = if info.os_name.trim().is_empty() || info.os_name == "Unknown" {
            "Unknown".to_string()
        } else if info.os_version.trim().is_empty() || info.os_version == "Unknown" {
            info.os_name.clone()
        } else if info.os_name.contains(&info.os_version) {
            info.os_name.clone()
        } else {
            format!("{} {}", info.os_name, info.os_version)
        };

        let kernel = if info.kernel.is_empty() {
            "Unknown".to_string()
        } else {
            info.kernel.clone()
        };
        let architecture = if info.architecture.is_empty() {
            "Unknown".to_string()
        } else {
            info.architecture.clone()
        };
        let cpu = if info.cpu_model.is_empty() {
            "Unknown".to_string()
        } else {
            info.cpu_model.clone()
        };

        Self {
            os,
            kernel,
            architecture,
            cpu,
            memory: format_memory_gb(info.memory_gb),
            uptime: if info.uptime_seconds == 0 {
                "Unknown".to_string()
            } else {
                format_uptime(info.uptime_seconds)
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportModel {
    pub header: ReportHeader,
    pub system_info: ReportSystemInfo,
    pub ai_risk: Option<String>,
    pub ai_recommendations: Vec<RecommendationRow>,
    pub execution_result: String,
    pub update_type: Option<String>,
    pub snapshot_status: Option<String>,
    pub reboot_status: Option<String>,
    pub package_summary: Option<PackageSummaryMetrics>,
    pub change_summary: ChangeSummary,
    pub validation_notes: Vec<String>,
    pub selection_rows: Vec<SelectionRow>,
    pub selection_notes: Vec<String>,
    pub package_evidence: Vec<ReportPackageRow>,
    pub package_rows: Vec<PackageTableRow>,
    pub flatpak_rows: Vec<FlatpakRow>,
    pub log_entries: Vec<ReportLogEntry>,
    pub reconciliation: ReconciliationSummary,
}

impl ReportModel {
    pub fn from_store(store: &ReportStore, run_id: &str) -> Result<Self, String> {
        let run = store
            .list_runs(1000)?
            .into_iter()
            .find(|row| row.run_id == run_id)
            .ok_or_else(|| format!("run not found: {run_id}"))?;
        let events = store.load_events(run_id)?;
        let packages = store.load_packages(run_id)?;
        let ai_assessment = store.load_ai_assessment(run_id)?;
        Self::from_rows_with_packages_and_ai_assessment(run, events, packages, ai_assessment, true)
    }

    pub fn from_rows(run: RunRow, events: Vec<EventRow>) -> Result<Self, String> {
        Self::from_rows_with_packages(run, events, Vec::new())
    }

    pub fn from_rows_with_packages(
        run: RunRow,
        events: Vec<EventRow>,
        packages: Vec<PackageEvidenceRow>,
    ) -> Result<Self, String> {
        Self::from_rows_with_packages_and_ai_assessment(run, events, packages, None, false)
    }

    pub fn from_rows_with_packages_and_ai_assessment(
        run: RunRow,
        events: Vec<EventRow>,
        packages: Vec<PackageEvidenceRow>,
        ai_assessment: Option<AiAssessmentRow>,
        durable_ai_only: bool,
    ) -> Result<Self, String> {
        let ops_events = ops_events_from_rows(&events);
        let ai_triage = ai_assessment
            .as_ref()
            .and_then(ai_triage_from_assessment_row);
        Self::from_parts(
            run,
            Some(&events),
            Some(&packages),
            ops_events,
            ai_triage,
            durable_ai_only,
        )
    }

    pub fn from_ops_events(run: RunRow, events: Vec<OpsEvent>) -> Result<Self, String> {
        Self::from_parts(run, None, None, events, None, false)
    }

    fn from_parts(
        run: RunRow,
        event_rows: Option<&[EventRow]>,
        package_evidence_rows: Option<&[PackageEvidenceRow]>,
        events: Vec<OpsEvent>,
        ai_triage: Option<(Option<String>, Vec<RecommendationRow>)>,
        durable_ai_only: bool,
    ) -> Result<Self, String> {
        let (ai_risk, ai_recommendations) = if durable_ai_only {
            ai_triage.unwrap_or_else(|| (None, Vec::new()))
        } else {
            ai_triage.unwrap_or_else(|| ai_triage_from_events(&events))
        };
        let repos_requested = requested_repos(&run.selection_json);
        let repos_effective = effective_repos(&repos_requested, &events);
        let (selection_rows, selection_notes) = selection_summary(
            &run.selection_json,
            &events,
            &repos_requested,
            &repos_effective,
        );
        let header = ReportHeader {
            run_id: run.run_id.clone(),
            started_at_ms: run.started_at_ms,
            ended_at_ms: run.ended_at_ms,
            verdict: run.verdict.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
            app_version: run.app_version.clone(),
            repos_requested: repos_requested.clone(),
            repos_effective: repos_effective.clone(),
        };

        let package_evidence = package_evidence_rows
            .map(report_package_rows_from_evidence)
            .unwrap_or_default();
        let package_summary = PackageSummaryMetrics::from_rows(&package_evidence);
        let package_rows = package_evidence_rows
            .map(package_rows_from_package_evidence)
            .unwrap_or_default();
        let flatpak_rows = flatpak_rows_from_events(&events);

        let log_entries = events
            .iter()
            .filter(|event| is_report_log_event(event))
            .map(report_log_entry_from_event)
            .collect::<Vec<_>>();

        let reconciliation =
            reconciliation_from_events(&events).unwrap_or_else(|| ReconciliationSummary {
                verdict: run.verdict.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
                attempted: run.attempted.unwrap_or(0),
                installed: run.installed.unwrap_or(0),
                failed: run.failed.unwrap_or(0),
                unaccounted: run.unaccounted.unwrap_or(0),
            });
        let execution_result = header.verdict.clone();
        let update_type = derive_update_type(&run.selection_json, &events);
        let snapshot_status = derive_snapshot_status(&run.selection_json, &events);
        let reboot_status = derive_reboot_status(&ai_recommendations, &events);
        let change_summary = build_change_summary(
            &run.selection_json,
            event_rows.unwrap_or(&[]),
            &events,
            &reconciliation,
            package_summary.as_ref(),
            snapshot_status.as_deref(),
            update_type.as_deref(),
            &flatpak_rows,
            &package_rows,
            &repos_requested,
            &repos_effective,
            ai_risk.as_deref(),
        );
        let validation_notes = build_validation_notes(
            &run.selection_json,
            &events,
            &repos_requested,
            &repos_effective,
            snapshot_status.as_deref(),
            &reconciliation,
        );

        Ok(Self {
            header,
            system_info: ReportSystemInfo::unknown(),
            ai_risk,
            ai_recommendations,
            execution_result,
            update_type,
            snapshot_status,
            reboot_status,
            package_summary,
            change_summary,
            validation_notes,
            selection_rows,
            selection_notes,
            package_evidence,
            package_rows,
            flatpak_rows,
            log_entries,
            reconciliation,
        })
    }

    pub fn with_system_info(mut self, system_info: Option<&SystemInfo>) -> Self {
        self.system_info = ReportSystemInfo::from_system_info(system_info);
        self
    }
}

fn format_memory_gb(memory_gb: u64) -> String {
    if memory_gb == 0 {
        "Unknown".to_string()
    } else {
        format!("{memory_gb} GB")
    }
}

fn ops_events_from_rows(events: &[EventRow]) -> Vec<OpsEvent> {
    let has_canonical_preview_result = events
        .iter()
        .any(|event| event.event_type == "preview.result");
    let has_canonical_apply_result = events.iter().any(|event| {
        event.event_type == "zypper.apply.result"
            && event.message.starts_with("Apply completed with exit code ")
    });
    let mut converted = Vec::new();
    for event in events {
        converted.extend(ops_events_from_row(
            event,
            has_canonical_preview_result,
            has_canonical_apply_result,
        ));
    }
    dedupe_report_milestones(converted)
}

fn dedupe_report_milestones(events: Vec<OpsEvent>) -> Vec<OpsEvent> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::with_capacity(events.len());

    for event in events {
        let Some(key) = report_milestone_dedupe_key(&event) else {
            deduped.push(event);
            continue;
        };

        if seen.insert(key) {
            deduped.push(event);
        }
    }

    deduped
}

fn report_milestone_dedupe_key(event: &OpsEvent) -> Option<String> {
    match &event.kind {
        OpsEventKind::PreviewResult { packages } => Some(format!(
            "preview.result|phase={}|severity={}|packages={packages}",
            event.phase, event.severity
        )),
        OpsEventKind::ApplyResult { exit_code } => Some(format!(
            "zypper.apply.result|phase={}|severity={}|exit_code={exit_code}",
            event.phase, event.severity
        )),
        _ => None,
    }
}

fn ops_events_from_row(
    event: &EventRow,
    has_canonical_preview_result: bool,
    has_canonical_apply_result: bool,
) -> Vec<OpsEvent> {
    match event.event_type.as_str() {
        "run.start" => vec![typed_event(event, OpsEventKind::RunStart)],
        "run.end" | "run.result" => vec![typed_event(event, OpsEventKind::RunEnd)],
        "snapshot.start" => vec![typed_event(event, OpsEventKind::SnapshotStart)],
        "btrfs.result" => vec![typed_event(event, btrfs_kind(event))],
        "preview.start" => vec![typed_event(event, OpsEventKind::PreviewStart)],
        "preview.result" => preview_result_event(event).into_iter().collect(),
        "zypper.preview.plan" if !has_canonical_preview_result => {
            preview_result_event(event).into_iter().collect()
        }
        "zypper.preview.plan" => Vec::new(),
        "ai.assessment" => ai_analysis_event(event).into_iter().collect(),
        "apply.start" => vec![typed_event(event, OpsEventKind::ApplyStart)],
        "zypper.apply.result"
            if has_canonical_apply_result
                && !event.message.starts_with("Apply completed with exit code ") =>
        {
            Vec::new()
        }
        "zypper.apply.result" => apply_result_event(event).into_iter().collect(),
        "PackageResult" => package_installed_event(event).into_iter().collect(),
        "flatpak.package" => flatpak_updated_event(event).into_iter().collect(),
        "reconcile.summary" | "ReconcileSummary" => reconcile_events(event),
        "journal.vacuum.result" => vec![typed_event(
            event,
            OpsEventKind::Error {
                message: event.message.clone(),
            },
        )],
        "flatpak.update.result" => {
            if event.severity == "error" {
                vec![typed_event(
                    event,
                    OpsEventKind::Error {
                        message: event.message.clone(),
                    },
                )]
            } else {
                Vec::new()
            }
        }
        "error" => vec![typed_event(
            event,
            OpsEventKind::Error {
                message: event.message.clone(),
            },
        )],
        "progress" => legacy_progress_events(event),
        _ => Vec::new(),
    }
}

fn typed_event(event: &EventRow, kind: OpsEventKind) -> OpsEvent {
    OpsEvent {
        ts_ms: event.ts_ms,
        phase: event.phase.clone(),
        severity: event.severity.clone(),
        kind,
    }
}

fn btrfs_kind(event: &EventRow) -> OpsEventKind {
    let payload = serde_json::from_str::<Value>(&event.payload_json).ok();
    let exit_code = payload
        .as_ref()
        .and_then(|payload| payload.get("exit_code").and_then(Value::as_i64))
        .unwrap_or(-1);
    if exit_code == 0 {
        OpsEventKind::SnapshotSuccess {
            snapshot_id: payload
                .as_ref()
                .and_then(|payload| payload.get("snapshot_id").and_then(Value::as_u64)),
        }
    } else {
        OpsEventKind::SnapshotFailure {
            reason: payload
                .as_ref()
                .and_then(|payload| payload.get("reason").and_then(Value::as_str))
                .map(ToString::to_string)
                .unwrap_or_else(|| event.message.clone()),
        }
    }
}

fn preview_result_event(event: &EventRow) -> Option<OpsEvent> {
    let payload = serde_json::from_str::<Value>(&event.payload_json).ok()?;
    let packages = payload
        .get("packages")
        .and_then(Value::as_u64)
        .or_else(|| payload.get("changes").and_then(Value::as_u64))
        .unwrap_or(0) as usize;
    Some(typed_event(event, OpsEventKind::PreviewResult { packages }))
}

fn ai_analysis_event(event: &EventRow) -> Option<OpsEvent> {
    let (risk, rationale, recommendations) = parse_ai_assessment_payload(&event.payload_json)
        .or_else(|| parse_ai_assessment_text(&event.message))?;
    Some(typed_event(
        event,
        OpsEventKind::AIAnalysis {
            risk: risk?,
            rationale,
            recommendations,
        },
    ))
}

fn package_installed_event(event: &EventRow) -> Option<OpsEvent> {
    let payload = serde_json::from_str::<Value>(&event.payload_json).ok()?;
    let name = string_field(&payload, "name").or_else(|| string_field(&payload, "package"))?;
    let from = string_field(&payload, "from_version");
    let to = string_field(&payload, "to_version");
    let repo = string_field(&payload, "repo");
    let arch = string_field(&payload, "arch");
    let status = string_field(&payload, "status")
        .unwrap_or_else(|| "installed".to_string())
        .to_ascii_lowercase();

    let kind = match status.as_str() {
        "removed" => OpsEventKind::PackageRemoved {
            name,
            from,
            to,
            repo,
            arch,
        },
        "upgraded" | "updated" => OpsEventKind::PackageUpgraded {
            name,
            from,
            to,
            repo,
            arch,
        },
        _ => OpsEventKind::PackageInstalled {
            name,
            from,
            to,
            repo,
            arch,
        },
    };

    Some(typed_event(event, kind))
}

fn apply_result_event(event: &EventRow) -> Option<OpsEvent> {
    let payload = serde_json::from_str::<Value>(&event.payload_json).ok()?;
    let exit_code = payload
        .get("exit_code")
        .and_then(Value::as_i64)
        .unwrap_or(-1) as i32;
    Some(typed_event(event, OpsEventKind::ApplyResult { exit_code }))
}

fn flatpak_updated_event(event: &EventRow) -> Option<OpsEvent> {
    let payload = serde_json::from_str::<Value>(&event.payload_json).ok()?;
    Some(typed_event(
        event,
        OpsEventKind::FlatpakUpdated {
            app_id: string_field(&payload, "app_id")?,
        },
    ))
}

fn reconcile_events(event: &EventRow) -> Vec<OpsEvent> {
    let mut events = Vec::new();
    let Some(payload) = serde_json::from_str::<Value>(&event.payload_json).ok() else {
        return events;
    };

    events.push(typed_event(
        event,
        OpsEventKind::ReconcileSummary {
            attempted: i64_field(&payload, "attempted").unwrap_or(0).max(0) as u32,
            installed: i64_field(&payload, "installed").unwrap_or(0).max(0) as u32,
            failed: i64_field(&payload, "failed").unwrap_or(0).max(0) as u32,
            unaccounted: i64_field(&payload, "unaccounted").unwrap_or(0).max(0) as u32,
            verdict: string_field(&payload, "verdict").unwrap_or_else(|| "UNKNOWN".to_string()),
        },
    ));

    if let Some(rows) = payload.get("package_rows").and_then(Value::as_array) {
        for row in rows {
            if let Some(name) = string_field(row, "name") {
                let from = string_field(row, "from_version");
                let to = string_field(row, "to_version");
                let repo = string_field(row, "repo");
                let arch = string_field(row, "arch");
                let status = string_field(row, "status")
                    .unwrap_or_else(|| "installed".to_string())
                    .to_ascii_lowercase();
                let kind = match status.as_str() {
                    "removed" => OpsEventKind::PackageRemoved {
                        name,
                        from,
                        to,
                        repo,
                        arch,
                    },
                    "upgraded" | "updated" => OpsEventKind::PackageUpgraded {
                        name,
                        from,
                        to,
                        repo,
                        arch,
                    },
                    _ => OpsEventKind::PackageInstalled {
                        name,
                        from,
                        to,
                        repo,
                        arch,
                    },
                };
                events.push(typed_event(event, kind));
            }
        }
    }

    events
}

fn legacy_progress_events(event: &EventRow) -> Vec<OpsEvent> {
    if let Some(ai) = ai_analysis_event(event) {
        return vec![ai];
    }

    let trimmed = event.message.trim();
    if trimmed == "Executing updates plan" {
        return vec![typed_event(event, OpsEventKind::RunStart)];
    }
    if trimmed == "Running zypper preview" {
        return vec![typed_event(event, OpsEventKind::PreviewStart)];
    }
    if trimmed == "Please wait: creating pre-update snapshot" {
        return vec![typed_event(event, OpsEventKind::SnapshotStart)];
    }
    if trimmed == "Packman repo not found; running standard zypper dup instead" {
        return vec![typed_event(
            event,
            OpsEventKind::Error {
                message: event.message.clone(),
            },
        )];
    }

    if matches!(event.severity.as_str(), "warn" | "error") {
        return vec![typed_event(
            event,
            OpsEventKind::Error {
                message: event.message.clone(),
            },
        )];
    }

    Vec::new()
}

fn report_log_entry_from_event(event: &OpsEvent) -> ReportLogEntry {
    ReportLogEntry {
        ts_ms: event.ts_ms,
        severity: non_empty_log_field(&event.severity),
        phase: non_empty_log_field(&event.phase),
        event_type: non_empty_log_field(&event_type_name(&event.kind)),
        message: non_empty_log_field(&event_message(&event.kind)),
    }
}

fn non_empty_log_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

fn event_type_name(kind: &OpsEventKind) -> String {
    match kind {
        OpsEventKind::RunStart => "run.start",
        OpsEventKind::RunEnd => "run.end",
        OpsEventKind::SnapshotStart => "snapshot.start",
        OpsEventKind::SnapshotSuccess { .. } | OpsEventKind::SnapshotFailure { .. } => {
            "btrfs.result"
        }
        OpsEventKind::PreviewStart => "preview.start",
        OpsEventKind::PreviewResult { .. } => "preview.result",
        OpsEventKind::AIAnalysis { .. } => "ai.assessment",
        OpsEventKind::ApplyStart => "apply.start",
        OpsEventKind::ApplyResult { .. } => "zypper.apply.result",
        OpsEventKind::PackageInstalled { .. }
        | OpsEventKind::PackageRemoved { .. }
        | OpsEventKind::PackageUpgraded { .. } => "PackageResult",
        OpsEventKind::FlatpakUpdated { .. } => "flatpak.package",
        OpsEventKind::ReconcileSummary { .. } => "reconcile.summary",
        OpsEventKind::Error { .. } => "error",
    }
    .to_string()
}

fn event_message(kind: &OpsEventKind) -> String {
    match kind {
        OpsEventKind::RunStart => "Executing updates plan".to_string(),
        OpsEventKind::RunEnd => "Run completed".to_string(),
        OpsEventKind::SnapshotStart => "Starting pre-update snapshot".to_string(),
        OpsEventKind::SnapshotSuccess { .. } => "Created pre-update snapshot".to_string(),
        OpsEventKind::SnapshotFailure { reason } => reason.clone(),
        OpsEventKind::PreviewStart => "Running zypper preview".to_string(),
        OpsEventKind::PreviewResult { packages } => {
            format!("Preview result with {packages} package(s)")
        }
        OpsEventKind::AIAnalysis {
            risk,
            rationale: _,
            recommendations,
        } => {
            if recommendations.is_empty() {
                format!("AI_ASSESSMENT:{risk}")
            } else {
                format!("AI_ASSESSMENT:{risk}|{}", recommendations.join("|"))
            }
        }
        OpsEventKind::ApplyStart => "Applying updates".to_string(),
        OpsEventKind::ApplyResult { exit_code } => {
            format!("Apply completed with exit code {exit_code}")
        }
        OpsEventKind::PackageInstalled {
            name,
            from,
            to,
            repo,
            arch,
        } => package_message_from_parsed_update(
            name,
            "installed",
            from.as_deref(),
            to.as_deref(),
            repo.as_deref(),
            arch.as_deref(),
        ),
        OpsEventKind::PackageRemoved {
            name,
            from,
            to,
            repo,
            arch,
        } => package_message_from_parsed_update(
            name,
            "removed",
            from.as_deref(),
            to.as_deref(),
            repo.as_deref(),
            arch.as_deref(),
        ),
        OpsEventKind::PackageUpgraded {
            name,
            from,
            to,
            repo,
            arch,
        } => package_message_from_parsed_update(
            name,
            "upgraded",
            from.as_deref(),
            to.as_deref(),
            repo.as_deref(),
            arch.as_deref(),
        ),
        OpsEventKind::FlatpakUpdated { app_id } => format!("Updated {app_id}"),
        OpsEventKind::ReconcileSummary {
            attempted,
            installed,
            failed,
            unaccounted,
            verdict,
        } => format!(
            "Attempted={attempted} Installed={installed} Failed={failed} Unaccounted={unaccounted} Verdict={verdict}"
        ),
        OpsEventKind::Error { message } => message.clone(),
    }
}

fn package_rows_from_package_evidence(rows: &[PackageEvidenceRow]) -> Vec<PackageTableRow> {
    rows.iter()
        .map(|row| PackageTableRow {
            name: row.package_name.clone(),
            status: row
                .result
                .clone()
                .or_else(|| row.action.clone())
                .unwrap_or_else(|| "recorded".to_string()),
            from_version: row.from_version.clone(),
            to_version: row.to_version.clone(),
            repo: row.repository.clone(),
            arch: row.arch.clone(),
            message: package_message_from_evidence(row),
        })
        .collect()
}

fn report_package_rows_from_evidence(rows: &[PackageEvidenceRow]) -> Vec<ReportPackageRow> {
    rows.iter()
        .map(|row| ReportPackageRow {
            package_name: row.package_name.clone(),
            from_version: row.from_version.clone(),
            to_version: row.to_version.clone(),
            arch: row.arch.clone(),
            repository: row.repository.clone(),
            action: row.action.clone(),
            result: row.result.clone(),
            risk: row.risk.clone(),
        })
        .collect()
}

fn push_unique_name(items: &mut Vec<String>, name: &str) {
    if !items.iter().any(|item| item == name) {
        items.push(name.to_string());
    }
}

fn canonical_risk(value: Option<&str>) -> Option<&'static str> {
    let risk = value?.trim();
    if risk.is_empty() {
        return None;
    }

    if risk.eq_ignore_ascii_case("red") {
        Some("red")
    } else if risk.eq_ignore_ascii_case("amber") {
        Some("amber")
    } else if risk.eq_ignore_ascii_case("green") {
        Some("green")
    } else {
        None
    }
}

fn canonical_text_metric(value: Option<&str>) -> Option<String> {
    let text = value?.trim();
    if text.is_empty() {
        return None;
    }

    Some(text.to_ascii_lowercase())
}

fn count_metrics_from_map(counts: BTreeMap<String, usize>) -> Vec<CountMetric> {
    counts
        .into_iter()
        .map(|(label, count)| CountMetric {
            label: title_case_metric_label(&label),
            count,
        })
        .collect()
}

fn title_case_metric_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '_' || ch == '-' { ' ' } else { ch })
        .collect::<String>()
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn package_message_from_evidence(row: &PackageEvidenceRow) -> String {
    let status = row
        .result
        .as_deref()
        .or(row.action.as_deref())
        .unwrap_or("recorded");
    let mut parts = vec![format!("{} {}", row.package_name, status)];

    match (row.from_version.as_deref(), row.to_version.as_deref()) {
        (Some(from), Some(to)) if from != to => parts.push(format!("{from} -> {to}")),
        (None, Some(to)) => parts.push(format!("-> {to}")),
        (Some(from), None) => parts.push(from.to_string()),
        _ => {}
    }

    if let Some(repo) = row.repository.as_deref() {
        parts.push(format!("repo={repo}"));
    }
    if let Some(arch) = row.arch.as_deref() {
        parts.push(format!("arch={arch}"));
    }
    if let Some(risk) = row.risk.as_deref() {
        parts.push(format!("risk={risk}"));
    }

    parts.join(" ")
}

fn package_message_from_parsed_update(
    name: &str,
    status: &str,
    from_version: Option<&str>,
    to_version: Option<&str>,
    repo: Option<&str>,
    arch: Option<&str>,
) -> String {
    let mut parts = vec![format!("{name} {status}")];

    match (from_version, to_version) {
        (Some(from), Some(to)) if from != to => parts.push(format!("{from} -> {to}")),
        (None, Some(to)) => parts.push(format!("-> {to}")),
        (Some(from), None) => parts.push(from.to_string()),
        _ => {}
    }

    if let Some(repo) = repo {
        parts.push(format!("repo={repo}"));
    }
    if let Some(arch) = arch {
        parts.push(format!("arch={arch}"));
    }

    parts.join(" ")
}

fn is_report_log_event(event: &OpsEvent) -> bool {
    !matches!(
        event.kind,
        OpsEventKind::PackageInstalled { .. }
            | OpsEventKind::PackageRemoved { .. }
            | OpsEventKind::PackageUpgraded { .. }
    )
}

fn reconciliation_from_events(events: &[OpsEvent]) -> Option<ReconciliationSummary> {
    events.iter().find_map(|event| {
        let OpsEventKind::ReconcileSummary {
            attempted,
            installed,
            failed,
            unaccounted,
            verdict,
        } = &event.kind
        else {
            return None;
        };

        Some(ReconciliationSummary {
            verdict: verdict.clone(),
            attempted: i64::from(*attempted),
            installed: i64::from(*installed),
            failed: i64::from(*failed),
            unaccounted: i64::from(*unaccounted),
        })
    })
}

fn selection_summary(
    selection_json: &str,
    events: &[OpsEvent],
    repos_requested: &[String],
    repos_effective: &[String],
) -> (Vec<SelectionRow>, Vec<String>) {
    let Ok(value) = serde_json::from_str::<Value>(selection_json) else {
        return (Vec::new(), Vec::new());
    };

    let Value::Object(map) = value else {
        return (Vec::new(), Vec::new());
    };

    let mut rows = Vec::new();
    let mut notes = Vec::new();

    let snapshot_requested = map
        .get("snapshot_before_update")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let snapshot_effective = snapshot_succeeded(events);
    rows.push(SelectionRow {
        name: "Snapshot Before Update".to_string(),
        requested: snapshot_requested,
        effective: snapshot_effective,
    });
    if snapshot_requested && !snapshot_effective {
        notes.push("Snapshot Before Update requested but not executed.".to_string());
    }

    let zypper_requested = map
        .get("zypper_dup")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || map
            .get("prefer_packman")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let zypper_effective = zypper_effective(events);
    let zypper_dup_requested = map
        .get("zypper_dup")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    rows.push(SelectionRow {
        name: "Zypper Dup".to_string(),
        requested: zypper_dup_requested,
        effective: zypper_dup_requested && zypper_effective,
    });
    if zypper_requested && !zypper_effective {
        notes.push("Zypper Dup requested but no apply result recorded.".to_string());
    }

    let prefer_packman_requested = map
        .get("prefer_packman")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let observed_repos = observed_package_repos(events);
    let prefer_packman_effective = prefer_packman_requested
        && observed_repos
            .iter()
            .any(|repo| looks_like_packman_repo(repo));
    rows.push(SelectionRow {
        name: "Prefer Packman".to_string(),
        requested: prefer_packman_requested,
        effective: prefer_packman_effective,
    });
    if prefer_packman_requested && !prefer_packman_effective {
        notes.push("Prefer Packman requested but not effective.".to_string());
    }

    let flatpak_requested = map.get("flatpak").and_then(Value::as_bool).unwrap_or(false);
    let flatpak_effective = flatpak_requested && flatpak_updated(events);
    rows.push(SelectionRow {
        name: "Flatpak".to_string(),
        requested: flatpak_requested,
        effective: flatpak_effective,
    });
    if flatpak_requested && !flatpak_effective {
        notes.push("Flatpak requested but no structured update result was recorded.".to_string());
    }

    let journal_requested = map
        .get("journal_vacuum")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let journal_effective = journal_requested && has_phase(events, "journal");
    rows.push(SelectionRow {
        name: "Journal Vacuum".to_string(),
        requested: journal_requested,
        effective: journal_effective,
    });
    if journal_requested && !journal_effective {
        notes.push("Journal Vacuum requested but no result recorded.".to_string());
    }

    let mode_value = map.get("mode").map(pretty_value).unwrap_or_default();
    rows.push(SelectionRow {
        name: if mode_value.is_empty() {
            "Mode".to_string()
        } else {
            format!("Mode: {mode_value}")
        },
        requested: !mode_value.is_empty(),
        effective: !mode_value.is_empty(),
    });

    let risk_filter_value = map.get("risk_filter").map(pretty_value).unwrap_or_default();
    rows.push(SelectionRow {
        name: if risk_filter_value.is_empty() {
            "Risk Filter".to_string()
        } else {
            format!("Risk Filter: {risk_filter_value}")
        },
        requested: !risk_filter_value.is_empty(),
        effective: !risk_filter_value.is_empty(),
    });

    let repos_value = if repos_requested.is_empty() {
        String::new()
    } else {
        repos_requested.join(", ")
    };
    let repos_requested = !repos_requested.is_empty();
    rows.push(SelectionRow {
        name: if repos_value.is_empty() {
            "Repos".to_string()
        } else {
            format!("Repos: {repos_value}")
        },
        requested: repos_requested,
        effective: !repos_effective.is_empty(),
    });
    if repos_requested && !zypper_effective {
        notes.push("Repos were requested but no zypper apply result was recorded.".to_string());
    }

    (rows, notes)
}

fn zypper_effective(events: &[OpsEvent]) -> bool {
    events.iter().any(|event| {
        matches!(
            event.kind,
            OpsEventKind::ApplyStart
                | OpsEventKind::PackageInstalled { .. }
                | OpsEventKind::PackageRemoved { .. }
                | OpsEventKind::PackageUpgraded { .. }
                | OpsEventKind::ApplyResult { .. }
        )
    })
}

fn snapshot_succeeded(events: &[OpsEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event.kind, OpsEventKind::SnapshotSuccess { .. }))
}

fn requested_repos(selection_json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(selection_json) else {
        return Vec::new();
    };

    value
        .get("repos")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|repo| !repo.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn effective_repos(repos_requested: &[String], events: &[OpsEvent]) -> Vec<String> {
    if !zypper_effective(events) {
        return Vec::new();
    }

    let observed_repos = observed_package_repos(events);
    if observed_repos.is_empty() {
        return repos_requested.to_vec();
    }

    repos_requested
        .iter()
        .filter(|repo| repo_matches_observed(repo, &observed_repos))
        .cloned()
        .collect()
}

fn looks_like_packman_repo(repo: &str) -> bool {
    repo.to_ascii_lowercase().contains("packman")
}

fn observed_package_repos(events: &[OpsEvent]) -> std::collections::BTreeSet<String> {
    events
        .iter()
        .filter_map(|event| match &event.kind {
            OpsEventKind::PackageInstalled { repo, .. }
            | OpsEventKind::PackageRemoved { repo, .. }
            | OpsEventKind::PackageUpgraded { repo, .. } => repo.clone(),
            _ => None,
        })
        .filter(|repo| !repo.trim().is_empty())
        .collect()
}

fn repo_matches_observed(
    requested: &str,
    observed_repos: &std::collections::BTreeSet<String>,
) -> bool {
    let requested_lc = requested.to_ascii_lowercase();
    observed_repos.iter().any(|observed| {
        let observed_lc = observed.to_ascii_lowercase();
        observed_lc == requested_lc
            || observed_lc.contains(&requested_lc)
            || requested_lc.contains(&observed_lc)
            || (looks_like_packman_repo(&requested_lc) && looks_like_packman_repo(&observed_lc))
    })
}

fn flatpak_updated(events: &[OpsEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event.kind, OpsEventKind::FlatpakUpdated { .. }))
}

fn has_phase(events: &[OpsEvent], phase: &str) -> bool {
    events.iter().any(|event| event.phase == phase)
}

fn ai_triage_from_events(events: &[OpsEvent]) -> (Option<String>, Vec<RecommendationRow>) {
    events
        .iter()
        .rev()
        .find_map(ai_triage_from_event)
        .unwrap_or_else(|| (None, Vec::new()))
}

fn ai_triage_from_event(event: &OpsEvent) -> Option<(Option<String>, Vec<RecommendationRow>)> {
    match &event.kind {
        OpsEventKind::AIAnalysis {
            risk,
            recommendations,
            ..
        } => Some((
            Some(risk.clone()),
            normalize_recommendations(recommendations.clone()),
        )),
        _ => None,
    }
}

fn ai_triage_from_assessment_row(
    row: &AiAssessmentRow,
) -> Option<(Option<String>, Vec<RecommendationRow>)> {
    let recommendations = recommendations_from_json_text(&row.recommendations_json)?;
    if row.risk_level.is_none() && recommendations.is_empty() {
        None
    } else {
        Some((
            row.risk_level.clone(),
            normalize_recommendations(recommendations),
        ))
    }
}

fn derive_update_type(selection_json: &str, events: &[OpsEvent]) -> Option<String> {
    let value = serde_json::from_str::<Value>(selection_json).ok()?;
    let Value::Object(map) = value else {
        return None;
    };

    let mut parts = Vec::new();
    if map
        .get("zypper_dup")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        parts.push("Zypper Dup".to_string());
    } else if zypper_effective(events) {
        parts.push("Package Update".to_string());
    }
    if map.get("flatpak").and_then(Value::as_bool).unwrap_or(false) {
        parts.push("Flatpak".to_string());
    }
    if map
        .get("journal_vacuum")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        parts.push("Journal Vacuum".to_string());
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" + "))
    }
}

fn derive_snapshot_status(selection_json: &str, events: &[OpsEvent]) -> Option<String> {
    if let Some(reason) = events.iter().find_map(|event| match &event.kind {
        OpsEventKind::SnapshotFailure { reason } => Some(reason.clone()),
        _ => None,
    }) {
        return Some(format!("Failed ({reason})"));
    }
    if events
        .iter()
        .any(|event| matches!(event.kind, OpsEventKind::SnapshotSuccess { .. }))
    {
        return Some("Created".to_string());
    }

    let requested = serde_json::from_str::<Value>(selection_json)
        .ok()
        .and_then(|value| value.get("snapshot_before_update").cloned())
        .and_then(|value| value.as_bool());

    match requested {
        Some(true) => Some("Requested but not executed".to_string()),
        Some(false) => Some("Not requested".to_string()),
        None => None,
    }
}

fn derive_reboot_status(
    recommendations: &[RecommendationRow],
    events: &[OpsEvent],
) -> Option<String> {
    if recommendations
        .iter()
        .any(|item| item.recommendation.to_ascii_lowercase().contains("reboot"))
    {
        return Some("Likely".to_string());
    }

    if events.iter().any(|event| {
        matches!(
            event.kind,
            OpsEventKind::PackageInstalled { ref name, .. }
                | OpsEventKind::PackageRemoved { ref name, .. }
                | OpsEventKind::PackageUpgraded { ref name, .. }
                if name.to_ascii_lowercase().starts_with("kernel")
        )
    }) {
        return Some("Likely".to_string());
    }

    None
}

fn build_change_summary(
    selection_json: &str,
    event_rows: &[EventRow],
    events: &[OpsEvent],
    reconciliation: &ReconciliationSummary,
    package_summary: Option<&PackageSummaryMetrics>,
    snapshot_status: Option<&str>,
    update_type: Option<&str>,
    flatpak_rows: &[FlatpakRow],
    package_rows: &[PackageTableRow],
    repos_requested: &[String],
    repos_effective: &[String],
    ai_risk: Option<&str>,
) -> ChangeSummary {
    let ai_metadata = ai_change_summary_metadata(event_rows, ai_risk);

    ChangeSummary {
        total_package_count: package_summary
            .map(|summary| summary.total_count)
            .or_else(|| total_package_count(reconciliation, events)),
        risk_item_counts: package_summary
            .map(|summary| summary.risk_counts.clone())
            .filter(RiskItemCounts::has_any)
            .or_else(|| ai_metadata.risk_counts.filter(RiskItemCounts::has_any)),
        action_counts: package_summary
            .map(|summary| summary.action_counts.clone())
            .unwrap_or_default(),
        result_counts: package_summary
            .map(|summary| summary.result_counts.clone())
            .unwrap_or_default(),
        notable_high_risk_packages: package_summary
            .map(|summary| summary.high_risk_packages.clone())
            .unwrap_or_default(),
        notable_red_items: ai_metadata.notable_red_items,
        repo_vendor_anomalies: repo_vendor_anomalies(
            selection_json,
            package_rows,
            repos_requested,
            repos_effective,
            ai_metadata.repo_vendor_anomalies,
        ),
        package_lock_count: package_lock_count(event_rows),
        snapshot_status: snapshot_status.map(ToString::to_string),
        flatpak_count: (!flatpak_rows.is_empty()).then_some(flatpak_rows.len()),
        update_type: update_type.map(ToString::to_string),
    }
}

#[derive(Debug, Default)]
struct ChangeSummaryAiMetadata {
    risk_counts: Option<RiskItemCounts>,
    notable_red_items: Vec<String>,
    repo_vendor_anomalies: Vec<String>,
}

fn ai_change_summary_metadata(
    event_rows: &[EventRow],
    ai_risk: Option<&str>,
) -> ChangeSummaryAiMetadata {
    let Some(payload) = event_rows
        .iter()
        .rev()
        .find(|event| event.event_type == "ai.assessment")
        .and_then(|event| serde_json::from_str::<Value>(&event.payload_json).ok())
    else {
        return ChangeSummaryAiMetadata::default();
    };

    let risk_counts = risk_counts_from_value(&payload);
    let notable_red_items = notable_red_items_from_value(&payload, ai_risk);
    let repo_vendor_anomalies = repo_vendor_anomalies_from_value(&payload);

    ChangeSummaryAiMetadata {
        risk_counts,
        notable_red_items,
        repo_vendor_anomalies,
    }
}

fn total_package_count(
    reconciliation: &ReconciliationSummary,
    events: &[OpsEvent],
) -> Option<usize> {
    if reconciliation.attempted >= 0 {
        let attempted = reconciliation.attempted as usize;
        if attempted > 0 {
            return Some(attempted);
        }
    }

    events.iter().rev().find_map(|event| match event.kind {
        OpsEventKind::PreviewResult { packages } => Some(packages),
        _ => None,
    })
}

fn package_lock_count(event_rows: &[EventRow]) -> Option<usize> {
    event_rows
        .iter()
        .rev()
        .find(|event| event.event_type == "package.locks")
        .and_then(|event| serde_json::from_str::<Value>(&event.payload_json).ok())
        .and_then(|payload| payload.get("locks").and_then(Value::as_u64))
        .map(|count| count as usize)
}

fn risk_counts_from_value(value: &Value) -> Option<RiskItemCounts> {
    let risk_counts = value.get("risk_counts").unwrap_or(value);
    let counts = RiskItemCounts {
        red: count_field(risk_counts, &["red", "red_count"]),
        amber: count_field(risk_counts, &["amber", "amber_count"]),
        green: count_field(risk_counts, &["green", "green_count"]),
    };

    counts.has_any().then_some(counts)
}

fn count_field(value: &Value, keys: &[&str]) -> Option<usize> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
        .map(|count| count as usize)
}

fn notable_red_items_from_value(value: &Value, ai_risk: Option<&str>) -> Vec<String> {
    let explicit = string_array_field(value, &["notable_red_items", "red_items"]);
    if !explicit.is_empty() {
        return explicit;
    }

    if matches!(ai_risk, Some("Red")) {
        return value
            .get("canonical_risk")
            .and_then(|risk| risk.get("reasons"))
            .map(string_array_value)
            .unwrap_or_default();
    }

    Vec::new()
}

fn repo_vendor_anomalies(
    selection_json: &str,
    package_rows: &[PackageTableRow],
    repos_requested: &[String],
    repos_effective: &[String],
    mut ai_anomalies: Vec<String>,
) -> Vec<String> {
    let mut anomalies = Vec::new();

    let missing_requested = repos_requested
        .iter()
        .filter(|repo| !repos_effective.iter().any(|effective| effective == *repo))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_requested.is_empty() {
        anomalies.push(format!(
            "Requested repos not effective: {}",
            missing_requested.join(", ")
        ));
    }

    let package_repos = package_rows
        .iter()
        .filter_map(|row| row.repo.clone())
        .filter(|repo| !repo.trim().is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    if package_repos.len() > 1 {
        let has_packman = package_repos
            .iter()
            .any(|repo| looks_like_packman_repo(repo));
        let has_official = package_repos
            .iter()
            .any(|repo| looks_like_official_repo(repo));
        if has_packman && has_official {
            anomalies.push(format!(
                "Mixed package sources detected: {}",
                package_repos.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }

    let prefer_packman_requested = serde_json::from_str::<Value>(selection_json)
        .ok()
        .and_then(|value| value.get("prefer_packman").cloned())
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if prefer_packman_requested
        && !repos_effective
            .iter()
            .any(|repo| looks_like_packman_repo(repo))
    {
        anomalies
            .push("Packman preference requested but no Packman repo was effective.".to_string());
    }

    anomalies.append(&mut ai_anomalies);
    dedup_preserve_order(anomalies)
}

fn repo_vendor_anomalies_from_value(value: &Value) -> Vec<String> {
    let explicit = string_array_field(
        value,
        &["repo_vendor_anomalies", "repository_vendor_anomalies"],
    );
    if !explicit.is_empty() {
        return explicit;
    }

    value
        .get("canonical_risk")
        .and_then(|risk| risk.get("reasons"))
        .map(string_array_value)
        .unwrap_or_default()
        .into_iter()
        .filter(|reason| {
            let lower = reason.to_ascii_lowercase();
            lower.contains("repo")
                || lower.contains("vendor")
                || lower.contains("packman")
                || lower.contains("mix")
        })
        .collect()
}

fn string_array_field(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| value.get(*key).map(string_array_value))
        .unwrap_or_default()
}

fn string_array_value(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .filter_map(normalize_optional_text)
            .collect(),
        Value::String(text) => split_recommendations(text),
        _ => Vec::new(),
    }
}

fn looks_like_official_repo(repo: &str) -> bool {
    let repo = repo.to_ascii_lowercase();
    repo.contains("repo-oss")
        || repo.contains("repo-non-oss")
        || repo.contains("repo-update")
        || repo.contains("opensuse")
        || repo.contains("tumbleweed")
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut deduped = Vec::new();
    for item in items {
        let key = item.to_ascii_lowercase();
        if seen.insert(key) {
            deduped.push(item);
        }
    }
    deduped
}

fn build_validation_notes(
    selection_json: &str,
    events: &[OpsEvent],
    repos_requested: &[String],
    repos_effective: &[String],
    snapshot_status: Option<&str>,
    reconciliation: &ReconciliationSummary,
) -> Vec<String> {
    let selection = serde_json::from_str::<Value>(selection_json).ok();
    let snapshot_requested = selection
        .as_ref()
        .and_then(|value| value.get("snapshot_before_update"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let flatpak_requested = selection
        .as_ref()
        .and_then(|value| value.get("flatpak"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let journal_requested = selection
        .as_ref()
        .and_then(|value| value.get("journal_vacuum"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let prefer_packman_requested = selection
        .as_ref()
        .and_then(|value| value.get("prefer_packman"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut notes = Vec::new();

    if snapshot_requested && matches!(snapshot_status, Some("Requested but not executed")) {
        notes.push(
            "Snapshot before update was requested but no structured snapshot result was recorded."
                .to_string(),
        );
    }
    if let Some(status) = snapshot_status {
        if status.starts_with("Failed") {
            notes.push(format!("Snapshot result: {status}."));
        }
    }

    if prefer_packman_requested
        && !repos_effective
            .iter()
            .any(|repo| looks_like_packman_repo(repo))
    {
        notes.push(
            "Prefer Packman was requested but no effective Packman repository was observed."
                .to_string(),
        );
    }

    if flatpak_requested && !flatpak_updated(events) {
        notes.push(
            "Flatpak was requested but no structured Flatpak update rows were recorded."
                .to_string(),
        );
    }

    if journal_requested && !has_phase(events, "journal") {
        notes.push(
            "Journal vacuum was requested but no structured journal result was recorded."
                .to_string(),
        );
    }

    if !repos_requested.is_empty() && !zypper_effective(events) {
        notes.push(
            "Repositories were requested but no structured package apply activity was recorded."
                .to_string(),
        );
    }

    if let Some(exit_code) = events.iter().find_map(|event| match event.kind {
        OpsEventKind::ApplyResult { exit_code } if exit_code != 0 => Some(exit_code),
        _ => None,
    }) {
        notes.push(format!("Package apply exited with code {exit_code}."));
    }

    let structured_error_count = events
        .iter()
        .filter(|event| matches!(event.kind, OpsEventKind::Error { .. }))
        .count();
    if structured_error_count > 0 {
        notes.push(format!(
            "{structured_error_count} structured error event(s) were recorded."
        ));
    }

    if reconciliation.failed > 0 {
        notes.push(format!(
            "{} package change(s) failed reconciliation.",
            reconciliation.failed
        ));
    }
    if reconciliation.unaccounted > 0 {
        notes.push(format!(
            "{} package change(s) remained unaccounted for.",
            reconciliation.unaccounted
        ));
    }

    dedup_preserve_order(notes)
}

fn normalize_recommendations(items: Vec<String>) -> Vec<RecommendationRow> {
    items
        .into_iter()
        .enumerate()
        .filter_map(|(index, item)| recommendation_row_from_text(index + 1, &item))
        .collect()
}

fn recommendation_row_from_text(index: usize, text: &str) -> Option<RecommendationRow> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (step, recommendation) = split_recommendation_step(trimmed)
        .unwrap_or_else(|| ((index + 0).to_string(), trimmed.to_string()));

    Some(RecommendationRow {
        step,
        recommendation,
        reason: None,
    })
}

fn split_recommendation_step(text: &str) -> Option<(String, String)> {
    let mut digits = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.peek().copied() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            chars.next();
        } else {
            break;
        }
    }

    if digits.is_empty() {
        return None;
    }

    while let Some(ch) = chars.peek().copied() {
        if ch == ')' || ch == '.' || ch == ':' || ch.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }

    let remainder = chars.collect::<String>().trim().to_string();
    if remainder.is_empty() {
        None
    } else {
        Some((digits, remainder))
    }
}

fn parse_ai_assessment_text(input: &str) -> Option<(Option<String>, Option<String>, Vec<String>)> {
    let marker_index = input.find("AI_ASSESSMENT:")?;
    let assessment = input.get(marker_index + "AI_ASSESSMENT:".len()..)?.trim();
    let mut tokens = assessment
        .split('|')
        .map(str::trim)
        .filter(|token| !token.is_empty());

    let risk = tokens.next().and_then(normalize_optional_text)?;
    let recommendations = tokens.flat_map(split_recommendations).collect::<Vec<_>>();

    Some((Some(risk), None, recommendations))
}

fn recommendations_from_json_text(input: &str) -> Option<Vec<String>> {
    let value = serde_json::from_str::<Value>(input).ok()?;
    recommendations_from_value(&value)
}

fn parse_ai_assessment_payload(
    payload_json: &str,
) -> Option<(Option<String>, Option<String>, Vec<String>)> {
    let value = serde_json::from_str::<Value>(payload_json).ok()?;
    let Value::Object(map) = value else {
        return None;
    };

    let risk = map
        .get("ai_risk")
        .and_then(Value::as_str)
        .or_else(|| map.get("risk").and_then(Value::as_str));
    let rationale = map
        .get("rationale")
        .and_then(Value::as_str)
        .or_else(|| map.get("reason").and_then(Value::as_str))
        .or_else(|| map.get("short_rationale").and_then(Value::as_str))
        .and_then(normalize_optional_text);

    let recommendations = map
        .get("ai_recommendations")
        .and_then(recommendations_from_value)
        .or_else(|| {
            map.get("recommendations")
                .and_then(recommendations_from_value)
        })
        .or_else(|| {
            map.get("summary")
                .and_then(Value::as_str)
                .map(split_recommendations)
        })
        .unwrap_or_default();

    if risk.is_none() && rationale.is_none() && recommendations.is_empty() {
        None
    } else {
        Some((
            risk.and_then(normalize_optional_text),
            rationale,
            recommendations,
        ))
    }
}

fn recommendations_from_value(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Array(items) => {
            let recommendations = items
                .iter()
                .filter_map(Value::as_str)
                .flat_map(split_recommendations)
                .collect::<Vec<_>>();
            Some(recommendations)
        }
        Value::String(text) => Some(split_recommendations(text)),
        _ => None,
    }
}

fn split_recommendations(input: &str) -> Vec<String> {
    let lines = input
        .lines()
        .filter_map(normalize_optional_text)
        .collect::<Vec<_>>();

    let joined = lines.join(" ");
    let compact = strip_recommendation_label(&joined);
    let numbered = split_numbered_recommendations(compact);
    if !numbered.is_empty() {
        return numbered;
    }

    lines
}

fn normalize_optional_text(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn strip_recommendation_label(input: &str) -> &str {
    let trimmed = input.trim();
    for prefix in ["Recommendations:", "Recommendation:"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim();
        }
    }
    trimmed
}

fn split_numbered_recommendations(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let starts = recommendation_marker_starts(trimmed);
    if starts.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();
    for (index, (start, marker_len)) in starts.iter().copied().enumerate() {
        let body_start = start + marker_len;
        let body_end = starts
            .get(index + 1)
            .map(|(next_start, _)| *next_start)
            .unwrap_or(trimmed.len());
        let body = trimmed[body_start..body_end].trim();
        if !body.is_empty() {
            items.push(body.to_string());
        }
    }

    items
}

fn recommendation_marker_starts(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let mut starts = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(marker_len) = recommendation_marker_len(input, index) {
            let previous_is_boundary = index == 0 || bytes[index - 1].is_ascii_whitespace();
            if previous_is_boundary {
                starts.push((index, marker_len));
                index += marker_len;
                continue;
            }
        }
        index += 1;
    }

    starts
}

fn recommendation_marker_len(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    if start >= bytes.len() || !bytes[start].is_ascii_digit() {
        return None;
    }

    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }

    if index >= bytes.len() || !matches!(bytes[index], b')' | b'.' | b':') {
        return None;
    }
    index += 1;

    let whitespace_start = index;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }

    if index == whitespace_start {
        return None;
    }

    Some(index - start)
}

fn flatpak_rows_from_events(events: &[OpsEvent]) -> Vec<FlatpakRow> {
    let mut rows = BTreeMap::new();

    for event in events {
        let Some(row) = flatpak_row_from_event(event) else {
            continue;
        };

        rows.entry(row.app_id.clone()).or_insert(row);
    }

    rows.into_values().collect()
}

fn flatpak_row_from_event(event: &OpsEvent) -> Option<FlatpakRow> {
    let OpsEventKind::FlatpakUpdated { app_id } = &event.kind else {
        return None;
    };
    Some(FlatpakRow {
        app_id: app_id.clone(),
        name: None,
        from_version: None,
        to_version: None,
        origin: None,
        status: "success".to_string(),
        message: event_message(&event.kind),
    })
}

fn pretty_value(value: &Value) -> String {
    match value {
        Value::Bool(v) => {
            if *v {
                "yes".to_string()
            } else {
                "no".to_string()
            }
        }
        Value::String(v) => v.clone(),
        Value::Number(v) => v.to_string(),
        Value::Array(values) => values
            .iter()
            .map(pretty_value)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Null => "none".to_string(),
        Value::Object(_) => value.to_string(),
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(|v| v.to_string())
}

fn i64_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key)?.as_i64()
}
