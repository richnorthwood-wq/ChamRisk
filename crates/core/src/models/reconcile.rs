// models/reconcile.rs
use crate::models::{PackageEventKind, PlannedAction};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileStatus {
    Succeeded,    // planned item completed successfully
    Failed,       // planned item attempted and failed
    Skipped,      // explicitly skipped
    NotAttempted, // no matching event found in this run
    Ambiguous,    // multiple possible matches / low-confidence match
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchConfidence {
    Exact,  // backend + normalised name + arch matched
    Strong, // backend + normalised name matched
    Weak,   // normalised name only (or version mismatch)
}

#[derive(Debug, Clone)]
pub struct ReconcileMatch {
    pub status: ReconcileStatus,
    pub match_confidence: MatchConfidence,

    // planned side
    pub triage_id: String,
    pub planned_action: PlannedAction,
    pub planned_package_name: String,
    pub planned_package_name_norm: String,
    pub planned_arch: Option<String>,
    pub planned_from_version: Option<String>,
    pub planned_to_version: Option<String>,

    // observed side (if matched)
    pub matched_event_index: Option<usize>, // index into ProcessRun.events
    pub actual_event_kind: Option<PackageEventKind>,
    pub actual_package_name: Option<String>,
    pub actual_arch: Option<String>,
    pub actual_from_version: Option<String>,
    pub actual_to_version: Option<String>,

    // diagnostics
    pub reason: Option<String>, // e.g. "dependency conflict"
    pub note: String,           // one-line reference for UI
}

#[derive(Debug, Clone)]
pub struct ReconcileResult {
    pub run_id: String,
    pub total_planned: usize,
    pub matched_success: usize,
    pub matched_failed: usize,
    pub skipped: usize,
    pub not_attempted: usize,
    pub ambiguous: usize,

    pub items: Vec<ReconcileMatch>,
}
