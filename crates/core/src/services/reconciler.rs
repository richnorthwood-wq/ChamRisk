// crates/core/src/services/reconciler.rs

use crate::models::{
    MatchConfidence, PackageEventKind, PlannedAction, ProcessRun, ReconcileMatch, ReconcileResult,
    ReconcileStatus, TriagePackage,
};

fn kind_to_status(kind: &PackageEventKind) -> ReconcileStatus {
    match kind {
        PackageEventKind::InstallSucceeded
        | PackageEventKind::UpdateSucceeded
        | PackageEventKind::UpgradeSucceeded
        | PackageEventKind::DowngradeSucceeded
        | PackageEventKind::RemoveSucceeded => ReconcileStatus::Succeeded,

        PackageEventKind::InstallFailed
        | PackageEventKind::UpdateFailed
        | PackageEventKind::UpgradeFailed
        | PackageEventKind::DowngradeFailed
        | PackageEventKind::RemoveFailed => ReconcileStatus::Failed,

        PackageEventKind::Skipped => ReconcileStatus::Skipped,
        PackageEventKind::Planned => ReconcileStatus::NotAttempted,
    }
}

fn action_matches_event(action: &PlannedAction, kind: &PackageEventKind) -> bool {
    use crate::models::PackageEventKind::*;
    use crate::models::PlannedAction::*;

    matches!(
        (action, kind),
        (Install, InstallSucceeded | InstallFailed)
            | (Remove, RemoveSucceeded | RemoveFailed)
            | (Downgrade, DowngradeSucceeded | DowngradeFailed)
            | (
                Update,
                UpdateSucceeded | UpdateFailed | UpgradeSucceeded | UpgradeFailed
            )
            | (
                Upgrade,
                UpgradeSucceeded | UpgradeFailed | UpdateSucceeded | UpdateFailed
            )
    )
}

fn arch_matches(planned: &Option<String>, actual: &Option<String>) -> bool {
    match (planned, actual) {
        (Some(p), Some(a)) => p.eq_ignore_ascii_case(a),
        (None, _) => true, // if planned doesn't care, treat as match
        _ => false,
    }
}

fn version_to_matches(planned_to: &Option<String>, actual_to: &Option<String>) -> bool {
    match (planned_to, actual_to) {
        (Some(p), Some(a)) => p == a,
        _ => false,
    }
}

fn note_for(
    status: &ReconcileStatus,
    pkg: &str,
    from_v: &Option<String>,
    to_v: &Option<String>,
    reason: &Option<String>,
) -> String {
    let v = match (from_v, to_v) {
        (Some(f), Some(t)) => format!("{f} → {t}"),
        (None, Some(t)) => format!("→ {t}"),
        (Some(f), None) => format!("{f} → ?"),
        (None, None) => String::from(""),
    };

    let base = match status {
        ReconcileStatus::Succeeded => "Succeeded",
        ReconcileStatus::Failed => "Failed",
        ReconcileStatus::Skipped => "Skipped",
        ReconcileStatus::NotAttempted => "Not attempted",
        ReconcileStatus::Ambiguous => "Ambiguous",
    };

    let mut s = if v.is_empty() {
        format!("{base}: {pkg}")
    } else {
        format!("{base}: {pkg} ({v})")
    };

    if let Some(r) = reason.as_ref().filter(|x| !x.trim().is_empty()) {
        s.push_str(&format!(" — {r}"));
    }
    s
}

pub fn reconcile_triage_against_run(
    triage_items: &[TriagePackage],
    run: &ProcessRun,
) -> ReconcileResult {
    let mut items: Vec<ReconcileMatch> = Vec::with_capacity(triage_items.len());

    let mut matched_success = 0usize;
    let mut matched_failed = 0usize;
    let mut skipped = 0usize;
    let mut not_attempted = 0usize;
    let mut ambiguous = 0usize;

    // Pre-index events by their position for easy referencing.
    // (Small N, so we keep it simple; if it grows, we can hash-map it.)
    for t in triage_items {
        let planned_norm = t.package_name_norm.clone();

        // 1) Primary candidates: backend + normalised name
        let mut candidates: Vec<usize> = run
            .events
            .iter()
            .enumerate()
            .filter(|(_, e)| e.backend == t.backend && e.package_name_norm == planned_norm)
            .map(|(i, _)| i)
            .collect();

        let mut match_confidence = MatchConfidence::Strong;

        // 2) If no backend match, fallback: name only across backends (Weak)
        if candidates.is_empty() {
            candidates = run
                .events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.package_name_norm == planned_norm)
                .map(|(i, _)| i)
                .collect();

            if !candidates.is_empty() {
                match_confidence = MatchConfidence::Weak;
            }
        }

        // 3) No candidates at all → NotAttempted
        if candidates.is_empty() {
            not_attempted += 1;
            items.push(ReconcileMatch {
                status: ReconcileStatus::NotAttempted,
                match_confidence,
                triage_id: t.triage_id.clone(),
                planned_action: t.planned_action.clone(),
                planned_package_name: t.package_name.clone(),
                planned_package_name_norm: t.package_name_norm.clone(),
                planned_arch: t.arch.clone(),
                planned_from_version: t.planned_from_version.clone(),
                planned_to_version: t.planned_to_version.clone(),
                matched_event_index: None,
                actual_event_kind: None,
                actual_package_name: None,
                actual_arch: None,
                actual_from_version: None,
                actual_to_version: None,
                reason: None,
                note: note_for(
                    &ReconcileStatus::NotAttempted,
                    &t.package_name,
                    &t.planned_from_version,
                    &t.planned_to_version,
                    &None,
                ),
            });
            continue;
        }

        // 4) Filter candidates by action-kind compatibility (if possible)
        let mut action_candidates: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&idx| action_matches_event(&t.planned_action, &run.events[idx].kind))
            .collect();

        // If that made it empty, fall back to original candidates.
        if action_candidates.is_empty() {
            action_candidates = candidates.clone();
        }

        // 5) Prefer arch match if triage specifies arch
        let mut arch_candidates: Vec<usize> = action_candidates
            .iter()
            .copied()
            .filter(|&idx| arch_matches(&t.arch, &run.events[idx].arch))
            .collect();

        if arch_candidates.is_empty() {
            arch_candidates = action_candidates;
        } else {
            // If we found arch-matching candidates and triage provided arch, bump confidence.
            if t.arch.is_some() {
                match_confidence = MatchConfidence::Exact;
            }
        }

        // 6) Prefer matching "to_version" if available
        let mut version_candidates: Vec<usize> = arch_candidates
            .iter()
            .copied()
            .filter(|&idx| version_to_matches(&t.planned_to_version, &run.events[idx].to_version))
            .collect();

        if version_candidates.is_empty() {
            version_candidates = arch_candidates;
        }

        // 7) Decide final match (if multiple, mark ambiguous)
        let chosen_idx = *version_candidates.last().unwrap(); // latest occurrence wins
        let is_ambiguous = version_candidates.len() > 1;

        let ev = &run.events[chosen_idx];

        let mut status = kind_to_status(&ev.kind);
        let reason = ev.reason.clone();

        // If the best we found is just "Planned", treat it as NotAttempted
        // unless there are other candidates that indicate an actual outcome.
        if status == ReconcileStatus::NotAttempted {
            // look for any non-Planned candidate for same package
            if let Some(&alt_idx) = candidates
                .iter()
                .rev()
                .find(|&&idx| run.events[idx].kind != PackageEventKind::Planned)
            {
                let alt = &run.events[alt_idx];
                status = kind_to_status(&alt.kind);
            }
        }

        let final_status = if is_ambiguous {
            ReconcileStatus::Ambiguous
        } else {
            status
        };

        match final_status {
            ReconcileStatus::Succeeded => matched_success += 1,
            ReconcileStatus::Failed => matched_failed += 1,
            ReconcileStatus::Skipped => skipped += 1,
            ReconcileStatus::NotAttempted => not_attempted += 1,
            ReconcileStatus::Ambiguous => ambiguous += 1,
        }

        items.push(ReconcileMatch {
            status: final_status.clone(),
            match_confidence,
            triage_id: t.triage_id.clone(),
            planned_action: t.planned_action.clone(),
            planned_package_name: t.package_name.clone(),
            planned_package_name_norm: t.package_name_norm.clone(),
            planned_arch: t.arch.clone(),
            planned_from_version: t.planned_from_version.clone(),
            planned_to_version: t.planned_to_version.clone(),
            matched_event_index: Some(chosen_idx),
            actual_event_kind: Some(ev.kind.clone()),
            actual_package_name: Some(ev.package_name.clone()),
            actual_arch: ev.arch.clone(),
            actual_from_version: ev.from_version.clone(),
            actual_to_version: ev.to_version.clone(),
            reason: reason.clone(),
            note: note_for(
                &final_status,
                &ev.package_name,
                &ev.from_version,
                &ev.to_version,
                &reason,
            ),
        });
    }

    ReconcileResult {
        run_id: run.run_id.clone(),
        total_planned: triage_items.len(),
        matched_success,
        matched_failed,
        skipped,
        not_attempted,
        ambiguous,
        items,
    }
}
