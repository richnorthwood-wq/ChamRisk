use chamrisk_core::models::{
    Confidence, EventLevel, MatchConfidence, PackageBackend, PackageEvent, PackageEventKind,
    PlannedAction, ProcessRun, ProcessStatus, ProcessSummary, ReconcileStatus, TriagePackage,
};
use chamrisk_core::services::reconciler::reconcile_triage_against_run;

fn mk_run(events: Vec<PackageEvent>) -> ProcessRun {
    ProcessRun {
        run_id: "run-1".to_string(),
        backend: PackageBackend::Zypper,
        command: "zypper".to_string(),
        args: vec!["patch".to_string()],
        started_at_utc: "2026-02-27T10:00:00Z".to_string(),
        ended_at_utc: Some("2026-02-27T10:00:05Z".to_string()),
        duration_ms: Some(5000),
        events,
        summary: ProcessSummary {
            process_name: "zypper".to_string(),
            process_type: "update".to_string(),
            status: ProcessStatus::Success,
            reboot_recommended: false,
            test_required: false,
            summary_line: "ok".to_string(),
            exit_code: Some(0),
            confidence: Confidence::High,
            error_category: None,
        },
    }
}

// Adjust this to match crates/core/src/models/triage.rs exactly.
// The idea: keep it boring and explicit.
fn mk_triage(
    triage_id: &str,
    name: &str,
    norm: &str,
    action: PlannedAction,
    to_version: Option<&str>,
) -> TriagePackage {
    TriagePackage {
        triage_id: triage_id.to_string(),
        backend: PackageBackend::Zypper,
        package_name: name.to_string(),
        package_name_norm: norm.to_string(),
        arch: None,
        planned_action: action,
        planned_from_version: None,
        planned_to_version: to_version.map(|s| s.to_string()),
        selected: true,
        source_repo: None,
    }
}

#[test]
fn reconcile_success_and_failure() {
    let triage = vec![
        mk_triage("t1", "vim", "vim", PlannedAction::Upgrade, Some("9.0-2")),
        mk_triage(
            "t2",
            "kernel-default",
            "kernel-default",
            PlannedAction::Upgrade,
            Some("6.8.1"),
        ),
    ];

    let run = mk_run(vec![
        PackageEvent {
            ts_ms: Some(1),
            backend: PackageBackend::Zypper,
            kind: PackageEventKind::UpgradeSucceeded,
            package_name: "vim".to_string(),
            package_name_norm: "vim".to_string(),
            arch: None,
            from_version: Some("9.0-1".to_string()),
            to_version: Some("9.0-2".to_string()),
            repo: None,
            level: EventLevel::Info,
            raw_line: None,
            reason: None,
        },
        PackageEvent {
            ts_ms: Some(2),
            backend: PackageBackend::Zypper,
            kind: PackageEventKind::UpgradeFailed,
            package_name: "kernel-default".to_string(),
            package_name_norm: "kernel-default".to_string(),
            arch: None,
            from_version: Some("6.8.0".to_string()),
            to_version: Some("6.8.1".to_string()),
            repo: None,
            level: EventLevel::Error,
            raw_line: None,
            reason: Some("dependency conflict".to_string()),
        },
    ]);

    let result = reconcile_triage_against_run(&triage, &run);

    assert_eq!(result.total_planned, 2);
    assert_eq!(result.matched_success, 1);
    assert_eq!(result.matched_failed, 1);
    assert_eq!(result.skipped, 0);
    assert_eq!(result.not_attempted, 0);
    assert_eq!(result.ambiguous, 0);

    let t1 = result.items.iter().find(|i| i.triage_id == "t1").unwrap();
    assert_eq!(t1.status, ReconcileStatus::Succeeded);
    assert_eq!(t1.match_confidence, MatchConfidence::Strong);

    let t2 = result.items.iter().find(|i| i.triage_id == "t2").unwrap();
    assert_eq!(t2.status, ReconcileStatus::Failed);
    assert!(t2.note.contains("dependency conflict"));
}
