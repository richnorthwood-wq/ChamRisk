use chamrisk_core::models::{
    CommandResult, Confidence, PackageBackend, PackageChange, PackageLock, ProcessRun,
    ProcessStatus, ProcessSummary, ReconcileResult, UpdateAction, UpdatePlan,
};
use chamrisk_ops::events::{OpsEvent as StructuredOpsEvent, OpsEventKind};
use chamrisk_ops::runner::{LogStream, OperationKind, OpsEvent, RunSummary};
use chamrisk_ui::app::RiskFilter;
use chamrisk_ui::{AppEvent, LogLevel, LogStage, MaintenanceApp, Tab};

fn sample_run_summary() -> RunSummary {
    RunSummary {
        verdict: "PASS".to_string(),
        attempted: 1,
        installed: 1,
        failed: 0,
        unaccounted: 0,
        process_run: Some(ProcessRun {
            run_id: "run-1".to_string(),
            backend: PackageBackend::Zypper,
            command: "zypper".to_string(),
            args: Vec::new(),
            started_at_utc: "0".to_string(),
            ended_at_utc: None,
            duration_ms: None,
            events: Vec::new(),
            summary: ProcessSummary {
                process_name: "zypper".to_string(),
                process_type: "update".to_string(),
                status: ProcessStatus::Success,
                reboot_recommended: false,
                test_required: false,
                summary_line: "Completed with exit code 0".to_string(),
                exit_code: Some(0),
                confidence: Confidence::Medium,
                error_category: None,
            },
        }),
        reconcile: Some(ReconcileResult {
            run_id: "run-1".to_string(),
            total_planned: 1,
            matched_success: 1,
            matched_failed: 0,
            skipped: 0,
            not_attempted: 0,
            ambiguous: 0,
            items: Vec::new(),
        }),
    }
}

#[test]
fn keyboard_shortcuts_match() {
    let app = MaintenanceApp::default();
    assert!(matches!(
        app.handle_shortcut(true, false, 'q'),
        Some(AppEvent::Quit)
    ));
    assert!(matches!(
        app.handle_shortcut(true, false, 'r'),
        Some(AppEvent::Refresh)
    ));
    assert!(matches!(
        app.handle_shortcut(true, true, 't'),
        Some(AppEvent::DemoUpdates)
    ));
}

#[test]
fn keeps_logs_separate() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::Log {
        stream: LogStream::Updates,
        line: "INFO: preview check".into(),
    });
    app.apply_ops_event(OpsEvent::Log {
        stream: LogStream::Btrfs,
        line: "ERROR: snapshot failed".into(),
    });
    assert_eq!(app.updates_log, vec!["INFO: preview check"]);
    assert_eq!(app.btrfs_log, vec!["ERROR: snapshot failed"]);
    assert_eq!(app.logs.len(), 2);
    assert_eq!(app.logs[0].level, LogLevel::Info);
    assert_eq!(app.logs[0].stage, LogStage::Preview);
    assert_eq!(app.logs[0].message, "INFO: preview check");
    assert!(!app.logs[0].timestamp.is_empty());
    assert_eq!(app.logs[1].level, LogLevel::Error);
    assert_eq!(app.logs[1].stage, LogStage::System);
    assert_eq!(app.logs[1].message, "ERROR: snapshot failed");
    assert!(!app.logs[1].timestamp.is_empty());
}

#[test]
fn package_manager_lock_logs_are_classified_as_lock_stage() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: "INFO: Starting lock operation (add) for nano".into(),
    });
    app.apply_ops_event(OpsEvent::Log {
        stream: LogStream::PackageManager,
        line: "INFO: Refreshing package locks after 'add'".into(),
    });

    assert!(app
        .logs
        .iter()
        .any(|entry| entry.stage == LogStage::Locks
            && entry.message.contains("Starting lock operation")));
    assert!(app.logs.iter().any(|entry| entry.stage == LogStage::Locks
        && entry.message.contains("Refreshing package locks")));
}

#[test]
fn counts_and_details() {
    let mut app = MaintenanceApp::default();
    app.set_changes(vec![
        PackageChange {
            name: "a".into(),
            arch: None,
            action: UpdateAction::VendorChange,
            from: None,
            to: None,
            repo: None,
            vendor: Some("VendorA -> VendorB".into()),
            kind: None,
        },
        PackageChange {
            name: "b".into(),
            arch: None,
            action: UpdateAction::RepoChange,
            from: None,
            to: None,
            repo: Some("RepoA -> RepoB".into()),
            vendor: None,
            kind: None,
        },
    ]);
    assert_eq!(app.counts.all, 2);
    assert_eq!(app.counts.vendor_changes, 1);
    assert_eq!(app.counts.repo_changes, 1);
    app.selected = Some(1);
    assert_eq!(app.selected_details().unwrap().name, "b");
    app.active_tab = Tab::Reports;
}

#[test]
fn package_triage_uses_core_risk_engine_for_systemd() {
    let pkg = PackageChange {
        name: "systemd".into(),
        arch: Some("x86_64".into()),
        action: UpdateAction::Upgrade,
        from: Some("1.0.0".into()),
        to: Some("1.0.1".into()),
        repo: Some("repo-oss".into()),
        vendor: None,
        kind: None,
    };

    assert_eq!(
        MaintenanceApp::package_risk_category(&pkg),
        RiskFilter::Amber
    );
}

#[test]
fn package_triage_keeps_leaf_upgrade_green() {
    let pkg = PackageChange {
        name: "nano".into(),
        arch: Some("x86_64".into()),
        action: UpdateAction::Upgrade,
        from: Some("1.0.0".into()),
        to: Some("1.0.1".into()),
        repo: Some("repo-oss".into()),
        vendor: None,
        kind: None,
    };

    assert_eq!(
        MaintenanceApp::package_risk_category(&pkg),
        RiskFilter::Green
    );
}

#[test]
fn journal_only_run_skips_reconciliation_summary() {
    let mut app = MaintenanceApp::default();
    app.active_tab = Tab::Reports;
    app.execution_selection.zypper_dup = false;
    app.execution_selection.packman_preference = false;
    app.execution_selection.flatpaks = false;
    app.execution_selection.journal_vacuum = true;
    app.begin_updates_run(false);
    app.apply_ops_event(OpsEvent::UpdatePlan(UpdatePlan {
        changes: vec![PackageChange {
            name: "stale-plan".into(),
            arch: None,
            action: UpdateAction::Install,
            from: None,
            to: Some("1.0".into()),
            repo: Some("OSS".into()),
            vendor: None,
            kind: None,
        }],
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    }));

    app.apply_ops_event(OpsEvent::CommandResult {
        operation: OperationKind::UpdatesJournalVacuum,
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    });

    assert!(!app
        .updates_log
        .iter()
        .any(|line| line == "Reconciliation summary"));
    assert!(app.last_reconcile.is_none());
}

#[test]
fn package_ops_still_emit_reconciliation_summary() {
    let mut app = MaintenanceApp::default();
    app.active_tab = Tab::Reports;
    app.execution_selection.zypper_dup = true;
    app.execution_selection.flatpaks = false;
    app.execution_selection.packman_preference = false;
    app.begin_updates_run(true);
    app.apply_ops_event(OpsEvent::UpdatePlan(UpdatePlan {
        changes: vec![PackageChange {
            name: "pkg".into(),
            arch: None,
            action: UpdateAction::Install,
            from: None,
            to: Some("1.0".into()),
            repo: Some("OSS".into()),
            vendor: None,
            kind: None,
        }],
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    }));

    app.apply_ops_event(OpsEvent::RunSummary(sample_run_summary()));

    assert!(app
        .updates_log
        .iter()
        .any(|line| line == "Reconciliation summary"));
}

#[test]
fn triage_preview_events_do_not_append_to_visible_updates_log() {
    let mut app = MaintenanceApp::default();
    app.updates_log.push("existing".to_string());

    app.apply_ops_event(OpsEvent::Structured(StructuredOpsEvent::from_kind(
        OpsEventKind::PreviewStart,
    )));
    assert!(app.preview_running);
    assert_eq!(app.updates_log, vec!["existing"]);

    app.apply_ops_event(OpsEvent::Structured(StructuredOpsEvent::from_kind(
        OpsEventKind::PreviewResult { packages: 3 },
    )));
    assert!(!app.preview_running);
    assert_eq!(app.last_preview_packages, Some(3));
    assert_eq!(app.updates_log, vec!["existing"]);
}

#[test]
fn triage_refresh_update_plan_does_not_append_refresh_completed() {
    let mut app = MaintenanceApp::default();
    app.updates_log.push("existing".to_string());
    app.triage_preview_status = chamrisk_ui::app::TriagePreviewStatus::Updating;

    app.apply_ops_event(OpsEvent::UpdatePlan(UpdatePlan {
        changes: vec![PackageChange {
            name: "pkg".into(),
            arch: None,
            action: UpdateAction::Upgrade,
            from: Some("1.0".into()),
            to: Some("1.1".into()),
            repo: Some("OSS".into()),
            vendor: None,
            kind: None,
        }],
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    }));

    assert_eq!(
        app.triage_preview_status,
        chamrisk_ui::app::TriagePreviewStatus::Complete
    );
    assert!(app.update_plan.is_some());
    assert_eq!(app.updates_log, vec!["existing"]);
}

#[test]
fn package_manager_preview_plan_still_updates_package_manager_state() {
    let mut app = MaintenanceApp::default();
    app.updates_log.push("existing".to_string());
    app.package_manager.busy_preview = true;

    app.apply_ops_event(OpsEvent::UpdatePlan(UpdatePlan {
        changes: vec![PackageChange {
            name: "pkg".into(),
            arch: None,
            action: UpdateAction::Install,
            from: None,
            to: Some("1.0".into()),
            repo: Some("OSS".into()),
            vendor: None,
            kind: None,
        }],
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    }));

    assert!(!app.package_manager.busy_preview);
    assert!(app.package_manager.preview_error.is_none());
    assert!(app.package_manager.preview_plan.is_some());
    assert_eq!(app.updates_log, vec!["existing"]);
}

#[test]
fn flatpak_only_run_does_not_reuse_stale_zypper_plan() {
    let mut app = MaintenanceApp::default();
    app.active_tab = Tab::Reports;

    app.begin_updates_run(true);
    app.apply_ops_event(OpsEvent::UpdatePlan(UpdatePlan {
        changes: vec![PackageChange {
            name: "pkg".into(),
            arch: None,
            action: UpdateAction::Install,
            from: None,
            to: Some("1.0".into()),
            repo: Some("OSS".into()),
            vendor: None,
            kind: None,
        }],
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    }));
    app.apply_ops_event(OpsEvent::RunSummary(sample_run_summary()));
    assert!(app.last_reconcile.is_some());
    let reconciliation_summaries_before = app
        .updates_log
        .iter()
        .filter(|line| *line == "Reconciliation summary")
        .count();

    app.execution_selection.zypper_dup = false;
    app.execution_selection.packman_preference = false;
    app.execution_selection.flatpaks = true;
    app.begin_updates_run(false);
    app.apply_ops_event(OpsEvent::CommandResult {
        operation: OperationKind::UpdatesFlatpak,
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    });

    assert!(app.last_reconcile.is_none());
    assert!(!app
        .updates_log
        .iter()
        .any(|line| line == "INFO: Running zypper preview"));
    assert_eq!(
        app.updates_log
            .iter()
            .filter(|line| *line == "Reconciliation summary")
            .count(),
        reconciliation_summaries_before
    );
    assert!(!app
        .updates_log
        .iter()
        .any(|line| line.contains("Attempted=0") && line.contains("Verdict=SKIP")));
}

#[test]
fn install_events_are_visible_in_on_screen_log() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::Structured(StructuredOpsEvent::from_kind(
        OpsEventKind::PackageInstalled {
            name: "mesa".into(),
            from: None,
            to: Some("1.2.3".into()),
            repo: Some("OSS".into()),
            arch: Some("x86_64".into()),
        },
    )));

    let install_row = app
        .logs
        .iter()
        .find(|entry| entry.message == "INFO: Installed mesa")
        .expect("expected install event in on-screen log");
    assert_eq!(install_row.stage, LogStage::Install);
    assert_eq!(install_row.level, LogLevel::Info);
}

#[test]
fn reconciliation_events_are_visible_in_on_screen_log() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::RunSummary(sample_run_summary()));

    assert!(app
        .logs
        .iter()
        .any(|entry| entry.stage == LogStage::Reconciliation
            && entry.message == "Reconciliation summary"));
    assert!(app
        .logs
        .iter()
        .any(|entry| entry.stage == LogStage::Reconciliation
            && entry.message.contains("Attempted=1")
            && entry.message.contains("Verdict=PASS")));
}

#[test]
fn reconcile_summary_and_run_summary_yield_one_visible_stats_row() {
    let mut app = MaintenanceApp::default();

    app.apply_ops_event(OpsEvent::Structured(StructuredOpsEvent::from_kind(
        OpsEventKind::ReconcileSummary {
            attempted: 1,
            installed: 1,
            failed: 0,
            unaccounted: 0,
            verdict: "PASS".into(),
        },
    )));
    app.apply_ops_event(OpsEvent::RunSummary(sample_run_summary()));

    assert_eq!(
        app.updates_log
            .iter()
            .filter(|line| **line == "Reconciliation summary")
            .count(),
        1
    );
    assert_eq!(
        app.updates_log
            .iter()
            .filter(|line| {
                line.contains("Attempted=1")
                    && line.contains("Installed=1")
                    && line.contains("Failed=0")
                    && line.contains("Unaccounted=0")
                    && line.contains("Verdict=PASS")
            })
            .count(),
        1
    );
}

#[test]
fn package_locks_event_populates_package_manager_lock_state() {
    let mut app = MaintenanceApp::default();
    app.package_manager.locks_busy = true;
    app.package_manager.locks_error = Some("old".into());
    app.apply_ops_event(OpsEvent::PackageLocks(vec![PackageLock {
        lock_id: Some("1".into()),
        name: "MozillaFirefox".into(),
        match_type: Some("package".into()),
        repository: None,
        comment: None,
        raw_entry: "| 1 | MozillaFirefox | package |".into(),
    }]));

    assert_eq!(app.package_manager.locks.len(), 1);
    assert_eq!(app.package_manager.active_lock_count(), 1);
    assert!(!app.package_manager.locks_busy);
    assert_eq!(app.package_manager.locks_error, None);
}

#[test]
fn package_manager_active_lock_count_ignores_informational_rows() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::PackageLocks(vec![PackageLock {
        lock_id: None,
        name: "There are no package locks defined.".into(),
        match_type: None,
        repository: None,
        comment: None,
        raw_entry: "There are no package locks defined.".into(),
    }]));

    assert_eq!(app.package_manager.locks.len(), 1);
    assert_eq!(app.package_manager.active_lock_count(), 0);
}

#[test]
fn package_manager_active_lock_count_ignores_blank_ids_and_counts_real_ids() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::PackageLocks(vec![
        PackageLock {
            lock_id: Some("   ".into()),
            name: "informational".into(),
            match_type: None,
            repository: None,
            comment: None,
            raw_entry: "informational".into(),
        },
        PackageLock {
            lock_id: Some("1".into()),
            name: "MozillaFirefox".into(),
            match_type: Some("package".into()),
            repository: None,
            comment: None,
            raw_entry: "| 1 | MozillaFirefox | package |".into(),
        },
    ]));

    assert_eq!(app.package_manager.locks.len(), 2);
    assert_eq!(app.package_manager.active_lock_count(), 1);
}

#[test]
fn package_lock_error_updates_package_manager_tab_state() {
    let mut app = MaintenanceApp::default();
    app.package_manager.locks_busy = true;
    app.apply_ops_event(OpsEvent::Error("PKG_LOCKS: zypper locks failed".into()));

    assert!(!app.package_manager.locks_busy);
    assert_eq!(
        app.package_manager.locks_error.as_deref(),
        Some("PKG_LOCKS: zypper locks failed")
    );
}

#[test]
fn package_lock_action_prefix_errors_update_lock_state() {
    let mut app = MaintenanceApp::default();

    for line in [
        "PKG_LOCK_ADD: add failed",
        "PKG_LOCK_REMOVE: remove failed",
        "PKG_LOCK_CLEAN: clean failed",
    ] {
        app.package_manager.locks_busy = true;
        app.apply_ops_event(OpsEvent::Error(line.into()));
        assert!(!app.package_manager.locks_busy);
        assert_eq!(app.package_manager.locks_error.as_deref(), Some(line));
    }
}

#[test]
fn package_lock_completion_failure_preserves_lock_error() {
    let mut app = MaintenanceApp::default();
    let line = "PKG_LOCK_ADD: add failed".to_string();

    app.package_manager.locks_busy = true;
    app.apply_ops_event(OpsEvent::Error(line.clone()));
    app.apply_ops_event(OpsEvent::PackageLockOperationCompleted {
        action: "add".into(),
        name: "nano".into(),
        success: false,
        message: line,
    });

    assert_eq!(
        app.package_manager.locks_error.as_deref(),
        Some("PKG_LOCK_ADD: add failed")
    );
    assert!(!app.package_manager.locks_busy);
}
