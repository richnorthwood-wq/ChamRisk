use chamrisk_ops::report_model::ReportModel;
use chamrisk_ops::report_store::{PackageEvidenceRow, ReportStore};
use tempfile::tempdir;

fn canonical_package_rows(run_id: &str) -> Vec<PackageEvidenceRow> {
    vec![
        PackageEvidenceRow {
            run_id: run_id.to_string(),
            package_name: "kernel-default".to_string(),
            from_version: Some("6.8.0".to_string()),
            to_version: Some("6.9.0".to_string()),
            arch: Some("x86_64".to_string()),
            repository: Some("repo-oss".to_string()),
            action: Some("upgrade".to_string()),
            result: Some("succeeded".to_string()),
            risk: Some("red".to_string()),
        },
        PackageEvidenceRow {
            run_id: run_id.to_string(),
            package_name: "mesa".to_string(),
            from_version: Some("24.0".to_string()),
            to_version: Some("24.1".to_string()),
            arch: Some("x86_64".to_string()),
            repository: Some("packman".to_string()),
            action: Some("upgrade".to_string()),
            result: Some("succeeded".to_string()),
            risk: Some("amber".to_string()),
        },
    ]
}

fn persist_canonical_update_events(store: &ReportStore, run_id: &str) {
    store
        .append_event(
            run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":2}"#,
            "Preview result with 2 package(s)",
        )
        .expect("append preview result");
    store
        .append_event(
            run_id,
            "zypper",
            "info",
            "zypper.apply.result",
            r#"{"exit_code":0}"#,
            "Completed with exit code 0",
        )
        .expect("append apply result");
    store
        .append_event(
            run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":2,"installed":2,"failed":0,"unaccounted":0}"#,
            "reconciliation complete",
        )
        .expect("append reconcile summary");
    store
        .replace_packages(run_id, &canonical_package_rows(run_id))
        .expect("persist package evidence");
}

#[test]
fn builds_report_model_from_seeded_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(
            r#"{"zypper_dup":true,"flatpak":false,"repos":["oss","packman"],"risk_filter":"amber"}"#,
            "1.2.3",
        )
        .expect("start run");

    store
        .upsert_ai_assessment(
            &run_id,
            Some("Green"),
            r#"["1) Apply updates.","2) Reboot after update."]"#,
        )
        .expect("persist ai assessment");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "progress",
            r#"{}"#,
            " AI_ASSESSMENT:  Green  |  1) Apply updates.  \n 2) Reboot after update. ",
        )
        .expect("append ai assessment log");
    store
        .append_event(
            &run_id,
            "apply",
            "info",
            "PackageResult",
            r#"{"name":"mesa","status":"installed","from_version":"24.0","to_version":"24.1","repo":"packman","arch":"x86_64"}"#,
            "mesa installed",
        )
        .expect("append package result");
    store
        .append_event(
            &run_id,
            "flatpak",
            "info",
            "flatpak.package",
            r#"{"app_id":"dev.zed.Zed"}"#,
            "Updated dev.zed.Zed",
        )
        .expect("append flatpak package");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
            "reconciliation complete",
        )
        .expect("append reconcile summary");
    store
        .finish_run(&run_id, 5_000, "PASS", 1, 1, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.header.run_id, run_id);
    assert_eq!(model.header.ended_at_ms, Some(5_000));
    assert_eq!(model.header.verdict, "PASS");
    assert_eq!(model.header.app_version, "1.2.3");
    assert_eq!(
        model.header.repos_requested,
        vec!["oss".to_string(), "packman".to_string()]
    );
    assert_eq!(model.header.repos_effective, vec!["packman".to_string()]);
    assert!(model
        .selection_rows
        .iter()
        .any(|row| row.name == "Zypper Dup" && row.requested && row.effective));
    assert!(model
        .selection_rows
        .iter()
        .any(|row| row.name == "Risk Filter: amber" && row.requested && row.effective));
    assert!(model
        .selection_rows
        .iter()
        .any(|row| row.name == "Repos: oss, packman" && row.requested && row.effective));

    assert!(model.package_rows.is_empty());
    assert!(model.package_evidence.is_empty());
    assert!(model.package_summary.is_none());

    assert_eq!(model.log_entries.len(), 3);
    assert!(model.log_entries[0].ts_ms > 0);
    assert_eq!(model.log_entries[0].severity, "info");
    assert_eq!(model.log_entries[0].phase, "run");
    assert_eq!(model.log_entries[0].event_type, "ai.assessment");
    assert!(model.log_entries[0].message.contains("AI_ASSESSMENT:"));
    assert_eq!(model.log_entries[1].severity, "info");
    assert_eq!(model.log_entries[1].phase, "flatpak");
    assert_eq!(model.log_entries[1].event_type, "flatpak.package");
    assert_eq!(model.log_entries[1].message, "Updated dev.zed.Zed");
    assert_eq!(model.log_entries[2].severity, "info");
    assert_eq!(model.log_entries[2].phase, "reconcile");
    assert_eq!(model.log_entries[2].event_type, "reconcile.summary");
    assert_eq!(
        model.log_entries[2].message,
        "Attempted=1 Installed=1 Failed=0 Unaccounted=0 Verdict=PASS"
    );

    assert_eq!(model.reconciliation.verdict, "PASS");
    assert_eq!(model.reconciliation.attempted, 1);
    assert_eq!(model.reconciliation.installed, 1);
    assert_eq!(model.reconciliation.failed, 0);
    assert_eq!(model.reconciliation.unaccounted, 0);
    assert_eq!(model.execution_result, "PASS");
    assert_eq!(model.update_type.as_deref(), Some("Zypper Dup"));
    assert_eq!(model.snapshot_status, None);
    assert_eq!(model.reboot_status.as_deref(), Some("Likely"));
    assert_eq!(model.ai_risk.as_deref(), Some("Green"));
    assert_eq!(
        model.ai_recommendations,
        vec![
            chamrisk_ops::report_model::RecommendationRow {
                step: "1".to_string(),
                recommendation: "Apply updates.".to_string(),
                reason: None,
            },
            chamrisk_ops::report_model::RecommendationRow {
                step: "2".to_string(),
                recommendation: "Reboot after update.".to_string(),
                reason: None,
            }
        ]
    );
    assert_eq!(model.flatpak_rows.len(), 1);
    assert_eq!(model.flatpak_rows[0].app_id, "dev.zed.Zed");
    assert_eq!(model.flatpak_rows[0].status, "success");
    assert_eq!(model.flatpak_rows[0].origin, None);
    assert_eq!(model.change_summary.total_package_count, Some(1));
    assert_eq!(model.change_summary.flatpak_count, Some(1));
    assert_eq!(
        model.change_summary.update_type.as_deref(),
        Some("Zypper Dup")
    );
    assert!(model
        .change_summary
        .repo_vendor_anomalies
        .iter()
        .any(|item| item.contains("Requested repos not effective: oss")));
}

#[test]
fn end_to_end_update_ai_report_workflow_keeps_one_canonical_run_id() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-e2e-canonical-run.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(
            r#"{"zypper_dup":true,"flatpak":false,"repos":["repo-oss","packman"]}"#,
            "1.2.3",
        )
        .expect("start update run");

    persist_canonical_update_events(&store, &run_id);
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("persist ai assessment");
    store
        .finish_run(&run_id, 5_000, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let events = store.load_events(&run_id).expect("load events");
    assert!(events
        .iter()
        .any(|event| event.event_type == "preview.result"));
    assert!(events
        .iter()
        .any(|event| event.event_type == "ReconcileSummary"));

    let packages = store.load_packages(&run_id).expect("load packages");
    assert_eq!(packages.len(), 2);
    assert!(packages.iter().all(|row| row.run_id == run_id));

    let ai_row = store
        .load_ai_assessment(&run_id)
        .expect("load ai assessment")
        .expect("ai row");
    assert_eq!(ai_row.run_id, run_id);
    assert_eq!(ai_row.risk_level.as_deref(), Some("Amber"));

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");
    assert_eq!(model.header.run_id, run_id);
    assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
    assert_eq!(model.ai_recommendations.len(), 2);
    assert_eq!(model.package_evidence.len(), 2);
    assert_eq!(model.reconciliation.verdict, "PASS");
}

#[test]
fn ai_attempt_before_canonical_run_creation_does_not_attach_to_other_active_run() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-e2e-no-stolen-active-run.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let unrelated_active_run = store
        .start_run(r#"{"flatpak":true}"#, "1.2.3")
        .expect("start unrelated active run");

    let err = store
        .upsert_ai_assessment(
            "future-update-run",
            Some("Red"),
            r#"["1) Do not proceed."]"#,
        )
        .expect_err("unknown run should fail");
    assert!(err.contains("failed to upsert ai assessment"));
    assert!(store
        .load_ai_assessment(&unrelated_active_run)
        .expect("load unrelated ai row")
        .is_none());

    let update_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start update run");
    persist_canonical_update_events(&store, &update_run);
    store
        .upsert_ai_assessment(
            &update_run,
            Some("Green"),
            r#"["1) Apply updates.","2) Reboot after update."]"#,
        )
        .expect("persist update ai");
    store
        .finish_run(&update_run, 5_000, "PASS", 2, 2, 0, 0)
        .expect("finish update run");

    let model = ReportModel::from_store(&store, &update_run).expect("build report model");
    assert_eq!(model.header.run_id, update_run);
    assert_eq!(model.ai_risk.as_deref(), Some("Green"));
    assert!(store
        .load_ai_assessment(&unrelated_active_run)
        .expect("reload unrelated ai row")
        .is_none());
}

#[test]
fn multiple_runs_in_one_session_keep_ai_assessments_isolated() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-e2e-multi-run-isolation.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_a = store
        .start_run(r#"{"zypper_dup":true,"repos":["repo-oss"]}"#, "1.2.3")
        .expect("start run a");
    persist_canonical_update_events(&store, &run_a);
    store
        .upsert_ai_assessment(&run_a, Some("Amber"), r#"["1) Snapshot first."]"#)
        .expect("persist ai a");
    store
        .finish_run(&run_a, 5_000, "PASS", 2, 2, 0, 0)
        .expect("finish run a");

    let run_b = store
        .start_run(r#"{"zypper_dup":true,"repos":["packman"]}"#, "1.2.3")
        .expect("start run b");
    persist_canonical_update_events(&store, &run_b);
    store
        .upsert_ai_assessment(
            &run_b,
            Some("Red"),
            r#"["1) Review vendor changes.","2) Reboot after update."]"#,
        )
        .expect("persist ai b");
    store
        .finish_run(&run_b, 6_000, "PASS", 2, 2, 0, 0)
        .expect("finish run b");

    let model_a = ReportModel::from_store(&store, &run_a).expect("build model a");
    let model_b = ReportModel::from_store(&store, &run_b).expect("build model b");

    assert_eq!(model_a.header.run_id, run_a);
    assert_eq!(model_a.ai_risk.as_deref(), Some("Amber"));
    assert_eq!(model_a.ai_recommendations.len(), 1);

    assert_eq!(model_b.header.run_id, run_b);
    assert_eq!(model_b.ai_risk.as_deref(), Some("Red"));
    assert_eq!(model_b.ai_recommendations.len(), 2);
}

#[test]
fn failed_unrelated_run_does_not_steal_ai_assessment_from_real_update_run() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-e2e-failed-run-isolation.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let failed_run = store
        .start_run(r#"{"flatpak":true,"journal_vacuum":true}"#, "1.2.3")
        .expect("start failed run");
    store
        .append_event(
            &failed_run,
            "flatpak",
            "error",
            "progress",
            r#"{}"#,
            "Flatpak system update requires sudo password",
        )
        .expect("append failure event");
    store
        .finish_run(&failed_run, 2_000, "FAIL", 0, 0, 0, 0)
        .expect("finish failed run");

    let update_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start update run");
    persist_canonical_update_events(&store, &update_run);
    store
        .upsert_ai_assessment(
            &update_run,
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("persist update ai");
    store
        .finish_run(&update_run, 5_000, "PASS", 2, 2, 0, 0)
        .expect("finish update run");

    assert!(store
        .load_ai_assessment(&failed_run)
        .expect("load failed run ai")
        .is_none());

    let model = ReportModel::from_store(&store, &update_run).expect("build update model");
    assert_eq!(model.header.run_id, update_run);
    assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
    assert_eq!(model.reconciliation.verdict, "PASS");
}

#[test]
fn from_rows_can_still_parse_pipe_delimited_ai_assessment_from_persisted_event() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-ai-assessment.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Green","recommendations":["1) Apply updates.","2) Reboot after update."]}"#,
            "AI_ASSESSMENT:Green|1) Apply updates.|2) Reboot after update.",
        )
        .expect("append ai assessment");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let run = store
        .list_runs(10)
        .expect("list runs")
        .into_iter()
        .find(|row| row.run_id == run_id)
        .expect("run row");
    let events = store.load_events(&run_id).expect("load events");
    let model = ReportModel::from_rows(run, events).expect("build report model");

    assert_eq!(model.ai_risk.as_deref(), Some("Green"));
    assert_eq!(
        model.ai_recommendations,
        vec![
            chamrisk_ops::report_model::RecommendationRow {
                step: "1".to_string(),
                recommendation: "Apply updates.".to_string(),
                reason: None,
            },
            chamrisk_ops::report_model::RecommendationRow {
                step: "2".to_string(),
                recommendation: "Reboot after update.".to_string(),
                reason: None,
            }
        ]
    );
}

#[test]
fn from_store_reads_durable_ai_assessment_without_event_fallback() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-ai-assessment-store.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.2.3")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("persist ai assessment");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let model = ReportModel::from_store(&reopened, &run_id).expect("build report model");

    assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
    assert_eq!(model.ai_recommendations.len(), 2);
    assert_eq!(
        model.ai_recommendations[0].recommendation,
        "Snapshot first."
    );
    assert_eq!(
        model.ai_recommendations[1].recommendation,
        "Reboot after update."
    );
}

#[test]
fn from_store_prefers_durable_ai_assessment_over_transient_event_values() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-durable-ai-wins.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("persist durable ai assessment");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","recommendations":["1) Do not proceed."]}"#,
            "AI_ASSESSMENT:Red|1) Do not proceed.",
        )
        .expect("append conflicting transient ai event");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
    assert_eq!(model.ai_recommendations.len(), 2);
    assert_eq!(
        model.ai_recommendations[0].recommendation,
        "Snapshot first."
    );
    assert_eq!(
        model.ai_recommendations[1].recommendation,
        "Reboot after update."
    );
}

#[test]
fn from_store_returns_not_available_ai_fields_when_no_ai_assessment_row_exists() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-no-ai-assessment-row.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Green","recommendations":["1) Apply updates.","2) Reboot after update."]}"#,
            "AI_ASSESSMENT:Green|1) Apply updates.|2) Reboot after update.",
        )
        .expect("append transient ai assessment event");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let model = ReportModel::from_store(&reopened, &run_id).expect("build report model");

    assert_eq!(model.ai_risk, None);
    assert!(model.ai_recommendations.is_empty());
}

#[test]
fn falls_back_to_run_row_reconciliation_when_summary_event_is_missing() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-fallback.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":true,"journal_vacuum":false}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "flatpak",
            "error",
            "progress",
            r#"{}"#,
            "Flatpak system update requires sudo password",
        )
        .expect("append event");
    store
        .finish_run(&run_id, 9_000, "FAIL", 3, 1, 2, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.package_rows.len(), 0);
    assert_eq!(model.reconciliation.verdict, "FAIL");
    assert_eq!(model.reconciliation.attempted, 3);
    assert_eq!(model.reconciliation.installed, 1);
    assert_eq!(model.reconciliation.failed, 2);
    assert_eq!(model.reconciliation.unaccounted, 0);
    assert_eq!(model.execution_result, "FAIL");
    assert_eq!(model.log_entries.len(), 1);
    assert!(model.package_evidence.is_empty());
    assert_eq!(
        model.log_entries[0].message,
        "Flatpak system update requires sudo password"
    );
    assert_eq!(model.ai_risk, None);
    assert!(model.ai_recommendations.is_empty());
    assert!(model
        .selection_notes
        .iter()
        .any(|note| note == "Flatpak requested but no structured update result was recorded."));
    assert!(model.validation_notes.contains(
        &"Flatpak was requested but no structured Flatpak update rows were recorded.".to_string()
    ));
    assert!(model
        .validation_notes
        .contains(&"1 structured error event(s) were recorded.".to_string()));
}

#[test]
fn flatpak_only_structured_rows_populate_report_counts_and_detail() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-flatpak-structured.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "flatpak",
            "info",
            "flatpak.package",
            r#"{"app_id":"com.cherry_ai.CherryStudio"}"#,
            "Updated com.cherry_ai.CherryStudio",
        )
        .expect("append flatpak package");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "reconcile.summary",
            r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
            "Attempted=1 Installed=1 Failed=0 Unaccounted=0 Verdict=PASS",
        )
        .expect("append reconcile summary");
    store
        .finish_run(&run_id, 9_000, "PASS", 1, 1, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.update_type.as_deref(), Some("Flatpak"));
    assert_eq!(model.execution_result, "PASS");
    assert_eq!(model.reconciliation.verdict, "PASS");
    assert_eq!(model.reconciliation.attempted, 1);
    assert_eq!(model.reconciliation.installed, 1);
    assert_eq!(model.flatpak_rows.len(), 1);
    assert_eq!(model.flatpak_rows[0].app_id, "com.cherry_ai.CherryStudio");
    assert_eq!(
        model.flatpak_rows[0].message,
        "Updated com.cherry_ai.CherryStudio"
    );
    assert_eq!(model.change_summary.flatpak_count, Some(1));
    assert!(!model.validation_notes.iter().any(|note| {
        note == "Flatpak was requested but no structured Flatpak update rows were recorded."
    }));
}

#[test]
fn separates_update_risk_execution_result_and_reconciliation_result() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-status-separation.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .upsert_ai_assessment(&run_id, Some("Red"), r#"["1) Proceed carefully."]"#)
        .expect("persist ai");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","recommendations":["1) Proceed carefully."]}"#,
            "AI_ASSESSMENT:Red|1) Proceed carefully.",
        )
        .expect("append ai");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":18,"installed":18,"failed":0,"unaccounted":0}"#,
            "reconciliation complete",
        )
        .expect("append reconcile summary");
    store
        .finish_run(&run_id, 5_000, "PASS", 18, 18, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.ai_risk.as_deref(), Some("Red"));
    assert_eq!(model.execution_result, "PASS");
    assert_eq!(model.reconciliation.verdict, "PASS");
}

#[test]
fn recommendation_text_is_split_into_ordered_structured_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-recommendations.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#""1) Review repos.\n2) Snapshot first.\n3) Reboot after update.""#,
        )
        .expect("persist ai");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.ai_recommendations.len(), 3);
    assert_eq!(model.ai_recommendations[0].step, "1");
    assert_eq!(model.ai_recommendations[0].recommendation, "Review repos.");
    assert_eq!(model.ai_recommendations[1].step, "2");
    assert_eq!(
        model.ai_recommendations[1].recommendation,
        "Snapshot first."
    );
    assert_eq!(model.ai_recommendations[2].step, "3");
    assert_eq!(
        model.ai_recommendations[2].recommendation,
        "Reboot after update."
    );
    assert!(model
        .ai_recommendations
        .iter()
        .all(|item| item.reason.is_none()));
}

#[test]
fn builds_change_summary_from_structured_run_data() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-change-summary.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"prefer_packman":true,"repos":["repo-oss","packman"],"snapshot_before_update":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","risk_counts":{"red":2,"amber":1,"green":4},"notable_red_items":["kernel-default vendor change","systemd package set"],"repo_vendor_anomalies":["Vendor change candidates present"]}"#,
            "AI_ASSESSMENT:Red|1) Review vendor changes.",
        )
        .expect("append ai");
    store
        .append_event(
            &run_id,
            "package_manager",
            "info",
            "package.locks",
            r#"{"locks":3}"#,
            "Loaded 3 package lock(s)",
        )
        .expect("append locks");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "PackageResult",
            r#"{"name":"mesa","status":"installed","to_version":"24.1","repo":"repo-oss"}"#,
            "mesa installed",
        )
        .expect("append package 1");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "PackageResult",
            r#"{"name":"ffmpeg","status":"installed","to_version":"8.0","repo":"packman"}"#,
            "ffmpeg installed",
        )
        .expect("append package 2");
    store
        .append_event(
            &run_id,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "Created pre-update snapshot",
        )
        .expect("append snapshot");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":2,"installed":2,"failed":0,"unaccounted":0}"#,
            "reconciliation complete",
        )
        .expect("append reconcile");
    store
        .replace_packages(
            &run_id,
            &[
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "mesa".to_string(),
                    from_version: None,
                    to_version: Some("24.1".to_string()),
                    arch: None,
                    repository: Some("repo-oss".to_string()),
                    action: Some("install".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("green".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "ffmpeg".to_string(),
                    from_version: None,
                    to_version: Some("8.0".to_string()),
                    arch: None,
                    repository: Some("packman".to_string()),
                    action: Some("install".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
            ],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 5_000, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.change_summary.total_package_count, Some(2));
    assert_eq!(model.change_summary.package_lock_count, Some(3));
    assert_eq!(
        model.change_summary.snapshot_status.as_deref(),
        Some("Created")
    );
    assert_eq!(
        model.change_summary.risk_item_counts,
        Some(chamrisk_ops::report_model::RiskItemCounts {
            red: None,
            amber: Some(1),
            green: Some(1),
        })
    );
    assert_eq!(
        model.change_summary.action_counts,
        vec![chamrisk_ops::report_model::CountMetric {
            label: "Install".to_string(),
            count: 2,
        }]
    );
    assert_eq!(
        model.change_summary.result_counts,
        vec![chamrisk_ops::report_model::CountMetric {
            label: "Succeeded".to_string(),
            count: 2,
        }]
    );
    assert_eq!(
        model.change_summary.notable_high_risk_packages,
        vec!["ffmpeg".to_string()]
    );
    assert_eq!(
        model.change_summary.notable_red_items,
        vec![
            "kernel-default vendor change".to_string(),
            "systemd package set".to_string()
        ]
    );
    assert!(model
        .change_summary
        .repo_vendor_anomalies
        .iter()
        .any(|item| item.contains("Vendor change candidates present")));
    assert!(model
        .change_summary
        .repo_vendor_anomalies
        .iter()
        .any(|item| item.contains("Mixed package sources detected")));
}

#[test]
fn change_summary_handles_partial_structured_data_without_filler() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-change-summary-partial.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":5}"#,
            "Preview result with 5 package(s)",
        )
        .expect("append preview");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.change_summary.total_package_count, Some(5));
    assert_eq!(model.change_summary.package_lock_count, None);
    assert_eq!(model.change_summary.flatpak_count, None);
    assert_eq!(model.change_summary.risk_item_counts, None);
    assert!(model.change_summary.notable_red_items.is_empty());
    assert!(model.change_summary.repo_vendor_anomalies.is_empty());
}

#[test]
fn splits_single_line_numbered_recommendation_blob_without_report_rationale() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-recommendation-blob.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Red"),
            r#""Recommendations: 1) Review vendor changes. 2) Take snapshot first. 3) Reboot after update.""#,
        )
        .expect("persist ai");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.ai_recommendations.len(), 3);
    assert_eq!(model.ai_recommendations[0].step, "1");
    assert_eq!(
        model.ai_recommendations[0].recommendation,
        "Review vendor changes."
    );
    assert_eq!(model.ai_recommendations[1].step, "2");
    assert_eq!(
        model.ai_recommendations[1].recommendation,
        "Take snapshot first."
    );
    assert_eq!(model.ai_recommendations[2].step, "3");
    assert_eq!(
        model.ai_recommendations[2].recommendation,
        "Reboot after update."
    );
}

#[test]
fn reconcile_summary_payload_does_not_create_package_detail_rows_without_packages_table_data() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-summary-package-rows.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"flatpak":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "reconcile.summary",
            r#"{"verdict":"PASS","attempted":4,"installed":4,"failed":0,"unaccounted":0,"package_rows":[{"name":"ffmpeg","status":"upgraded","from_version":"7.1","to_version":"8.0.1","repo":"Packman","arch":"x86_64","message":"ffmpeg upgraded 7.1 -> 8.0.1 repo=Packman arch=x86_64"},{"name":"libavcodec","status":"upgraded","from_version":"7.1","to_version":"8.0.1","repo":"Packman","arch":"x86_64","message":"libavcodec upgraded 7.1 -> 8.0.1 repo=Packman arch=x86_64"},{"name":"libavfilter","status":"upgraded","from_version":"7.1","to_version":"8.0.1","repo":"Packman","arch":"x86_64","message":"libavfilter upgraded 7.1 -> 8.0.1 repo=Packman arch=x86_64"},{"name":"libavformat","status":"upgraded","from_version":"7.1","to_version":"8.0.1","repo":"Packman","arch":"x86_64","message":"libavformat upgraded 7.1 -> 8.0.1 repo=Packman arch=x86_64"}]}"#,
            "Attempted=4 Installed=4 Failed=0 Unaccounted=0 Verdict=PASS",
        )
        .expect("append reconcile summary");
    store
        .append_event(
            &run_id,
            "flatpak",
            "info",
            "flatpak.package",
            r#"{"app_id":"dev.zed.Zed"}"#,
            "Updated dev.zed.Zed",
        )
        .expect("append flatpak package");
    store
        .finish_run(&run_id, 9_000, "PASS", 4, 4, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert!(model.reconciliation.attempted > 0);
    assert!(model.package_rows.is_empty());
    assert!(model.package_evidence.is_empty());

    assert_eq!(model.flatpak_rows.len(), 1);
    assert_eq!(model.flatpak_rows[0].app_id, "dev.zed.Zed");
}

#[test]
fn selection_effective_reflects_runtime_deviations() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-effective.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(
            r#"{"zypper_dup":true,"prefer_packman":true,"flatpak":false,"repos":["oss","packman-essentials"]}"#,
            "1.2.3",
        )
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "progress",
            r#"{}"#,
            "Packman repo not found; running standard zypper dup instead",
        )
        .expect("append fallback event");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "zypper.apply.result",
            r#"{"exit_code":0}"#,
            "Completed with exit code 0",
        )
        .expect("append apply result");
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model.header.repos_requested,
        vec!["oss".to_string(), "packman-essentials".to_string()]
    );
    assert_eq!(
        model.header.repos_effective,
        vec!["oss".to_string(), "packman-essentials".to_string()]
    );
    assert!(model
        .selection_rows
        .iter()
        .any(|row| row.name == "Prefer Packman" && row.requested && !row.effective));
    assert!(model
        .selection_rows
        .iter()
        .any(|row| row.name == "Repos: oss, packman-essentials" && row.requested && row.effective));
    assert!(model
        .selection_notes
        .iter()
        .any(|note| note == "Prefer Packman requested but not effective."));
}

#[test]
fn canonical_preview_result_wins_over_legacy_preview_plan_in_report_log() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-preview-dedupe.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":5}"#,
            "Preview result with 5 package(s)",
        )
        .expect("append canonical preview result");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "zypper.preview.plan",
            r#"{"changes":5,"command":["zypper","dup"],"exit_code":0}"#,
            "Preview plan with 5 change(s)",
        )
        .expect("append legacy preview plan");
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "preview.result")
            .count(),
        1
    );
    assert_eq!(
        model
            .log_entries
            .iter()
            .find(|entry| entry.event_type == "preview.result")
            .map(|entry| entry.message.as_str()),
        Some("Preview result with 5 package(s)")
    );
}

#[test]
fn duplicate_persisted_preview_results_collapse_to_one_report_log_entry() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-preview-identical-dedupe.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    for _ in 0..2 {
        store
            .append_event(
                &run_id,
                "zypper",
                "info",
                "preview.result",
                r#"{"packages":5}"#,
                "Preview result with 5 package(s)",
            )
            .expect("append duplicate preview result");
    }
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "preview.result")
            .count(),
        1
    );
}

#[test]
fn canonical_apply_result_wins_over_legacy_apply_result_row_in_report_log() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-apply-dedupe.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "zypper.apply.result",
            r#"{"exit_code":0}"#,
            "Apply completed with exit code 0",
        )
        .expect("append canonical apply result");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "zypper.apply.result",
            r#"{"exit_code":0}"#,
            "Completed with exit code 0",
        )
        .expect("append legacy apply result");
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "zypper.apply.result")
            .count(),
        1
    );
    assert_eq!(
        model
            .log_entries
            .iter()
            .find(|entry| entry.event_type == "zypper.apply.result")
            .map(|entry| entry.message.as_str()),
        Some("Apply completed with exit code 0")
    );
}

#[test]
fn duplicate_persisted_apply_results_collapse_to_one_report_log_entry() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-apply-identical-dedupe.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    for _ in 0..2 {
        store
            .append_event(
                &run_id,
                "zypper",
                "info",
                "zypper.apply.result",
                r#"{"exit_code":0}"#,
                "Apply completed with exit code 0",
            )
            .expect("append duplicate apply result");
    }
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "zypper.apply.result")
            .count(),
        1
    );
}

#[test]
fn materially_distinct_milestone_results_remain_visible() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-distinct-milestones.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":5}"#,
            "Preview result with 5 package(s)",
        )
        .expect("append preview 5");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":7}"#,
            "Preview result with 7 package(s)",
        )
        .expect("append preview 7");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "zypper.apply.result",
            r#"{"exit_code":0}"#,
            "Apply completed with exit code 0",
        )
        .expect("append apply ok");
    store
        .append_event(
            &run_id,
            "zypper",
            "error",
            "zypper.apply.result",
            r#"{"exit_code":1}"#,
            "Apply completed with exit code 1",
        )
        .expect("append apply error");
    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "preview.result")
            .count(),
        2
    );
    assert!(model
        .log_entries
        .iter()
        .any(|entry| entry.message == "Preview result with 5 package(s)"));
    assert!(model
        .log_entries
        .iter()
        .any(|entry| entry.message == "Preview result with 7 package(s)"));
    assert_eq!(
        model
            .log_entries
            .iter()
            .filter(|entry| entry.event_type == "zypper.apply.result")
            .count(),
        2
    );
}

#[test]
fn uses_only_structured_events_for_packages_and_flatpak_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-mixed-logs.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"flatpak":true}"#, "1.2.3")
        .expect("start run");

    for line in [
        "+------------+--------------+-------------------+-------------------------+---------+--------+---------+",
        "| Repository | Name         | Current           | New                     | Status  | Arch   | Kind    |",
        "|------------+--------------+-------------------+-------------------------+---------+--------+---------|",
        "| Packman     | ffmpeg-8     | 8.0.1-3.2         | 8.0.1-1699.4.pm.51      | upgrade | x86_64 | package |",
        "| Packman     | libavcodec62 | 8.0.1-3.2         | 8.0.1-1699.4.pm.51      | upgrade | x86_64 | package |",
        "+------------+--------------+-------------------+-------------------------+---------+--------+---------+",
        "Updating app/dev.zed.Zed/x86_64/stable flathub ...done",
    ] {
        store
            .append_event(&run_id, "updates", "info", "log", r#"{"stream":"Updates"}"#, line)
            .expect("append log");
    }

    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "PackageResult",
            r#"{"name":"ffmpeg","status":"installed","from_version":"7.1","to_version":"8.0","repo":"Packman","arch":"x86_64"}"#,
            "ffmpeg installed",
        )
        .expect("append package result");
    store
        .append_event(
            &run_id,
            "flatpak",
            "info",
            "flatpak.package",
            r#"{"app_id":"dev.zed.Zed"}"#,
            "Updated dev.zed.Zed",
        )
        .expect("append flatpak package");
    store
        .finish_run(&run_id, 9_000, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    let package_names = model
        .package_rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>();
    assert!(package_names.is_empty());
    assert!(model.package_evidence.is_empty());
    assert!(model.package_summary.is_none());

    assert_eq!(model.flatpak_rows.len(), 1);
    assert_eq!(model.flatpak_rows[0].app_id, "dev.zed.Zed");
    assert_eq!(model.flatpak_rows[0].message, "Updated dev.zed.Zed");
}

#[test]
fn ignores_flatpak_progress_noise_without_structured_flatpak_events() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-flatpak-noise.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":true}"#, "1.2.3")
        .expect("start run");

    for line in [
        "",
        "   ",
        ".....done",
        "...done",
        "data...",
        "download progress",
    ] {
        store
            .append_event(
                &run_id,
                "updates",
                "info",
                "log",
                r#"{"stream":"Updates"}"#,
                line,
            )
            .expect("append noise log");
    }

    store
        .finish_run(&run_id, 9_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert!(model.flatpak_rows.is_empty());
}

#[test]
fn report_semantics_do_not_depend_on_ui_wording_when_payloads_match() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-wording-stability.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_a = store
        .start_run(
            r#"{"zypper_dup":true,"snapshot_before_update":true}"#,
            "1.2.3",
        )
        .expect("start run a");
    store
        .append_event(
            &run_a,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Amber","rationale":"Kernel changes detected.","recommendations":["1) Snapshot first.","2) Reboot after update."],"risk_counts":{"amber":2,"green":3}}"#,
            "AI assessment v1",
        )
        .expect("append ai a");
    store
        .append_event(
            &run_a,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "Created pre-update snapshot",
        )
        .expect("append snapshot a");
    store
        .append_event(
            &run_a,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":4,"installed":4,"failed":0,"unaccounted":0}"#,
            "reconcile wording a",
        )
        .expect("append reconcile a");
    store
        .finish_run(&run_a, 5_000, "PASS", 4, 4, 0, 0)
        .expect("finish run a");

    let run_b = store
        .start_run(
            r#"{"zypper_dup":true,"snapshot_before_update":true}"#,
            "1.2.3",
        )
        .expect("start run b");
    store
        .append_event(
            &run_b,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Amber","rationale":"Kernel changes detected.","recommendations":["1) Snapshot first.","2) Reboot after update."],"risk_counts":{"amber":2,"green":3}}"#,
            "Completely different UI wording that should not matter",
        )
        .expect("append ai b");
    store
        .append_event(
            &run_b,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "Another snapshot sentence",
        )
        .expect("append snapshot b");
    store
        .append_event(
            &run_b,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":4,"installed":4,"failed":0,"unaccounted":0}"#,
            "Another reconciliation sentence",
        )
        .expect("append reconcile b");
    store
        .finish_run(&run_b, 5_000, "PASS", 4, 4, 0, 0)
        .expect("finish run b");

    let model_a = ReportModel::from_store(&store, &run_a).expect("build model a");
    let model_b = ReportModel::from_store(&store, &run_b).expect("build model b");

    assert_eq!(model_a.ai_risk, model_b.ai_risk);
    assert_eq!(model_a.ai_recommendations, model_b.ai_recommendations);
    assert_eq!(model_a.execution_result, model_b.execution_result);
    assert_eq!(model_a.reconciliation, model_b.reconciliation);
    assert_eq!(model_a.snapshot_status, model_b.snapshot_status);
    assert_eq!(model_a.change_summary, model_b.change_summary);
}

#[test]
fn from_store_prefers_persisted_package_evidence_for_historical_runs() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-packages-table.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "PackageResult",
            r#"{"name":"mesa","status":"installed","from_version":"24.0","to_version":"24.1","repo":"event-repo","arch":"x86_64"}"#,
            "event wording should not drive historical report detail",
        )
        .expect("append package event");
    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "mesa".to_string(),
                from_version: Some("24.0".to_string()),
                to_version: Some("24.1".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("packages-table-repo".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("amber".to_string()),
            }],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 5_000, "PASS", 1, 1, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.package_rows.len(), 1);
    assert_eq!(model.package_evidence.len(), 1);
    assert_eq!(model.package_evidence[0].package_name, "mesa");
    assert_eq!(
        model.package_evidence[0].repository.as_deref(),
        Some("packages-table-repo")
    );
    assert_eq!(model.package_evidence[0].action.as_deref(), Some("upgrade"));
    assert_eq!(
        model.package_evidence[0].result.as_deref(),
        Some("succeeded")
    );
    assert_eq!(model.package_evidence[0].risk.as_deref(), Some("amber"));
    assert_eq!(
        model
            .package_summary
            .as_ref()
            .map(|summary| summary.total_count),
        Some(1)
    );
    assert_eq!(
        model.change_summary.action_counts,
        vec![chamrisk_ops::report_model::CountMetric {
            label: "Upgrade".to_string(),
            count: 1,
        }]
    );
    assert_eq!(
        model.change_summary.result_counts,
        vec![chamrisk_ops::report_model::CountMetric {
            label: "Succeeded".to_string(),
            count: 1,
        }]
    );
    assert_eq!(
        model.change_summary.notable_high_risk_packages,
        vec!["mesa".to_string()]
    );
    assert_eq!(model.package_rows[0].name, "mesa");
    assert_eq!(
        model.package_rows[0].repo.as_deref(),
        Some("packages-table-repo")
    );
    assert!(model.package_rows[0].message.contains("risk=amber"));
    assert!(!model.package_rows[0]
        .message
        .contains("event wording should not drive"));
}

#[test]
fn package_rows_keep_non_blank_risk_for_high_impact_package_evidence() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-package-risk.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .replace_packages(
            &run_id,
            &[
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "kernel-default".to_string(),
                    from_version: Some("6.8.0".to_string()),
                    to_version: Some("6.9.0".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "mesa".to_string(),
                    from_version: Some("24.1".to_string()),
                    to_version: Some("24.0".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("downgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "ffmpeg".to_string(),
                    from_version: Some("8.0".to_string()),
                    to_version: None,
                    arch: Some("x86_64".to_string()),
                    repository: Some("packman".to_string()),
                    action: Some("remove".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
            ],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 5_000, "PASS", 3, 3, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.package_evidence.len(), 3);
    assert!(model
        .package_evidence
        .iter()
        .all(|row| matches!(row.risk.as_deref(), Some("amber" | "red" | "green"))));
    assert!(model
        .package_rows
        .iter()
        .all(|row| row.message.contains("risk=amber")));
}

#[test]
fn report_model_carries_zero_package_evidence_when_packages_table_is_empty() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-zero-package-evidence.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.2.3")
        .expect("start run");
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert!(model.package_evidence.is_empty());
    assert!(model.package_summary.is_none());
    assert!(model.package_rows.is_empty());
}

#[test]
fn package_evidence_is_not_built_from_log_strings_when_packages_table_is_empty() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-package-evidence-no-logs.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    for line in [
        "| Repository | Name | Current | New | Status | Arch |",
        "| Packman | ffmpeg | 7.1 | 8.0 | upgrade | x86_64 |",
    ] {
        store
            .append_event(
                &run_id,
                "updates",
                "info",
                "log",
                r#"{"stream":"Updates"}"#,
                line,
            )
            .expect("append log");
    }
    store
        .finish_run(&run_id, 5_000, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert!(model.package_evidence.is_empty());
    assert!(model.package_summary.is_none());
    assert!(model.package_rows.is_empty());
}

#[test]
fn persisted_package_evidence_remains_available_when_events_are_sparse() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-sparse-events-packages.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
            "reconciliation complete",
        )
        .expect("append reconcile");
    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "mesa".to_string(),
                from_version: Some("24.0".to_string()),
                to_version: Some("24.1".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("repo-oss".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("green".to_string()),
            }],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 5_000, "PASS", 1, 1, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build report model");

    assert_eq!(model.package_evidence.len(), 1);
    assert_eq!(model.package_rows.len(), 1);
    assert_eq!(model.package_rows[0].name, "mesa");
    assert_eq!(
        model
            .package_summary
            .as_ref()
            .map(|summary| summary.total_count),
        Some(1)
    );
    assert_eq!(model.log_entries.len(), 1);
    assert_eq!(model.log_entries[0].event_type, "reconcile.summary");
}

#[test]
fn package_summary_metrics_are_derived_from_persisted_package_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-model-package-summary.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"prefer_packman":true}"#, "1.2.3")
        .expect("start run");
    store
        .replace_packages(
            &run_id,
            &[
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "kernel-default".to_string(),
                    from_version: Some("6.8.0".to_string()),
                    to_version: Some("6.9.0".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("red".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "ffmpeg".to_string(),
                    from_version: Some("7.1".to_string()),
                    to_version: Some("8.0".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("packman".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "mesa".to_string(),
                    from_version: Some("24.0".to_string()),
                    to_version: Some("24.1".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("install".to_string()),
                    result: Some("failed".to_string()),
                    risk: Some("green".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "patterns-base".to_string(),
                    from_version: None,
                    to_version: Some("20260312".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: None,
                    result: None,
                    risk: None,
                },
            ],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 5_000, "PASS", 4, 3, 1, 0)
        .expect("finish run");

    let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let model = ReportModel::from_store(&reopened, &run_id).expect("build report model");
    let summary = model.package_summary.expect("package summary");

    assert_eq!(summary.total_count, 4);
    assert_eq!(
        summary.risk_counts,
        chamrisk_ops::report_model::RiskItemCounts {
            red: Some(1),
            amber: Some(1),
            green: Some(1),
        }
    );
    assert_eq!(
        summary.action_counts,
        vec![
            chamrisk_ops::report_model::CountMetric {
                label: "Install".to_string(),
                count: 1,
            },
            chamrisk_ops::report_model::CountMetric {
                label: "Upgrade".to_string(),
                count: 2,
            },
        ]
    );
    assert_eq!(
        summary.result_counts,
        vec![
            chamrisk_ops::report_model::CountMetric {
                label: "Failed".to_string(),
                count: 1,
            },
            chamrisk_ops::report_model::CountMetric {
                label: "Succeeded".to_string(),
                count: 2,
            },
        ]
    );
    assert_eq!(
        summary.high_risk_packages,
        vec!["kernel-default".to_string()]
    );
    assert_eq!(model.change_summary.total_package_count, Some(4));
    assert_eq!(
        model.change_summary.risk_item_counts,
        Some(summary.risk_counts.clone())
    );
    assert_eq!(
        model.change_summary.action_counts,
        vec![
            chamrisk_ops::report_model::CountMetric {
                label: "Install".to_string(),
                count: 1,
            },
            chamrisk_ops::report_model::CountMetric {
                label: "Upgrade".to_string(),
                count: 2,
            },
        ]
    );
    assert_eq!(
        model.change_summary.result_counts,
        vec![
            chamrisk_ops::report_model::CountMetric {
                label: "Failed".to_string(),
                count: 1,
            },
            chamrisk_ops::report_model::CountMetric {
                label: "Succeeded".to_string(),
                count: 2,
            },
        ]
    );
    assert_eq!(
        model.change_summary.notable_high_risk_packages,
        vec!["kernel-default".to_string()]
    );
}
