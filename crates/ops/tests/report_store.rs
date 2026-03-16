use chamrisk_ops::report_store::{PackageEvidenceRow, ReportStore};
use chamrisk_ops::tasks::{run_updates_plan_sync, UpdateRunSelection};
use rusqlite::params;
use std::sync::mpsc::channel;
use tempfile::tempdir;

#[test]
fn report_store_writes_lists_loads_and_prunes() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let old_run_id = store
        .start_run(r#"{"selection":["pkg-old"]}"#, "1.0.0")
        .expect("start old run");
    store
        .append_event(
            &old_run_id,
            "plan",
            "info",
            "selection.created",
            r#"{"count":1}"#,
            "created selection",
        )
        .expect("append old event");
    store
        .finish_run(&old_run_id, 1_000, "success", 1, 1, 0, 0)
        .expect("finish old run");

    let fresh_run_id = store
        .start_run(r#"{"selection":["pkg-new"]}"#, "1.2.3")
        .expect("start fresh run");
    store
        .append_event(
            &fresh_run_id,
            "plan",
            "info",
            "selection.created",
            r#"{"count":1}"#,
            "selection created",
        )
        .expect("append first fresh event");
    store
        .append_event(
            &fresh_run_id,
            "apply",
            "warn",
            "package.failed",
            r#"{"name":"pkg-new"}"#,
            "package failed",
        )
        .expect("append second fresh event");
    store
        .finish_run(&fresh_run_id, 4_000_000_000_000, "partial", 2, 1, 1, 0)
        .expect("finish fresh run");

    let runs = store.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].run_id, fresh_run_id);
    assert_eq!(runs[0].selection_json, r#"{"selection":["pkg-new"]}"#);
    assert_eq!(runs[0].verdict.as_deref(), Some("partial"));
    assert_eq!(runs[0].attempted, Some(2));
    assert_eq!(runs[0].installed, Some(1));
    assert_eq!(runs[0].failed, Some(1));
    assert_eq!(runs[0].unaccounted, Some(0));
    assert_eq!(runs[0].app_version, "1.2.3");
    assert_eq!(runs[1].run_id, old_run_id);

    let events = store.load_events(&fresh_run_id).expect("load fresh events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].run_id, fresh_run_id);
    assert_eq!(events[0].seq, 0);
    assert_eq!(events[0].phase, "plan");
    assert_eq!(events[0].severity, "info");
    assert_eq!(events[0].event_type, "selection.created");
    assert_eq!(events[0].payload_json, r#"{"count":1}"#);
    assert_eq!(events[0].message, "selection created");
    assert_eq!(events[1].seq, 1);
    assert_eq!(events[1].phase, "apply");
    assert_eq!(events[1].severity, "warn");
    assert_eq!(events[1].event_type, "package.failed");
    assert_eq!(events[1].payload_json, r#"{"name":"pkg-new"}"#);
    assert_eq!(events[1].message, "package failed");
    assert!(events[1].ts_ms >= events[0].ts_ms);

    let conn = rusqlite::Connection::open(&db_path).expect("open db for test setup");
    conn.execute(
        "UPDATE runs SET started_at_ms = ?2, ended_at_ms = ?3 WHERE run_id = ?1",
        params![old_run_id, 1_000, 2_000],
    )
    .expect("age old run");

    store.prune_older_than(30).expect("prune");

    let remaining_runs = store.list_runs(10).expect("list remaining runs");
    assert_eq!(remaining_runs.len(), 1);
    assert_eq!(remaining_runs[0].run_id, fresh_run_id);

    let old_events = store.load_events(&old_run_id).expect("load old events");
    assert!(old_events.is_empty());
    let remaining_events = store
        .load_events(&fresh_run_id)
        .expect("load remaining fresh events");
    assert_eq!(remaining_events.len(), 2);
}

#[test]
fn flatpak_only_run_persists_no_zypper_events_and_zero_summary_counters() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-flatpak.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");
    let seeded_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("seed old zypper run");
    store
        .append_event(
            &seeded_run,
            "zypper",
            "info",
            "zypper.preview.plan",
            r#"{"changes":1}"#,
            "seeded preview plan",
        )
        .expect("seed old event");
    store
        .finish_run(&seeded_run, 2_000, "PASS", 1, 1, 0, 0)
        .expect("finish seeded run");
    let (tx, rx) = channel();

    run_updates_plan_sync(
        tx,
        UpdateRunSelection {
            snapshot_before_update: false,
            zypper_dup: false,
            prefer_packman: false,
            flatpak: true,
            journal_vacuum: false,
            mode: "apply".to_string(),
            risk_filter: "all".to_string(),
            repos: vec!["packman".to_string()],
        },
        None,
        Some(store),
    );

    let events: Vec<_> = rx.try_iter().collect();
    assert!(events.iter().any(|event| matches!(event, chamrisk_ops::runner::OpsEvent::Error(line) if line == "Flatpak update blocked: requires sudo password")));

    let persisted = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let runs = persisted.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 2);
    assert!(runs[0].ended_at_ms.is_some());
    assert_eq!(runs[0].verdict.as_deref(), Some("FAIL"));
    assert_eq!(runs[0].attempted, Some(0));
    assert_eq!(runs[0].installed, Some(0));
    assert_eq!(runs[0].failed, Some(0));
    assert_eq!(runs[0].unaccounted, Some(0));

    let stored_events = persisted
        .load_events(&runs[0].run_id)
        .expect("load flatpak-only events");
    assert!(!stored_events.iter().any(|event| event.phase == "zypper"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "zypper.preview.plan"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "zypper.apply.result"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "reconcile.summary"));
}

#[test]
fn journal_only_run_persists_no_zypper_events_and_zero_summary_counters() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-journal.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");
    let seeded_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("seed old zypper run");
    store
        .append_event(
            &seeded_run,
            "zypper",
            "info",
            "zypper.preview.plan",
            r#"{"changes":1}"#,
            "seeded preview plan",
        )
        .expect("seed old event");
    store
        .finish_run(&seeded_run, 2_000, "PASS", 1, 1, 0, 0)
        .expect("finish seeded run");
    let (tx, rx) = channel();

    run_updates_plan_sync(
        tx,
        UpdateRunSelection {
            snapshot_before_update: false,
            zypper_dup: false,
            prefer_packman: false,
            flatpak: false,
            journal_vacuum: true,
            mode: "apply".to_string(),
            risk_filter: "all".to_string(),
            repos: vec![],
        },
        None,
        Some(store),
    );

    let events: Vec<_> = rx.try_iter().collect();
    assert!(events.iter().any(|event| matches!(event, chamrisk_ops::runner::OpsEvent::Error(line) if line == "Journal vacuum blocked: requires sudo password")));

    let persisted = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let runs = persisted.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 2);
    assert!(runs[0].ended_at_ms.is_some());
    assert_eq!(runs[0].verdict.as_deref(), Some("FAIL"));
    assert_eq!(runs[0].attempted, Some(0));
    assert_eq!(runs[0].installed, Some(0));
    assert_eq!(runs[0].failed, Some(0));
    assert_eq!(runs[0].unaccounted, Some(0));

    let stored_events = persisted
        .load_events(&runs[0].run_id)
        .expect("load journal-only events");
    assert!(!stored_events.iter().any(|event| event.phase == "zypper"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "zypper.preview.plan"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "zypper.apply.result"));
    assert!(!stored_events
        .iter()
        .any(|event| event.event_type == "reconcile.summary"));
}

#[test]
fn packages_table_has_required_schema_and_indexes() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-packages-schema.db");
    let _store = ReportStore::with_db_path(&db_path).expect("create report store");

    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    let mut stmt = conn
        .prepare("PRAGMA table_info(packages)")
        .expect("prepare table_info");
    let columns = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
        })
        .expect("query columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect columns");

    assert!(columns.contains(&("run_id".to_string(), 1)));
    assert!(columns.contains(&("package_name".to_string(), 1)));
    assert!(columns.iter().any(|(name, _)| name == "from_version"));
    assert!(columns.iter().any(|(name, _)| name == "to_version"));
    assert!(columns.iter().any(|(name, _)| name == "arch"));
    assert!(columns.iter().any(|(name, _)| name == "repository"));
    assert!(columns.iter().any(|(name, _)| name == "action"));
    assert!(columns.iter().any(|(name, _)| name == "result"));
    assert!(columns.iter().any(|(name, _)| name == "risk"));

    let mut fk_stmt = conn
        .prepare("PRAGMA foreign_key_list(packages)")
        .expect("prepare foreign_key_list");
    let foreign_keys = fk_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(6)?,
            ))
        })
        .expect("query foreign keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect foreign keys");
    assert!(foreign_keys.contains(&(
        "runs".to_string(),
        "run_id".to_string(),
        "run_id".to_string(),
        "CASCADE".to_string(),
    )));

    let mut index_stmt = conn
        .prepare("PRAGMA index_list(packages)")
        .expect("prepare index_list");
    let indexes = index_stmt
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query indexes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect indexes");
    assert!(indexes.contains(&"idx_packages_run_id".to_string()));
    assert!(indexes.contains(&"idx_packages_package_name".to_string()));
    assert!(indexes.contains(&"idx_packages_action".to_string()));
}

#[test]
fn ai_assessments_table_has_required_schema_foreign_key_and_cascade_delete() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-ai-assessments-schema.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable foreign keys");

    let mut stmt = conn
        .prepare("PRAGMA table_info(ai_assessments)")
        .expect("prepare table_info");
    let columns = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .expect("query columns")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect columns");

    assert!(columns.contains(&("run_id".to_string(), "TEXT".to_string(), 1)));
    assert!(columns
        .iter()
        .any(|(name, ty, _)| name == "risk_level" && ty == "TEXT"));
    assert!(columns
        .iter()
        .any(|(name, ty, _)| name == "recommendations_json" && ty == "TEXT"));
    assert!(columns.iter().any(|(name, _, _)| name == "created_at"));

    let mut fk_stmt = conn
        .prepare("PRAGMA foreign_key_list(ai_assessments)")
        .expect("prepare foreign_key_list");
    let foreign_keys = fk_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(6)?,
            ))
        })
        .expect("query foreign keys")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect foreign keys");
    assert!(foreign_keys.contains(&(
        "runs".to_string(),
        "run_id".to_string(),
        "run_id".to_string(),
        "CASCADE".to_string(),
    )));

    let insert_missing = conn.execute(
        "INSERT INTO ai_assessments(run_id, risk_level, recommendations_json) VALUES (?1, ?2, ?3)",
        params!["missing-run", "Amber", "[\"1) Snapshot first.\"]"],
    );
    assert!(insert_missing.is_err());

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .upsert_ai_assessment(&run_id, Some("Amber"), r#"["1) Snapshot first."]"#)
        .expect("insert ai assessment");

    conn.execute("DELETE FROM runs WHERE run_id = ?1", params![&run_id])
        .expect("delete run");

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ai_assessments WHERE run_id = ?1",
            params![&run_id],
            |row| row.get(0),
        )
        .expect("count ai assessments");
    assert_eq!(count, 0);
}

#[test]
fn packages_rows_are_persisted_loaded_and_replaced_by_run_id() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-packages-load.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "kernel-default".to_string(),
                from_version: Some("6.8.1".to_string()),
                to_version: Some("6.8.5".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("repo-oss".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("amber".to_string()),
            }],
        )
        .expect("insert package");

    let packages = store.load_packages(&run_id).expect("load packages");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].run_id, run_id);
    assert_eq!(packages[0].package_name, "kernel-default");
    assert_eq!(packages[0].repository.as_deref(), Some("repo-oss"));
    assert_eq!(packages[0].action.as_deref(), Some("upgrade"));
    assert_eq!(packages[0].result.as_deref(), Some("succeeded"));
    assert_eq!(packages[0].risk.as_deref(), Some("amber"));

    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "systemd".to_string(),
                from_version: Some("255".to_string()),
                to_version: Some("256".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("repo-update".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: None,
            }],
        )
        .expect("replace packages");

    let replaced = store
        .load_packages(&run_id)
        .expect("load replaced packages");
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].package_name, "systemd");
}

#[test]
fn packages_foreign_key_and_cascade_delete_are_enforced() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-packages-fk.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "kernel-default".to_string(),
                from_version: None,
                to_version: Some("6.8.5".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("repo-oss".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: None,
            }],
        )
        .expect("insert package");

    let conn = rusqlite::Connection::open(&db_path).expect("open db");
    conn.pragma_update(None, "foreign_keys", "ON")
        .expect("enable foreign keys");

    let insert_missing = conn.execute(
        "INSERT INTO packages(
            run_id, package_name, from_version, to_version, arch, repository, action, result, risk
         ) VALUES (?1, ?2, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        params!["missing-run", "orphaned-package"],
    );
    assert!(insert_missing.is_err());

    conn.execute("DELETE FROM runs WHERE run_id = ?1", params![&run_id])
        .expect("delete run");

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM packages WHERE run_id = ?1",
            params![&run_id],
            |row| row.get(0),
        )
        .expect("count packages");
    assert_eq!(count, 0);
}

#[test]
fn ai_assessment_is_persisted_loaded_updated_and_survives_restart() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-ai-assessments-load.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("insert ai assessment");

    let initial = store
        .load_ai_assessment(&run_id)
        .expect("load ai assessment")
        .expect("ai assessment row");
    assert_eq!(initial.run_id, run_id);
    assert_eq!(initial.risk_level.as_deref(), Some("Amber"));
    assert_eq!(
        initial.recommendations_json,
        r#"["1) Snapshot first.","2) Reboot after update."]"#
    );
    assert!(initial.created_at.is_some());

    store
        .upsert_ai_assessment(&run_id, Some("Red"), r#"["1) Do not proceed."]"#)
        .expect("update ai assessment");

    let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let persisted = reopened
        .load_ai_assessment(&run_id)
        .expect("load ai assessment after restart")
        .expect("persisted ai assessment row");
    assert_eq!(persisted.risk_level.as_deref(), Some("Red"));
    assert_eq!(persisted.recommendations_json, r#"["1) Do not proceed."]"#);
}

#[test]
fn upsert_ai_assessment_for_latest_open_run_targets_active_run_only() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-ai-assessments-active.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let finished_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start finished run");
    store
        .finish_run(&finished_run, 1_000, "PASS", 0, 0, 0, 0)
        .expect("finish first run");

    let active_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start active run");

    assert_eq!(
        store.latest_open_run_id().expect("latest open run"),
        Some(active_run.clone())
    );

    let persisted_run = store
        .upsert_ai_assessment_for_latest_open_run(
            Some("Amber"),
            r#"["1) Snapshot first.","2) Reboot after update."]"#,
        )
        .expect("upsert active ai assessment");

    assert_eq!(persisted_run, Some(active_run.clone()));
    assert!(store
        .load_ai_assessment(&finished_run)
        .expect("load finished run ai assessment")
        .is_none());

    let assessment = store
        .load_ai_assessment(&active_run)
        .expect("load active run ai assessment")
        .expect("active ai assessment row");
    assert_eq!(assessment.risk_level.as_deref(), Some("Amber"));
    assert_eq!(
        assessment.recommendations_json,
        r#"["1) Snapshot first.","2) Reboot after update."]"#
    );

    store
        .finish_run(&active_run, 2_000, "PASS", 0, 0, 0, 0)
        .expect("finish active run");
    assert_eq!(store.latest_open_run_id().expect("no active run"), None);
}

#[test]
fn ensure_run_active_for_ai_rejects_unknown_and_closed_runs() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-ai-run-validation.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    assert_eq!(
        store
            .ensure_run_active_for_ai("missing-run")
            .expect_err("unknown run should fail"),
        "run not found for ai persistence: missing-run"
    );

    let active_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start active run");
    store
        .ensure_run_active_for_ai(&active_run)
        .expect("active run should validate");

    let closed_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start closed run");
    store
        .finish_run(&closed_run, 1_000, "PASS", 0, 0, 0, 0)
        .expect("finish closed run");

    assert_eq!(
        store
            .ensure_run_active_for_ai(&closed_run)
            .expect_err("closed run should fail"),
        format!("run already closed for ai persistence: {closed_run}")
    );
}

#[test]
fn run_cohesion_debug_summarizes_canonical_run_shape() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-run-cohesion.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":2}"#,
            "Preview result with 2 package(s)",
        )
        .expect("append preview");
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
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "kernel-default".to_string(),
                from_version: Some("6.8.0".to_string()),
                to_version: Some("6.9.0".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("repo-oss".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("red".to_string()),
            }],
        )
        .expect("replace packages");
    store
        .upsert_ai_assessment(&run_id, Some("Amber"), r#"["1) Snapshot first."]"#)
        .expect("persist ai");
    store
        .finish_run(&run_id, 1_000, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let diagnostic = store.inspect_run_cohesion(&run_id).expect("inspect run");
    assert!(diagnostic.run_exists);
    assert_eq!(diagnostic.event_count, 2);
    assert_eq!(diagnostic.package_count, 1);
    assert!(diagnostic.ai_assessment_present);
    assert_eq!(diagnostic.verdict.as_deref(), Some("PASS"));
    assert!(diagnostic.warnings.is_empty());

    let rendered = store
        .render_run_cohesion_debug(&run_id)
        .expect("render run cohesion");
    assert!(rendered.contains(&format!("run_id={run_id}")));
    assert!(rendered.contains("event_count=2"));
    assert!(rendered.contains("package_count=1"));
    assert!(rendered.contains("ai_assessment_present=true"));
}

#[test]
fn run_cohesion_debug_flags_orphan_like_ai_attachment_and_missing_ai_on_main_run() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-run-cohesion-anomalies.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let main_run = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start main run");
    store
        .append_event(
            &main_run,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":2}"#,
            "Preview result with 2 package(s)",
        )
        .expect("append preview");
    store
        .replace_packages(
            &main_run,
            &[PackageEvidenceRow {
                run_id: main_run.clone(),
                package_name: "mesa".to_string(),
                from_version: Some("24.0".to_string()),
                to_version: Some("24.1".to_string()),
                arch: Some("x86_64".to_string()),
                repository: Some("packman".to_string()),
                action: Some("upgrade".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("amber".to_string()),
            }],
        )
        .expect("replace main packages");
    store
        .finish_run(&main_run, 1_000, "PASS", 2, 2, 0, 0)
        .expect("finish main run");

    let incidental_run = store
        .start_run(r#"{"flatpak":true}"#, "1.0.0")
        .expect("start incidental run");
    store
        .append_event(
            &incidental_run,
            "flatpak",
            "error",
            "progress",
            r#"{}"#,
            "Flatpak system update requires sudo password",
        )
        .expect("append incidental event");
    store
        .upsert_ai_assessment(&incidental_run, Some("Red"), r#"["1) Do not proceed."]"#)
        .expect("persist incidental ai");
    store
        .finish_run(&incidental_run, 2_000, "FAIL", 0, 0, 0, 0)
        .expect("finish incidental run");

    let main_diagnostic = store
        .inspect_run_cohesion(&main_run)
        .expect("inspect main run");
    assert!(main_diagnostic
        .warnings
        .iter()
        .any(|warning| warning == "run has events/packages but no ai assessment"));

    let anomalies = store
        .inspect_ai_attachment_anomalies()
        .expect("inspect ai anomalies");
    let incidental = anomalies
        .iter()
        .find(|diagnostic| diagnostic.run_id == incidental_run)
        .expect("incidental ai diagnostic");
    assert!(incidental
        .warnings
        .iter()
        .any(|warning| { warning == "ai assessment attached to a tiny incidental run" }));
    assert!(incidental.warnings.iter().any(|warning| {
        warning == "ai assessment attached to a failed run with no package evidence"
    }));
}

#[test]
fn packages_can_be_retrieved_after_restart_with_stable_ordering() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-packages-restart.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .replace_packages(
            &run_id,
            &[
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "zypper".to_string(),
                    from_version: Some("1.0".to_string()),
                    to_version: Some("1.1".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("green".to_string()),
                },
                PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "kernel-default".to_string(),
                    from_version: Some("6.8.1".to_string()),
                    to_version: Some("6.8.5".to_string()),
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
                    action: Some("install".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                },
            ],
        )
        .expect("insert packages");

    let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
    let packages = reopened.load_packages(&run_id).expect("load packages");

    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0].package_name, "kernel-default");
    assert_eq!(packages[1].package_name, "ffmpeg");
    assert_eq!(packages[2].package_name, "zypper");
}

#[test]
fn prune_preview_only_runs_removes_preview_roots_and_keeps_execution_runs() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-prune-preview.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let preview_run = store
        .start_run(
            r#"{"snapshot_before_update":false,"zypper_dup":true,"prefer_packman":false,"flatpak":false,"journal_vacuum":false,"mode":"preview","risk_filter":"all","repos":[]}"#,
            "1.0.0",
        )
        .expect("start preview run");
    store
        .append_event(
            &preview_run,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":0}"#,
            "Preview result with 0 package(s)",
        )
        .expect("append preview result");

    let execution_run = store
        .start_run(
            r#"{"snapshot_before_update":false,"zypper_dup":false,"prefer_packman":false,"flatpak":true,"journal_vacuum":false,"mode":"apply","risk_filter":"all","repos":[]}"#,
            "1.0.0",
        )
        .expect("start execution run");
    store
        .append_event(
            &execution_run,
            "flatpak",
            "info",
            "flatpak.update.result",
            r#"{"exit_code":0}"#,
            "Completed with exit code 0",
        )
        .expect("append flatpak result");
    store
        .finish_run(&execution_run, 1_000, "PASS", 1, 1, 0, 0)
        .expect("finish execution run");

    let removed = store
        .prune_preview_only_runs()
        .expect("prune preview-only runs");
    assert_eq!(removed, 1);

    let runs = store.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, execution_run);
    assert!(store
        .load_events(&preview_run)
        .expect("load preview events")
        .is_empty());
}

#[test]
fn prune_preview_only_runs_removes_open_apply_mode_rows_with_only_preview_events() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-store-prune-preview-open-root.db");
    let store = ReportStore::with_db_path(&db_path).expect("create report store");

    let ghost_run = store
        .start_run(
            r#"{"snapshot_before_update":true,"zypper_dup":true,"prefer_packman":false,"flatpak":false,"journal_vacuum":false,"mode":"apply","risk_filter":"all","repos":["repo-oss"]}"#,
            "1.0.0",
        )
        .expect("start ghost run");
    store
        .append_event(
            &ghost_run,
            "zypper",
            "info",
            "preview.result",
            r#"{"packages":0}"#,
            "Preview result with 0 package(s)",
        )
        .expect("append preview result");
    store
        .append_event(
            &ghost_run,
            "zypper",
            "info",
            "zypper.preview.plan",
            r#"{"changes":0}"#,
            "Preview plan with 0 change(s)",
        )
        .expect("append preview plan");

    let kept_run = store
        .start_run(r#"{"flatpak":true,"mode":"apply"}"#, "1.0.0")
        .expect("start kept run");
    store
        .append_event(
            &kept_run,
            "flatpak",
            "info",
            "flatpak.update.result",
            r#"{"exit_code":0}"#,
            "Completed with exit code 0",
        )
        .expect("append kept event");
    store
        .finish_run(&kept_run, 1_000, "PASS", 1, 1, 0, 0)
        .expect("finish kept run");

    let removed = store
        .prune_preview_only_runs()
        .expect("prune preview-only runs");
    assert_eq!(removed, 1);

    let runs = store.list_runs(10).expect("list runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, kept_run);
}
