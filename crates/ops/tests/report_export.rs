use std::fs;
use std::io::Read;

use chamrisk_ops::health::SystemInfo;
use chamrisk_ops::report_export::render_odt;
use chamrisk_ops::report_model::ReportModel;
use chamrisk_ops::report_store::{PackageEvidenceRow, ReportStore};
use tempfile::tempdir;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[test]
fn renders_odt_from_template() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export.db");
    let template_path = temp.path().join("template.odt");
    let output_path = temp.path().join("output.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(
            r#"{"flatpak":true,"risk_filter":"green","journal_vacuum":false}"#,
            "1.0.0",
        )
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "progress",
            r#"{}"#,
            "AI_ASSESSMENT: Green | 1) Apply the selected updates.\n2) Reboot after update.",
        )
        .expect("append ai assessment");
    store
        .append_event(
            &run_id,
            "flatpak",
            "error",
            "error",
            r#"{}"#,
            "Flatpak system update requires sudo password",
        )
        .expect("append effective-selection event");
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
            "apply",
            "info",
            "PackageResult",
            r#"{"name":"mesa<gpu>","status":"installed","to_version":"24.1"}"#,
            "mesa <installed>",
        )
        .expect("append package result");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
            "done",
        )
        .expect("append summary");
    store
        .finish_run(&run_id, 1234, "PASS", 1, 1, 0, 0)
        .expect("finish run");
    store
        .replace_packages(
            &run_id,
            &[PackageEvidenceRow {
                run_id: run_id.clone(),
                package_name: "mesa<gpu>".to_string(),
                from_version: None,
                to_version: Some("24.1".to_string()),
                arch: None,
                repository: Some("repo-oss".to_string()),
                action: Some("install".to_string()),
                result: Some("succeeded".to_string()),
                risk: Some("green".to_string()),
            }],
        )
        .expect("persist packages");

    let system_info = SystemInfo {
        os_name: "openSUSE".to_string(),
        os_version: "Tumbleweed".to_string(),
        kernel: "6.8.5-1-default".to_string(),
        architecture: "x86_64".to_string(),
        cpu_model: "AMD Ryzen 7".to_string(),
        memory_gb: 32,
        uptime_seconds: 172_800,
    };
    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);

    render_odt(&model, &template_path, &output_path, Some(&system_info)).expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains(&run_id));
    assert!(content.contains("Executive Summary"));
    assert!(content.contains("System Context"));
    assert!(content.contains("Change Summary"));
    assert!(content.contains("Total Package Count Affected"));
    assert!(content.contains("Flatpak Impact"));
    assert!(content.contains("Update Type"));
    assert!(content.contains("AI Assessment"));
    assert!(content.contains("Execution and Validation"));
    assert!(content.contains("Detailed Evidence"));
    let executive_index = content
        .find("Executive Summary")
        .expect("executive summary section");
    let system_index = content
        .find("System Context")
        .expect("system context section");
    let change_index = content
        .find("Change Summary")
        .expect("change summary section");
    let ai_index = content
        .find("AI Assessment")
        .expect("ai assessment section");
    let validation_index = content
        .find("Execution and Validation")
        .expect("execution section");
    let evidence_index = content
        .find("Detailed Evidence")
        .expect("detailed evidence section");
    assert!(
        executive_index < system_index
            && system_index < change_index
            && change_index < ai_index
            && ai_index < validation_index
            && validation_index < evidence_index
    );
    assert!(content.contains("Update Risk"));
    assert!(content.contains("Execution Result"));
    assert!(content.contains("Reconciliation Result"));
    assert!(content.contains("Packages in Scope"));
    assert!(content.contains("Risk Mix"));
    assert!(content.contains("Green: 1"));
    assert!(content.contains("Actions"));
    assert!(content.contains("Install 1"));
    assert!(content.contains("Green"));
    assert!(content.contains("PASS"));
    assert!(content.contains("OS"));
    assert!(content.contains("openSUSE Tumbleweed"));
    assert!(content.contains("Kernel"));
    assert!(content.contains("6.8.5-1-default"));
    assert!(content.contains("App Version"));
    assert!(content.contains("1.0.0"));
    assert!(content.contains("Architecture"));
    assert!(content.contains("x86_64"));
    assert!(content.contains("CPU"));
    assert!(content.contains("AMD Ryzen 7"));
    assert!(content.contains("Memory"));
    assert!(content.contains("32 GB"));
    assert!(content.contains("Uptime"));
    assert!(content.contains("2d"));
    assert!(content.contains("1"));
    assert!(content.contains("Apply the selected updates."));
    assert!(content.contains("2"));
    assert!(content.contains("Reboot after update."));
    assert!(!content.contains("AI Assessment Summary"));
    assert!(content.contains("Recommendations"));
    assert!(!content.contains("Reason"));
    assert!(content.contains("1 structured error event(s) were recorded."));
    assert!(content.contains("Detailed Evidence"));
    assert!(content.contains("Packages"));
    assert!(content.contains("Flatpak"));
    assert!(content.contains("Log Excerpt"));
    let packages_index = content.find("Packages").expect("packages subsection");
    let logs_index = content.find("Log Excerpt").expect("logs subsection");
    assert!(packages_index < logs_index);
    assert!(content.contains("dev.zed.Zed"));
    assert!(content.contains("Updated dev.zed.Zed"));
    assert!(content.contains("mesa&lt;gpu&gt;"));
    assert!(content.contains("Repository"));
    assert!(content.contains("Action"));
    assert!(content.contains("Result"));
    assert!(content.contains("Risk"));
    assert!(content.contains("repo-oss"));
    assert!(content.contains("install"));
    assert!(content.contains("succeeded"));
    assert!(content.contains("green"));
    let mesa_occurrences = content.matches("mesa&lt;gpu&gt;").count();
    assert!(mesa_occurrences >= 1);
    assert!(content.contains("table:table"));
    assert!(!content.contains(">Notes<"));
}

#[test]
fn renders_package_summary_metrics_from_sqlite_package_evidence() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-package-summary.db");
    let template_path = temp.path().join("template-package-summary.odt");
    let output_path = temp.path().join("output-package-summary.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"prefer_packman":true}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","recommendations":["Review kernel updates."]}"#,
            "AI_ASSESSMENT:Red|1) Review kernel updates.",
        )
        .expect("append ai");
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
        .finish_run(&run_id, 1234, "PASS", 4, 3, 1, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Executive Summary"));
    assert!(content.contains("Packages in Scope"));
    assert!(content.contains("4"));
    assert!(content.contains("Risk Mix"));
    assert!(content.contains("Red: 1, Amber: 1, Green: 1"));
    assert!(content.contains("Actions"));
    assert!(content.contains("Install 1, Upgrade 2"));
    assert!(content.contains("High-Risk Packages"));
    assert!(content.contains("kernel-default"));
    assert!(content.contains("Change Summary"));
    assert!(content.contains("Results"));
    assert!(content.contains("Failed 1, Succeeded 2"));
}

#[test]
fn renders_package_risk_values_for_high_impact_package_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-package-risk.odt.db");
    let template_path = temp.path().join("template-package-risk.odt");
    let output_path = temp.path().join("output-package-risk.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
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
            ],
        )
        .expect("persist packages");
    store
        .finish_run(&run_id, 1234, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("kernel-default"));
    assert!(content.contains("mesa"));
    assert!(content.contains("Risk"));
    assert!(content.contains("amber"));
    assert!(!content
        .contains("kernel-default succeeded 6.8.0 -&gt; 6.9.0 repo=repo-oss arch=x86_64 risk="));
}

#[test]
fn renders_log_table_cells_with_non_timestamp_values() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-log.db");
    let template_path = temp.path().join("template-log.odt");
    let output_path = temp.path().join("output-log.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "journal",
            "warn",
            "journal.vacuum.result",
            r#"{"exit_code":1}"#,
            "Journal vacuum skipped",
        )
        .expect("append warn result");
    store
        .append_event(
            &run_id,
            "run",
            "error",
            "error",
            r#"{}"#,
            "Flatpak system update requires sudo password",
        )
        .expect("append error");
    store
        .append_event(
            &run_id,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "Created manual snapshot",
        )
        .expect("append info result");
    store
        .finish_run(&run_id, 1234, "FAIL", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);

    let system_info = test_system_info();
    render_odt(&model, &template_path, &output_path, Some(&system_info)).expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("warn"));
    assert!(content.contains("error"));
    assert!(content.contains("info"));
    assert!(content.contains("Risk Level"));
    assert!(content.contains("Not available"));
    assert!(content.contains("Detailed Evidence"));
    assert!(!content.contains("Packages"));
    assert!(!content.contains(">Flatpak<"));
    assert!(content.contains("Log Excerpt"));
    assert!(content.contains("journal"));
    assert!(content.contains("run"));
    assert!(content.contains("btrfs"));
    assert!(content.contains("error"));
    assert!(content.contains("btrfs.result"));
    assert!(content.contains("Journal vacuum skipped"));
    assert!(content.contains("Flatpak system update requires sudo password"));
    assert!(content.contains("Created pre-update snapshot"));
}

#[test]
fn renders_log_table_with_all_columns_for_synthetic_entries() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-log-columns.db");
    let template_path = temp.path().join("template-log-columns.odt");
    let output_path = temp.path().join("output-log-columns.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "journal",
            "warn",
            "journal.vacuum.result",
            r#"{"exit_code":1}"#,
            "message alpha",
        )
        .expect("append alpha");
    store
        .append_event(
            &run_id,
            "run",
            "error",
            "run.result",
            r#"{}"#,
            "message beta",
        )
        .expect("append beta");
    store
        .append_event(
            &run_id,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "message gamma",
        )
        .expect("append gamma");
    store
        .finish_run(&run_id, 1234, "FAIL", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);

    let system_info = test_system_info();
    render_odt(&model, &template_path, &output_path, Some(&system_info)).expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Timestamp"));
    assert!(content.contains("Severity"));
    assert!(content.contains("Phase"));
    assert!(content.contains("Type"));
    assert!(content.contains("Message"));
    assert!(content.contains("warn"));
    assert!(content.contains("journal"));
    assert!(content.contains("error"));
    assert!(content.contains("message alpha"));
    assert!(content.contains("error"));
    assert!(content.contains("run"));
    assert!(content.contains("run.end"));
    assert!(content.contains("Run completed"));
    assert!(content.contains("info"));
    assert!(content.contains("btrfs"));
    assert!(content.contains("btrfs.result"));
    assert!(content.contains("Created pre-update snapshot"));
}

#[test]
fn log_table_contains_derived_event_messages() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-log-messages.db");
    let template_path = temp.path().join("template-log-messages.odt");
    let output_path = temp.path().join("output-log-messages.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "journal",
            "warn",
            "journal.vacuum.result",
            r#"{"exit_code":1}"#,
            "message from events.message row 1",
        )
        .expect("append row 1");
    store
        .append_event(
            &run_id,
            "run",
            "error",
            "run.result",
            r#"{}"#,
            "message from events.message row 2",
        )
        .expect("append row 2");
    store
        .finish_run(&run_id, 1234, "FAIL", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);

    let system_info = test_system_info();
    render_odt(&model, &template_path, &output_path, Some(&system_info)).expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("message from events.message row 1"));
    assert!(content.contains("Run completed"));
}

#[test]
fn renders_statuses_separately_and_recommendations_as_multiple_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-status-separation.db");
    let template_path = temp.path().join("template-status-separation.odt");
    let output_path = temp.path().join("output-status-separation.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","recommendations":["1) Review repos.","2) Reboot after update."]}"#,
            "AI_ASSESSMENT:Red|1) Review repos.|2) Reboot after update.",
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
        .expect("append reconcile");
    store
        .finish_run(&run_id, 1234, "PASS", 18, 18, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Update Risk"));
    assert!(content.contains("Execution Result"));
    assert!(content.contains("Reconciliation Result"));
    assert!(content.contains("Red"));
    assert!(content.contains("PASS"));
    assert!(content.contains("Attempted"));
    assert!(content.contains("18"));
    assert!(content.contains("Recommendations"));
    assert!(!content.contains("Reason"));
    assert!(content.contains("1"));
    assert!(content.contains("Review repos."));
    assert!(content.contains("2"));
    assert!(content.contains("Reboot after update."));
    assert!(content.contains("Detailed Evidence"));
    assert!(!content.contains("Packages"));
    assert!(!content.contains("Flatpak"));
    assert!(content.contains("Log Excerpt"));
}

#[test]
fn renders_ai_assessment_from_durable_store_rows() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-ai-blob.db");
    let template_path = temp.path().join("template-ai-blob.odt");
    let output_path = temp.path().join("output-ai-blob.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Review vendor changes.","2) Take snapshot first.","3) Reboot after update."]"#,
        )
        .expect("persist ai assessment");
    store
        .finish_run(&run_id, 1234, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("AI Assessment"));
    assert!(content.contains("Update Risk"));
    assert!(content.contains("Risk Level"));
    assert!(content.contains("Amber"));
    assert!(!content.contains("AI Assessment Summary"));
    assert!(content.contains("Risk Level: Amber"));
    assert!(content.contains("Recommendations"));
    assert!(!content.contains("Reason"));
    assert!(!content.contains("Rationale"));
    assert!(content.contains("1"));
    assert!(content.contains("Review vendor changes."));
    assert!(content.contains("2"));
    assert!(content.contains("Take snapshot first."));
    assert!(content.contains("3"));
    assert!(content.contains("Reboot after update."));
    assert!(!content.contains("Recommendations: 1)"));
}

#[test]
fn report_ai_section_falls_back_to_not_available_without_durable_ai_row() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-no-ai-row.db");
    let template_path = temp.path().join("template-no-ai-row.odt");
    let output_path = temp.path().join("output-no-ai-row.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Amber","recommendations":["1) Snapshot first.","2) Reboot after update."]}"#,
            "AI_ASSESSMENT:Amber|1) Snapshot first.|2) Reboot after update.",
        )
        .expect("append transient ai event");
    store
        .finish_run(&run_id, 1234, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Risk Level: Not available"));
    assert!(content.contains("Recommendations: Not available"));
    assert!(!content.contains("Rationale"));
    assert!(!content.contains("Reason"));
    assert!(!content.contains("AI Recommendations"));
}

#[test]
fn renders_reason_column_only_when_any_recommendation_reason_exists() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-ai-reason-column.db");
    let template_path = temp.path().join("template-ai-reason-column.odt");
    let output_path = temp.path().join("output-ai-reason-column.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
        .expect("start run");
    store
        .upsert_ai_assessment(
            &run_id,
            Some("Amber"),
            r#"["1) Review vendor changes.","2) Reboot after update."]"#,
        )
        .expect("persist ai");
    store
        .finish_run(&run_id, 1234, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let mut model = ReportModel::from_store(&store, &run_id).expect("build model");
    model.ai_recommendations[0].reason = Some("Vendor shift detected".to_string());

    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Step"));
    assert!(content.contains("Recommendation"));
    assert!(content.contains("Reason"));
    assert!(content.contains("Vendor shift detected"));
    assert!(content.contains("Review vendor changes."));
    assert!(content.contains("Reboot after update."));
}

#[test]
fn renders_change_summary_from_structured_fields_and_omits_missing_items() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-change-summary.db");
    let template_path = temp.path().join("template-change-summary.odt");
    let output_path = temp.path().join("output-change-summary.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"zypper_dup":true,"prefer_packman":true,"repos":["repo-oss","packman"],"snapshot_before_update":true}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Red","risk_counts":{"red":2,"amber":1,"green":4},"notable_red_items":["kernel-default vendor change"],"repo_vendor_anomalies":["Vendor change candidates present"]}"#,
            "AI_ASSESSMENT:Red|1) Review vendor changes.",
        )
        .expect("append ai");
    store
        .append_event(
            &run_id,
            "package_manager",
            "info",
            "package.locks",
            r#"{"locks":2}"#,
            "Loaded 2 package lock(s)",
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
        .finish_run(&run_id, 1234, "PASS", 2, 2, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Change Summary"));
    assert!(content.contains("Total Package Count Affected"));
    assert!(content.contains("2"));
    assert!(content.contains("Risk Counts"));
    assert!(content.contains("Amber: 1, Green: 1"));
    assert!(content.contains("Actions"));
    assert!(content.contains("Install 2"));
    assert!(content.contains("Results"));
    assert!(content.contains("Succeeded 2"));
    assert!(content.contains("High-Risk Packages"));
    assert!(content.contains("ffmpeg"));
    assert!(content.contains("Notable Red Items"));
    assert!(content.contains("kernel-default vendor change"));
    assert!(content.contains("Repository/Vendor Anomalies"));
    assert!(content.contains("Vendor change candidates present"));
    assert!(content.contains("Mixed package sources detected"));
    assert!(content.contains("Package Locks"));
    assert!(content.contains("Snapshot Status"));
    assert!(content.contains("Created"));
    assert!(content.contains("Update Type"));
    assert!(content.contains("Zypper Dup"));
}

#[test]
fn omits_unavailable_change_summary_fields_in_sparse_report() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-change-summary-sparse.db");
    let template_path = temp.path().join("template-change-summary-sparse.odt");
    let output_path = temp.path().join("output-change-summary-sparse.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.0.0")
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
        .finish_run(&run_id, 1234, "PASS", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Change Summary"));
    assert!(content.contains("Total Package Count Affected"));
    assert!(content.contains("5"));
    assert!(!content.contains("Risk Counts"));
    assert!(!content.contains("Notable Red Items"));
    assert!(!content.contains("Repository/Vendor Anomalies"));
    assert!(!content.contains("Package Locks"));
    assert!(!content.contains("Flatpak Impact"));
}

#[test]
fn detailed_evidence_omits_package_table_when_package_evidence_is_empty() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-no-package-evidence.db");
    let template_path = temp.path().join("template-no-package-evidence.odt");
    let output_path = temp.path().join("output-no-package-evidence.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(r#"{"flatpak":false}"#, "1.0.0")
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "error",
            "error",
            r#"{}"#,
            "structured error only",
        )
        .expect("append error");
    store
        .finish_run(&run_id, 1234, "FAIL", 0, 0, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Detailed Evidence"));
    assert!(!content.contains("Packages"));
    assert!(content.contains("Log Excerpt"));
}

#[test]
fn report_export_semantics_survive_ui_wording_changes() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("report-export-wording-stability.db");
    let template_path = temp.path().join("template-wording-stability.odt");
    let output_path = temp.path().join("output-wording-stability.odt");
    let store = ReportStore::with_db_path(&db_path).expect("create store");

    let run_id = store
        .start_run(
            r#"{"zypper_dup":true,"snapshot_before_update":true}"#,
            "1.0.0",
        )
        .expect("start run");
    store
        .append_event(
            &run_id,
            "run",
            "info",
            "ai.assessment",
            r#"{"risk":"Amber","rationale":"Kernel changes detected.","recommendations":["1) Snapshot first.","2) Reboot after update."],"risk_counts":{"amber":2,"green":3}}"#,
            "Totally different visible wording",
        )
        .expect("append ai");
    store
        .append_event(
            &run_id,
            "btrfs",
            "info",
            "btrfs.result",
            r#"{"exit_code":0}"#,
            "Different snapshot sentence",
        )
        .expect("append snapshot");
    store
        .append_event(
            &run_id,
            "reconcile",
            "info",
            "ReconcileSummary",
            r#"{"verdict":"PASS","attempted":4,"installed":4,"failed":0,"unaccounted":0}"#,
            "Different reconciliation sentence",
        )
        .expect("append reconcile");
    store
        .finish_run(&run_id, 1234, "PASS", 4, 4, 0, 0)
        .expect("finish run");

    let model = ReportModel::from_store(&store, &run_id).expect("build model");
    create_template(&template_path);
    render_odt(
        &model,
        &template_path,
        &output_path,
        Some(&test_system_info()),
    )
    .expect("render odt");

    let file = fs::File::open(&output_path).expect("open output");
    let mut archive = ZipArchive::new(file).expect("open zip");
    let mut content = String::new();
    archive
        .by_name("content.xml")
        .expect("content.xml")
        .read_to_string(&mut content)
        .expect("read content.xml");

    assert!(content.contains("Executive Summary"));
    assert!(content.contains("Change Summary"));
    assert!(content.contains("AI Assessment"));
    assert!(content.contains("Execution and Validation"));
    assert!(content.contains("Amber"));
    assert!(content.contains("Snapshot first."));
    assert!(content.contains("Reboot after update."));
    assert!(content.contains("Risk Counts"));
    assert!(content.contains("Amber: 2, Green: 3"));
    assert!(content.contains("Snapshot Status"));
    assert!(content.contains("Created"));
    assert!(!content.contains("Totally different visible wording"));
    assert!(!content.contains("Different reconciliation sentence"));
}

fn create_template(path: &std::path::Path) {
    let file = fs::File::create(path).expect("create template");
    let mut writer = ZipWriter::new(file);

    writer
        .start_file(
            "mimetype",
            FileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .expect("mimetype");
    use std::io::Write;
    writer
        .write_all(b"application/vnd.oasis.opendocument.text")
        .expect("write mimetype");

    writer
        .add_directory(
            "META-INF/",
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .expect("meta dir");
    writer
        .start_file(
            "META-INF/manifest.xml",
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .expect("manifest");
    writer
        .write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#,
        )
        .expect("write manifest");

    writer
        .start_file(
            "content.xml",
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .expect("content");
    writer
        .write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
    xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
    xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
    office:version="1.2">
  <office:body>
    <office:text>
      {{REPORT_BODY}}
    </office:text>
  </office:body>
</office:document-content>"#,
        )
        .expect("write content");

    writer.finish().expect("finish template");
}

fn test_system_info() -> SystemInfo {
    SystemInfo {
        os_name: "Unknown".to_string(),
        os_version: "Unknown".to_string(),
        kernel: "Unknown".to_string(),
        architecture: "Unknown".to_string(),
        cpu_model: "Unknown".to_string(),
        memory_gb: 0,
        uptime_seconds: 0,
    }
}
