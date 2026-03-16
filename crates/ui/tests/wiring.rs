use chamrisk_core::models::{CommandResult, PackageChange, UpdateAction, UpdatePlan};
use chamrisk_ops::runner::OpsEvent;
use chamrisk_ui::MaintenanceApp;

#[test]
fn refresh_pipeline_parses_preview() {
    let mut app = MaintenanceApp::default();
    let changes = vec![
        PackageChange {
            name: "a".into(),
            arch: None,
            action: UpdateAction::VendorChange,
            from: None,
            to: None,
            repo: Some("OSS".into()),
            vendor: Some("VendorA -> VendorB".into()),
            kind: None,
        },
        PackageChange {
            name: "b".into(),
            arch: None,
            action: UpdateAction::RepoChange,
            from: None,
            to: None,
            repo: Some("Update -> OSS".into()),
            vendor: None,
            kind: None,
        },
        PackageChange {
            name: "c".into(),
            arch: None,
            action: UpdateAction::RepoChange,
            from: None,
            to: None,
            repo: Some("NonOSS -> OSS".into()),
            vendor: None,
            kind: None,
        },
    ];
    let plan = UpdatePlan {
        changes,
        command: Vec::new(),
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    };
    app.apply_ops_event(OpsEvent::UpdatePlan(plan));
    assert_eq!(app.counts.all, 3);
    assert_eq!(app.counts.vendor_changes, 1);
    assert_eq!(app.counts.repo_changes, 2);
}
