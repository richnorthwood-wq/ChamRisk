use chamrisk_ui::MaintenanceApp;

#[test]
fn execution_selection_defaults_enabled() {
    let app = MaintenanceApp::default();
    assert!(app.execution_selection.snapshot_before_update);
    assert!(app.execution_selection.zypper_dup);
    assert!(app.execution_selection.packman_preference);
    assert!(app.execution_selection.flatpaks);
    assert!(app.execution_selection.journal_vacuum);
}
