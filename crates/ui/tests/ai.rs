use chamrisk_ops::runner::OpsEvent;
use chamrisk_ui::MaintenanceApp;

#[test]
fn ai_errors_degrade_gracefully() {
    let mut app = MaintenanceApp::default();
    app.apply_ops_event(OpsEvent::Error(
        "AI preflight failed; triage disabled".into(),
    ));
    assert!(app.ai_state.last_error.is_some());
    app.apply_ops_event(OpsEvent::Progress("AI triage completed".into()));
    assert!(app.ai_state.preflight_ok);
}
