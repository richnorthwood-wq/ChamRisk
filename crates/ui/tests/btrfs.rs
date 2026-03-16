use chamrisk_core::models::{BtrfsSnapshotRow, CommandResult};
use chamrisk_ops::runner::{OperationKind, OpsEvent};
use chamrisk_ui::{MaintenanceApp, Tab};

#[test]
fn btrfs_banners_update() {
    let mut app = MaintenanceApp::default();
    app.active_tab = Tab::Btrfs;
    app.apply_ops_event(OpsEvent::Progress(
        "Please wait: running btrfs scrub".into(),
    ));
    assert!(app.btrfs_status.please_wait);
    assert!(!app.btrfs_status.completed);
    app.apply_ops_event(OpsEvent::CommandResult {
        operation: OperationKind::Btrfs,
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    });
    assert!(!app.btrfs_status.please_wait);
    assert!(app.btrfs_status.completed);
}

#[test]
fn btrfs_snapshot_rows_populate_state_and_mark_current_snapshot() {
    let mut app = MaintenanceApp::default();
    app.active_tab = Tab::Btrfs;

    app.apply_ops_event(OpsEvent::BtrfsSnapshots(vec![
        BtrfsSnapshotRow {
            snapshot_id: "1080".into(),
            is_current: false,
            snapshot_type: "single".into(),
            pre_number: None,
            date: "Mon Mar 9 18:35:00 2026".into(),
            user: "root".into(),
            used_space: "12.00 MiB".into(),
            cleanup: String::new(),
            description: "baseline".into(),
            userdata: String::new(),
        },
        BtrfsSnapshotRow {
            snapshot_id: "1081".into(),
            is_current: true,
            snapshot_type: "single".into(),
            pre_number: None,
            date: "Mon Mar 9 18:38:31 2026".into(),
            user: "root".into(),
            used_space: "656.00 KiB".into(),
            cleanup: String::new(),
            description: "writable copy of #1077".into(),
            userdata: String::new(),
        },
    ]));
    app.apply_ops_event(OpsEvent::CommandResult {
        operation: OperationKind::Btrfs,
        result: CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
    });

    assert_eq!(app.btrfs_snapshots.len(), 2);
    assert_eq!(app.btrfs_snapshots[1].snapshot_id, "1081");
    assert!(app.btrfs_snapshots[1].is_current);
    assert_eq!(app.btrfs_snapshots_error, None);
    assert!(app.btrfs_status.completed);
}

#[test]
fn btrfs_snapshot_export_requires_loaded_snapshot_rows() {
    let mut app = MaintenanceApp::default();

    assert!(!app.request_btrfs_snapshot_export());
    let dialog = app.info_dialog.expect("expected info dialog");
    assert_eq!(dialog.title, "Snapshot export");
    assert_eq!(dialog.message, "Please list snapshots first");
}

#[test]
fn btrfs_snapshot_export_is_allowed_when_rows_exist() {
    let mut app = MaintenanceApp::default();
    app.btrfs_snapshots.push(BtrfsSnapshotRow {
        snapshot_id: "1081".into(),
        is_current: true,
        snapshot_type: "single".into(),
        pre_number: None,
        date: "Mon Mar 9 18:38:31 2026".into(),
        user: "root".into(),
        used_space: "656.00 KiB".into(),
        cleanup: String::new(),
        description: "writable copy of #1077".into(),
        userdata: String::new(),
    });

    assert!(app.request_btrfs_snapshot_export());
    assert!(app.info_dialog.is_none());
}
