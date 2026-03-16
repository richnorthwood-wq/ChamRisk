use chamrisk_ops::events::OpsEventKind;
use chamrisk_ops::runner::{run_streaming, LogStream, OpsEvent};
use chamrisk_ops::tasks::run_updates_plan;
use std::sync::mpsc::channel;
use std::time::Duration;

#[test]
fn emits_log_and_completion() {
    let (tx, rx) = channel();
    run_streaming("bash", &["-lc", "echo hello"], LogStream::Updates, tx);

    let mut saw_log = false;
    let mut saw_result = false;
    for _ in 0..10 {
        if let Ok(event) = rx.recv_timeout(Duration::from_secs(1)) {
            match event {
                OpsEvent::Log { line, .. } if line.contains("hello") => saw_log = true,
                OpsEvent::CommandResult { result, .. } if result.exit_code == 0 => {
                    saw_result = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(saw_log);
    assert!(saw_result);
}

#[test]
fn stderr_is_logged_not_errored_on_success() {
    let (tx, rx) = channel();
    run_streaming("bash", &["-lc", "echo warning >&2"], LogStream::Updates, tx);

    let mut saw_stderr_log = false;
    let mut saw_error = false;
    let mut saw_result = false;

    for _ in 0..10 {
        if let Ok(event) = rx.recv_timeout(Duration::from_secs(1)) {
            match event {
                OpsEvent::Log { line, .. } if line.contains("warning") => saw_stderr_log = true,
                OpsEvent::Error(_) => saw_error = true,
                OpsEvent::CommandResult { result, .. } if result.exit_code == 0 => {
                    saw_result = true;
                    break;
                }
                _ => {}
            }
        }
    }

    assert!(saw_stderr_log);
    assert!(!saw_error);
    assert!(saw_result);
}

#[test]
fn non_zero_exit_emits_single_error_and_result() {
    let (tx, rx) = channel();
    run_streaming(
        "bash",
        &["-lc", "echo warning >&2; exit 7"],
        LogStream::Updates,
        tx,
    );

    let mut error_messages = Vec::new();
    let mut saw_result = false;

    for _ in 0..10 {
        if let Ok(event) = rx.recv_timeout(Duration::from_secs(1)) {
            match event {
                OpsEvent::Error(line) => error_messages.push(line),
                OpsEvent::CommandResult { result, .. } if result.exit_code == 7 => {
                    assert!(result.stderr.contains("warning"));
                    saw_result = true;
                    break;
                }
                _ => {}
            }
        }
    }

    assert_eq!(error_messages.len(), 1);
    assert!(error_messages[0].contains("failed with exit code 7"));
    assert!(error_messages[0].contains("warning"));
    assert!(saw_result);
}

#[test]
fn journal_vacuum_without_password_emits_clear_error() {
    let (tx, rx) = channel();
    run_updates_plan(tx, false, false, false, false, true, None);

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Progress(line)) => assert_eq!(line, "Executing updates plan"),
        other => panic!("expected progress event, got {other:?}"),
    }

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Structured(event)) if matches!(event.kind, OpsEventKind::RunStart) => {}
        other => panic!("expected run start event, got {other:?}"),
    }

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Error(line)) => {
            assert_eq!(line, "Journal vacuum blocked: requires sudo password")
        }
        other => panic!("expected journal vacuum error, got {other:?}"),
    }
}

#[test]
fn flatpak_only_run_does_not_emit_zypper_preview() {
    let (tx, rx) = channel();
    run_updates_plan(tx, false, false, false, true, false, None);

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Progress(line)) => assert_eq!(line, "Executing updates plan"),
        other => panic!("expected progress event, got {other:?}"),
    }

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Structured(event)) if matches!(event.kind, OpsEventKind::RunStart) => {}
        other => panic!("expected run start event, got {other:?}"),
    }

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(OpsEvent::Error(line)) => {
            assert_eq!(line, "Flatpak update blocked: requires sudo password")
        }
        other => panic!("expected flatpak sudo error, got {other:?}"),
    }

    while let Ok(event) = rx.recv_timeout(Duration::from_millis(50)) {
        if let OpsEvent::Structured(event) = event {
            assert!(!matches!(event.kind, OpsEventKind::PreviewStart));
        }
    }
}
