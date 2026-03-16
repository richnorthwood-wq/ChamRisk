use chamrisk_core::models::{PackageUpdate, UpdateAction, VendorGroup};
use chamrisk_core::risk::{assess_risk, fingerprint, RiskLevel};

fn update(name: &str, action: UpdateAction) -> PackageUpdate {
    PackageUpdate {
        name: name.to_string(),
        action,
        current_version: Some("1.0.0".into()),
        new_version: Some("1.0.1".into()),
        arch: Some("x86_64".into()),
        repository: Some("repo-oss".into()),
        vendor: None,
        vendor_group: VendorGroup::Official,
        vendor_change: false,
        repo_change: false,
    }
}

#[test]
fn systemd_upgrade_is_never_low() {
    let assessment = assess_risk(&[update("systemd", UpdateAction::Upgrade)]);

    assert!(assessment.level >= RiskLevel::Medium);
    assert!(assessment
        .reasons
        .iter()
        .any(|r| r.contains("systemd-family upgrade")));
}

#[test]
fn kernel_and_systemd_transaction_is_high() {
    let assessment = assess_risk(&[
        update("kernel-default", UpdateAction::Upgrade),
        update("systemd", UpdateAction::Upgrade),
    ]);

    assert_eq!(assessment.level, RiskLevel::High);
    assert!(assessment
        .reasons
        .iter()
        .any(|r| r.contains("systemd-family + kernel")));
}

#[test]
fn glibc_remove_is_high() {
    let assessment = assess_risk(&[update("glibc", UpdateAction::Remove)]);

    assert_eq!(assessment.level, RiskLevel::High);
    assert!(assessment
        .reasons
        .iter()
        .any(|r| r.contains("critical package remove/downgrade")));
}

#[test]
fn leaf_package_upgrade_can_be_low() {
    let assessment = assess_risk(&[update("nano", UpdateAction::Upgrade)]);

    assert_eq!(assessment.level, RiskLevel::Low);
}

#[test]
fn core_vendor_or_repo_shift_escalates_risk() {
    let mut shifted = update("systemd", UpdateAction::Upgrade);
    shifted.vendor_change = true;
    shifted.repo_change = true;

    let assessment = assess_risk(&[shifted]);

    assert!(assessment.level >= RiskLevel::Medium);
    assert!(assessment
        .reasons
        .iter()
        .any(|r| r.contains("vendor/repo shift")));
}

#[test]
fn fingerprint_and_assessment_reasons_are_stable_under_order_changes() {
    let mut a = update("systemd", UpdateAction::Upgrade);
    a.vendor_change = true;
    let b = update("kernel-default", UpdateAction::Upgrade);

    let first = vec![a.clone(), b.clone()];
    let second = vec![b, a];

    assert_eq!(fingerprint(&first), fingerprint(&second));

    let first_assessment = assess_risk(&first);
    let second_assessment = assess_risk(&second);
    assert_eq!(first_assessment.level, second_assessment.level);
    assert_eq!(first_assessment.reasons, second_assessment.reasons);
}
