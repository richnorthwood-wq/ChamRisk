use chamrisk_core::models::UpdateAction;
use chamrisk_core::zypper::{parse_packages_xml, parse_search_solvables_xml, parse_zypper_dry_run};

#[test]
fn parses_table_fixture() {
    let src = include_str!("fixtures/zypper_table.txt");
    let parsed = parse_zypper_dry_run(src);
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].name, "vim");
    assert_eq!(parsed[0].action, UpdateAction::Upgrade);
    assert_eq!(parsed[1].action, UpdateAction::VendorChange);
    assert!(parsed[1].vendor_change);
    assert!(parsed[2].repo_change);
}

#[test]
fn parses_verbose_fixture() {
    let src = include_str!("fixtures/zypper_verbose.txt");
    let parsed = parse_zypper_dry_run(src);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "yast2");
    assert_eq!(parsed[0].action, UpdateAction::Upgrade);
    assert_eq!(parsed[1].name, "mesa");
    assert_eq!(parsed[1].action, UpdateAction::VendorChange);
    assert!(parsed[1].vendor_change);
    assert!(parsed[1].repo_change);
}

#[test]
fn parses_table_with_leading_status_and_optional_vendor() {
    let src = r#"
| S | Repository | Name           | Current | New   | Status  | Arch   | Kind    |
|---+------------+----------------+---------+-------+---------+--------+---------|
| v | OSS        | nano           | 7.1-1   | 7.2-1 | upgrade | x86_64 | package |
|   | Update     | kernel-default | 6.0-1   | 6.1-1 | upgrade from update | x86_64 | package |
"#;

    let parsed = parse_zypper_dry_run(src);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "nano");
    assert_eq!(parsed[0].action, UpdateAction::Upgrade);
    assert_eq!(parsed[1].name, "kernel-default");
    assert!(parsed[1].repo_change);
}

#[test]
fn parses_packages_xml_fixture() {
    let src = include_str!("fixtures/packages.xml");
    let parsed = parse_packages_xml(src).expect("parse packages xml");
    assert_eq!(parsed.len(), 3);

    assert_eq!(parsed[0].name, "vim");
    assert_eq!(parsed[0].available_version.as_deref(), Some("9.0-1"));
    assert_eq!(parsed[0].arch.as_deref(), Some("x86_64"));
    assert_eq!(parsed[0].repository.as_deref(), Some("oss"));
    assert_eq!(parsed[0].summary.as_deref(), Some("Vi IMproved editor"));

    assert_eq!(parsed[1].name, "curl");
    assert_eq!(parsed[1].available_version.as_deref(), Some("8.6.0-2"));
    assert_eq!(parsed[1].repository.as_deref(), Some("updates"));
    assert_eq!(parsed[1].summary, None);

    assert_eq!(parsed[2].name, "nano");
    assert_eq!(parsed[2].available_version, None);
    assert_eq!(
        parsed[2].summary.as_deref(),
        Some("Small and friendly text editor")
    );
}

#[test]
fn parses_search_solvables_xml_fixture() {
    let src = include_str!("fixtures/search_packages_min.xml");
    let parsed = parse_search_solvables_xml(src).expect("parse search solvables xml");
    assert_eq!(parsed.len(), 2);

    let installed = parsed.iter().find(|r| r.name == "7zip").unwrap();
    assert!(installed.installed_version.is_some());

    let not_installed = parsed.iter().find(|r| r.name == "nano").unwrap();
    assert!(not_installed.installed_version.is_none());
}
