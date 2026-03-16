use chamrisk_ops::ai::parse_assessment;

#[test]
fn parses_strict_json_fields() {
    let parsed = parse_assessment("{\"summary\":\"safe\",\"risk\":\"low\"}").unwrap();
    assert_eq!(parsed.summary, "safe");
    assert_eq!(parsed.risk, "low");
}

#[test]
fn rejects_missing_fields() {
    assert!(parse_assessment("{\"summary\":\"ok\"}").is_none());
}

#[test]
fn parses_chat_completions_wrapper_content() {
    let raw = r#"{
        "id":"chatcmpl-test",
        "choices":[
            {
                "message":{
                    "content":"Risk: Amber\n1) Create a snapshot before updating.\n2) Update the multimedia stack in one transaction.\n3) Reboot after update.\n4) Test audio playback in PipeWire.\n5) Test video playback in VLC."
                }
            }
        ]
    }
    HTTP_STATUS:200
    "#;

    let parsed = parse_assessment(raw).unwrap();
    assert_eq!(parsed.risk, "Amber");
    assert_eq!(
        parsed.summary,
        "1) Create a snapshot before updating.\n2) Update the multimedia stack in one transaction.\n3) Reboot after update.\n4) Test audio playback in PipeWire.\n5) Test video playback in VLC."
    );
}

#[test]
fn parses_prefaced_six_line_assessment() {
    let raw = "Here is the triage result:\r\n\r\nRisk: Green\r\n1) Apply the selected updates.\r\n2) Reboot after update.\r\n3) Test audio playback.\r\n4) Test video playback.\r\n5) Check desktop login.\r\n";

    let parsed = parse_assessment(raw).unwrap();
    assert_eq!(parsed.risk, "Green");
    assert_eq!(
        parsed.summary,
        "1) Apply the selected updates.\n2) Reboot after update.\n3) Test audio playback.\n4) Test video playback.\n5) Check desktop login."
    );
}
