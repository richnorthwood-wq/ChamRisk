pub mod providers;

use crate::api::{
    active_provider, ai_enabled, is_no_api_key_configured_error, resolved_ai_runtime_config,
    ResolvedAiRuntimeConfig,
};
use crate::events::{OpsEvent as StructuredOpsEvent, OpsEventKind};
use crate::report_store::{AiPersistenceEligibility, ReportStore};
use crate::runner::{LogStream, OpsEvent};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::mpsc::Sender;
use std::thread;

const NO_UPDATES_OUTPUT: &str =
    "Risk: Green\n1) No updates pending.\n2) None.\n3) None.\n4) None.\n5) None.";
const CRITICAL_REMOVAL_PREFIXES: &[&str] = &[
    "libplasma",
    "plasma",
    "gnome",
    "xorg",
    "mesa",
    "wayland",
    "systemd",
    "glibc",
    "rpm",
    "libzypp",
    "kernel",
    "grub",
    "dracut",
];
const SYSTEM_PROMPT: &str = "You MUST output exactly 6 lines and nothing else.\n\
Output format is strict:\n\
Line 1: Risk: Green|Amber|Red\n\
Lines 2-6: exactly five numbered runbook phases:\n\
1) Pre-update safeguards: <step>\n\
2) Update execution: <step>\n\
3) Post-reboot core validation: <step>\n\
4) Post-reboot functional validation: <step>\n\
5) Optional deeper checks: <step>\n\
\n\
Rules (package_count > 0 case only):\n\
- Output exactly 6 lines. No bullets, no blank lines, no commentary.\n\
- Each action must be specific and executable. Do not use these words: careful, validate, consider, ensure, might, warrant.\n\
- Each action must be 120 characters or fewer.\n\
- If snapshot_selected is false, action 1 must instruct enabling/performing a snapshot/backup before proceeding.\n\
- If reboot_recommended is true, include 'Reboot after update.' in either Update execution or Post-reboot core validation.\n\
- If has_packman is true, include repo-mixing guidance in Pre-update safeguards or Update execution.\n\
- Use recommendation_themes.pre_update_safeguards, update_execution, post_reboot_core_validation, post_reboot_functional_validation, and optional_deeper_checks as the primary action source.\n\
- Suppress checks for system areas whose package families are absent.\n\
- Use the small generic fallback only if a runbook phase has no strong family-specific item.\n\
- If RiskCandidate is Red, use stronger safeguards and a fuller core-system runbook.\n\
- If RiskCandidate is Amber, keep the runbook targeted to the affected families.\n\
- If RiskCandidate is Green, keep the runbook short and limited to brief sanity checks.\n\
- Keep the wording concise and transaction-specific; this should read like a practical update runbook.\n\
- Do NOT mention vendor unless vendor-change data is explicitly provided in the input.\n\
- Do NOT output long package lists.\n\
- If referencing removals, say exactly: Review removals list (N items) - ensure desktop stack remains installable.\n\
- Do NOT state \"X -> Y replacement\" unless the input explicitly contains solver text \"replaced by\" or \"obsoletes\".\n\
- Risk must equal RiskCandidate unless specific evidence from prompt_summary justifies raising it.\n\
- Never lower risk below RiskCandidate.\n\
- If you raise risk above RiskCandidate, cite package names from prompt_summary in one action.\n\
- If critical_removal_gate.required is true, action 1 must be a Gate action requiring a zypper dup --dry-run confirmation that each critical removal has a corresponding replacement.\n\
- Keep critical removal references summarized with the provided counts and names only.\n\
- If critical_removal_gate.has_unmatched_removals is true, do not recommend proceeding; instruct resolving repos/vendor conflicts first.\n\
- Do not add commentary or extra lines.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAssessment {
    pub summary: String,
    pub risk: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssessmentPersistenceOutcome {
    Persisted,
    SkippedNoEligibleRun,
    Failed(String),
}

pub fn ai_preflight_and_assess(
    _endpoint: &str, // kept for compatibility; intentionally unused
    payload_json: &str,
    _api_key: Option<String>, // kept for compatibility; intentionally unused
    run_id: Option<String>,
    tx: Sender<OpsEvent>,
) {
    log_ai_triage_start(&tx, run_id.as_deref());

    match ai_enabled() {
        Ok(false) => {
            let _ = tx.send(OpsEvent::Progress(
                "AI triage disabled: no API selected".into(),
            ));
            return;
        }
        Ok(true) => {}
        Err(err) => {
            let _ = tx.send(OpsEvent::Error(format!(
                "AI configuration error; triage disabled: {err}"
            )));
            return;
        }
    }

    if package_count_from_payload(payload_json) == Some(0) {
        emit_assessment(&tx, run_id.as_deref(), &no_updates_assessment());
        return;
    }

    let guard_context = critical_removal_guard_from_payload(payload_json);
    let runtime_config = match resolved_ai_runtime_config() {
        Ok(runtime_config) => runtime_config,
        Err(err) => {
            if is_no_api_key_configured_error(&err) {
                let _ = tx.send(OpsEvent::Progress(
                    "AI triage disabled: no API key configured".into(),
                ));
                return;
            }
            let _ = tx.send(OpsEvent::Error(format!(
                "AI configuration error; triage disabled: {err}"
            )));
            return;
        }
    };
    let provider = match active_provider() {
        Ok(provider) => provider,
        Err(err) => {
            let _ = tx.send(OpsEvent::Error(format!(
                "AI provider error; triage disabled: {err}"
            )));
            return;
        }
    };
    let payload_json = payload_json.to_string();

    thread::spawn(move || {
        let tx2 = tx.clone();
        match run_provider_triage(provider, &runtime_config, &payload_json) {
            Ok(assessment) => {
                let assessment = enforce_critical_removal_gate(assessment, guard_context.as_ref());
                emit_assessment(&tx2, run_id.as_deref(), &assessment);
            }
            Err(err) => {
                let _ = tx2.send(OpsEvent::Error(err));
            }
        }
    });
}

fn run_provider_triage(
    provider: Box<dyn chamrisk_core::ai::AiProvider>,
    runtime_config: &ResolvedAiRuntimeConfig,
    payload_json: &str,
) -> Result<AiAssessment, String> {
    if provider.kind() != runtime_config.provider_kind {
        return Err(format!(
            "AI provider mismatch: runtime={:?} adapter={:?}",
            runtime_config.provider_kind,
            provider.kind()
        ));
    }

    let preflight = provider
        .test_connection(Some(runtime_config.api_key.as_str()))
        .map_err(|err| format!("AI preflight failed: {err}"))?;
    if !preflight.success {
        return Err(format!("AI preflight failed: {}", preflight.message));
    }

    let content = provider.run_triage(
        Some(runtime_config.api_key.as_str()),
        runtime_config.model_id.as_str(),
        SYSTEM_PROMPT,
        &build_ai_user_content(payload_json),
    )?;

    parse_assessment(&content).ok_or_else(|| "AI response parse failed".to_string())
}
fn package_count_from_payload(payload_json: &str) -> Option<usize> {
    let value = serde_json::from_str::<Value>(payload_json).ok()?;
    value
        .get("package_count")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .or_else(|| {
            value
                .get("plan_summary")
                .and_then(|plan| plan.get("total_packages"))
                .and_then(Value::as_u64)
                .map(|count| count as usize)
        })
}

fn no_updates_assessment() -> AiAssessment {
    parse_assessment(NO_UPDATES_OUTPUT).expect("deterministic no-updates output must parse")
}

fn log_ai_triage_start(tx: &Sender<OpsEvent>, run_id: Option<&str>) {
    let run_id = run_id.unwrap_or("transient-preview");
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::Updates,
        line: format!("INFO: AI triage start run_id={} status=started", run_id),
    });
}

fn emit_assessment(tx: &Sender<OpsEvent>, run_id: Option<&str>, assessment: &AiAssessment) {
    let recommendations = assessment_recommendations(assessment);
    let persistence_outcome =
        run_id.map(|run_id| persist_assessment_for_run_id(run_id, assessment, &recommendations));
    if let Some(run_id) = run_id {
        log_assessment_persistence(
            tx,
            run_id,
            &assessment.risk,
            persistence_outcome
                .clone()
                .expect("run_id presence should yield persistence outcome"),
        );
    }

    let _ = tx.send(OpsEvent::Progress(format!(
        "AI_ASSESSMENT:{}|{}",
        assessment.risk, assessment.summary
    )));
    let _ = tx.send(OpsEvent::Progress("AI triage completed".into()));

    if matches!(
        persistence_outcome,
        Some(AssessmentPersistenceOutcome::Persisted)
    ) {
        let _ = tx.send(OpsEvent::Structured(StructuredOpsEvent::from_kind(
            OpsEventKind::AIAnalysis {
                risk: assessment.risk.clone(),
                rationale: None,
                recommendations,
            },
        )));
    }
}

fn assessment_recommendations(assessment: &AiAssessment) -> Vec<String> {
    assessment
        .summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn persist_assessment_for_store(
    store: &ReportStore,
    run_id: &str,
    assessment: &AiAssessment,
    recommendations: &[String],
) -> AssessmentPersistenceOutcome {
    match store.ai_persistence_eligibility(run_id) {
        Ok(AiPersistenceEligibility::EligibleOpenRun) => {}
        Ok(AiPersistenceEligibility::MissingRun | AiPersistenceEligibility::ClosedRun) => {
            return AssessmentPersistenceOutcome::SkippedNoEligibleRun;
        }
        Err(err) => return AssessmentPersistenceOutcome::Failed(err),
    }

    let recommendations_json = json!(recommendations).to_string();
    match store.upsert_ai_assessment(
        run_id,
        Some(assessment.risk.as_str()),
        &recommendations_json,
    ) {
        Ok(()) => AssessmentPersistenceOutcome::Persisted,
        Err(err) => AssessmentPersistenceOutcome::Failed(err),
    }
}

pub fn persist_assessment_snapshot_for_run(
    store: &ReportStore,
    run_id: &str,
    assessment: &AiAssessment,
) -> Result<(), String> {
    let recommendations = assessment_recommendations(assessment);
    match persist_assessment_for_store(store, run_id, assessment, &recommendations) {
        AssessmentPersistenceOutcome::Persisted => Ok(()),
        AssessmentPersistenceOutcome::SkippedNoEligibleRun => {
            Err("no eligible open run".to_string())
        }
        AssessmentPersistenceOutcome::Failed(err) => Err(err),
    }
}

fn persist_assessment_for_run_id(
    run_id: &str,
    assessment: &AiAssessment,
    recommendations: &[String],
) -> AssessmentPersistenceOutcome {
    let store = match ReportStore::new() {
        Ok(store) => store,
        Err(err) => return AssessmentPersistenceOutcome::Failed(err),
    };
    persist_assessment_for_store(&store, run_id, assessment, recommendations)
}

fn log_assessment_persistence(
    tx: &Sender<OpsEvent>,
    run_id: &str,
    risk: &str,
    persist_result: AssessmentPersistenceOutcome,
) {
    let line = match persist_result {
        AssessmentPersistenceOutcome::Persisted => format!(
            "INFO: AI triage persist run_id={} risk={} status=upserted",
            run_id, risk
        ),
        AssessmentPersistenceOutcome::SkippedNoEligibleRun => format!(
            "INFO: AI triage persistence skipped run_id={} risk={} reason=no-eligible-open-run",
            run_id, risk
        ),
        AssessmentPersistenceOutcome::Failed(err) => format!(
            "ERROR: AI triage persist run_id={} risk={} status=failed error={err}",
            run_id, risk
        ),
    };
    let _ = tx.send(OpsEvent::Log {
        stream: LogStream::Updates,
        line,
    });
}

#[derive(Debug, Deserialize)]
struct AssessmentJson {
    summary: String,
    risk: String,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionsResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Message {
    content: String,
}

/// Parses:
/// 1) raw JSON: {"summary":"..","risk":".."}
/// 2) chat.completions JSON, where choices[0].message.content contains JSON (or prose)
/// 3) strict 6-line prose fallback
/// 4) legacy prose fallback with "Recommendation:"
pub fn parse_assessment(raw: &str) -> Option<AiAssessment> {
    let raw = strip_http_status_footer(raw).trim();

    // Case 1: raw is already {"summary":"..","risk":".."}
    if let Ok(a) = serde_json::from_str::<AssessmentJson>(raw) {
        return Some(AiAssessment {
            summary: a.summary,
            risk: a.risk,
        });
    }

    if let Some(obj) = extract_first_json_object(raw) {
        // A curl response may include trailing status text after the JSON body.
        if let Some(parsed) = parse_assessment_json_object(&obj) {
            return Some(parsed);
        }
    }

    if looks_like_json_object(raw) {
        return None;
    }

    // Last-resort prose fallback on raw
    parse_text_assessment(raw)
}

fn parse_assessment_json_object(raw: &str) -> Option<AiAssessment> {
    // Case 2: raw is a chat.completions response; parse content then parse JSON/prose inside it
    if let Ok(resp) = serde_json::from_str::<ChatCompletionsResponse>(raw) {
        let content = resp.choices.get(0)?.message.content.trim();
        let content = strip_code_fences(content);

        // Direct JSON in content
        if let Ok(a) = serde_json::from_str::<AssessmentJson>(content) {
            return Some(AiAssessment {
                summary: a.summary,
                risk: a.risk,
            });
        }
        if looks_like_json_object(content) {
            return None;
        }

        // JSON object embedded in content
        if let Some(obj) = extract_first_json_object(content) {
            if let Ok(a) = serde_json::from_str::<AssessmentJson>(&obj) {
                return Some(AiAssessment {
                    summary: a.summary,
                    risk: a.risk,
                });
            }
        }

        // Prose fallback
        return parse_text_assessment(content);
    }

    // Case 3: raw is an embedded/direct {"summary":"..","risk":".."} object
    if let Ok(a) = serde_json::from_str::<AssessmentJson>(raw) {
        return Some(AiAssessment {
            summary: a.summary,
            risk: a.risk,
        });
    }

    None
}

fn parse_text_assessment(s: &str) -> Option<AiAssessment> {
    parse_six_line_assessment(s).or_else(|| parse_legacy_assessment(s))
}

fn parse_six_line_assessment(s: &str) -> Option<AiAssessment> {
    let text = s.trim().replace("\r\n", "\n").replace('\r', "\n");
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if let Some(parsed) = parse_six_line_window(&lines) {
        return Some(parsed);
    }

    None
}

fn parse_legacy_assessment(s: &str) -> Option<AiAssessment> {
    let text = s.trim();
    if text.is_empty() {
        return None;
    }

    let risk = text
        .lines()
        .find_map(|l| l.strip_prefix("Risk:"))
        .map(normalize_risk)
        .unwrap_or_else(|| "Amber".to_string());

    let rec_start = text.find("Recommendation:");
    let mut summary = if let Some(idx) = rec_start {
        text[idx + "Recommendation:".len()..].trim().to_string()
    } else {
        text.to_string()
    };

    // hard cap for UI cleanliness; keep full text elsewhere if you want later
    const MAX: usize = 420;
    if summary.len() > MAX {
        summary.truncate(MAX);
        summary.push('…');
    }

    if summary.is_empty() {
        None
    } else {
        Some(AiAssessment { risk, summary })
    }
}

fn normalize_risk(raw_risk: &str) -> String {
    let risk_lc = raw_risk.to_lowercase();
    if risk_lc.contains("red") || risk_lc.contains("high") {
        "Red".to_string()
    } else if risk_lc.contains("green") || risk_lc.contains("low") {
        "Green".to_string()
    } else {
        "Amber".to_string()
    }
}

fn looks_like_json_object(s: &str) -> bool {
    matches!(serde_json::from_str::<Value>(s), Ok(Value::Object(_)))
}

fn strip_code_fences(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with("```") {
        let without_first = s.splitn(2, '\n').nth(1).unwrap_or("");
        return without_first
            .strip_suffix("```")
            .unwrap_or(without_first)
            .trim();
    }
    s
}

fn strip_http_status_footer(s: &str) -> &str {
    s.split("\nHTTP_STATUS:").next().unwrap_or(s)
}

fn parse_six_line_window(lines: &[&str]) -> Option<AiAssessment> {
    for start in 0..lines.len() {
        let Some(risk_line) = lines.get(start) else {
            break;
        };
        if !risk_line.trim_start().starts_with("Risk:") {
            continue;
        }
        if start + 6 > lines.len() {
            break;
        }

        let action_lines = &lines[start + 1..start + 6];
        let actions_are_numbered = action_lines
            .iter()
            .enumerate()
            .all(|(idx, line)| line.starts_with(&format!("{}) ", idx + 1)));

        if actions_are_numbered {
            let risk_line = risk_line.trim_start();
            return Some(AiAssessment {
                risk: normalize_risk(risk_line.trim_start_matches("Risk:").trim()),
                summary: action_lines.join("\n"),
            });
        }
    }

    None
}

/// Pull the first balanced JSON object `{ ... }` from a string.
fn extract_first_json_object(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut start: Option<usize> = None;
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;

    for (i, &b) in bytes.iter().enumerate() {
        let ch = b as char;

        if escape {
            escape = false;
            continue;
        }
        if in_string && ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }

        if ch == '{' {
            if start.is_none() {
                start = Some(i);
            }
            depth += 1;
        } else if ch == '}' {
            if start.is_some() {
                depth -= 1;
                if depth == 0 {
                    let st = start?;
                    let slice = &s[st..=i];
                    return Some(slice.to_string());
                }
            }
        }
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RiskCandidate {
    Green,
    Amber,
    Red,
}

impl RiskCandidate {
    fn as_str(self) -> &'static str {
        match self {
            Self::Green => "Green",
            Self::Amber => "Amber",
            Self::Red => "Red",
        }
    }
}

#[derive(Debug, Clone)]
struct CanonicalRiskContext {
    candidate: RiskCandidate,
    score_sum: i32,
    score_max: i32,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct AiPackageSummary {
    name: String,
    action: String,
    vendor: Option<String>,
    kind: Option<String>,
}

#[derive(Debug, Clone)]
struct CriticalRemovalMatch {
    package: AiPackageSummary,
    replacements: Vec<AiPackageSummary>,
}

#[derive(Debug, Clone)]
struct CriticalRemovalGuard {
    critical_removals: Vec<CriticalRemovalMatch>,
    unmatched_removals: Vec<String>,
}

#[derive(Debug)]
struct DerivedRiskContext {
    candidate: RiskCandidate,
    reasons: Vec<String>,
    total_updates: usize,
    red_markers: usize,
    removals_count: usize,
    vendor_changes_count: usize,
    kernel_update: bool,
    firmware_update: bool,
    packman_enabled: bool,
    critical_removals_summary: String,
    red_marked_items_summary: String,
    critical_removal_gate: Value,
    canonical: Option<CanonicalRiskContext>,
}

fn build_ai_user_content(payload_json: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(payload_json) else {
        return payload_json.trim().to_string();
    };

    let derived = derive_risk_context(&value);
    let DerivedRiskContext {
        candidate,
        reasons,
        total_updates,
        red_markers,
        removals_count,
        vendor_changes_count,
        kernel_update: _kernel_update,
        firmware_update: _firmware_update,
        packman_enabled,
        critical_removals_summary,
        red_marked_items_summary,
        critical_removal_gate,
        canonical,
    } = derived;

    let Some(map) = value.as_object_mut() else {
        return payload_json.trim().to_string();
    };

    map.insert(
        "prompt_summary".to_string(),
        json!({
            "counts": {
                "total_updates": total_updates,
                "red_markers": red_markers,
                "removals_count": removals_count,
                "vendor_changes_count": vendor_changes_count
            },
            "canonical_risk": canonical.as_ref().map(|risk| {
                json!({
                    "level": risk.candidate.as_str(),
                    "score_sum": risk.score_sum,
                    "score_max": risk.score_max,
                    "reasons": risk.reasons,
                })
            }),
            "critical_removals": critical_removals_summary,
            "red_markers": red_marked_items_summary,
            "repo_state": {
                "packman_enabled": packman_enabled,
                "vendor_changes_present": vendor_changes_count > 0
            }
        }),
    );
    map.insert(
        "ai_risk_context".to_string(),
        json!({
            "RiskCandidate": candidate.as_str(),
            "RiskReasons": reasons,
            "RiskSource": if canonical.is_some() { "core::risk::assess_risk()" } else { "heuristic-fallback" },
            "CanonicalRisk": canonical.as_ref().map(|risk| {
                json!({
                    "level": risk.candidate.as_str(),
                    "score_sum": risk.score_sum,
                    "score_max": risk.score_max,
                    "reasons": risk.reasons,
                })
            }),
            "counts": {
                "total_updates": total_updates,
                "red_markers": red_markers,
                "removals_count": removals_count,
                "vendor_changes_count": vendor_changes_count
            }
        }),
    );
    map.insert("critical_removal_gate".to_string(), critical_removal_gate);

    let request = map
        .entry("request".to_string())
        .or_insert_with(|| json!({}));
    if let Some(request_map) = request.as_object_mut() {
        append_string_items(
            request_map,
            "constraints",
            &[
                "Canonical transaction risk comes from core::risk::assess_risk(); do not re-derive a lower risk independently.",
                "Risk must equal RiskCandidate unless specific evidence from prompt_summary justifies raising it.",
                "Never lower risk below RiskCandidate.",
                "If you raise risk above RiskCandidate, cite package names from prompt_summary in one action.",
                "If critical_removal_gate.required is true, action 1 must be the Gate action.",
                "If critical_removal_gate.has_unmatched_removals is true, do not recommend proceeding until repos/vendor conflicts are resolved.",
            ],
        );
        append_string_items(
            request_map,
            "include",
            &[
                "prompt_summary: use only these compact counts and package-name summaries",
                "critical_removal_gate: use only the required and unmatched flags",
                "ai_risk_context: respect RiskCandidate, RiskSource, CanonicalRisk, and RiskReasons",
            ],
        );
    }

    serde_json::to_string(&value).unwrap_or_else(|_| payload_json.trim().to_string())
}

fn derive_risk_context(payload: &Value) -> DerivedRiskContext {
    let packages = collect_packages(payload);
    let total_updates = package_count_from_value(payload).unwrap_or(packages.len());
    let canonical = canonical_risk_from_payload(payload);
    let full_removals = packages
        .iter()
        .filter(|pkg| pkg.action == "Remove")
        .collect::<Vec<_>>();
    let critical_removal_guard = build_critical_removal_guard(&packages);
    let critical_removal_names = critical_removal_guard
        .critical_removals
        .iter()
        .map(|entry| entry.package.name.clone())
        .collect::<Vec<_>>();
    let red_marked_items = packages
        .iter()
        .filter(|pkg| is_red_marked_package(pkg))
        .map(|pkg| pkg.name.clone())
        .collect::<Vec<_>>();
    let red_markers = red_marked_items.len();
    let vendor_changes_count = packages.iter().filter(|pkg| is_vendor_change(pkg)).count();
    let kernel_update = packages.iter().any(|pkg| is_kernel_package(&pkg.name));
    let firmware_update = packages.iter().any(|pkg| is_firmware_package(&pkg.name));
    let packman_enabled = payload
        .get("plan_summary")
        .and_then(|v| v.get("has_packman"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || payload
            .get("signals")
            .and_then(|v| v.get("packman_preference_selected"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

    // Risk classification must come from core::risk::assess_risk() when canonical_risk is present.
    // These heuristics are retained only as compact prompt context and compatibility fallback.
    let heuristic = derive_heuristic_risk_context(
        &critical_removal_names,
        red_markers,
        total_updates,
        vendor_changes_count,
        kernel_update,
        firmware_update,
        packman_enabled,
        &critical_removal_guard,
    );

    let (candidate, reasons) = if let Some(canonical) = canonical.as_ref() {
        let mut reasons = canonical.reasons.clone();
        if !critical_removal_guard.unmatched_removals.is_empty() {
            reasons.push(format!(
                "Critical removals without detected replacements: {}",
                critical_removal_guard.unmatched_removals.join(", ")
            ));
        }
        if reasons.is_empty() {
            reasons.push("Canonical core risk engine reported no explicit reasons".to_string());
        }
        (canonical.candidate, reasons)
    } else {
        heuristic
    };

    DerivedRiskContext {
        candidate,
        reasons,
        total_updates,
        red_markers,
        removals_count: full_removals.len(),
        vendor_changes_count,
        kernel_update,
        firmware_update,
        packman_enabled,
        critical_removals_summary: summarize_package_names(&critical_removal_names, 10),
        red_marked_items_summary: summarize_package_names(&red_marked_items, 10),
        critical_removal_gate: critical_removal_gate_json(&critical_removal_guard),
        canonical,
    }
}

fn derive_heuristic_risk_context(
    critical_removal_names: &[String],
    red_markers: usize,
    total_updates: usize,
    vendor_changes_count: usize,
    kernel_update: bool,
    firmware_update: bool,
    packman_enabled: bool,
    critical_removal_guard: &CriticalRemovalGuard,
) -> (RiskCandidate, Vec<String>) {
    let mut candidate = RiskCandidate::Green;
    let mut reasons = Vec::new();

    if !critical_removal_names.is_empty() {
        candidate = RiskCandidate::Red;
        reasons.push(format!(
            "Critical removals detected: {}",
            critical_removal_names.join(", ")
        ));
    }
    if red_markers >= 10 {
        candidate = RiskCandidate::Red;
        reasons.push(format!(
            "{red_markers} red-marked packages detected (threshold: 10)"
        ));
    }
    if total_updates >= 1000 && (kernel_update || firmware_update) {
        if kernel_update && firmware_update {
            candidate = RiskCandidate::Red;
            reasons.push(format!(
                "{total_updates} updates include both kernel and firmware changes"
            ));
        } else {
            candidate = candidate.max(RiskCandidate::Amber);
            reasons.push(format!(
                "{total_updates} updates include {} changes",
                if kernel_update { "kernel" } else { "firmware" }
            ));
        }
    }
    if vendor_changes_count > 0 {
        candidate = candidate.max(RiskCandidate::Amber);
        reasons.push(format!(
            "{vendor_changes_count} vendor change packages detected"
        ));
    }
    if packman_enabled {
        candidate = candidate.max(RiskCandidate::Amber);
        reasons.push("Packman is enabled for this update plan".to_string());
    }
    if !critical_removal_guard.unmatched_removals.is_empty() {
        reasons.push(format!(
            "Critical removals without detected replacements: {}",
            critical_removal_guard.unmatched_removals.join(", ")
        ));
    }
    if reasons.is_empty() {
        reasons.push("No deterministic high-risk rules triggered".to_string());
    }

    (candidate, reasons)
}

fn canonical_risk_from_payload(payload: &Value) -> Option<CanonicalRiskContext> {
    let canonical = payload.get("canonical_risk")?;
    let level = canonical.get("level")?.as_str()?;
    let candidate = normalize_candidate(level)?;
    let score_sum = canonical
        .get("score_sum")
        .and_then(Value::as_i64)
        .map(|n| n.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
        .unwrap_or_default();
    let score_max = canonical
        .get("score_max")
        .and_then(Value::as_i64)
        .map(|n| n.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
        .unwrap_or_default();
    let reasons = canonical
        .get("reasons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    Some(CanonicalRiskContext {
        candidate,
        score_sum,
        score_max,
        reasons,
    })
}

fn normalize_candidate(raw: &str) -> Option<RiskCandidate> {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("high") || lower.contains("red") {
        Some(RiskCandidate::Red)
    } else if lower.contains("medium") || lower.contains("amber") {
        Some(RiskCandidate::Amber)
    } else if lower.contains("low") || lower.contains("green") {
        Some(RiskCandidate::Green)
    } else {
        None
    }
}

fn append_string_items(map: &mut serde_json::Map<String, Value>, key: &str, extras: &[&str]) {
    let values = map
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));

    if let Some(items) = values.as_array_mut() {
        for extra in extras {
            let exists = items
                .iter()
                .any(|item| item.as_str().map(|s| s == *extra).unwrap_or(false));
            if !exists {
                items.push(Value::String((*extra).to_string()));
            }
        }
    }
}

fn collect_packages(payload: &Value) -> Vec<AiPackageSummary> {
    payload
        .get("categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|category| category.get("packages").and_then(Value::as_array))
        .flatten()
        .filter_map(|pkg| {
            let name = pkg.get("name").and_then(Value::as_str)?.trim().to_string();
            if name.is_empty() {
                return None;
            }

            Some(AiPackageSummary {
                name,
                action: pkg
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                vendor: optional_non_empty_string(pkg.get("vendor")),
                kind: optional_non_empty_string(pkg.get("kind")),
            })
        })
        .collect()
}

fn optional_non_empty_string(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn critical_removal_gate_json(guard: &CriticalRemovalGuard) -> Value {
    json!({
        "required": !guard.critical_removals.is_empty(),
        "has_unmatched_removals": !guard.unmatched_removals.is_empty(),
        "critical_removals_count": guard.critical_removals.len(),
        "unmatched_removals_count": guard.unmatched_removals.len(),
    })
}

fn is_red_marked_package(pkg: &AiPackageSummary) -> bool {
    matches!(pkg.action.as_str(), "Remove" | "Downgrade" | "VendorChange")
        || pkg
            .vendor
            .as_deref()
            .map(|vendor| vendor.contains("->"))
            .unwrap_or(false)
        || is_kernel_package(&pkg.name)
}

fn is_vendor_change(pkg: &AiPackageSummary) -> bool {
    pkg.action == "VendorChange"
        || pkg
            .vendor
            .as_deref()
            .map(|vendor| vendor.contains("->"))
            .unwrap_or(false)
}

fn is_kernel_package(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("kernel")
}

fn is_firmware_package(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("firmware")
}

fn is_critical_removal(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    CRITICAL_REMOVAL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn package_count_from_value(value: &Value) -> Option<usize> {
    value
        .get("package_count")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .or_else(|| {
            value
                .get("plan_summary")
                .and_then(|plan| plan.get("total_packages"))
                .and_then(Value::as_u64)
                .map(|count| count as usize)
        })
}

fn critical_removal_guard_from_payload(payload_json: &str) -> Option<CriticalRemovalGuard> {
    let value = serde_json::from_str::<Value>(payload_json).ok()?;
    let packages = collect_packages(&value);
    let guard = build_critical_removal_guard(&packages);
    if guard.critical_removals.is_empty() {
        None
    } else {
        Some(guard)
    }
}

fn build_critical_removal_guard(packages: &[AiPackageSummary]) -> CriticalRemovalGuard {
    let install_candidates = packages
        .iter()
        .filter(|pkg| pkg.action != "Remove")
        .cloned()
        .collect::<Vec<_>>();

    let critical_removals = packages
        .iter()
        .filter(|pkg| pkg.action == "Remove" && is_critical_removal(&pkg.name))
        .cloned()
        .map(|package| {
            let replacements = install_candidates
                .iter()
                .filter(|candidate| looks_like_replacement(&package, candidate))
                .cloned()
                .collect::<Vec<_>>();
            CriticalRemovalMatch {
                package,
                replacements,
            }
        })
        .collect::<Vec<_>>();

    let unmatched_removals = critical_removals
        .iter()
        .filter(|entry| entry.replacements.is_empty())
        .map(|entry| entry.package.name.clone())
        .collect::<Vec<_>>();

    CriticalRemovalGuard {
        critical_removals,
        unmatched_removals,
    }
}

fn looks_like_replacement(removed: &AiPackageSummary, candidate: &AiPackageSummary) -> bool {
    if removed.name.eq_ignore_ascii_case(&candidate.name) {
        return true;
    }

    let removed_family = package_family(&removed.name);
    let candidate_family = package_family(&candidate.name);
    if removed_family == candidate_family {
        return true;
    }

    if capability_stem(&removed.name) == capability_stem(&candidate.name) {
        return true;
    }

    if let (Some(removed_kind), Some(candidate_kind)) =
        (removed.kind.as_deref(), candidate.kind.as_deref())
    {
        if !removed_kind.is_empty()
            && !candidate_kind.is_empty()
            && removed_kind.eq_ignore_ascii_case(candidate_kind)
        {
            return true;
        }
    }

    false
}

fn package_family(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut family = String::new();
    for ch in lower.chars() {
        if matches!(ch, '-' | '_' | '.' | '+') || ch.is_ascii_digit() {
            break;
        }
        family.push(ch);
    }

    if family.is_empty() {
        lower
    } else {
        family
    }
}

fn capability_stem(name: &str) -> String {
    package_family(name).trim_start_matches("lib").to_string()
}

fn summarize_package_names(names: &[String], limit: usize) -> String {
    if names.is_empty() {
        return "none".to_string();
    }

    let shown = names.iter().take(limit).cloned().collect::<Vec<_>>();
    let remaining = names.len().saturating_sub(limit);
    if remaining > 0 {
        format!("{} and {} more", shown.join(", "), remaining)
    } else {
        shown.join(", ")
    }
}

fn enforce_critical_removal_gate(
    assessment: AiAssessment,
    guard: Option<&CriticalRemovalGuard>,
) -> AiAssessment {
    let Some(guard) = guard else {
        return assessment;
    };

    let mut actions = assessment
        .summary
        .lines()
        .map(strip_action_number)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    while actions.len() < 5 {
        actions.push("None.".to_string());
    }
    actions.truncate(5);

    let critical_count = guard.critical_removals.len();

    actions[0] = if guard.unmatched_removals.is_empty() {
        "Gate: Re-run zypper dup --dry-run and confirm every critical removal has a replacement."
            .to_string()
    } else {
        "Gate: Re-run zypper dup --dry-run; unresolved critical removals still need replacements."
            .to_string()
    };
    actions[1] = format!(
        "Review removals list ({} items) - ensure desktop stack remains installable.",
        critical_count
    );

    if !guard.unmatched_removals.is_empty() {
        actions[2] = "Do not proceed; resolve repos/vendor conflicts first.".to_string();
    }

    AiAssessment {
        risk: "Red".to_string(),
        summary: actions
            .into_iter()
            .take(5)
            .enumerate()
            .map(|(idx, action)| format!("{}) {}", idx + 1, action))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn strip_action_number(line: &str) -> String {
    if let Some((_, rest)) = line.split_once(") ") {
        rest.trim().to_string()
    } else {
        line.trim().to_string()
    }
}

#[cfg(test)]
fn normalize_chat_payload(payload_json: &str, default_model: &str) -> String {
    // If it's already a valid-ish chat payload (has messages), just ensure model exists.
    if let Ok(mut v) = serde_json::from_str::<Value>(payload_json) {
        if v.get("messages").is_some() {
            if v.get("model").is_none() {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert(
                        "model".to_string(),
                        Value::String(default_model.to_string()),
                    );
                }
            }
            return serde_json::to_string(&v).unwrap_or_else(|_| payload_json.to_string());
        }
    }

    let user_content = build_ai_user_content(payload_json);

    // NOTE: the commas in `messages` are critical. Missing one causes the exact error you saw.
    let wrapped = json!({
        "model": default_model,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": user_content
            }
        ],
        "temperature": 0.0
    });

    serde_json::to_string(&wrapped).unwrap_or_else(|_| payload_json.to_string())
}

#[cfg(test)]
static CURL_CALL_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_model::ReportModel;
    use crate::report_store::ReportStore;
    use crate::tasks::{create_master_run_with_optional_plan_in_store, UpdateRunSelection};
    use chamrisk_core::ai::{
        AiConnectionConfig, AiConnectionTestResult, AiModelDescriptor, AiProvider, AiProviderKind,
        AiProviderMetadata,
    };
    use chamrisk_core::models::{CommandResult, PackageChange, UpdateAction, UpdatePlan};
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn parses_strict_six_line_assessment() {
        let parsed = parse_assessment(NO_UPDATES_OUTPUT).unwrap();
        assert_eq!(parsed.risk, "Green");
        assert_eq!(
            parsed.summary,
            "1) No updates pending.\n2) None.\n3) None.\n4) None.\n5) None."
        );
    }

    #[test]
    fn chat_payload_uses_resolved_model_without_hard_coded_fallback() {
        let payload = r#"{"package_count":1}"#;

        let wrapped = normalize_chat_payload(payload, "gpt-4.1");
        let value: Value = serde_json::from_str(&wrapped).expect("wrapped payload");

        assert_eq!(value["model"], "gpt-4.1");
    }

    #[derive(Clone)]
    struct FakeProvider {
        kind: AiProviderKind,
        calls: Arc<Mutex<Vec<(String, String, String)>>>,
        response: Result<String, String>,
    }

    impl AiProvider for FakeProvider {
        fn kind(&self) -> AiProviderKind {
            self.kind
        }

        fn metadata(&self) -> AiProviderMetadata {
            AiProviderMetadata {
                kind: self.kind,
                display_name: "Fake".to_string(),
                description: None,
                supports_custom_base_url: false,
                supports_connection_test: true,
            }
        }

        fn connection_config(&self) -> &AiConnectionConfig {
            static CONFIG: std::sync::LazyLock<AiConnectionConfig> =
                std::sync::LazyLock::new(AiConnectionConfig::default);
            &CONFIG
        }

        fn available_models(&self) -> &[AiModelDescriptor] {
            &[]
        }

        fn validate_config(&self) -> Result<(), String> {
            Ok(())
        }

        fn test_connection(
            &self,
            _resolved_api_key: Option<&str>,
        ) -> Result<AiConnectionTestResult, String> {
            Ok(AiConnectionTestResult {
                provider: self.kind,
                success: true,
                latency_ms: None,
                message: "ok".to_string(),
                resolved_model_id: Some("selected-model".to_string()),
            })
        }

        fn list_models(
            &self,
            _resolved_api_key: Option<&str>,
        ) -> Result<Vec<AiModelDescriptor>, String> {
            Ok(Vec::new())
        }

        fn run_triage(
            &self,
            _resolved_api_key: Option<&str>,
            model_id: &str,
            system_prompt: &str,
            user_prompt: &str,
        ) -> Result<String, String> {
            self.calls.lock().expect("calls lock").push((
                model_id.to_string(),
                system_prompt.to_string(),
                user_prompt.to_string(),
            ));
            self.response.clone()
        }
    }

    #[test]
    fn run_provider_triage_routes_to_selected_provider_and_model() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = FakeProvider {
            kind: AiProviderKind::Anthropic,
            calls: calls.clone(),
            response: Ok("Risk: Green\n1) A\n2) B\n3) C\n4) D\n5) E".to_string()),
        };
        let runtime_config = ResolvedAiRuntimeConfig {
            provider_kind: AiProviderKind::Anthropic,
            model_id: "claude-3-7-sonnet-latest".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            api_key: "sk-ant-valid-test-key-1234567890".to_string(),
        };

        let assessment = run_provider_triage(
            Box::new(provider),
            &runtime_config,
            r#"{"package_count":1,"plan_summary":{"total_packages":1}}"#,
        )
        .expect("triage assessment");

        assert_eq!(assessment.risk, "Green");
        let calls = calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "claude-3-7-sonnet-latest");
        assert_eq!(calls[0].1, SYSTEM_PROMPT);
        assert!(calls[0].2.contains("\"package_count\":1"));
    }

    #[test]
    fn run_provider_triage_rejects_provider_kind_mismatch() {
        let provider = FakeProvider {
            kind: AiProviderKind::OpenAi,
            calls: Arc::new(Mutex::new(Vec::new())),
            response: Ok("Risk: Green\n1) A\n2) B\n3) C\n4) D\n5) E".to_string()),
        };
        let runtime_config = ResolvedAiRuntimeConfig {
            provider_kind: AiProviderKind::Anthropic,
            model_id: "claude-3-7-sonnet-latest".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            api_key: "sk-ant-valid-test-key-1234567890".to_string(),
        };

        let err = run_provider_triage(
            Box::new(provider),
            &runtime_config,
            r#"{"package_count":1}"#,
        )
        .expect_err("provider mismatch should fail");

        assert!(err.contains("AI provider mismatch"));
    }

    #[test]
    fn no_updates_short_circuits_before_curl() {
        CURL_CALL_COUNT.store(0, Ordering::SeqCst);
        let (tx, rx) = channel();
        let payload = r#"{"package_count":0,"plan_summary":{"total_packages":0}}"#;
        let run_id = "explicit-run-id".to_string();

        ai_preflight_and_assess("", payload, None, Some(run_id.clone()), tx);

        let first = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let second = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let third = rx.recv_timeout(Duration::from_millis(100)).unwrap();
        let fourth = rx.recv_timeout(Duration::from_millis(100)).unwrap();

        assert_eq!(
            first,
            OpsEvent::Log {
                stream: LogStream::Updates,
                line: format!("INFO: AI triage start run_id={run_id} status=started"),
            }
        );
        assert!(matches!(
            second,
            OpsEvent::Log {
                stream: LogStream::Updates,
                line,
            } if line.contains("INFO: AI triage persistence skipped")
                && line.contains("run_id=explicit-run-id")
                && line.contains("risk=Green")
        ));
        assert_eq!(
            third,
            OpsEvent::Progress(
                "AI_ASSESSMENT:Green|1) No updates pending.\n2) None.\n3) None.\n4) None.\n5) None."
                    .into()
            )
        );
        assert_eq!(fourth, OpsEvent::Progress("AI triage completed".into()));
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert_eq!(CURL_CALL_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn persist_assessment_skips_unknown_and_closed_runs_without_error() {
        let temp = tempdir().expect("tempdir");
        let db_path = temp.path().join("ai-assessment-run-validation.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let assessment = AiAssessment {
            risk: "Amber".to_string(),
            summary: "1) Snapshot first.".to_string(),
        };
        let recommendations = assessment_recommendations(&assessment);

        assert_eq!(
            persist_assessment_for_store(&store, "missing-run", &assessment, &recommendations),
            AssessmentPersistenceOutcome::SkippedNoEligibleRun
        );
        assert!(store
            .load_ai_assessment("missing-run")
            .expect("load missing run ai")
            .is_none());

        let closed_run = store
            .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
            .expect("start run");
        store
            .finish_run(&closed_run, 1_000, "PASS", 0, 0, 0, 0)
            .expect("finish run");

        assert_eq!(
            persist_assessment_for_store(&store, &closed_run, &assessment, &recommendations),
            AssessmentPersistenceOutcome::SkippedNoEligibleRun
        );
        assert!(store
            .load_ai_assessment(&closed_run)
            .expect("load closed run ai")
            .is_none());
    }

    #[test]
    fn persists_successful_assessment_to_explicit_run_id() {
        let temp = tempdir().expect("tempdir");
        let db_path = temp.path().join("ai-assessment-runtime.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");

        let unrelated_run = store
            .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
            .expect("start unrelated run");

        let update_run = store
            .start_run(r#"{"zypper_dup":true}"#, "1.0.0")
            .expect("start update run");
        let assessment = AiAssessment {
            risk: "Amber".to_string(),
            summary: "1) Snapshot first.\n2) Reboot after update.".to_string(),
        };
        let recommendations = assessment_recommendations(&assessment);

        assert_eq!(
            persist_assessment_for_store(&store, &update_run, &assessment, &recommendations),
            AssessmentPersistenceOutcome::Persisted
        );

        let row = store
            .load_ai_assessment(&update_run)
            .expect("load ai assessment")
            .expect("persisted ai assessment");
        assert_eq!(row.risk_level.as_deref(), Some("Amber"));
        assert_eq!(
            row.recommendations_json,
            r#"["1) Snapshot first.","2) Reboot after update."]"#
        );
        assert!(store
            .load_ai_assessment(&unrelated_run)
            .expect("load unrelated run")
            .is_none());

        store
            .finish_run(&update_run, 1_000, "PASS", 0, 0, 0, 0)
            .expect("finish update run");
        store
            .finish_run(&unrelated_run, 1_000, "FAIL", 0, 0, 0, 0)
            .expect("finish unrelated run");

        let model = ReportModel::from_store(&store, &update_run).expect("build report model");
        assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
        assert_eq!(model.ai_recommendations.len(), 2);
        assert_eq!(
            model.ai_recommendations[0].recommendation,
            "Snapshot first."
        );
        assert_eq!(
            model.ai_recommendations[1].recommendation,
            "Reboot after update."
        );
    }

    #[test]
    fn persists_assessment_to_master_run_without_creating_ai_only_root() {
        let temp = tempdir().expect("tempdir");
        let db_path = temp.path().join("ai-assessment-master-run.db");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let selection = UpdateRunSelection::from_flags(true, true, false, false, false);
        let plan = UpdatePlan {
            changes: vec![PackageChange {
                name: "mesa".to_string(),
                arch: Some("x86_64".to_string()),
                action: UpdateAction::Upgrade,
                from: Some("24.0".to_string()),
                to: Some("24.1".to_string()),
                repo: Some("repo-oss".to_string()),
                vendor: Some("openSUSE".to_string()),
                kind: None,
            }],
            command: vec![
                "zypper".to_string(),
                "dup".to_string(),
                "--dry-run".to_string(),
            ],
            result: CommandResult {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        };
        let master_run_id =
            create_master_run_with_optional_plan_in_store(&store, &selection, Some(&plan))
                .expect("create master run");
        let assessment = AiAssessment {
            risk: "Amber".to_string(),
            summary: "1) Snapshot first.\n2) Reboot after update.".to_string(),
        };
        let recommendations = assessment_recommendations(&assessment);

        assert_eq!(
            persist_assessment_for_store(&store, &master_run_id, &assessment, &recommendations),
            AssessmentPersistenceOutcome::Persisted
        );

        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, master_run_id);
        let row = store
            .load_ai_assessment(&master_run_id)
            .expect("load ai assessment")
            .expect("persisted ai assessment");
        assert_eq!(row.run_id, master_run_id);
    }

    #[test]
    fn persistence_logging_keeps_real_failures_as_errors() {
        let (tx, rx) = channel();

        log_assessment_persistence(
            &tx,
            "eligible-run",
            "Amber",
            AssessmentPersistenceOutcome::Failed("sqlite busy".to_string()),
        );

        assert_eq!(
            rx.recv_timeout(Duration::from_millis(100)).unwrap(),
            OpsEvent::Log {
                stream: LogStream::Updates,
                line: "ERROR: AI triage persist run_id=eligible-run risk=Amber status=failed error=sqlite busy".to_string(),
            }
        );
    }

    #[test]
    fn skipped_persistence_does_not_emit_structured_ai_event() {
        let (tx, rx) = channel();
        let assessment = AiAssessment {
            risk: "Green".to_string(),
            summary: "1) No updates pending.".to_string(),
        };

        emit_assessment(&tx, Some("closed-or-missing-run"), &assessment);

        let events: Vec<_> = rx.try_iter().collect();
        assert!(events.iter().any(|event| matches!(
            event,
            OpsEvent::Log {
                stream: LogStream::Updates,
                line,
            } if line.contains("INFO: AI triage persistence skipped")
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            OpsEvent::Progress(line) if line.starts_with("AI_ASSESSMENT:Green|")
        )));
        assert!(!events.iter().any(|event| matches!(
            event,
            OpsEvent::Structured(StructuredOpsEvent {
                kind: OpsEventKind::AIAnalysis { .. },
                ..
            })
        )));
    }

    #[test]
    fn derives_red_risk_for_critical_removals() {
        let payload = json!({
            "package_count": 2,
            "plan_summary": {
                "total_packages": 2,
                "has_packman": false
            },
            "signals": {
                "packman_preference_selected": false
            },
            "categories": [
                {
                    "category": "Core System",
                    "count": 2,
                    "packages": [
                        {
                            "name": "glibc",
                            "action": "Remove",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        },
                        {
                            "name": "bash",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        }
                    ]
                }
            ]
        });

        let derived = derive_risk_context(&payload);

        assert_eq!(derived.candidate, RiskCandidate::Red);
        assert!(derived.canonical.is_none());
        assert!(derived
            .reasons
            .iter()
            .any(|reason| reason.contains("Critical removals detected: glibc")));
        assert_eq!(derived.removals_count, 1);
        assert_eq!(derived.critical_removals_summary, "glibc");
        assert_eq!(derived.red_marked_items_summary, "glibc");
        assert_eq!(
            derived.critical_removal_gate["has_unmatched_removals"],
            Value::Bool(true)
        );
    }

    #[test]
    fn canonical_risk_overrides_heuristic_candidate() {
        let payload = json!({
            "package_count": 1,
            "plan_summary": {
                "total_packages": 1,
                "has_packman": false
            },
            "canonical_risk": {
                "level": "Medium",
                "score_sum": 8,
                "score_max": 8,
                "reasons": ["tx systemd-family upgrade touches core init/session plumbing"]
            },
            "categories": [
                {
                    "category": "Core System",
                    "count": 1,
                    "packages": [
                        {
                            "name": "systemd",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        }
                    ]
                }
            ]
        });

        let derived = derive_risk_context(&payload);

        assert_eq!(derived.candidate, RiskCandidate::Amber);
        assert_eq!(derived.canonical.as_ref().unwrap().score_sum, 8);
        assert_eq!(derived.canonical.as_ref().unwrap().score_max, 8);
        assert!(derived
            .reasons
            .iter()
            .any(|reason| reason.contains("systemd-family upgrade")));
        assert!(derived.red_marked_items_summary == "none");
    }

    #[test]
    fn build_ai_user_content_exposes_canonical_risk_context() {
        let payload = json!({
            "package_count": 1,
            "plan_summary": {
                "total_packages": 1,
                "has_packman": false
            },
            "canonical_risk": {
                "level": "High",
                "score_sum": 15,
                "score_max": 10,
                "reasons": ["tx systemd-family + kernel transaction can affect boot and userspace together"]
            },
            "categories": [
                {
                    "category": "Core System",
                    "count": 1,
                    "packages": [
                        {
                            "name": "kernel-default",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        }
                    ]
                }
            ]
        });

        let content = build_ai_user_content(&payload.to_string());
        let enriched: Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            enriched["ai_risk_context"]["RiskSource"],
            Value::String("core::risk::assess_risk()".to_string())
        );
        assert_eq!(
            enriched["ai_risk_context"]["RiskCandidate"],
            Value::String("Red".to_string())
        );
        assert_eq!(
            enriched["prompt_summary"]["canonical_risk"]["score_max"],
            Value::from(10)
        );
        assert_eq!(
            enriched["prompt_summary"]["canonical_risk"]["reasons"][0],
            Value::String(
                "tx systemd-family + kernel transaction can affect boot and userspace together"
                    .to_string()
            )
        );
    }

    #[test]
    fn canonical_risk_prevents_heuristic_override_when_signals_disagree() {
        let payload = json!({
            "package_count": 1,
            "plan_summary": {
                "total_packages": 1,
                "has_packman": true
            },
            "signals": {
                "packman_preference_selected": true
            },
            "canonical_risk": {
                "level": "Low",
                "score_sum": 3,
                "score_max": 3,
                "reasons": ["pkg nano [1.0.0 → 1.0.1] (upgrade)"]
            },
            "categories": [
                {
                    "category": "Editors",
                    "count": 1,
                    "packages": [
                        {
                            "name": "nano",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE -> packman"
                        }
                    ]
                }
            ]
        });

        let derived = derive_risk_context(&payload);

        // Legacy heuristics remain as secondary prompt context, but they must not override
        // canonical_risk once the core engine has classified the transaction.
        assert_eq!(derived.candidate, RiskCandidate::Green);
        assert_eq!(
            derived.canonical.as_ref().unwrap().candidate,
            RiskCandidate::Green
        );
        assert!(derived
            .reasons
            .iter()
            .any(|reason| reason.contains("pkg nano")));
        assert!(!derived
            .reasons
            .iter()
            .any(|reason| reason.contains("vendor change packages detected")));
    }

    #[test]
    fn canonical_systemd_upgrade_is_at_least_medium_in_ai_context() {
        let payload = json!({
            "package_count": 1,
            "plan_summary": {
                "total_packages": 1,
                "has_packman": false
            },
            "canonical_risk": {
                "level": "Medium",
                "score_sum": 8,
                "score_max": 8,
                "reasons": ["tx systemd-family upgrade touches core init/session plumbing"]
            },
            "categories": [
                {
                    "category": "Core System",
                    "count": 1,
                    "packages": [
                        {
                            "name": "systemd",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        }
                    ]
                }
            ]
        });

        let enriched: Value =
            serde_json::from_str(&build_ai_user_content(&payload.to_string())).unwrap();

        assert_eq!(
            enriched["ai_risk_context"]["RiskCandidate"],
            Value::String("Amber".to_string())
        );
        assert_eq!(
            enriched["ai_risk_context"]["CanonicalRisk"]["level"],
            Value::String("Amber".to_string())
        );
    }

    #[test]
    fn canonical_systemd_and_kernel_transaction_is_high_in_ai_context() {
        let payload = json!({
            "package_count": 2,
            "plan_summary": {
                "total_packages": 2,
                "has_packman": false
            },
            "canonical_risk": {
                "level": "High",
                "score_sum": 15,
                "score_max": 10,
                "reasons": ["tx systemd-family + kernel transaction can affect boot and userspace together"]
            },
            "categories": [
                {
                    "category": "Core System",
                    "count": 2,
                    "packages": [
                        {
                            "name": "systemd",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        },
                        {
                            "name": "kernel-default",
                            "action": "Upgrade",
                            "repo": "repo-oss",
                            "vendor": "openSUSE"
                        }
                    ]
                }
            ]
        });

        let enriched: Value =
            serde_json::from_str(&build_ai_user_content(&payload.to_string())).unwrap();

        assert_eq!(
            enriched["ai_risk_context"]["RiskCandidate"],
            Value::String("Red".to_string())
        );
        assert_eq!(
            enriched["prompt_summary"]["canonical_risk"]["level"],
            Value::String("Red".to_string())
        );
    }

    #[test]
    fn critical_removal_gate_detects_replacement_by_family() {
        let packages = vec![
            AiPackageSummary {
                name: "glibc".to_string(),
                action: "Remove".to_string(),
                vendor: Some("openSUSE".to_string()),
                kind: Some("package".to_string()),
            },
            AiPackageSummary {
                name: "glibc-locale".to_string(),
                action: "Install".to_string(),
                vendor: Some("openSUSE".to_string()),
                kind: Some("package".to_string()),
            },
        ];

        let guard = build_critical_removal_guard(&packages);

        assert_eq!(guard.critical_removals.len(), 1);
        assert_eq!(guard.unmatched_removals.len(), 0);
        assert_eq!(
            guard.critical_removals[0].replacements[0].name,
            "glibc-locale"
        );
    }

    #[test]
    fn enforce_gate_adds_stop_action_for_unmatched_critical_removals() {
        let assessment = AiAssessment {
            risk: "Amber".to_string(),
            summary: "1) Proceed with caution.\n2) Reboot after update.\n3) Test login.\n4) Test audio.\n5) Check logs.".to_string(),
        };
        let guard = CriticalRemovalGuard {
            critical_removals: vec![CriticalRemovalMatch {
                package: AiPackageSummary {
                    name: "glibc".to_string(),
                    action: "Remove".to_string(),
                    vendor: Some("openSUSE".to_string()),
                    kind: Some("package".to_string()),
                },
                replacements: Vec::new(),
            }],
            unmatched_removals: vec!["glibc".to_string()],
        };

        let enforced = enforce_critical_removal_gate(assessment, Some(&guard));

        assert_eq!(enforced.risk, "Red");
        assert!(enforced.summary.contains(
            "1) Gate: Re-run zypper dup --dry-run; unresolved critical removals still need replacements."
        ));
        assert!(enforced.summary.contains(
            "2) Review removals list (1 items) - ensure desktop stack remains installable."
        ));
        assert!(enforced
            .summary
            .contains("3) Do not proceed; resolve repos/vendor conflicts first."));
    }
}
