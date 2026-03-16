use crate::health::SystemInfo;
use crate::report_model::{ReportModel, ReportSystemInfo};
use chrono::{Local, TimeZone};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub fn render_odt(
    model: &ReportModel,
    template_path: &Path,
    output_path: &Path,
    system_info: Option<&SystemInfo>,
) -> Result<(), String> {
    let temp = tempdir().map_err(|err| format!("failed to create temp dir: {err}"))?;
    let unzip_dir = temp.path().join("template");
    fs::create_dir_all(&unzip_dir)
        .map_err(|err| format!("failed to create unzip dir {}: {err}", unzip_dir.display()))?;

    unzip_template(template_path, &unzip_dir)?;

    let content_path = unzip_dir.join("content.xml");
    let content = fs::read_to_string(&content_path)
        .map_err(|err| format!("failed to read {}: {err}", content_path.display()))?;
    let report_body = build_report_body(model, system_info);
    let rendered = inject_report_body(&content, &report_body);

    fs::write(&content_path, rendered)
        .map_err(|err| format!("failed to write {}: {err}", content_path.display()))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create output dir {}: {err}", parent.display()))?;
    }

    zip_dir(&unzip_dir, output_path)
}

fn build_report_body(model: &ReportModel, system_info: Option<&SystemInfo>) -> String {
    let mut body = String::new();
    body.push_str(&build_executive_summary_section(model));
    body.push_str(&build_system_context_section(model, system_info));
    body.push_str(&build_change_summary_section(model));
    body.push_str(&build_ai_assessment_section(model));
    body.push_str(&build_execution_validation_section(model));
    if let Some(section) = build_detailed_evidence_section(model) {
        body.push_str(&section);
    }
    body
}

fn inject_report_body(content: &str, report_body: &str) -> String {
    if content.contains("{{REPORT_BODY}}") {
        return content.replace("{{REPORT_BODY}}", report_body);
    }

    let stripped = strip_legacy_placeholders(content);
    let insert_at = stripped.find("</office:text>").unwrap_or(stripped.len());

    let mut rendered = String::with_capacity(stripped.len() + report_body.len());
    rendered.push_str(&stripped[..insert_at]);
    rendered.push_str(report_body);
    rendered.push_str(&stripped[insert_at..]);
    rendered
}

fn strip_legacy_placeholders(content: &str) -> String {
    let mut rendered = content.to_string();
    for pattern in [
        "<text:p>{{RUN_ID}}</text:p>",
        "<text:p>{{STARTED_AT}}</text:p>",
        "<text:p>{{ENDED_AT}}</text:p>",
        "<text:p>Notes: {{SELECTION_NOTES}}</text:p>",
        "<text:p>AI Risk: {{AI_RISK}}</text:p>",
        "<text:p>AI Recommendations: {{AI_RECOMMENDATIONS}}</text:p>",
        "<text:p>{{VERDICT}}</text:p>",
        "<text:p>{{RECONCILIATION}}</text:p>",
        "{{SELECTION_TABLE}}",
        "{{PACKAGE_TABLE}}",
        "{{FLATPAK_TABLE}}",
        "{{LOG_TABLE}}",
        "{{SYSTEM_SECTION}}",
        "{{REPORT_BODY}}",
    ] {
        rendered = rendered.replace(pattern, "");
    }
    rendered
}

fn build_executive_summary_section(model: &ReportModel) -> String {
    let mut rows = vec![
        ("Update Risk", display_optional(model.ai_risk.as_deref())),
        ("Execution Result", model.execution_result.clone()),
        (
            "Reconciliation Result",
            model.reconciliation.verdict.clone(),
        ),
        ("Start Time", format_ts(model.header.started_at_ms)),
        (
            "End Time",
            model
                .header
                .ended_at_ms
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Duration",
            format_duration(model.header.started_at_ms, model.header.ended_at_ms),
        ),
        ("Run ID", model.header.run_id.clone()),
        (
            "Update Type",
            display_optional(model.update_type.as_deref()),
        ),
        (
            "Snapshot Status",
            display_optional(model.snapshot_status.as_deref()),
        ),
        (
            "Reboot Likely/Required",
            display_optional(model.reboot_status.as_deref()),
        ),
    ];

    if let Some(package_summary) = model.package_summary.as_ref() {
        rows.push(("Packages in Scope", package_summary.total_count.to_string()));
        if let Some(summary) = package_summary.risk_counts.summary_text() {
            rows.push(("Risk Mix", summary));
        }
        if let Some(summary) =
            crate::report_model::CountMetric::summary_text(&package_summary.action_counts)
        {
            rows.push(("Actions", summary));
        }
        if !package_summary.high_risk_packages.is_empty() {
            rows.push((
                "High-Risk Packages",
                package_summary.high_risk_packages.join(", "),
            ));
        }
    }

    section_with_table(
        "Executive Summary",
        &["Field", "Value"],
        &rows
            .iter()
            .map(|(label, value)| vec![(*label).to_string(), value.clone()])
            .collect::<Vec<_>>(),
    )
}

fn build_system_context_section(model: &ReportModel, system_info: Option<&SystemInfo>) -> String {
    let info = ReportSystemInfo::from_system_info(system_info);
    let rows = vec![
        vec!["OS".to_string(), info.os],
        vec!["Kernel".to_string(), info.kernel],
        vec!["Architecture".to_string(), info.architecture],
        vec!["CPU".to_string(), info.cpu],
        vec!["Memory".to_string(), info.memory],
        vec!["Uptime".to_string(), info.uptime],
        vec!["Run ID".to_string(), model.header.run_id.clone()],
        vec!["Started".to_string(), format_ts(model.header.started_at_ms)],
        vec![
            "Ended".to_string(),
            model
                .header
                .ended_at_ms
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string()),
        ],
        vec!["App Version".to_string(), model.header.app_version.clone()],
    ];

    section_with_table("System Context", &["Property", "Value"], &rows)
}

fn build_change_summary_section(model: &ReportModel) -> String {
    let rows = model
        .change_summary
        .rows()
        .into_iter()
        .map(|row| vec![row.label, row.value, row.note])
        .collect::<Vec<_>>();

    section_with_table("Change Summary", &["Item", "Value", "Note"], &rows)
}

fn build_ai_assessment_section(model: &ReportModel) -> String {
    let mut section = section_heading("AI Assessment");
    section.push_str(&paragraph(&format!(
        "Risk Level: {}",
        display_optional(model.ai_risk.as_deref())
    )));

    if model.ai_recommendations.is_empty() {
        section.push_str(&paragraph("Recommendations: Not available"));
    } else if model.ai_recommendations.iter().all(|item| {
        item.reason
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
    }) {
        section.push_str(&paragraph("Recommendations"));
        for item in &model.ai_recommendations {
            section.push_str(&paragraph(&format!(
                "{}. {}",
                item.step, item.recommendation
            )));
        }
    } else {
        let rows = model
            .ai_recommendations
            .iter()
            .map(|item| {
                vec![
                    item.step.clone(),
                    item.recommendation.clone(),
                    item.reason.clone().unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>();
        section.push_str(&build_table(
            "AI Recommendations",
            &["Step", "Recommendation", "Reason"],
            &rows,
        ));
    }

    section
}

fn build_execution_validation_section(model: &ReportModel) -> String {
    let mut rows = vec![
        vec![
            "Execution Result".to_string(),
            model.execution_result.clone(),
        ],
        vec![
            "Reconciliation Result".to_string(),
            model.reconciliation.verdict.clone(),
        ],
        vec![
            "Attempted".to_string(),
            model.reconciliation.attempted.to_string(),
        ],
        vec![
            "Installed".to_string(),
            model.reconciliation.installed.to_string(),
        ],
        vec![
            "Failed".to_string(),
            model.reconciliation.failed.to_string(),
        ],
        vec![
            "Unaccounted".to_string(),
            model.reconciliation.unaccounted.to_string(),
        ],
    ];

    if !model.validation_notes.is_empty() {
        rows.push(vec![
            "Post-check Outcomes".to_string(),
            model.validation_notes.join(" "),
        ]);
    }

    section_with_table("Execution and Validation", &["Field", "Value"], &rows)
}

fn build_detailed_evidence_section(model: &ReportModel) -> Option<String> {
    let mut section = section_heading("Detailed Evidence");
    let mut evidence_sections = 0usize;

    if !model.package_evidence.is_empty() {
        evidence_sections += 1;
        section.push_str(&subsection_heading("Packages"));
        section.push_str(&build_package_evidence_table(model));
    }
    if !model.flatpak_rows.is_empty() {
        evidence_sections += 1;
        section.push_str(&subsection_heading("Flatpak"));
        section.push_str(&build_flatpak_table(model));
    }
    if !model.log_entries.is_empty() {
        evidence_sections += 1;
        section.push_str(&subsection_heading("Log Excerpt"));
        section.push_str(&build_log_table(model));
    }

    if evidence_sections == 0 {
        None
    } else {
        Some(section)
    }
}

fn section_with_table(title: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut section = section_heading(title);
    section.push_str(&build_table(title, headers, rows));
    section
}

fn section_heading(title: &str) -> String {
    format!(
        "<text:h text:outline-level=\"2\">{}</text:h>",
        xml_escape(title)
    )
}

fn subsection_heading(title: &str) -> String {
    format!(
        "<text:h text:outline-level=\"3\">{}</text:h>",
        xml_escape(title)
    )
}

fn paragraph(text: &str) -> String {
    format!("<text:p>{}</text:p>", xml_escape(text))
}

fn build_table(name: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut table_rows = String::new();
    table_rows.push_str(&table_row(headers));
    for row in rows {
        let cells = row.iter().map(String::as_str).collect::<Vec<_>>();
        table_rows.push_str(&table_row(&cells));
    }
    wrap_table(name, headers.len(), &table_rows)
}

fn unzip_template(template_path: &Path, dest_dir: &Path) -> Result<(), String> {
    let file = fs::File::open(template_path)
        .map_err(|err| format!("failed to open template {}: {err}", template_path.display()))?;
    let mut archive =
        ZipArchive::new(file).map_err(|err| format!("failed to open odt archive: {err}"))?;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| format!("failed to read archive entry {index}: {err}"))?;
        let out_path = sanitize_join(dest_dir, entry.name())?;

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|err| format!("failed to create dir {}: {err}", out_path.display()))?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create dir {}: {err}", parent.display()))?;
        }

        let mut out_file = fs::File::create(&out_path)
            .map_err(|err| format!("failed to create {}: {err}", out_path.display()))?;
        std::io::copy(&mut entry, &mut out_file)
            .map_err(|err| format!("failed to extract {}: {err}", out_path.display()))?;
    }

    Ok(())
}

fn zip_dir(source_dir: &Path, output_path: &Path) -> Result<(), String> {
    let file = fs::File::create(output_path)
        .map_err(|err| format!("failed to create output {}: {err}", output_path.display()))?;
    let mut writer = ZipWriter::new(file);

    let mimetype_path = source_dir.join("mimetype");
    if mimetype_path.exists() {
        let bytes = fs::read(&mimetype_path)
            .map_err(|err| format!("failed to read {}: {err}", mimetype_path.display()))?;
        writer
            .start_file(
                "mimetype",
                FileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .map_err(|err| format!("failed to start mimetype entry: {err}"))?;
        writer
            .write_all(&bytes)
            .map_err(|err| format!("failed to write mimetype entry: {err}"))?;
    }

    let mut stack = vec![source_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|err| format!("failed to read dir {}: {err}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to list dir {}: {err}", dir.display()))?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            let rel = path
                .strip_prefix(source_dir)
                .map_err(|err| format!("failed to strip prefix: {err}"))?;
            let name = rel
                .to_str()
                .ok_or_else(|| format!("non-utf8 archive path: {}", rel.display()))?
                .replace('\\', "/");

            if name == "mimetype" {
                continue;
            }

            if path.is_dir() {
                writer
                    .add_directory(
                        format!("{name}/"),
                        FileOptions::default().compression_method(CompressionMethod::Deflated),
                    )
                    .map_err(|err| format!("failed to add directory {name}: {err}"))?;
                stack.push(path);
                continue;
            }

            let mut input = fs::File::open(&path)
                .map_err(|err| format!("failed to open {}: {err}", path.display()))?;
            let mut bytes = Vec::new();
            input
                .read_to_end(&mut bytes)
                .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
            writer
                .start_file(
                    name,
                    FileOptions::default().compression_method(CompressionMethod::Deflated),
                )
                .map_err(|err| format!("failed to add file {}: {err}", path.display()))?;
            writer
                .write_all(&bytes)
                .map_err(|err| format!("failed to write file {}: {err}", path.display()))?;
        }
    }

    writer
        .finish()
        .map_err(|err| format!("failed to finish odt archive: {err}"))?;
    Ok(())
}

fn sanitize_join(base: &Path, name: &str) -> Result<PathBuf, String> {
    let joined = base.join(name);
    let normalized = joined
        .components()
        .fold(PathBuf::new(), |mut acc, component| {
            use std::path::Component;
            match component {
                Component::Prefix(prefix) => acc.push(prefix.as_os_str()),
                Component::RootDir => acc.push(Path::new("/")),
                Component::CurDir => {}
                Component::ParentDir => {
                    acc.pop();
                }
                Component::Normal(part) => acc.push(part),
            }
            acc
        });

    if !normalized.starts_with(base) {
        return Err(format!("archive entry escapes destination: {name}"));
    }
    Ok(normalized)
}

fn build_package_evidence_table(model: &ReportModel) -> String {
    let rows = model
        .package_evidence
        .iter()
        .map(|row| {
            vec![
                row.package_name.clone(),
                row.from_version.clone().unwrap_or_default(),
                row.to_version.clone().unwrap_or_default(),
                row.arch.clone().unwrap_or_default(),
                row.repository.clone().unwrap_or_default(),
                row.action.clone().unwrap_or_default(),
                row.result.clone().unwrap_or_default(),
                row.risk.clone().unwrap_or_default(),
            ]
        })
        .collect::<Vec<_>>();
    build_table(
        "Packages",
        &[
            "Package",
            "From",
            "To",
            "Arch",
            "Repository",
            "Action",
            "Result",
            "Risk",
        ],
        &rows,
    )
}

fn build_log_table(model: &ReportModel) -> String {
    let rows = model
        .log_entries
        .iter()
        .map(|entry| {
            vec![
                format_ts(entry.ts_ms),
                entry.severity.clone(),
                entry.phase.clone(),
                entry.event_type.clone(),
                log_message(entry).to_string(),
            ]
        })
        .collect::<Vec<_>>();
    build_table(
        "Log",
        &["Timestamp", "Severity", "Phase", "Type", "Message"],
        &rows,
    )
}

fn log_message(entry: &crate::report_model::ReportLogEntry) -> &str {
    entry.message.as_str()
}

fn build_flatpak_table(model: &ReportModel) -> String {
    let rows = model
        .flatpak_rows
        .iter()
        .map(|row| {
            vec![
                row.app_id.clone(),
                row.status.clone(),
                row.from_version.clone().unwrap_or_default(),
                row.to_version.clone().unwrap_or_default(),
                row.origin.clone().unwrap_or_default(),
                row.message.clone(),
            ]
        })
        .collect::<Vec<_>>();
    build_table(
        "Flatpak",
        &["App ID", "Status", "From", "To", "Origin", "Message"],
        &rows,
    )
}

fn wrap_table(name: &str, column_count: usize, rows: &str) -> String {
    format!(
        "<table:table table:name=\"{name}\"><table:table-column table:number-columns-repeated=\"{column_count}\"/>{rows}</table:table>",
        name = xml_escape(name),
        column_count = column_count,
        rows = rows
    )
}

fn table_row(cells: &[&str]) -> String {
    let cells = cells
        .iter()
        .map(|cell| {
            format!(
                "<table:table-cell office:value-type=\"string\"><text:p>{}</text:p></table:table-cell>",
                xml_escape(cell)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<table:table-row>{cells}</table:table-row>")
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn format_ts(ts_ms: i64) -> String {
    Local
        .timestamp_millis_opt(ts_ms)
        .single()
        .map(|ts| ts.format("%Y-%m-%d %H:%M:%S%.3f %Z").to_string())
        .unwrap_or_else(|| ts_ms.to_string())
}

fn display_optional(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Not available")
        .to_string()
}

fn format_duration(started_at_ms: i64, ended_at_ms: Option<i64>) -> String {
    let Some(ended_at_ms) = ended_at_ms else {
        return "-".to_string();
    };
    if ended_at_ms <= started_at_ms {
        return "0s".to_string();
    }

    let total_seconds = (ended_at_ms - started_at_ms) / 1000;
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;

    if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
