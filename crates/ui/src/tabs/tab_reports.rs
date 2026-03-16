use crate::{packages_table, MaintenanceApp, Risk, Row};
use chamrisk_ops::report_export::render_odt;
use chamrisk_ops::report_model::ReportModel;
use chamrisk_ops::report_store::ReportStore;
use chamrisk_ops::report_store::{EventRow, PackageEvidenceRow};
use chrono::{Local, TimeZone};
use eframe::egui;
use egui::{Align, Layout, TextStyle};
use egui_extras::{Column, TableBuilder};
use rfd::FileDialog;
use std::fs;
use std::path::{Path, PathBuf};

pub fn ui(app: &mut MaintenanceApp, _ctx: &egui::Context, ui: &mut egui::Ui) {
    const SECTION_GAP: f32 = 10.0;
    const MIN_TOP_HEIGHT: f32 = 140.0;
    const MAX_TOP_HEIGHT: f32 = 320.0;
    const IDEAL_TOP_HEIGHT: f32 = 220.0;
    const IDEAL_STACKED_TOP_HEIGHT: f32 = 360.0;
    const MIN_PACKAGE_HEIGHT: f32 = 140.0;
    const MIN_WIDE_PANE_WIDTH: f32 = 300.0;

    app.ensure_history_loaded();

    ui.heading("Reports");
    let available_for_group = ui.available_height().max(0.0);

    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), available_for_group),
        Layout::top_down(Align::Min),
        |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_height(available_for_group);
                ui.horizontal(|ui| {
                    ui.heading("History");
                    if ui.button("Refresh").clicked() {
                        app.refresh_history();
                    }
                    ui.add_space(12.0);
                    let can_export = app.history_selected_run_id.is_some();
                    if ui
                        .add_enabled(can_export, egui::Button::new("Export Report (.odt)"))
                        .clicked()
                    {
                        export_selected_report(app);
                    }
                    if ui.button("Export Log").clicked() {
                        export_updates_log(app);
                    }
                });

                if let Some(status) = &app.history_status {
                    ui.label(status);
                }

                ui.add_space(8.0);
                let content_size =
                    egui::vec2(ui.available_width().max(0.0), ui.available_height().max(0.0));
                ui.allocate_ui_with_layout(content_size, Layout::top_down(Align::Min), |ui| {
                    let content_width = content_size.x;
                    let content_height = content_size.y;
                    let can_use_wide_top_band =
                        content_width >= (MIN_WIDE_PANE_WIDTH * 2.0) + 12.0;

                    if can_use_wide_top_band {
                        let top_available = (content_height - SECTION_GAP - MIN_PACKAGE_HEIGHT)
                            .max(0.0);
                        let top_band_height = if top_available >= MIN_TOP_HEIGHT {
                            IDEAL_TOP_HEIGHT.clamp(MIN_TOP_HEIGHT, top_available.min(MAX_TOP_HEIGHT))
                        } else {
                            top_available
                        };
                        let pane_width = ((content_width - 12.0) / 2.0).max(0.0);

                        ui.allocate_ui_with_layout(
                            egui::vec2(content_width, top_band_height),
                            Layout::top_down(Align::Min),
                            |ui| {
                                ui.horizontal_top(|ui| {
                                    let top_pane_size = egui::vec2(pane_width, top_band_height);
                                    ui.allocate_ui_with_layout(
                                        top_pane_size,
                                        Layout::top_down(Align::Min),
                                        |ui| {
                                            render_history_runs_table(ui, app, top_pane_size);
                                        },
                                    );
                                    ui.add_space(12.0);
                                    ui.allocate_ui_with_layout(
                                        top_pane_size,
                                        Layout::top_down(Align::Min),
                                        |ui| {
                                            render_history_events_table(
                                                ui,
                                                &app.history_events,
                                                top_pane_size,
                                            );
                                        },
                                    );
                                });
                            },
                        );

                        ui.add_space(SECTION_GAP);
                        let package_height = ui.available_height().max(MIN_PACKAGE_HEIGHT);
                        render_history_packages_table(
                            ui,
                            app,
                            egui::vec2(content_width, package_height),
                        );
                    } else {
                        let stacked_gap = 8.0;
                        let top_available = (content_height
                            - SECTION_GAP
                            - MIN_PACKAGE_HEIGHT
                            - stacked_gap)
                            .max(0.0);
                        let top_band_height = if top_available >= (MIN_TOP_HEIGHT * 2.0) {
                            IDEAL_STACKED_TOP_HEIGHT.clamp(
                                MIN_TOP_HEIGHT * 2.0,
                                top_available.min(MAX_TOP_HEIGHT * 2.0 + stacked_gap),
                            )
                        } else {
                            top_available
                        };
                        let top_pane_height =
                            ((top_band_height - stacked_gap).max(0.0) / 2.0).max(0.0);
                        let top_pane_size = egui::vec2(content_width, top_pane_height);

                        ui.allocate_ui_with_layout(
                            egui::vec2(content_width, top_band_height),
                            Layout::top_down(Align::Min),
                            |ui| {
                                ui.allocate_ui_with_layout(
                                    top_pane_size,
                                    Layout::top_down(Align::Min),
                                    |ui| {
                                        render_history_runs_table(ui, app, top_pane_size);
                                    },
                                );
                                ui.add_space(stacked_gap);
                                ui.allocate_ui_with_layout(
                                    top_pane_size,
                                    Layout::top_down(Align::Min),
                                    |ui| {
                                        render_history_events_table(
                                            ui,
                                            &app.history_events,
                                            top_pane_size,
                                        );
                                    },
                                );
                            },
                        );

                        ui.add_space(SECTION_GAP);
                        let package_height = ui.available_height().max(MIN_PACKAGE_HEIGHT);
                        render_history_packages_table(
                            ui,
                            app,
                            egui::vec2(content_width, package_height),
                        );
                    }
                });
            });
        },
    );

    if let Some(status) = &app.export_status {
        ui.label(status);
    }
}

fn render_history_runs_table(ui: &mut egui::Ui, app: &mut MaintenanceApp, pane_size: egui::Vec2) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(pane_size.x);
        ui.set_height(pane_size.y);
        ui.label(egui::RichText::new("History").strong());
        ui.add_space(4.0);
        let row_height = ui.text_style_height(&TextStyle::Body) + 8.0;
        let height = ui.available_height().max(0.0);
        let mut clicked_run_id: Option<String> = None;

        ui.push_id("reports_history_runs_table", |ui| {
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .vscroll(true)
                .min_scrolled_height(height)
                .max_scroll_height(height)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::exact(170.0))
                .column(Column::exact(170.0))
                .column(Column::exact(70.0))
                .column(Column::exact(42.0))
                .column(Column::exact(42.0))
                .column(Column::exact(42.0))
                .column(Column::remainder())
                .header(row_height, |mut header| {
                    header.col(|ui| {
                        ui.strong("Started");
                    });
                    header.col(|ui| {
                        ui.strong("Ended");
                    });
                    header.col(|ui| {
                        ui.strong("Verdict");
                    });
                    header.col(|ui| {
                        ui.strong("A");
                    });
                    header.col(|ui| {
                        ui.strong("I");
                    });
                    header.col(|ui| {
                        ui.strong("F");
                    });
                    header.col(|ui| {
                        ui.strong("U");
                    });
                })
                .body(|mut body| {
                    for run in &app.history_runs {
                        let selected =
                            app.history_selected_run_id.as_deref() == Some(run.run_id.as_str());
                        body.row(row_height, |mut row| {
                            row.col(|ui| {
                                let text = if selected {
                                    egui::RichText::new(format_ts(run.started_at_ms))
                                        .color(egui::Color32::BLACK)
                                        .strong()
                                } else {
                                    egui::RichText::new(format_ts(run.started_at_ms))
                                };
                                let mut button = egui::Button::new(text)
                                    .frame(false)
                                    .min_size(egui::vec2(ui.available_width(), row_height));
                                if selected {
                                    button = button.fill(ui.visuals().selection.bg_fill);
                                }
                                if ui.add(button).clicked() {
                                    clicked_run_id = Some(run.run_id.clone());
                                }
                            });
                            row.col(|ui| {
                                ui.label(
                                    run.ended_at_ms
                                        .map(format_ts)
                                        .unwrap_or_else(|| "-".to_string()),
                                );
                            });
                            row.col(|ui| {
                                ui.label(run.verdict.as_deref().unwrap_or("RUN"));
                            });
                            row.col(|ui| {
                                ui.label(run.attempted.unwrap_or(0).to_string());
                            });
                            row.col(|ui| {
                                ui.label(run.installed.unwrap_or(0).to_string());
                            });
                            row.col(|ui| {
                                ui.label(run.failed.unwrap_or(0).to_string());
                            });
                            row.col(|ui| {
                                ui.label(run.unaccounted.unwrap_or(0).to_string());
                            });
                        });
                    }
                });
        });

        if let Some(run_id) = clicked_run_id {
            app.select_history_run(run_id);
        }
    });
}

fn render_history_events_table(ui: &mut egui::Ui, events: &[EventRow], pane_size: egui::Vec2) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(pane_size.x);
        ui.set_height(pane_size.y);
        ui.label(egui::RichText::new("Events").strong());
        ui.add_space(4.0);
        if events.is_empty() {
            let message_height = ui.available_height().max(0.0);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), message_height),
                Layout::centered_and_justified(egui::Direction::TopDown),
                |ui| {
                    ui.label("No events for the selected run.");
                },
            );
            return;
        }

        let row_height = ui.text_style_height(&TextStyle::Body) + 8.0;
        let height = ui.available_height().max(0.0);
        let content_width = 170.0 + 64.0 + 120.0 + 320.0;
        ui.push_id("reports_history_events_table", |ui| {
            egui::ScrollArea::horizontal()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_min_width(content_width);
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .vscroll(true)
                        .min_scrolled_height(height)
                        .max_scroll_height(height)
                        .cell_layout(Layout::left_to_right(Align::Center))
                        .column(Column::exact(170.0))
                        .column(Column::exact(64.0))
                        .column(Column::exact(120.0))
                        .column(Column::remainder())
                        .header(row_height, |mut header| {
                            header.col(|ui| {
                                ui.strong("Time");
                            });
                            header.col(|ui| {
                                ui.strong("Level");
                            });
                            header.col(|ui| {
                                ui.strong("Type");
                            });
                            header.col(|ui| {
                                ui.strong("Message");
                            });
                        })
                        .body(|mut body| {
                            for event in events {
                                body.row(row_height, |mut row| {
                                    row.col(|ui| {
                                        ui.label(format_ts(event.ts_ms));
                                    });
                                    row.col(|ui| {
                                        ui.label(event.severity.to_ascii_uppercase());
                                    });
                                    row.col(|ui| {
                                        ui.label(&event.event_type);
                                    });
                                    row.col(|ui| {
                                        ui.add_sized(
                                            [ui.available_width(), row_height],
                                            egui::Label::new(&event.message).truncate(true),
                                        );
                                    });
                                });
                            }
                        });
                });
        });
    });
}

fn render_history_packages_table(
    ui: &mut egui::Ui,
    app: &mut MaintenanceApp,
    pane_size: egui::Vec2,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(pane_size.x);
        ui.set_height(pane_size.y.max(0.0));
        ui.label(egui::RichText::new("Package Evidence").strong());
        ui.add_space(4.0);
        let remaining_height = ui.available_height().max(0.0);

        if app.history_selected_run_id.is_none() {
            show_centered_message(
                ui,
                "Select a run to view package evidence.",
                remaining_height,
            );
            return;
        }

        if app.history_packages.is_empty() {
            show_centered_message(
                ui,
                "No package evidence stored for the selected run.",
                remaining_height,
            );
            return;
        }

        let mut rows = app
            .history_packages
            .iter()
            .enumerate()
            .map(history_package_row)
            .collect::<Vec<_>>();
        ui.push_id("reports_history_packages_table", |ui| {
            packages_table(
                ui,
                &mut rows,
                &mut app.history_package_sort,
                &mut app.history_package_selected,
                remaining_height,
                false,
            );
        });
    });
}

fn show_centered_message(ui: &mut egui::Ui, msg: &str, height: f32) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), height.max(0.0)),
        Layout::centered_and_justified(egui::Direction::TopDown),
        |ui| {
            ui.label(msg);
        },
    );
}

fn history_package_row((index, package): (usize, &PackageEvidenceRow)) -> Row {
    Row {
        index,
        risk: match package.risk.as_deref() {
            Some("red") | Some("Red") => Risk::Red,
            Some("amber") | Some("Amber") => Risk::Amber,
            _ => Risk::Green,
        },
        recon: package.result.clone().unwrap_or_default(),
        name: package.package_name.clone(),
        action: package.action.clone().unwrap_or_default(),
        from: package.from_version.clone().unwrap_or_default(),
        to: package.to_version.clone().unwrap_or_default(),
        repo: package.repository.clone().unwrap_or_default(),
        vendor: String::new(),
        arch: package.arch.clone().unwrap_or_default(),
    }
}

fn format_ts(ts_ms: i64) -> String {
    match Local.timestamp_millis_opt(ts_ms).single() {
        Some(ts) => ts.format("%Y-%m-%dT%H:%M:%S%.3f %:z").to_string(),
        None => ts_ms.to_string(),
    }
}

pub(crate) fn auto_export_report_for_run(app: &mut MaintenanceApp, run_id: &str) {
    let store = match ReportStore::new() {
        Ok(store) => store,
        Err(err) => {
            app.export_status = Some(format!("Auto-save report failed: {err}"));
            return;
        }
    };

    match auto_export_report_for_run_with_store(
        &store,
        run_id,
        app.settings.reports.default_export_location.as_deref(),
        app.system_info.as_ref(),
    ) {
        Ok(path) => {
            app.export_status = Some(format!("Auto-saved report to {}", path.display()));
        }
        Err(err) => {
            app.export_status = Some(err);
        }
    }
}

fn export_selected_report(app: &mut MaintenanceApp) {
    let Some(run_id) = app.history_selected_run_id.clone() else {
        app.history_status = Some("Select a run to export".to_string());
        return;
    };

    let default_file_name = app
        .history_runs
        .iter()
        .find(|run| run.run_id == run_id)
        .map(|run| format_report_file_name(run.started_at_ms))
        .unwrap_or_else(|| format!("chamrisk-report-{run_id}.odt"));

    let mut dialog = FileDialog::new().set_file_name(&default_file_name);
    if let Some(path) = app.settings.reports.default_export_location.as_deref() {
        dialog = dialog.set_directory(path);
    }
    let output_path = dialog.save_file();
    let Some(output_path) = output_path else {
        return;
    };
    app.set_default_report_export_location(&output_path);

    let template_path = report_template_path();
    let result = generate_report(
        &run_id,
        &template_path,
        &output_path,
        app.system_info.as_ref(),
    );

    match result {
        Ok(()) => {
            app.history_status = Some(format!("Exported report to {}", output_path.display()));
        }
        Err(err) => {
            app.history_status = Some(format!("Report export failed: {err}"));
        }
    }
}

pub(crate) fn auto_export_report_for_run_with_store(
    store: &ReportStore,
    run_id: &str,
    default_export_location: Option<&Path>,
    system_info: Option<&chamrisk_ops::health::SystemInfo>,
) -> Result<PathBuf, String> {
    let output_dir = default_export_location.ok_or_else(|| {
        "Auto-save report skipped: no default report export location is configured".to_string()
    })?;
    if !output_dir.exists() {
        return Err(
            "Auto-save report failed: default report export location does not exist".to_string(),
        );
    }
    if !output_dir.is_dir() {
        return Err(
            "Auto-save report failed: default report export location must be a directory"
                .to_string(),
        );
    }

    let run = store
        .list_runs(10_000)?
        .into_iter()
        .find(|run| run.run_id == run_id)
        .ok_or_else(|| format!("Auto-save report failed: run not found: {run_id}"))?;

    let output_path = output_dir.join(format_report_file_name(run.started_at_ms));
    let template_path = report_template_path();
    generate_report_with_store(store, run_id, &template_path, &output_path, system_info)
        .map_err(|err| format!("Auto-save report failed: {err}"))?;
    Ok(output_path)
}

pub(crate) fn export_updates_log(app: &mut MaintenanceApp) {
    let mut dialog = FileDialog::new().set_file_name("updates_log.txt");
    if let Some(path) = app.settings.reports.default_export_location.as_deref() {
        dialog = dialog.set_directory(path);
    }

    if let Some(path) = dialog.save_file() {
        app.set_default_report_export_location(&path);
        let payload = app.state.updates_log.join("\n");
        match fs::write(&path, payload) {
            Ok(_) => app.export_status = Some(format!("Exported log to {}", path.display())),
            Err(err) => app.export_status = Some(format!("Export failed: {err}")),
        }
    }
}

fn generate_report(
    run_id: &str,
    template_path: &Path,
    output_path: &Path,
    system_info: Option<&chamrisk_ops::health::SystemInfo>,
) -> Result<(), String> {
    let store = ReportStore::new()?;
    generate_report_with_store(&store, run_id, template_path, output_path, system_info)
}

fn load_report_model(store: &ReportStore, run_id: &str) -> Result<ReportModel, String> {
    ReportModel::from_store(store, run_id)
}

fn generate_report_with_store(
    store: &ReportStore,
    run_id: &str,
    template_path: &Path,
    output_path: &Path,
    system_info: Option<&chamrisk_ops::health::SystemInfo>,
) -> Result<(), String> {
    eprintln!("INFO: workflow.report.export run_id={run_id} status=started");
    let model = match load_report_model(store, run_id) {
        Ok(model) => model,
        Err(err) => {
            eprintln!("ERROR: workflow.report.export run_id={run_id} status=failed error={err}");
            return Err(err);
        }
    };
    match render_odt(&model, template_path, output_path, system_info) {
        Ok(()) => {
            eprintln!("INFO: workflow.report.export run_id={run_id} status=completed");
            Ok(())
        }
        Err(err) => {
            eprintln!("ERROR: workflow.report.export run_id={run_id} status=failed error={err}");
            Err(err)
        }
    }
}

fn report_template_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../assets")
        .join("report_template.odt")
}

fn format_report_file_name(ts_ms: i64) -> String {
    match Local.timestamp_millis_opt(ts_ms).single() {
        Some(ts) => format!("chamrisk-report-{}.odt", ts.format("%Y-%m-%d %H:%M:%S")),
        None => format!("chamrisk-report-{ts_ms}.odt"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auto_export_report_for_run_with_store, generate_report_with_store, load_report_model,
    };
    use chamrisk_ops::report_store::{PackageEvidenceRow, ReportStore};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("chamrisk-ui-{name}-{unique}.db"))
    }

    #[test]
    fn load_report_model_uses_selected_retained_run_id() {
        let db_path = temp_db_path("historical-report");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");

        let older_run = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start older run");
        store
            .upsert_ai_assessment(
                &older_run,
                Some("Amber"),
                r#"["1) Review vendor changes."]"#,
            )
            .expect("persist older ai");
        store
            .append_event(
                &older_run,
                "run",
                "info",
                "ai.assessment",
                r#"{"risk":"Amber","recommendations":["1) Review vendor changes."]}"#,
                "AI_ASSESSMENT:Amber|1) Review vendor changes.",
            )
            .expect("append older ai");
        store
            .append_event(
                &older_run,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "older reconcile",
            )
            .expect("append older reconcile");
        store
            .replace_packages(
                &older_run,
                &[PackageEvidenceRow {
                    run_id: older_run.clone(),
                    package_name: "mesa".to_string(),
                    from_version: Some("24.0".to_string()),
                    to_version: Some("24.1".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("amber".to_string()),
                }],
            )
            .expect("persist older packages");
        store
            .finish_run(&older_run, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish older run");

        let newer_run = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start newer run");
        store
            .upsert_ai_assessment(&newer_run, Some("Green"), r#"["1) Apply updates."]"#)
            .expect("persist newer ai");
        store
            .append_event(
                &newer_run,
                "run",
                "info",
                "ai.assessment",
                r#"{"risk":"Green","recommendations":["1) Apply updates."]}"#,
                "AI_ASSESSMENT:Green|1) Apply updates.",
            )
            .expect("append newer ai");
        store
            .append_event(
                &newer_run,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "newer reconcile",
            )
            .expect("append newer reconcile");
        store
            .replace_packages(
                &newer_run,
                &[PackageEvidenceRow {
                    run_id: newer_run.clone(),
                    package_name: "kernel-default".to_string(),
                    from_version: Some("6.8.0".to_string()),
                    to_version: Some("6.9.0".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("red".to_string()),
                }],
            )
            .expect("persist newer packages");
        store
            .finish_run(&newer_run, 2_000, "PASS", 1, 1, 0, 0)
            .expect("finish newer run");

        let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
        let model = load_report_model(&reopened, &older_run).expect("load historical report");

        assert_eq!(model.header.run_id, older_run);
        assert_eq!(model.ai_risk.as_deref(), Some("Amber"));
        assert_eq!(model.package_evidence.len(), 1);
        assert_eq!(model.package_evidence[0].package_name, "mesa");
        assert_eq!(
            model
                .package_summary
                .as_ref()
                .map(|summary| summary.total_count),
            Some(1)
        );
        assert!(model.log_entries.iter().any(|entry| {
            entry
                .message
                .contains("Attempted=1 Installed=1 Failed=0 Unaccounted=0 Verdict=PASS")
        }));
        assert!(!model
            .package_evidence
            .iter()
            .any(|row| row.package_name == "kernel-default"));

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn report_export_loads_the_same_canonical_run_id_that_was_created() {
        let db_path = temp_db_path("canonical-run-export");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");

        let run_id = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start run");
        store
            .append_event(
                &run_id,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "reconcile",
            )
            .expect("append reconcile");
        store
            .finish_run(&run_id, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish run");

        let model = load_report_model(&store, &run_id).expect("load report model");
        assert_eq!(model.header.run_id, run_id);

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn load_report_model_returns_missing_run_error() {
        let db_path = temp_db_path("missing-run");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");

        let err = load_report_model(&store, "missing-run-id").expect_err("missing run should fail");
        assert!(err.contains("run not found"));

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn generate_report_with_store_writes_report_for_retained_run_after_restart() {
        let db_path = temp_db_path("historical-render");
        let output_path = std::env::temp_dir().join(format!(
            "chamrisk-report-test-{}.odt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let template_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets")
            .join("report_template.odt");

        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let run_id = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start run");
        store
            .append_event(
                &run_id,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "reconciliation complete",
            )
            .expect("append reconcile");
        store
            .replace_packages(
                &run_id,
                &[PackageEvidenceRow {
                    run_id: run_id.clone(),
                    package_name: "mesa".to_string(),
                    from_version: Some("24.0".to_string()),
                    to_version: Some("24.1".to_string()),
                    arch: Some("x86_64".to_string()),
                    repository: Some("repo-oss".to_string()),
                    action: Some("upgrade".to_string()),
                    result: Some("succeeded".to_string()),
                    risk: Some("green".to_string()),
                }],
            )
            .expect("persist packages");
        store
            .finish_run(&run_id, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish run");

        let reopened = ReportStore::with_db_path(&db_path).expect("reopen report store");
        generate_report_with_store(&reopened, &run_id, &template_path, &output_path, None)
            .expect("render retained report");

        let metadata = fs::metadata(&output_path).expect("report output metadata");
        assert!(metadata.len() > 0);

        let _ = fs::remove_file(output_path);
        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn auto_export_report_with_store_writes_report_for_canonical_run() {
        let db_path = temp_db_path("auto-export-success");
        let output_dir = std::env::temp_dir().join(format!(
            "chamrisk-auto-export-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&output_dir).expect("create output dir");

        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let run_id = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start run");
        store
            .append_event(
                &run_id,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "reconciliation complete",
            )
            .expect("append reconcile");
        store
            .finish_run(&run_id, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish run");

        let output_path =
            auto_export_report_for_run_with_store(&store, &run_id, Some(&output_dir), None)
                .expect("auto export report");

        assert!(output_path.starts_with(&output_dir));
        assert!(output_path.exists());

        let _ = fs::remove_file(output_path);
        let _ = fs::remove_dir_all(output_dir);
        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn auto_export_report_with_store_requires_configured_default_location() {
        let db_path = temp_db_path("auto-export-no-dir");
        let store = ReportStore::with_db_path(&db_path).expect("create report store");
        let run_id = store
            .start_run(r#"{"zypper_dup":true}"#, "1.2.3")
            .expect("start run");
        store
            .append_event(
                &run_id,
                "reconcile",
                "info",
                "ReconcileSummary",
                r#"{"verdict":"PASS","attempted":1,"installed":1,"failed":0,"unaccounted":0}"#,
                "reconciliation complete",
            )
            .expect("append reconcile");
        store
            .finish_run(&run_id, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish run");

        let err = auto_export_report_for_run_with_store(&store, &run_id, None, None)
            .expect_err("missing default export location");
        assert_eq!(
            err,
            "Auto-save report skipped: no default report export location is configured"
        );

        let _ = fs::remove_file(db_path);
    }
}
