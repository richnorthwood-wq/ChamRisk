use crate::MaintenanceApp;
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use rfd::FileDialog;
use std::fs;

pub fn ui(app: &mut MaintenanceApp, _ctx: &egui::Context, ui: &mut egui::Ui) {
    ui.heading("Btrfs");

    ui.horizontal(|ui| {
        if ui.button("Create Snapshot").clicked() {
            app.request_btrfs_snapshot();
        }
        if ui.button("Start Scrub").clicked() {
            app.request_btrfs_scrub();
        }
        if ui.button("List Snapshots").clicked() {
            app.request_btrfs_list_snapshots();
        }
        if ui.button("Export snapshot list").clicked() {
            export_btrfs_snapshot_list(app);
        }
    });

    ui.separator();

    if app.state.btrfs_status.please_wait {
        ui.colored_label(egui::Color32::YELLOW, "Please wait...");
    }
    if app.state.btrfs_status.completed {
        ui.colored_label(egui::Color32::GREEN, "Completed");
    }
    if let Some(err) = &app.state.btrfs_snapshots_error {
        ui.colored_label(
            egui::Color32::YELLOW,
            format!("Snapshot parse error: {err}"),
        );
    }
    if let Some(status) = &app.export_status {
        ui.label(status);
    }

    ui.separator();
    ui.label("Snapshots");

    let table_height = ui.available_height().max(220.0);
    egui::ScrollArea::vertical()
        .id_source("btrfs_snapshots_scroll")
        .max_height(table_height)
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            if app.state.btrfs_snapshots.is_empty() {
                ui.label("No snapshots loaded.");
                return;
            }

            let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
            let selected_text = ui.visuals().widgets.active.fg_stroke.color;
            let bg_fill = ui.visuals().selection.bg_fill.gamma_multiply(0.35);
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .column(Column::initial(92.0).at_least(72.0))
                .column(Column::initial(74.0).at_least(64.0))
                .column(Column::initial(62.0).at_least(52.0))
                .column(Column::initial(176.0).at_least(160.0))
                .column(Column::initial(72.0).at_least(60.0))
                .column(Column::initial(96.0).at_least(84.0))
                .column(Column::initial(86.0).at_least(72.0))
                .column(Column::remainder().at_least(220.0))
                .column(Column::initial(120.0).at_least(96.0))
                .header(row_height, |mut header| {
                    for title in [
                        "Snapshot #",
                        "Type",
                        "Pre #",
                        "Date",
                        "User",
                        "Used Space",
                        "Cleanup",
                        "Description",
                        "Userdata",
                    ] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, app.state.btrfs_snapshots.len(), |mut row| {
                        let snapshot = &app.state.btrfs_snapshots[row.index()];
                        let cell = |ui: &mut egui::Ui, text: &str| {
                            if snapshot.is_current {
                                egui::Frame::none().fill(bg_fill).show(ui, |ui| {
                                    ui.colored_label(selected_text, text);
                                });
                            } else {
                                ui.label(text);
                            }
                        };

                        row.col(|ui| {
                            let snapshot_label = if snapshot.is_current {
                                format!("{} (current)", snapshot.snapshot_id)
                            } else {
                                snapshot.snapshot_id.clone()
                            };
                            cell(ui, &snapshot_label);
                        });
                        row.col(|ui| cell(ui, &snapshot.snapshot_type));
                        row.col(|ui| cell(ui, snapshot.pre_number.as_deref().unwrap_or("")));
                        row.col(|ui| cell(ui, &snapshot.date));
                        row.col(|ui| cell(ui, &snapshot.user));
                        row.col(|ui| cell(ui, &snapshot.used_space));
                        row.col(|ui| cell(ui, &snapshot.cleanup));
                        row.col(|ui| cell(ui, &snapshot.description));
                        row.col(|ui| cell(ui, &snapshot.userdata));
                    });
                });
        });
}

fn export_btrfs_snapshot_list(app: &mut MaintenanceApp) {
    if !app.state.request_btrfs_snapshot_export() {
        return;
    }

    let mut dialog = FileDialog::new().set_file_name("btrfs-snapshot-list.csv");
    if let Some(path) = app.settings.reports.default_export_location.as_deref() {
        dialog = dialog.set_directory(path);
    }

    let Some(path) = dialog.save_file() else {
        return;
    };

    app.set_default_report_export_location(&path);
    let payload = build_btrfs_snapshot_csv(&app.state.btrfs_snapshots);
    match fs::write(&path, payload) {
        Ok(_) => app.export_status = Some(format!("Exported snapshot list to {}", path.display())),
        Err(err) => app.export_status = Some(format!("Snapshot export failed: {err}")),
    }
}

fn build_btrfs_snapshot_csv(rows: &[chamrisk_core::models::BtrfsSnapshotRow]) -> String {
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(
        [
            csv_field("Snapshot #"),
            csv_field("Type"),
            csv_field("Pre #"),
            csv_field("Date"),
            csv_field("User"),
            csv_field("Used Space"),
            csv_field("Cleanup"),
            csv_field("Description"),
            csv_field("Userdata"),
        ]
        .join(","),
    );

    for row in rows {
        let snapshot_label = if row.is_current {
            format!("{} (current)", row.snapshot_id)
        } else {
            row.snapshot_id.clone()
        };

        lines.push(
            [
                csv_field(&snapshot_label),
                csv_field(&row.snapshot_type),
                csv_field(row.pre_number.as_deref().unwrap_or("")),
                csv_field(&row.date),
                csv_field(&row.user),
                csv_field(&row.used_space),
                csv_field(&row.cleanup),
                csv_field(&row.description),
                csv_field(&row.userdata),
            ]
            .join(","),
        );
    }

    lines.join("\n")
}

fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::build_btrfs_snapshot_csv;
    use chamrisk_core::models::BtrfsSnapshotRow;

    #[test]
    fn snapshot_csv_contains_headers_and_rows() {
        let csv = build_btrfs_snapshot_csv(&[BtrfsSnapshotRow {
            snapshot_id: "42".into(),
            is_current: false,
            snapshot_type: "single".into(),
            pre_number: None,
            date: "Tue Mar 10 10:00:00 2026".into(),
            user: "root".into(),
            used_space: "12.00 MiB".into(),
            cleanup: "timeline".into(),
            description: "before update".into(),
            userdata: String::new(),
        }]);

        assert!(csv.starts_with("\"Snapshot #\",\"Type\",\"Pre #\""));
        assert!(csv.contains("\"42\",\"single\",\"\",\"Tue Mar 10 10:00:00 2026\""));
        assert!(csv.contains("\"before update\""));
    }

    #[test]
    fn snapshot_csv_preserves_current_marker() {
        let csv = build_btrfs_snapshot_csv(&[BtrfsSnapshotRow {
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
        }]);

        assert!(csv.contains("\"1081 (current)\""));
    }
}
