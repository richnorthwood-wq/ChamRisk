use crate::{toggle_mark, MaintenanceApp};
use chamrisk_core::models::PackageAction;
use eframe::egui;
use egui::{Align, Layout, TextStyle};
use egui_extras::{Column, TableBuilder};

fn is_locked_package(name: &str, locked_name_index: &std::collections::HashSet<String>) -> bool {
    locked_name_index.contains(name)
}

fn ellipsize(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn truncated_cell(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) {
    ui.add(egui::Label::new(text).truncate(true));
}

fn selectable_table_text(
    ui: &mut egui::Ui,
    selected: bool,
    text: impl Into<String>,
) -> egui::Response {
    let selected_text_color = ui.visuals().widgets.active.fg_stroke.color;
    let normal_text_color = ui.visuals().text_color();
    let text = text.into();
    let rich_text = egui::RichText::new(text).color(if selected {
        selected_text_color
    } else {
        normal_text_color
    });

    ui.scope(|ui| {
        ui.visuals_mut().selection.stroke.color = selected_text_color;
        ui.selectable_label(selected, rich_text)
    })
    .inner
}

pub fn ui(app: &mut MaintenanceApp, _ctx: &egui::Context, ui: &mut egui::Ui) {
    ui.heading("Package Manager");

    ui.horizontal(|ui| {
        if ui.button("Refresh Index").clicked() {
            app.request_refresh_package_index();
        }

        if ui.button("Search").clicked() {
            let term = app.state.package_manager.search.clone();
            let installed_only = app.state.package_manager.installed_mode;
            app.request_search_packages(term, installed_only);
        }
        ui.add(
            egui::TextEdit::singleline(&mut app.state.package_manager.search)
                .hint_text("Search packages")
                .desired_width(240.0),
        );
        if ui.button("Clear search").clicked() {
            app.state.package_manager.search.clear();
        }

        ui.checkbox(
            &mut app.state.package_manager.installed_mode,
            "Installed only",
        );
        ui.checkbox(&mut app.state.package_manager.dry_run, "Dry-run");
    });

    app.state.package_manager.rebuild_filtered();
    let locked_name_index = app.state.package_manager.lock_name_index();

    let selected_package_name = app
        .state
        .package_manager
        .selected
        .and_then(|idx| app.state.package_manager.rows.get(idx))
        .map(|pkg| pkg.name.clone());
    let selected_lock_ref = app
        .state
        .package_manager
        .selected_lock
        .and_then(|idx| app.state.package_manager.locks.get(idx))
        .map(|lock| {
            lock.lock_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .unwrap_or(lock.name.as_str())
                .to_string()
        });
    let selected_package_mark_state = app
        .state
        .package_manager
        .selected
        .and_then(|idx| app.state.package_manager.rows.get(idx))
        .map(|pkg| {
            let name = pkg.name.clone();
            let installed = pkg.installed_version.is_some();
            let upgradeable = installed
                && pkg.available_version.is_some()
                && pkg.available_version != pkg.installed_version;
            let locked = is_locked_package(&name, &locked_name_index);
            (name, locked, installed, upgradeable)
        });

    ui.horizontal(|ui| {
        let has_marks = !app.state.package_manager.marks.is_empty();

        if ui
            .add_enabled(
                has_marks && !app.state.package_manager.busy_preview,
                egui::Button::new("Preview"),
            )
            .clicked()
        {
            app.request_preview_package_transaction(app.state.package_manager.marks.clone());
        }

        if ui
            .add_enabled(
                has_marks && !app.state.package_manager.busy_apply,
                egui::Button::new("Apply"),
            )
            .clicked()
        {
            let marks = app.state.package_manager.marks.clone();
            let dry_run = app.state.package_manager.dry_run;
            app.request_apply_package_transaction(marks, dry_run);
        }

        if ui
            .add_enabled(has_marks, egui::Button::new("Clear marks"))
            .clicked()
        {
            app.state.package_manager.marks.clear();
        }

        ui.add_space(12.0);

        if let Some((name, _, installed, upgradeable)) = selected_package_mark_state.as_ref() {
            if ui
                .add_enabled(!*installed, egui::Button::new("Mark Install"))
                .clicked()
            {
                toggle_mark(
                    &mut app.state.package_manager.marks,
                    name,
                    PackageAction::Install,
                );
            }
            if ui
                .add_enabled(*upgradeable, egui::Button::new("Mark Upgrade"))
                .clicked()
            {
                toggle_mark(
                    &mut app.state.package_manager.marks,
                    name,
                    PackageAction::Upgrade,
                );
            }
            if ui
                .add_enabled(*installed, egui::Button::new("Mark Remove"))
                .clicked()
            {
                toggle_mark(
                    &mut app.state.package_manager.marks,
                    name,
                    PackageAction::Remove,
                );
            }
        }

        ui.add_space(12.0);
        ui.label(format!("Marked: {}", app.state.package_manager.marks.len()));
    });

    if app.state.package_manager.busy {
        ui.label("Loading package index...");
    }
    if let Some(err) = &app.state.package_manager.last_error {
        ui.colored_label(egui::Color32::YELLOW, format!("Error: {err}"));
    }
    if app.state.package_manager.locks_busy {
        ui.label("Loading package locks...");
    }
    if let Some(err) = &app.state.package_manager.locks_error {
        ui.colored_label(egui::Color32::YELLOW, format!("Locks error: {err}"));
    }
    if app.state.package_manager.busy_apply {
        ui.label("Applying transaction...");
    }
    if let Some(err) = &app.state.package_manager.apply_error {
        ui.colored_label(egui::Color32::YELLOW, format!("Apply error: {err}"));
    }

    let avail_h = ui.available_height();
    let preview_h = if app.state.package_manager.preview_plan.is_some() {
        160.0
    } else {
        0.0
    };
    let locks_h = 170.0;
    let chrome = 150.0;
    let gap = 12.0;
    let table_h = (avail_h - preview_h - locks_h - chrome - gap).max(220.0);

    egui::ScrollArea::vertical()
        .id_source("pkg_table_scroll")
        .max_height(table_h)
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            let row_height = ui.text_style_height(&TextStyle::Body) + 8.0;

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::remainder().at_least(180.0).clip(true))
                .column(Column::exact(88.0))
                .column(Column::exact(56.0))
                .column(
                    Column::initial(112.0)
                        .at_least(96.0)
                        .at_most(140.0)
                        .clip(true),
                )
                .column(
                    Column::initial(112.0)
                        .at_least(96.0)
                        .at_most(140.0)
                        .clip(true),
                )
                .column(
                    Column::initial(200.0)
                        .at_least(140.0)
                        .at_most(280.0)
                        .clip(true),
                )
                .column(Column::exact(72.0))
                .header(row_height, |mut header| {
                    header.col(|ui| {
                        ui.strong("Name");
                    });
                    header.col(|ui| {
                        ui.strong("Mark");
                    });
                    header.col(|ui| {
                        ui.strong("Locked");
                    });
                    header.col(|ui| {
                        ui.strong("Installed");
                    });
                    header.col(|ui| {
                        ui.strong("Available");
                    });
                    header.col(|ui| {
                        ui.strong("Repo");
                    });
                    header.col(|ui| {
                        ui.strong("Arch");
                    });
                })
                .body(|body| {
                    let len = app.state.package_manager.filtered.len();
                    body.rows(row_height, len, |mut row| {
                        let vis_index = row.index();
                        let row_index = app.state.package_manager.filtered[vis_index];
                        let pkg = &app.state.package_manager.rows[row_index];
                        let is_sel = app.state.package_manager.selected == Some(row_index);

                        row.col(|ui| {
                            let display_name = ellipsize(&pkg.name, 48);
                            let mut resp = selectable_table_text(ui, is_sel, &display_name);
                            if display_name != pkg.name {
                                resp = resp.on_hover_text(&pkg.name);
                            }
                            if resp.clicked() {
                                app.state.package_manager.selected = Some(row_index);
                            }
                        });
                        row.col(|ui| {
                            let mark = app
                                .state
                                .package_manager
                                .marks
                                .get(&pkg.name)
                                .map(|m| match m {
                                    PackageAction::Install => "Install",
                                    PackageAction::Upgrade => "Upgrade",
                                    PackageAction::Remove => "Remove",
                                })
                                .unwrap_or("");
                            truncated_cell(ui, mark);
                        });
                        row.col(|ui| {
                            let locked = is_locked_package(&pkg.name, &locked_name_index);
                            truncated_cell(ui, if locked { "Yes" } else { "" });
                        });
                        row.col(|ui| {
                            truncated_cell(ui, pkg.installed_version.as_deref().unwrap_or(""));
                        });
                        row.col(|ui| {
                            truncated_cell(ui, pkg.available_version.as_deref().unwrap_or(""));
                        });
                        row.col(|ui| {
                            truncated_cell(ui, pkg.repository.as_deref().unwrap_or(""));
                        });
                        row.col(|ui| {
                            truncated_cell(ui, pkg.arch.as_deref().unwrap_or(""));
                        });
                    });
                });
        });

    ui.separator();
    ui.group(|ui| {
        ui.label("Package Locks");
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !app.state.package_manager.locks_busy,
                    egui::Button::new("Refresh Locks"),
                )
                .clicked()
            {
                app.request_refresh_package_locks();
            }

            if ui
                .add_enabled(
                    selected_package_name.is_some() && !app.state.package_manager.locks_busy,
                    egui::Button::new("Add Lock to Selected Package"),
                )
                .clicked()
            {
                if let Some(package_name) = selected_package_name.clone() {
                    app.request_add_package_lock(package_name);
                }
            }

            if ui
                .add_enabled(
                    selected_lock_ref.is_some() && !app.state.package_manager.locks_busy,
                    egui::Button::new("Remove Selected Lock"),
                )
                .clicked()
            {
                if let Some(lock_ref) = selected_lock_ref.clone() {
                    app.request_remove_package_lock(lock_ref);
                }
            }

            if ui
                .add_enabled(
                    !app.state.package_manager.locks_busy,
                    egui::Button::new("Clean Useless Locks"),
                )
                .clicked()
            {
                app.request_clean_package_locks();
            }

            ui.label(format!(
                "Active locks: {}",
                app.state.package_manager.active_lock_count()
            ));
        });

        let locks_h = 130.0;
        egui::ScrollArea::vertical()
            .id_source("pkg_locks_scroll")
            .max_height(locks_h)
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let row_height = ui.text_style_height(&TextStyle::Body) + 6.0;
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .column(Column::auto().at_least(46.0))
                    .column(Column::remainder().at_least(160.0))
                    .column(Column::auto().at_least(90.0))
                    .column(Column::remainder().at_least(220.0))
                    .header(row_height, |mut header| {
                        header.col(|ui| {
                            ui.strong("ID");
                        });
                        header.col(|ui| {
                            ui.strong("Name");
                        });
                        header.col(|ui| {
                            ui.strong("Type");
                        });
                        header.col(|ui| {
                            ui.strong("Raw");
                        });
                    })
                    .body(|body| {
                        let len = app.state.package_manager.locks.len();
                        body.rows(row_height, len, |mut row| {
                            let row_index = row.index();
                            let lock = &app.state.package_manager.locks[row_index];
                            let is_sel = app.state.package_manager.selected_lock == Some(row_index);
                            row.col(|ui| {
                                let label = lock.lock_id.as_deref().unwrap_or("-");
                                let resp = ui.selectable_label(is_sel, label);
                                if resp.clicked() {
                                    app.state.package_manager.selected_lock = Some(row_index);
                                }
                            });
                            row.col(|ui| {
                                ui.label(&lock.name);
                            });
                            row.col(|ui| {
                                ui.label(lock.match_type.as_deref().unwrap_or(""));
                            });
                            row.col(|ui| {
                                ui.monospace(&lock.raw_entry);
                            });
                        });
                    });
            });
    });

    ui.separator();

    if let Some((name, locked, _, _)) = selected_package_mark_state.as_ref() {
        ui.horizontal(|ui| {
            ui.label(format!("Selected: {name}"));
            ui.add_space(12.0);
            ui.label(format!("Locked: {}", if *locked { "Yes" } else { "No" }));
            ui.add_space(12.0);
            ui.label(format!("Marked: {}", app.state.package_manager.marks.len()));
        });
    }

    if app.state.package_manager.busy_preview {
        ui.label("Building preview...");
    }
    if let Some(err) = &app.state.package_manager.preview_error {
        ui.colored_label(egui::Color32::YELLOW, format!("Preview error: {err}"));
    }
    if let Some(plan) = &app.state.package_manager.preview_plan {
        let mut installs = 0usize;
        let mut upgrades = 0usize;
        let mut removes = 0usize;

        for change in &plan.changes {
            match change.action {
                chamrisk_core::models::UpdateAction::Install => installs += 1,
                chamrisk_core::models::UpdateAction::Upgrade
                | chamrisk_core::models::UpdateAction::Downgrade => upgrades += 1,
                chamrisk_core::models::UpdateAction::Remove => removes += 1,
                _ => {}
            }
        }

        ui.label(format!(
            "Preview: installs {installs}, upgrades {upgrades}, removes {removes}"
        ));

        let max_rows = 20usize;
        egui::ScrollArea::vertical()
            .max_height(160.0)
            .show(ui, |ui| {
                for change in plan.changes.iter().take(max_rows) {
                    ui.label(format!("{} — {:?}", change.name, change.action));
                }
                if plan.changes.len() > max_rows {
                    ui.label(format!("…and {} more", plan.changes.len() - max_rows));
                }
            });
    }
}
