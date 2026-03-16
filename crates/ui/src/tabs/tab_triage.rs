use crate::{
    ai_enabled, ai_ux_state, build_ai_payload_from_plan, count_kernel_core, packages_table,
    reboot_recommended_from_plan, yes_no, MaintenanceApp, Risk, Row, AI_LABEL_NOT_AVAILABLE,
    AI_LABEL_NO_AI_AVAILABLE, AI_LABEL_NO_API_KEY_CONFIGURED, AI_LABEL_NO_API_SELECTED,
    AI_LABEL_SELECT_MODEL, AI_TRIAGE_DISABLED_NO_KEY_MESSAGE,
};
use chamrisk_core::ai::AiSettings;
use chamrisk_core::models::CommandResult;
use chamrisk_ops::provider_registry::provider_for_config;
use chamrisk_ops::runner::{OperationKind, OpsEvent};
use chamrisk_ui::app::RiskFilter;
use eframe::egui;

fn filter_button(ui: &mut egui::Ui, selected: bool, label: impl Into<String>) -> egui::Response {
    let visuals = ui.visuals();
    let text = if selected {
        egui::RichText::new(label.into())
            .color(egui::Color32::WHITE)
            .strong()
    } else {
        egui::RichText::new(label.into()).strong()
    };

    let mut button = egui::Button::new(text)
        .rounding(egui::Rounding::same(999.0))
        .stroke(visuals.widgets.inactive.bg_stroke)
        .min_size(egui::vec2(72.0, 28.0));

    if selected {
        button = button.fill(visuals.selection.bg_fill);
    }

    ui.add(button)
}

pub fn ui(app: &mut MaintenanceApp, ctx: &egui::Context, ui: &mut egui::Ui) {
    let mut preview_refresh_active = app.refresh_preview_in_progress();

    if preview_refresh_active {
        ctx.request_repaint();
    }

    if ctx.input(|i| i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::Y)) {
        if app.state.update_plan.is_none() {
            app.request_refresh_preview();
            preview_refresh_active = true;
            app.state
                .updates_log
                .push("Sim: requested preview (no plan yet)".to_string());
        } else {
            app.state.begin_updates_run(true);
            app.state.apply_ops_event(OpsEvent::CommandResult {
                operation: OperationKind::UpdatesZypperApply,
                result: CommandResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            });
            app.state
                .updates_log
                .push("Sim: injected completion (exit 0)".to_string());
        }
        ctx.request_repaint();
    }

    ui.heading("Triage & AI");
    ui.add_space(2.0);

    ui.horizontal_wrapped(|ui| {
        ui.horizontal(|ui| {
            let refresh_button_label = if preview_refresh_active {
                "Refreshing..."
            } else {
                "Refresh Preview"
            };
            if ui
                .add_enabled(
                    !preview_refresh_active,
                    egui::Button::new(refresh_button_label),
                )
                .clicked()
            {
                app.request_refresh_preview();
                preview_refresh_active = true;
                ctx.request_repaint();
            }

            if preview_refresh_active {
                ui.add(egui::Spinner::new().size(16.0));
            }
        });

        if preview_refresh_active {
            ui.add_space(4.0);
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            let preview_status_text = if preview_refresh_active {
                "Checking for updates…"
            } else {
                match app.state.last_preview_packages {
                    Some(0) => "System up to date",
                    Some(_) => "Preview complete — updates available",
                    None => app.state.triage_preview_status.label(),
                }
            };
            ui.set_min_width(180.0);
            ui.horizontal(|ui| {
                ui.label(preview_status_text);
                if preview_refresh_active {
                    ui.add(egui::Spinner::new());
                }
            });
        });
    });

    ui.add_space(6.0);
    let reboot_recommended = reboot_recommended_from_plan(&app.state.changes);
    let (kernel_count, core_count) = count_kernel_core(&app.state.changes);
    let ai_state = ai_ux_state(&app.ai_settings, &app.ai_configuration);
    let triage_button_enabled = !matches!(
        ai_state,
        crate::AiUxState::ModelsUnavailable | crate::AiUxState::ModelNotSelected
    );

    let total_width = ui.available_width().max(0.0);
    let gap = 12.0;
    let min_summary_width = 280.0;
    let max_summary_width = 340.0;
    let min_tasks_width = 250.0;
    let max_tasks_width = 300.0;
    let min_center_width = 280.0;
    let can_fit_wide_top_band =
        total_width >= min_summary_width + min_tasks_width + min_center_width + (gap * 2.0);

    if !can_fit_wide_top_band {
        render_summary_panel(ui, app, reboot_recommended, kernel_count, core_count);
        ui.add_space(6.0);
        render_ai_results_panel(
            ui,
            app,
            &ai_state,
            triage_button_enabled,
            reboot_recommended,
            kernel_count,
            core_count,
        );
        ui.add_space(6.0);
        render_task_selection_panel(ui, app, ui.available_width().max(0.0));
    } else {
        let summary_width = (total_width * 0.23).clamp(min_summary_width, max_summary_width);
        let tasks_width = (total_width * 0.20).clamp(min_tasks_width, max_tasks_width);
        let center_width =
            (total_width - summary_width - tasks_width - (gap * 2.0)).max(min_center_width);

        ui.allocate_ui_with_layout(
            egui::vec2(total_width, 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_min_width(total_width);
                ui.set_max_width(total_width);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(summary_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_width(summary_width);
                            ui.set_max_width(summary_width);
                            render_summary_panel(
                                ui,
                                app,
                                reboot_recommended,
                                kernel_count,
                                core_count,
                            );
                        },
                    );

                    ui.add_space(gap);

                    ui.allocate_ui_with_layout(
                        egui::vec2(center_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_width(center_width);
                            ui.set_max_width(center_width);
                            render_ai_results_panel(
                                ui,
                                app,
                                &ai_state,
                                triage_button_enabled,
                                reboot_recommended,
                                kernel_count,
                                core_count,
                            );
                        },
                    );

                    ui.add_space(gap);

                    ui.allocate_ui_with_layout(
                        egui::vec2(tasks_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_min_width(tasks_width);
                            ui.set_max_width(tasks_width);
                            render_task_selection_panel(ui, app, tasks_width);
                        },
                    );
                });
            },
        );
    }

    ui.add_space(8.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.vertical(|ui| {
            ui.label(egui::RichText::new("Package filters").strong());
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                if filter_button(
                    ui,
                    app.state.risk_filter == RiskFilter::All,
                    format!("All ({})", app.state.triage_counts.all),
                )
                .clicked()
                {
                    app.state.risk_filter = RiskFilter::All;
                }
                if filter_button(
                    ui,
                    app.state.risk_filter == RiskFilter::Red,
                    format!("Red ({})", app.state.triage_counts.red),
                )
                .clicked()
                {
                    app.state.risk_filter = RiskFilter::Red;
                }
                if filter_button(
                    ui,
                    app.state.risk_filter == RiskFilter::Amber,
                    format!("Amber ({})", app.state.triage_counts.amber),
                )
                .clicked()
                {
                    app.state.risk_filter = RiskFilter::Amber;
                }
                if filter_button(
                    ui,
                    app.state.risk_filter == RiskFilter::Green,
                    format!("Green ({})", app.state.triage_counts.green),
                )
                .clicked()
                {
                    app.state.risk_filter = RiskFilter::Green;
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Search");
                ui.text_edit_singleline(&mut app.state.filter_text);
                if ui.button("Clear").clicked() {
                    app.state.filter_text.clear();
                }
            });
        });
    });

    ui.add_space(4.0);
    let package_region_height = ui.available_height().max(220.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width().max(0.0), package_region_height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_height(package_region_height - 8.0);
                let show_up_to_date_panel = app.state.triage_preview_status
                    == chamrisk_ui::app::TriagePreviewStatus::Complete
                    && app.state.changes.is_empty()
                    && app.state.last_preview_packages == Some(0);

                if show_up_to_date_panel {
                    ui.with_layout(
                        egui::Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.vertical_centered(|ui| {
                                ui.heading("✔ System up to date");
                                ui.label("No updates are available for this system.");
                            });
                        },
                    );
                } else {
                    let mut rows = package_rows(app);
                    packages_table(
                        ui,
                        &mut rows,
                        &mut app.state.sort_state,
                        &mut app.state.selected,
                        ui.available_height().max(160.0),
                        true,
                    );
                }
            });
        },
    );
}

fn render_summary_panel(
    ui: &mut egui::Ui,
    app: &MaintenanceApp,
    reboot_recommended: bool,
    kernel_count: usize,
    core_count: usize,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(egui::RichText::new("Summary").strong());
        ui.add_space(4.0);
        let repo_summary = if app.state.triage_repos.is_empty() {
            "Repositories: (none)".to_string()
        } else {
            format!("Repositories: {}", app.state.triage_repos.join(", "))
        };

        ui.label(format!("Total updates: {}", app.state.triage_counts.all));
        ui.label(format!(
            "Risk counts: red {}, amber {}, green {}",
            app.state.triage_counts.red,
            app.state.triage_counts.amber,
            app.state.triage_counts.green
        ));
        ui.label(repo_summary);
        ui.label(format!(
            "Snapshot before update: {}",
            yes_no(app.state.execution_selection.snapshot_before_update)
        ));
        ui.label(format!(
            "Prefer Packman: {}",
            yes_no(app.state.execution_selection.packman_preference)
        ));
        ui.label(format!(
            "Reboot recommended: {}",
            yes_no(reboot_recommended)
        ));
        ui.label(format!("Kernel updates: {kernel_count}"));
        ui.label(format!("Core system updates: {core_count}"));

        let mut drivers: Vec<&str> = Vec::new();
        if app
            .state
            .triage_repos
            .iter()
            .any(|r| r.to_lowercase().contains("packman"))
        {
            drivers.push("Packman repo involved");
        }
        if !app.state.execution_selection.snapshot_before_update {
            drivers.push("No snapshot selected");
        }
        if reboot_recommended {
            drivers.push("Reboot recommended (core/kernel changes)");
        } else if kernel_count > 0 {
            drivers.push("Kernel/boot changes present");
        } else if core_count > 0 {
            drivers.push("Core system changes present");
        }
        if app.state.changes.iter().any(|c| {
            let n = c.name.to_lowercase();
            n.contains("ffmpeg")
                || n.contains("libav")
                || n.contains("libheif")
                || n.contains("pipewire")
        }) {
            drivers.push("Multimedia codec stack");
        }

        let risk_drivers = if drivers.is_empty() {
            "None detected".to_string()
        } else {
            drivers.join(" • ")
        };

        ui.add_space(4.0);
        ui.label(egui::RichText::new(format!("Risk drivers: {risk_drivers}")).strong());
    });
}

fn render_task_selection_panel(ui: &mut egui::Ui, app: &mut MaintenanceApp, panel_width: f32) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(panel_width);
        ui.set_width(panel_width);
        ui.set_max_width(panel_width);
        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
            let content_width = panel_width.max(0.0);

            ui.label(egui::RichText::new("Actions").strong());
            ui.add_space(4.0);
            ui.allocate_ui_with_layout(
                egui::vec2(content_width, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(egui::RichText::new("Pick what should happen after review."));
                },
            );
            ui.add_space(4.0);

            if app.state.btrfs_available {
                wrapped_checkbox_row(
                    ui,
                    &mut app.state.execution_selection.snapshot_before_update,
                    "Snapshot before update",
                );
            } else {
                app.state.execution_selection.snapshot_before_update = false;
                ui.add_enabled_ui(false, |ui| {
                    wrapped_checkbox_row(
                        ui,
                        &mut app.state.execution_selection.snapshot_before_update,
                        "Snapshot before update",
                    );
                })
                .response
                .on_hover_text("Snapshots require a Btrfs filesystem.");
            }

            wrapped_checkbox_row(
                ui,
                &mut app.state.execution_selection.zypper_dup,
                "zypper dup",
            );
            wrapped_checkbox_row(
                ui,
                &mut app.state.execution_selection.packman_preference,
                "Prefer Packman (allow vendor change)",
            );
            wrapped_checkbox_row(
                ui,
                &mut app.state.execution_selection.flatpaks,
                "Flatpak updates",
            );
            wrapped_checkbox_row(
                ui,
                &mut app.state.execution_selection.journal_vacuum,
                "Journal vacuum (14 days)",
            );

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Run Selected Tasks").clicked() {
                    app.request_run_selected_execution(app.selection_from_triage_state());
                }
            });
        });
    });
}

fn wrapped_checkbox_row(ui: &mut egui::Ui, value: &mut bool, label: &str) {
    let row_width = ui.available_width().max(0.0);
    let checkbox_width = 18.0;
    let label_width = (row_width - checkbox_width - 8.0).max(0.0);

    ui.scope(|ui| {
        ui.set_width(row_width);
        ui.set_max_width(row_width);
        ui.spacing_mut().item_spacing.x = 6.0;

        let row_response = ui
            .allocate_ui_with_layout(
                egui::vec2(row_width, 0.0),
                egui::Layout::left_to_right(egui::Align::Min),
                |ui| {
                    let checkbox_response =
                        ui.add_sized([checkbox_width, 18.0], egui::Checkbox::without_text(value));
                    let label_response = ui.allocate_ui_with_layout(
                        egui::vec2(label_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.label(egui::RichText::new(label));
                        },
                    );

                    let label_response = label_response.response;
                    if label_response.clicked() {
                        *value = !*value;
                    }

                    checkbox_response.union(label_response)
                },
            )
            .inner;

        if row_response.clicked() {
            ui.ctx().request_repaint();
        }
    });
}

fn render_ai_results_panel(
    ui: &mut egui::Ui,
    app: &mut MaintenanceApp,
    ai_state: &crate::AiUxState,
    triage_button_enabled: bool,
    reboot_recommended: bool,
    kernel_count: usize,
    core_count: usize,
) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(egui::RichText::new("AI risks and recommendations").strong());
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(triage_button_enabled, egui::Button::new("Run AI Triage"))
                .clicked()
            {
                if !ai_enabled(&app.ai_settings) {
                    app.state.ai_state.last_error =
                        Some("AI triage disabled: no API selected".to_string());
                } else if matches!(ai_state, crate::AiUxState::NoKeyConfigured) {
                    app.state.ai_state.last_error =
                        Some(AI_TRIAGE_DISABLED_NO_KEY_MESSAGE.to_string());
                } else if app.state.ai_state.enabled {
                    let payload = build_ai_payload_from_plan(
                        &app.state.changes,
                        app.state.execution_selection.snapshot_before_update,
                        app.state.execution_selection.packman_preference,
                        reboot_recommended,
                        kernel_count,
                        core_count,
                    );
                    app.request_ai_triage_for_active_run(payload);
                } else {
                    app.state.ai_state.last_error =
                        Some("AI triage is disabled; continuing without triage".to_string());
                }
            }

            ui.label(ai_provider_model_status_text(
                &app.ai_settings,
                &app.ai_configuration,
            ));
        });

        ui.add_space(6.0);
        let risk_size = 18.0;
        let body_size = 16.0;

        if let Some(risk) = &app.state.ai_state.assessment_risk {
            ui.label(
                egui::RichText::new(format!("Risk: {risk}"))
                    .size(risk_size)
                    .strong(),
            );
        } else {
            ui.label(egui::RichText::new("Risk: (none)").size(risk_size));
        }

        ui.add_space(6.0);

        if let Some(summary) = &app.state.ai_state.assessment_summary {
            ui.label(egui::RichText::new(summary).size(body_size));
        } else {
            ui.label(egui::RichText::new("Actions: (none)").size(body_size));
        }

        if let Some(err) = &app.state.ai_state.last_error {
            ui.add_space(6.0);
            let status = egui::RichText::new(format!("Status: {err}")).size(body_size);
            if err == "AI triage disabled: no API selected"
                || err == AI_TRIAGE_DISABLED_NO_KEY_MESSAGE
            {
                ui.label(status);
            } else {
                ui.colored_label(egui::Color32::YELLOW, status);
            }
        }
    });
}

fn package_rows(app: &MaintenanceApp) -> Vec<Row> {
    let mut rows = app
        .state
        .filtered_updates()
        .into_iter()
        .map(|(idx, pkg)| {
            let recon = app
                .state
                .last_reconcile
                .as_ref()
                .and_then(|r| {
                    r.items
                        .iter()
                        .find(|m| m.triage_id == format!("plan-{idx}"))
                })
                .map(|m| match m.status {
                    chamrisk_core::models::ReconcileStatus::Succeeded => "OK".to_string(),
                    chamrisk_core::models::ReconcileStatus::Failed => "FAIL".to_string(),
                    chamrisk_core::models::ReconcileStatus::Skipped => "SKIP".to_string(),
                    chamrisk_core::models::ReconcileStatus::NotAttempted => "NA".to_string(),
                    chamrisk_core::models::ReconcileStatus::Ambiguous => "?".to_string(),
                })
                .unwrap_or_default();

            Row {
                index: idx,
                risk: match chamrisk_ui::MaintenanceApp::package_risk_category(pkg) {
                    RiskFilter::Red => Risk::Red,
                    RiskFilter::Amber => Risk::Amber,
                    RiskFilter::Green => Risk::Green,
                    RiskFilter::All => Risk::Green,
                },
                recon,
                name: pkg.name.clone(),
                action: format!("{:?}", pkg.action),
                from: pkg.from.clone().unwrap_or_default(),
                to: pkg.to.clone().unwrap_or_default(),
                repo: pkg.repo.clone().unwrap_or_default(),
                vendor: pkg.vendor.clone().unwrap_or_default(),
                arch: pkg.arch.clone().unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();

    let filter = app.state.filter_text.trim().to_lowercase();
    if !filter.is_empty() {
        rows.retain(|row| {
            row.name.to_lowercase().contains(&filter)
                || row.action.to_lowercase().contains(&filter)
                || row.repo.to_lowercase().contains(&filter)
                || row.arch.to_lowercase().contains(&filter)
        });
    }

    rows
}

fn ai_provider_model_status_text(
    ai_settings: &AiSettings,
    ai_configuration: &crate::AiConfigurationUiState,
) -> String {
    match ai_ux_state(ai_settings, ai_configuration) {
        crate::AiUxState::NoProvider if !ai_enabled(ai_settings) => {
            return AI_LABEL_NO_API_SELECTED.to_string();
        }
        crate::AiUxState::NoProvider => {
            return AI_LABEL_NO_AI_AVAILABLE.to_string();
        }
        crate::AiUxState::NoKeyConfigured => return AI_LABEL_NO_API_KEY_CONFIGURED.to_string(),
        crate::AiUxState::ModelsUnavailable | crate::AiUxState::ModelNotSelected => {
            return AI_LABEL_SELECT_MODEL.to_string();
        }
        crate::AiUxState::NotAvailable => return AI_LABEL_NOT_AVAILABLE.to_string(),
        crate::AiUxState::NotTested | crate::AiUxState::Ready => {}
    }

    let Some(config) = ai_settings
        .provider_configs
        .iter()
        .find(|config| config.metadata.kind == ai_settings.selected_provider)
    else {
        return AI_LABEL_NO_AI_AVAILABLE.to_string();
    };

    if !config.enabled || provider_for_config(config).is_none() {
        return AI_LABEL_NO_AI_AVAILABLE.to_string();
    }

    let model_id = ai_settings
        .last_selected_model_by_provider
        .iter()
        .find(|(kind, _)| *kind == ai_settings.selected_provider)
        .map(|(_, model_id)| model_id.as_str())
        .or_else(|| {
            config
                .available_models
                .first()
                .map(|model| model.id.as_str())
        });

    let Some(model_id) = model_id else {
        return AI_LABEL_SELECT_MODEL.to_string();
    };

    let model_label = config
        .available_models
        .iter()
        .find(|model| model.id == model_id)
        .map(|model| model.display_name.as_str())
        .unwrap_or(model_id);

    format!("{} / {}", config.metadata.display_name, model_label)
}

#[cfg(test)]
mod tests {
    use super::ai_provider_model_status_text;
    use crate::{
        AiConfigurationUiState, AI_LABEL_AVAILABLE, AI_LABEL_NOT_AVAILABLE,
        AI_LABEL_NO_API_KEY_CONFIGURED,
    };
    use chamrisk_core::ai::{AiModelDescriptor, AiProviderKind, AiSettings};
    use chamrisk_ui::ai_settings::default_ai_settings;

    fn settings_with_provider(provider: AiProviderKind) -> AiSettings {
        let mut settings = default_ai_settings();
        settings.selected_provider = provider;
        settings
    }

    fn provider_models_mut(
        settings: &mut AiSettings,
        provider: AiProviderKind,
    ) -> &mut Vec<AiModelDescriptor> {
        &mut settings
            .provider_configs
            .iter_mut()
            .find(|config| config.metadata.kind == provider)
            .expect("provider config")
            .available_models
    }

    #[test]
    fn triage_status_shows_no_ai_available_without_registered_provider() {
        let settings = settings_with_provider(AiProviderKind::Custom);

        assert_eq!(
            ai_provider_model_status_text(&settings, &AiConfigurationUiState::default()),
            "AI provider unavailable"
        );
    }

    #[test]
    fn triage_status_shows_select_model_without_loaded_models() {
        let settings = settings_with_provider(AiProviderKind::OpenAi);

        assert_eq!(
            ai_provider_model_status_text(&settings, &AiConfigurationUiState::default()),
            "Select model"
        );
    }

    #[test]
    fn triage_status_shows_selected_model_when_available() {
        let mut settings = settings_with_provider(AiProviderKind::OpenAi);
        *provider_models_mut(&mut settings, AiProviderKind::OpenAi) = vec![AiModelDescriptor {
            id: "gpt-4.1".to_string(),
            display_name: "GPT-4.1".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1".to_string())];
        let ui_state = AiConfigurationUiState {
            connection_status: AI_LABEL_AVAILABLE.to_string(),
            selected_model_id: Some("gpt-4.1".to_string()),
            selected_model_label: "GPT-4.1".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            ai_provider_model_status_text(&settings, &ui_state),
            "OpenAI / GPT-4.1"
        );
    }

    #[test]
    fn triage_status_shows_selected_model_after_restart_without_requiring_retest() {
        let mut settings = settings_with_provider(AiProviderKind::OpenAi);
        *provider_models_mut(&mut settings, AiProviderKind::OpenAi) = vec![AiModelDescriptor {
            id: "gpt-4.1".to_string(),
            display_name: "GPT-4.1".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1".to_string())];
        let ui_state = AiConfigurationUiState {
            selected_model_id: Some("gpt-4.1".to_string()),
            selected_model_label: "GPT-4.1".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            ai_provider_model_status_text(&settings, &ui_state),
            "OpenAI / GPT-4.1"
        );
    }

    #[test]
    fn triage_status_shows_not_available_after_failed_connection() {
        let mut settings = settings_with_provider(AiProviderKind::OpenAi);
        *provider_models_mut(&mut settings, AiProviderKind::OpenAi) = vec![AiModelDescriptor {
            id: "gpt-4.1".to_string(),
            display_name: "GPT-4.1".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        let ui_state = AiConfigurationUiState {
            connection_status: AI_LABEL_NOT_AVAILABLE.to_string(),
            selected_model_id: Some("gpt-4.1".to_string()),
            selected_model_label: "GPT-4.1".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            ai_provider_model_status_text(&settings, &ui_state),
            AI_LABEL_NOT_AVAILABLE
        );
    }

    #[test]
    fn triage_status_shows_no_key_configured_when_provider_has_no_key() {
        let mut settings = settings_with_provider(AiProviderKind::OpenAi);
        settings.provider_configs[0].connection.api_key_file_name = None;
        settings.provider_configs[0].connection.api_key_env_var = None;
        let ui_state = AiConfigurationUiState::default();

        assert_eq!(
            ai_provider_model_status_text(&settings, &ui_state),
            AI_LABEL_NO_API_KEY_CONFIGURED
        );
    }

    #[test]
    fn triage_status_prefers_selected_provider_model_after_provider_switch() {
        let mut settings = settings_with_provider(AiProviderKind::Anthropic);
        *provider_models_mut(&mut settings, AiProviderKind::OpenAi) = vec![AiModelDescriptor {
            id: "gpt-4.1".to_string(),
            display_name: "GPT-4.1".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        *provider_models_mut(&mut settings, AiProviderKind::Anthropic) = vec![AiModelDescriptor {
            id: "claude-3-7-sonnet-latest".to_string(),
            display_name: "Claude 3.7 Sonnet".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: false,
        }];
        settings.last_selected_model_by_provider = vec![
            (AiProviderKind::OpenAi, "gpt-4.1".to_string()),
            (
                AiProviderKind::Anthropic,
                "claude-3-7-sonnet-latest".to_string(),
            ),
        ];

        let ui_state = AiConfigurationUiState {
            selected_model_id: Some("claude-3-7-sonnet-latest".to_string()),
            selected_model_label: "Claude 3.7 Sonnet".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            ai_provider_model_status_text(&settings, &ui_state),
            "Anthropic / Claude 3.7 Sonnet"
        );
    }
}
