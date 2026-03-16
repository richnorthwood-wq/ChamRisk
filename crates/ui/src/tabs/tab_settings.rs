use crate::{
    ai_enabled, ai_ux_state, AiUxState, MaintenanceApp, AI_LABEL_NOT_AVAILABLE,
    AI_LABEL_NOT_TESTED, AI_LABEL_NO_AI_AVAILABLE, AI_LABEL_NO_API_KEY_CONFIGURED,
    AI_LABEL_NO_API_SELECTED, AI_LABEL_SELECT_MODEL,
};
use chamrisk_core::ai::{AiProviderConfig, AiProviderKind, AiSecretStorageMode};
use chamrisk_ops::provider_registry::provider_for_config;
use chamrisk_ui::settings::{LayoutDensity, ThemePreference};
use eframe::egui;
use rfd::FileDialog;

fn selectable_combo_text(
    ui: &mut egui::Ui,
    selected: bool,
    label: impl Into<String>,
) -> egui::Response {
    let selected_text_color = ui.visuals().widgets.active.fg_stroke.color;
    let normal_text_color = ui.visuals().text_color();
    let rich_text = egui::RichText::new(label.into()).color(if selected {
        selected_text_color
    } else {
        normal_text_color
    });

    ui.selectable_label(selected, rich_text)
}

pub fn ui(app: &mut MaintenanceApp, ctx: &egui::Context, ui: &mut egui::Ui) {
    ui.heading("Configuration");
    ui.label("These settings are stored in ~/.config/chamrisk/ui_settings.json");
    ui.add_space(8.0);

    let previous = app.settings.clone();
    let mut changed = false;
    let mut ai_changed = false;

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("Appearance");

        ui.horizontal(|ui| {
            ui.label("Theme");
            egui::ComboBox::from_id_source("settings_theme")
                .selected_text(app.settings.appearance.theme.label())
                .show_ui(ui, |ui| {
                    changed |= ui
                        .selectable_value(
                            &mut app.settings.appearance.theme,
                            ThemePreference::System,
                            ThemePreference::System.label(),
                        )
                        .changed();
                    changed |= ui
                        .selectable_value(
                            &mut app.settings.appearance.theme,
                            ThemePreference::Light,
                            ThemePreference::Light.label(),
                        )
                        .changed();
                    changed |= ui
                        .selectable_value(
                            &mut app.settings.appearance.theme,
                            ThemePreference::Dark,
                            ThemePreference::Dark.label(),
                        )
                        .changed();
                });
        });

        ui.horizontal(|ui| {
            ui.label("Accent colour");
            let color = &mut app.settings.appearance.accent_color;
            let mut rgba =
                egui::Color32::from_rgba_unmultiplied(color.r, color.g, color.b, color.a);
            if ui.color_edit_button_srgba(&mut rgba).changed() {
                color.r = rgba.r();
                color.g = rgba.g();
                color.b = rgba.b();
                color.a = rgba.a();
                changed = true;
            }
        });

        ui.horizontal(|ui| {
            ui.label("Font size");
            changed |= ui
                .add(
                    egui::Slider::new(&mut app.settings.appearance.font_size, 10.0..=24.0)
                        .fixed_decimals(1),
                )
                .changed();
        });

        ui.horizontal(|ui| {
            ui.label("Layout density");
            egui::ComboBox::from_id_source("settings_density")
                .selected_text(app.settings.appearance.density.label())
                .show_ui(ui, |ui| {
                    changed |= ui
                        .selectable_value(
                            &mut app.settings.appearance.density,
                            LayoutDensity::Compact,
                            LayoutDensity::Compact.label(),
                        )
                        .changed();
                    changed |= ui
                        .selectable_value(
                            &mut app.settings.appearance.density,
                            LayoutDensity::Comfortable,
                            LayoutDensity::Comfortable.label(),
                        )
                        .changed();
                });
        });
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("Behaviour");

        changed |= ui
            .checkbox(
                &mut app.settings.behavior.remember_last_tab,
                "Remember last tab",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut app.settings.behavior.auto_refresh_on_launch,
                "Auto-refresh on launch",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut app.settings.behavior.logs_expanded_by_default,
                "Logs expanded by default",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut app.settings.behavior.confirm_before_execution,
                "Require confirmation for all executions",
            )
            .changed();
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("AI Configuration");
        ui.label("AI is optional. Choose a provider only if you want AI triage.");

        let provider_options = selectable_provider_options(app);
        if provider_options.is_empty() {
            ui.label(AI_LABEL_NO_AI_AVAILABLE);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("API key");
                ui.add_enabled(
                    false,
                    egui::TextEdit::singleline(&mut app.ai_configuration.draft_api_key)
                        .password(true)
                        .desired_width(320.0)
                        .hint_text("Enter API key"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Provider check");
                ui.label(AI_LABEL_NOT_TESTED);
            });
            ui.horizontal(|ui| {
                ui.label("Model");
                ui.add_enabled_ui(false, |ui| {
                    egui::ComboBox::from_id_source("settings_ai_model_disabled")
                        .selected_text(AI_LABEL_SELECT_MODEL)
                        .show_ui(ui, |_| {});
                });
            });
            return;
        }

        let selected_provider_label = provider_options
            .iter()
            .find(|(kind, _)| *kind == app.ai_settings.selected_provider)
            .map(|(_, label)| label.as_str())
            .unwrap_or(provider_options[0].1.as_str());

        ui.horizontal(|ui| {
            ui.label("Provider");
            egui::ComboBox::from_id_source("settings_ai_provider")
                .selected_text(selected_provider_label)
                .show_ui(ui, |ui| {
                    for (kind, label) in &provider_options {
                        let is_selected = app.ai_settings.selected_provider == *kind;
                        if selectable_combo_text(ui, is_selected, label.as_str()).clicked() {
                            app.set_selected_ai_provider(*kind);
                            ai_changed = true;
                        }
                    }
                });
        });

        ui.horizontal(|ui| {
            ui.label("API key");
            let provider_selected = app.ai_settings.selected_provider != AiProviderKind::NoneSelected;
            ui.add_enabled_ui(provider_selected, |ui| {
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut app.ai_configuration.draft_api_key)
                            .password(true)
                            .desired_width(320.0)
                            .hint_text("Paste API key"),
                    )
                    .changed()
                {
                    app.ai_configuration.connection_status = AI_LABEL_NOT_TESTED.to_string();
                    app.ai_configuration.connection_status_detail = None;
                    app.clear_loaded_model_state();
                    ai_changed = true;
                }
            });
        });
        if app.ai_settings.selected_provider != AiProviderKind::NoneSelected {
            ui.small("Leave this blank if you are not ready to use AI triage yet.");
        }

        ui.horizontal(|ui| {
            ui.label("Where to keep your API key");
            let provider_selected = app.ai_settings.selected_provider != AiProviderKind::NoneSelected;
            ui.add_enabled_ui(provider_selected, |ui| {
                let selected_text = match app.ai_settings.storage_mode {
                    AiSecretStorageMode::InternalEncryptedStorage => {
                        "Internal encrypted storage"
                    }
                    AiSecretStorageMode::LocalFileStorage => "Local file storage",
                };
                egui::ComboBox::from_id_source("settings_ai_storage_mode")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        if selectable_combo_text(
                            ui,
                            app.ai_settings.storage_mode
                                == AiSecretStorageMode::InternalEncryptedStorage,
                            "Internal encrypted storage (recommended)",
                        )
                        .clicked()
                        {
                            app.ai_settings.storage_mode =
                                AiSecretStorageMode::InternalEncryptedStorage;
                            ai_changed = true;
                        }
                        if selectable_combo_text(
                            ui,
                            app.ai_settings.storage_mode == AiSecretStorageMode::LocalFileStorage,
                            "Local file storage",
                        )
                        .clicked()
                        {
                            app.ai_settings.storage_mode = AiSecretStorageMode::LocalFileStorage;
                            ai_changed = true;
                        }
                    });
            });
        });
        if app.ai_settings.selected_provider != AiProviderKind::NoneSelected {
            ui.small(
                "Internal encrypted storage keeps the key in ChamRisk's encrypted store. Local file storage keeps it in your user config folder.",
            );
        }

        ui.horizontal(|ui| {
            let ai_state = ai_ux_state(&app.ai_settings, &app.ai_configuration);
            let supports_test = selected_provider_config(app)
                .map(|config| {
                    config.metadata.supports_connection_test
                        && !matches!(ai_state, AiUxState::NoProvider | AiUxState::NoKeyConfigured)
                })
                .unwrap_or(false);
            if ui
                .add_enabled(supports_test, egui::Button::new("Test"))
                .clicked()
            {
                app.run_ai_connection_test();
            }
            ui.vertical(|ui| {
                ui.label(format!("Provider check: {}", app.ai_configuration.connection_status));
                if let Some(detail) = app.ai_configuration.connection_status_detail.as_deref() {
                    if !detail.trim().is_empty() {
                        ui.small(detail);
                    }
                }
            });
        });

        ui.horizontal(|ui| {
            ui.label("Model");
            let available_models = selected_provider_config(app)
                .map(|config| config.available_models.clone())
                .unwrap_or_default();
            let model_dropdown_enabled = !available_models.is_empty()
                && !matches!(
                    ai_ux_state(&app.ai_settings, &app.ai_configuration),
                    AiUxState::NoProvider
                        | AiUxState::NoKeyConfigured
                        | AiUxState::ModelsUnavailable
                        | AiUxState::NotAvailable
                );
            ui.add_enabled_ui(model_dropdown_enabled, |ui| {
                egui::ComboBox::from_id_source("settings_ai_model")
                    .selected_text(app.ai_configuration.selected_model_label.as_str())
                    .show_ui(ui, |ui| {
                        if available_models.is_empty() {
                            ui.label(AI_LABEL_SELECT_MODEL);
                            return;
                        }
                        for model in &available_models {
                            let is_selected = app.ai_configuration.selected_model_id.as_deref()
                                == Some(model.id.as_str());
                            if selectable_combo_text(ui, is_selected, model.display_name.as_str())
                                .clicked()
                            {
                                app.set_selected_ai_model(model.id.clone());
                                ai_changed = true;
                            }
                        }
                    });
            });
        });

        let ai_state = ai_ux_state(&app.ai_settings, &app.ai_configuration);
        let hint = match ai_state {
            AiUxState::NoProvider if !ai_enabled(&app.ai_settings) => Some(AI_LABEL_NO_API_SELECTED),
            AiUxState::NoProvider => Some(AI_LABEL_NO_AI_AVAILABLE),
            AiUxState::NoKeyConfigured => Some(AI_LABEL_NO_API_KEY_CONFIGURED),
            AiUxState::NotTested => Some(AI_LABEL_NOT_TESTED),
            AiUxState::NotAvailable => Some(AI_LABEL_NOT_AVAILABLE),
            AiUxState::ModelsUnavailable | AiUxState::ModelNotSelected => {
                Some(AI_LABEL_SELECT_MODEL)
            }
            AiUxState::Ready => None,
        };
        if let Some(hint) = hint {
            ui.small(hint);
        }
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("History and Reports");

        changed |= ui
            .checkbox(
                &mut app.settings.reports.auto_save_report_after_updates_run,
                "Auto-save report after successful updates run",
            )
            .changed();

        ui.horizontal(|ui| {
            ui.label("History retention days");
            let response = ui.add(
                egui::DragValue::new(&mut app.settings.history.retention_days)
                    .clamp_range(1..=3650),
            );
            if response.changed() && app.settings.history.retention_days == 0 {
                app.settings.history.retention_days = 1;
                app.settings_status = Some("History retention must be at least 1 day".to_string());
            }
            changed |= response.changed();
        });

        ui.horizontal(|ui| {
            ui.label("Default report export location");
            let response = ui.add(
                egui::TextEdit::singleline(&mut app.settings_export_path_input)
                    .desired_width(320.0)
                    .hint_text("Leave blank to use the file dialog default"),
            );
            if response.changed() {
                changed = true;
            }

            if ui.button("Choose...").clicked() {
                let mut dialog = FileDialog::new();
                if let Some(path) = app.settings.reports.default_export_location.as_deref() {
                    dialog = dialog.set_directory(path);
                }
                if let Some(path) = dialog.pick_folder() {
                    app.settings_export_path_input = path.display().to_string();
                    app.settings.reports.default_export_location = Some(path);
                    changed = true;
                }
            }

            if ui.button("Clear").clicked()
                && (app
                    .settings
                    .reports
                    .default_export_location
                    .take()
                    .is_some()
                    || !app.settings_export_path_input.is_empty())
            {
                app.settings_export_path_input.clear();
                changed = true;
            }
        });

        if let Err(err) = app.validate_export_path_input() {
            ui.colored_label(egui::Color32::YELLOW, err);
        }
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("Legal");
        ui.label("Review the maintenance disclaimer and acknowledgement status in About / Legal.");
        if ui.button("Open About / Legal").clicked() {
            app.state.active_tab = chamrisk_ui::Tab::About;
        }
    });

    if changed {
        match app.validate_export_path_input() {
            Ok(path) => {
                app.settings.reports.default_export_location = path;
                app.apply_and_persist_settings(ctx, &previous);
            }
            Err(err) => {
                app.settings_status = Some(err);
                app.settings.reports.default_export_location =
                    previous.reports.default_export_location.clone();
            }
        }
    }

    if ai_changed {
        app.apply_and_persist_ai_configuration();
    }

    if let Some(status) = &app.settings_status {
        ui.add_space(8.0);
        ui.label(status);
    }
}

fn selectable_provider_options(app: &MaintenanceApp) -> Vec<(AiProviderKind, String)> {
    let mut options = vec![(AiProviderKind::NoneSelected, "No API Selected".to_string())];
    options.extend(
        app.ai_settings
            .provider_configs
            .iter()
            .filter(|config| config.enabled && provider_for_config(config).is_some())
            .map(|config| (config.metadata.kind, config.metadata.display_name.clone())),
    );
    options
}

fn selected_provider_config(app: &MaintenanceApp) -> Option<&AiProviderConfig> {
    app.ai_settings
        .provider_configs
        .iter()
        .find(|config| config.metadata.kind == app.ai_settings.selected_provider)
}

#[cfg(test)]
mod tests {
    use super::selectable_provider_options;
    use crate::{
        AiConfigurationUiState, ExecutionRunnerModalState, HealthState, MaintenanceApp,
        SystemWorkbookExportState,
    };
    use chamrisk_core::ai::{AiProviderKind, AiSecretStorageMode};
    use chamrisk_ops::health::SystemTelemetry;
    use chamrisk_ops::runner::Runner;
    use chamrisk_ui::ai_settings::default_ai_settings;
    use chamrisk_ui::app::{SortState, UpdateStatus};
    use chamrisk_ui::settings::AppSettings;
    use chamrisk_ui::{MaintenanceApp as AppState, Tab};
    use std::sync::mpsc::channel;
    use std::time::Instant;

    fn test_app() -> MaintenanceApp {
        let (tx, rx) = channel();
        MaintenanceApp {
            state: AppState::default(),
            settings: AppSettings::default(),
            ai_settings: default_ai_settings(),
            ai_configuration: AiConfigurationUiState::default(),
            health_state: HealthState {
                pulse: None,
                report: None,
                last_update: Instant::now(),
                running: false,
            },
            console_open: false,
            console_height: 220.0,
            system_info: None,
            telemetry: SystemTelemetry::default(),
            update_status: UpdateStatus::default(),
            execution_runner_modal: ExecutionRunnerModalState::default(),
            runner: Runner::new(),
            tx,
            rx,
            sudo_session: Default::default(),
            export_status: None,
            history_runs: Vec::new(),
            history_events: Vec::new(),
            history_packages: Vec::new(),
            history_selected_run_id: None,
            history_package_selected: None,
            history_package_sort: SortState::default(),
            history_status: None,
            history_dirty: false,
            settings_status: None,
            settings_export_path_input: String::new(),
            legal_status: None,
            system_workbook_export: SystemWorkbookExportState::default(),
            pending_action: None,
            system_dark_mode: false,
            suppress_initial_health_refresh: false,
            last_persisted_tab: Tab::Health,
            was_health_tab_active: false,
        }
    }

    #[test]
    fn selectable_provider_options_include_enabled_registered_providers() {
        let app = test_app();

        let providers = selectable_provider_options(&app);

        assert_eq!(providers.len(), 3);
        assert_eq!(providers[0].1, "No API Selected");
        assert_eq!(providers[1].1, "OpenAI");
        assert_eq!(providers[2].1, "Anthropic");
    }

    #[test]
    fn selectable_provider_options_exclude_disabled_or_unregistered_providers() {
        let mut app = test_app();
        for config in &mut app.ai_settings.provider_configs {
            config.enabled = false;
        }

        let providers = selectable_provider_options(&app);

        assert_eq!(
            providers,
            vec![(AiProviderKind::NoneSelected, "No API Selected".to_string())]
        );
    }

    #[test]
    fn default_storage_mode_is_internal_encrypted() {
        let app = test_app();
        assert_eq!(
            app.ai_settings.storage_mode,
            AiSecretStorageMode::InternalEncryptedStorage
        );
    }
}
