mod legal_ui;
mod tabs;
mod ui_text;

use chamrisk_core::ai::{
    AiModelDescriptor, AiProviderConfig, AiProviderKind, AiSettings, SecretResolver,
};
use chamrisk_core::models::{
    PackageAction, PackageChange, PackageUpdate, UpdateAction, VendorGroup,
};
use chamrisk_core::risk::{assess_risk, RiskLevel};
use chamrisk_ops::ai::ai_preflight_and_assess;
use chamrisk_ops::ai_secrets::resolver_for_ai_settings;
use chamrisk_ops::health::{
    collect_health_report, collect_system_info, collect_system_pulse, root_filesystem_is_btrfs,
    HealthReport, SystemInfo, SystemPulse, SystemTelemetry,
};
use chamrisk_ops::provider_registry::provider_for_config;
use chamrisk_ops::report_store::{
    AiPersistenceEligibility, EventRow, PackageEvidenceRow, ReportStore, RunRow,
};
use chamrisk_ops::runner::{OperationKind, OpsEvent, Runner};
use chamrisk_ops::system_workbook::default_workbook_path;
use chamrisk_ops::tasks;
use chamrisk_ui::about::{ACKNOWLEDGEMENT_TITLE, DISCLAIMER_TEXT};
use chamrisk_ui::app::{SortCol, SortState, UpdateStatus};
use chamrisk_ui::branding::brand_wordmark;
use chamrisk_ui::settings::{
    load_settings, save_settings, AccentColor, AppSettings, LayoutDensity, ThemePreference,
};
use chamrisk_ui::{
    load_ai_settings, save_ai_settings, LogEntry, LogLevel, MaintenanceApp as AppState, Tab,
};
use chrono::Utc;
use eframe::egui;
use eframe::egui::style::Spacing;
use egui::{Align, Layout, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
type Event = OpsEvent;

#[derive(Clone)]
enum PendingAction {
    RefreshHealth,
    RefreshPreview,
    RunSelectedExecution {
        selection: tasks::UpdateRunSelection,
    },
    BtrfsSnapshot,
    BtrfsScrub,
    BtrfsListSnapshots,
    RefreshPackageIndex,
    SearchPackages {
        term: String,
        installed_only: bool,
    },
    PreviewPackageTransaction {
        marks: std::collections::HashMap<String, PackageAction>,
    },
    ApplyPackageTransaction {
        marks: std::collections::HashMap<String, PackageAction>,
        dry_run: bool,
    },
    RefreshPackageLocks,
    AddPackageLock {
        package_name: String,
    },
    RemovePackageLock {
        lock_ref: String,
    },
    CleanPackageLocks,
    RunAiTriage {
        payload: String,
        run_id: Option<String>,
    },
    PrepareSystemWorkbookExport,
}

impl PendingAction {
    fn requires_sudo(&self) -> bool {
        matches!(
            self,
            Self::RunSelectedExecution { .. }
                | Self::BtrfsSnapshot
                | Self::BtrfsScrub
                | Self::BtrfsListSnapshots
                | Self::ApplyPackageTransaction { .. }
                | Self::AddPackageLock { .. }
                | Self::RemovePackageLock { .. }
                | Self::CleanPackageLocks
                | Self::PrepareSystemWorkbookExport
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct SystemWorkbookExportState {
    pub running: bool,
    pub status: Option<String>,
    pub show_warning_modal: bool,
}

#[derive(Debug, Default)]
struct ExecutionRunnerModalState {
    visible: bool,
    started: bool,
    final_outcome: Option<String>,
}

impl ExecutionRunnerModalState {
    fn open_for_run(&mut self) {
        self.visible = true;
        self.started = false;
        self.final_outcome = None;
    }

    fn mark_started(&mut self) {
        self.visible = true;
        self.started = true;
    }

    fn finish(&mut self, outcome: String) {
        self.visible = true;
        self.started = true;
        self.final_outcome = Some(outcome);
    }

    fn dismiss(&mut self) {
        self.visible = false;
        self.started = false;
        self.final_outcome = None;
    }
}

struct SudoSessionState {
    sudo_password: Option<String>,
    sudo_validated: bool,
    remember_for_session: bool,
    show_sudo_modal: bool,
    startup_prompt_active: bool,
    pending_privileged_action: Option<PendingAction>,
    last_auth_error: Option<String>,
    password_input: String,
}

impl Default for SudoSessionState {
    fn default() -> Self {
        Self {
            sudo_password: None,
            sudo_validated: false,
            remember_for_session: true,
            show_sudo_modal: true,
            startup_prompt_active: true,
            pending_privileged_action: None,
            last_auth_error: None,
            password_input: String::new(),
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "ChamRisk",
        options,
        Box::new(|cc| Box::new(MaintenanceApp::new(cc))),
    )
}

pub(crate) struct MaintenanceApp {
    state: AppState,
    pub(crate) settings: AppSettings,
    pub(crate) ai_settings: AiSettings,
    pub(crate) ai_configuration: AiConfigurationUiState,
    health_state: HealthState,
    pub console_open: bool,
    pub console_height: f32,
    pub system_info: Option<SystemInfo>,
    pub telemetry: SystemTelemetry,
    pub update_status: UpdateStatus,
    execution_runner_modal: ExecutionRunnerModalState,
    runner: Runner,
    tx: Sender<OpsEvent>,
    rx: Receiver<OpsEvent>,
    sudo_session: SudoSessionState,
    export_status: Option<String>,
    pub(crate) history_runs: Vec<RunRow>,
    pub(crate) history_events: Vec<EventRow>,
    pub(crate) history_packages: Vec<PackageEvidenceRow>,
    pub(crate) history_selected_run_id: Option<String>,
    pub(crate) history_package_selected: Option<usize>,
    pub(crate) history_package_sort: SortState,
    pub(crate) history_status: Option<String>,
    pub(crate) history_dirty: bool,
    pub(crate) settings_status: Option<String>,
    pub(crate) settings_export_path_input: String,
    pub(crate) legal_status: Option<String>,
    pub(crate) system_workbook_export: SystemWorkbookExportState,
    pending_action: Option<PendingAction>,
    refresh_preview_requested: bool,
    system_dark_mode: bool,
    suppress_initial_health_refresh: bool,
    last_persisted_tab: Tab,
    was_health_tab_active: bool,
}

pub(crate) struct HealthState {
    pub pulse: Option<SystemPulse>,
    pub report: Option<HealthReport>,
    pub last_update: Instant,
    pub running: bool,
}

pub(crate) struct AiConfigurationUiState {
    pub draft_api_key: String,
    pub connection_status: String,
    pub connection_status_detail: Option<String>,
    pub selected_model_id: Option<String>,
    pub selected_model_label: String,
}

pub(crate) const AI_LABEL_NO_AI_AVAILABLE: &str = "AI provider unavailable";
pub(crate) const AI_LABEL_NO_API_SELECTED: &str = "No API Selected";
pub(crate) const AI_LABEL_NO_API_KEY_CONFIGURED: &str = "No API key configured";
pub(crate) const AI_LABEL_SELECT_MODEL: &str = "Select model";
pub(crate) const AI_LABEL_AVAILABLE: &str = "Available";
pub(crate) const AI_LABEL_NOT_AVAILABLE: &str = "Connection check failed";
pub(crate) const AI_LABEL_NOT_TESTED: &str = "Not checked yet";
const AI_CANONICAL_RUN_REQUIRED_MESSAGE: &str =
    "Run Refresh Preview first to create an active canonical run.";
const AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE: &str = "AI triage disabled: no API selected";
pub(crate) const AI_TRIAGE_DISABLED_NO_KEY_MESSAGE: &str =
    "AI triage disabled: no API key configured";
const AI_NO_KEY_CONFIGURED_DETAIL: &str = "Add an API key to enable AI triage for this provider.";
const AI_STORAGE_MIGRATION_REENTER_MESSAGE: &str =
    "Storage location changed. Re-enter the API key to keep using AI triage.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AiUxState {
    NoProvider,
    NoKeyConfigured,
    NotTested,
    NotAvailable,
    ModelsUnavailable,
    ModelNotSelected,
    Ready,
}

impl Default for AiConfigurationUiState {
    fn default() -> Self {
        Self {
            draft_api_key: String::new(),
            connection_status: AI_LABEL_NOT_TESTED.to_string(),
            connection_status_detail: None,
            selected_model_id: None,
            selected_model_label: AI_LABEL_SELECT_MODEL.to_string(),
        }
    }
}

impl MaintenanceApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel();
        spawn_telemetry_worker(tx.clone());
        let settings = load_settings();
        let ai_settings = load_ai_settings();
        let mut state = AppState::default();
        state.btrfs_available = root_filesystem_is_btrfs();
        state.active_tab = if settings.behavior.remember_last_tab {
            settings.session.last_tab.unwrap_or(Tab::Health)
        } else {
            Tab::Health
        };

        let mut app = Self {
            state,
            settings,
            ai_settings,
            ai_configuration: AiConfigurationUiState::default(),
            health_state: HealthState {
                pulse: None,
                report: None,
                last_update: Instant::now(),
                running: false,
            },
            console_open: false,
            console_height: 220.0,
            system_info: Some(collect_system_info()),
            telemetry: SystemTelemetry::default(),
            update_status: UpdateStatus::default(),
            execution_runner_modal: ExecutionRunnerModalState::default(),
            runner: Runner::new(),
            tx,
            rx,
            sudo_session: SudoSessionState::default(),
            export_status: None,
            history_runs: Vec::new(),
            history_events: Vec::new(),
            history_packages: Vec::new(),
            history_selected_run_id: None,
            history_package_selected: None,
            history_package_sort: SortState::default(),
            history_status: None,
            history_dirty: true,
            settings_status: None,
            settings_export_path_input: String::new(),
            legal_status: None,
            system_workbook_export: SystemWorkbookExportState::default(),
            pending_action: None,
            refresh_preview_requested: false,
            system_dark_mode: cc.egui_ctx.style().visuals.dark_mode,
            suppress_initial_health_refresh: false,
            last_persisted_tab: Tab::Health,
            was_health_tab_active: false,
        };

        app.console_open = app.settings.behavior.logs_expanded_by_default;
        app.settings_export_path_input = app
            .settings
            .reports
            .default_export_location
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        app.sync_ai_configuration_ui();
        app.suppress_initial_health_refresh = !app.settings.behavior.auto_refresh_on_launch;
        app.last_persisted_tab = app.state.active_tab;
        app.apply_settings_to_ctx(&cc.egui_ctx);
        app.prune_history();
        if app.settings.behavior.auto_refresh_on_launch {
            app.refresh_history();
            app.refresh_health();
        }
        app
    }

    fn reset_execution_progress(&mut self) {
        self.update_status = UpdateStatus::default();
    }

    fn open_execution_runner_modal(&mut self) {
        self.reset_execution_progress();
        self.execution_runner_modal.open_for_run();
    }

    fn completion_outcome_from_summary(summary: &chamrisk_ops::runner::RunSummary) -> String {
        match summary.verdict.as_str() {
            "PASS" => "Maintenance run completed successfully.".to_string(),
            "SKIP" => "Maintenance run finished with no selected tasks to execute.".to_string(),
            "BLOCKED" => "Maintenance run finished with blocked tasks.".to_string(),
            verdict => format!("Maintenance run finished with verdict {verdict}."),
        }
    }

    fn fallback_execution_outcome_from_state(&self) -> String {
        if let Some(reconcile) = self.state.last_reconcile.as_ref() {
            return format!(
                "Maintenance run finished with reconciliation summary: {} success, {} failed, {} skipped.",
                reconcile.matched_success, reconcile.matched_failed, reconcile.skipped
            );
        }

        if let Some(error_line) = self
            .state
            .updates_log
            .iter()
            .rev()
            .find(|line| line.starts_with("ERROR:"))
        {
            return format!("Maintenance run failed. {}", error_line.trim());
        }

        if let Some(run) = self.state.last_run.as_ref() {
            return format!(
                "Maintenance run finished with process status {:?}.",
                run.summary.status
            );
        }

        "Maintenance run finished.".to_string()
    }

    fn finish_execution_runner_modal_if_needed(&mut self, outcome: String) {
        if self.execution_runner_modal.final_outcome.is_none() {
            self.execution_runner_modal.finish(outcome);
        }
    }

    fn execution_modal_ok_enabled(&self) -> bool {
        self.execution_runner_modal.final_outcome.is_some()
    }

    fn execution_log_tail(&self, count: usize) -> Vec<String> {
        let len = self.state.updates_log.len();
        self.state.updates_log[len.saturating_sub(count)..len].to_vec()
    }

    fn derived_execution_package_total(&self) -> Option<u32> {
        self.state
            .current_run
            .as_ref()
            .and_then(|run| run.zypper_plan.as_ref())
            .or(self.state.update_plan.as_ref())
            .map(|plan| plan.changes.len() as u32)
            .filter(|total| *total > 0)
    }

    fn ensure_execution_progress_total(&mut self) {
        if self.update_status.total == 0 {
            if let Some(total) = self.derived_execution_package_total() {
                self.update_status.total = total;
                self.update_status.exact_progress = false;
            }
        }
    }

    fn advance_execution_progress_from_package_event(&mut self, package: &str) {
        if !self.state.active_execution || self.update_status.exact_progress {
            return;
        }

        self.ensure_execution_progress_total();
        self.update_status.active = true;
        if self.update_status.phase == "Idle" || self.update_status.phase.is_empty() {
            self.update_status.phase = "Updating".to_string();
        }
        self.update_status.current_package = package.to_string();
        self.update_status.processed = self.update_status.processed.saturating_add(1);
        if self.update_status.total > 0 {
            self.update_status.processed =
                self.update_status.processed.min(self.update_status.total);
        }
    }

    fn show_execution_runner_modal(&mut self, ctx: &egui::Context) {
        if !self.execution_runner_modal.visible {
            return;
        }

        let screen_rect = ctx.screen_rect();
        egui::Area::new(egui::Id::new("execution_runner_backdrop"))
            .order(egui::Order::Middle)
            .interactable(false)
            .fixed_pos(screen_rect.min)
            .show(ctx, |ui| {
                let backdrop_rect = egui::Rect::from_min_size(egui::Pos2::ZERO, screen_rect.size());
                ui.painter()
                    .rect_filled(backdrop_rect, 0.0, egui::Color32::from_black_alpha(160));
            });

        let stage = if self.state.active_execution {
            if self.update_status.phase.is_empty() {
                "Starting".to_string()
            } else {
                self.update_status.phase.clone()
            }
        } else {
            "Finished".to_string()
        };
        let modal_completed = self.execution_modal_ok_enabled();
        let log_tail = self.execution_log_tail(6);
        let package_total = if self.update_status.total > 0 {
            Some(self.update_status.total)
        } else {
            self.derived_execution_package_total()
        };
        let package_progress_label = package_total.map(|total| {
            if self.update_status.processed > 0 {
                format!(
                    "Applying package {} of {}",
                    self.update_status.processed, total
                )
            } else {
                format!("Packages in scope: {total}")
            }
        });

        egui::Window::new("Maintenance run in progress")
            .collapsible(false)
            .resizable(false)
            .movable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_min_width(560.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        if self.state.active_execution {
                            ui.add(egui::Spinner::new());
                        }
                        ui.strong(format!("Current stage: {stage}"));
                    });

                    if !self.update_status.current_package.trim().is_empty() {
                        ui.label(format!(
                            "Current package: {}",
                            self.update_status.current_package
                        ));
                    }

                    if let Some(progress_label) = package_progress_label {
                        ui.label(progress_label);
                    }

                    if let Some(total) = package_total {
                        let progress =
                            (self.update_status.processed as f32 / total as f32).clamp(0.0, 1.0);
                        ui.add_sized(
                            [ui.available_width(), 18.0],
                            egui::ProgressBar::new(progress),
                        );
                    }

                    ui.add_space(6.0);
                    ui.label("Recent activity");
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_height(132.0);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .stick_to_bottom(true)
                            .max_height(132.0)
                            .show(ui, |ui| {
                                for line in log_tail {
                                    ui.monospace(line);
                                }
                            });
                    });

                    ui.add_space(6.0);
                    if let Some(outcome) = self.execution_runner_modal.final_outcome.as_deref() {
                        ui.separator();
                        ui.label(format!("Final outcome: {outcome}"));
                    }

                    ui.add_space(8.0);
                    let ok_clicked = ui
                        .add_enabled(
                            modal_completed,
                            egui::Button::new("OK").min_size(egui::vec2(72.0, 28.0)),
                        )
                        .clicked();
                    if ok_clicked {
                        self.execution_runner_modal.dismiss();
                    }
                });
            });
    }

    fn apply_settings_to_ctx(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        let font_size = self.settings.appearance.font_size.clamp(10.0, 24.0);
        let spacing = style.spacing.clone();

        style.text_styles.insert(
            TextStyle::Small,
            egui::FontId::proportional((font_size - 2.0).max(9.0)),
        );
        style
            .text_styles
            .insert(TextStyle::Body, egui::FontId::proportional(font_size));
        style
            .text_styles
            .insert(TextStyle::Button, egui::FontId::proportional(font_size));
        style.text_styles.insert(
            TextStyle::Monospace,
            egui::FontId::monospace((font_size - 1.0).max(9.0)),
        );
        style.text_styles.insert(
            TextStyle::Heading,
            egui::FontId::proportional(font_size + 6.0),
        );

        style.spacing = match self.settings.appearance.density {
            LayoutDensity::Compact => Spacing {
                item_spacing: egui::vec2(6.0, 4.0),
                button_padding: egui::vec2(6.0, 3.0),
                indent: 14.0,
                interact_size: egui::vec2(36.0, 20.0),
                ..spacing.clone()
            },
            LayoutDensity::Comfortable => Spacing {
                item_spacing: egui::vec2(8.0, 8.0),
                button_padding: egui::vec2(8.0, 4.0),
                indent: 18.0,
                interact_size: egui::vec2(40.0, 24.0),
                ..spacing
            },
        };

        ctx.set_style(style);
        ctx.set_visuals(self.build_visuals());
    }

    fn build_visuals(&self) -> egui::Visuals {
        let mut visuals = match self.settings.appearance.theme {
            ThemePreference::Light => egui::Visuals::light(),
            ThemePreference::Dark => egui::Visuals::dark(),
            ThemePreference::System => {
                if self.system_dark_mode {
                    egui::Visuals::dark()
                } else {
                    egui::Visuals::light()
                }
            }
        };

        let AccentColor { r, g, b, a } = self.settings.appearance.accent_color;
        let accent = egui::Color32::from_rgba_unmultiplied(r, g, b, a);
        visuals.hyperlink_color = accent;
        visuals.selection.bg_fill = accent;
        visuals.selection.stroke.color = accent;
        visuals.widgets.active.bg_fill = accent;
        visuals.widgets.hovered.bg_fill = accent.gamma_multiply(0.85);
        visuals.widgets.open.bg_fill = accent.gamma_multiply(0.75);
        visuals
    }

    fn sync_settings_from_runtime(&mut self) {
        self.settings.session.last_tab = if self.settings.behavior.remember_last_tab {
            Some(self.state.active_tab)
        } else {
            None
        };
    }

    fn persist_settings(&mut self) {
        self.sync_settings_from_runtime();
        match save_settings(&self.settings) {
            Ok(()) => self.settings_status = None,
            Err(err) => self.settings_status = Some(format!("Settings save failed: {err}")),
        }
    }

    fn persist_ai_settings(&mut self) {
        match save_ai_settings(&self.ai_settings) {
            Ok(()) => {
                if matches!(
                    self.settings_status.as_deref(),
                    Some(message) if message.starts_with("AI settings save failed:")
                ) {
                    self.settings_status = None;
                }
            }
            Err(err) => self.settings_status = Some(format!("AI settings save failed: {err}")),
        }
    }

    pub(crate) fn apply_and_persist_ai_configuration(&mut self) {
        let previous_settings = load_ai_settings();
        let result = (|| -> Result<Option<String>, String> {
            let resolver = resolver_for_ai_settings(&self.ai_settings)?;
            let previous_resolver = if previous_settings.storage_mode
                != self.ai_settings.storage_mode
                && previous_settings.selected_provider == self.ai_settings.selected_provider
                && self.ai_settings.selected_provider != AiProviderKind::NoneSelected
            {
                Some(resolver_for_ai_settings(&previous_settings)?)
            } else {
                None
            };
            persist_ai_configuration(
                &previous_settings,
                previous_resolver.as_ref(),
                &mut self.ai_settings,
                &mut self.ai_configuration,
                &resolver,
                save_ai_settings,
            )
        })();

        match result {
            Ok(Some(message)) => {
                self.settings_status = Some(message);
            }
            Ok(None) => {
                if matches!(
                    self.settings_status.as_deref(),
                    Some(message)
                        if message.starts_with("AI settings save failed:")
                            || message.starts_with("Storage mode changed.")
                            || message.starts_with("Storage location updated.")
                ) {
                    self.settings_status = None;
                }
            }
            Err(err) => self.settings_status = Some(format!("AI settings save failed: {err}")),
        }
    }

    pub(crate) fn sync_ai_configuration_ui(&mut self) {
        self.ai_configuration.connection_status = AI_LABEL_NOT_TESTED.to_string();
        self.ai_configuration.connection_status_detail = None;
        let selected_model_id = resolve_selected_model_id(&self.ai_settings);
        self.ai_configuration.selected_model_id = selected_model_id.clone();
        self.ai_configuration.selected_model_label =
            selected_model_label_for_settings(&self.ai_settings, selected_model_id.as_deref());
    }

    pub(crate) fn set_selected_ai_provider(&mut self, provider: AiProviderKind) {
        if self.ai_settings.selected_provider == provider {
            return;
        }

        self.ai_settings.selected_provider = provider;
        self.ai_configuration.draft_api_key.clear();
        if provider == AiProviderKind::NoneSelected {
            self.ai_configuration.selected_model_id = None;
            self.ai_configuration.selected_model_label = AI_LABEL_SELECT_MODEL.to_string();
        }
        self.sync_ai_configuration_ui();
    }

    pub(crate) fn run_ai_connection_test(&mut self) {
        let result =
            (|| -> Result<(String, Option<String>, Option<Vec<AiModelDescriptor>>), String> {
                let resolver = resolver_for_ai_settings(&self.ai_settings)?;
                test_ai_provider_connection_with_env(
                    &self.ai_settings,
                    &self.ai_configuration,
                    &resolver,
                    |name| std::env::var(name).ok(),
                    |config, resolved_api_key| {
                        let provider = provider_for_config(config).ok_or_else(|| {
                            format!(
                                "no provider adapter is registered for selected provider: {:?}",
                                config.metadata.kind
                            )
                        })?;
                        let connection_result = provider.test_connection(resolved_api_key)?;
                        let models = if connection_result.success {
                            Some(provider.list_models(resolved_api_key)?)
                        } else {
                            None
                        };
                        Ok((
                            connection_result.success,
                            Some(connection_result.message),
                            models,
                        ))
                    },
                )
            })();

        match result {
            Ok((status, detail, models)) => {
                if let Some(models) = models {
                    apply_loaded_models(&mut self.ai_settings, &mut self.ai_configuration, models);
                    self.persist_ai_settings();
                } else if status == AI_LABEL_NOT_AVAILABLE {
                    self.clear_loaded_model_state();
                }
                self.ai_configuration.connection_status = status;
                self.ai_configuration.connection_status_detail = detail;
            }
            Err(err) => {
                self.clear_loaded_model_state();
                if err == AI_NO_KEY_CONFIGURED_DETAIL {
                    self.ai_configuration.connection_status = AI_LABEL_NOT_TESTED.to_string();
                    self.ai_configuration.connection_status_detail = Some(err);
                } else {
                    self.ai_configuration.connection_status = AI_LABEL_NOT_AVAILABLE.to_string();
                    self.ai_configuration.connection_status_detail = Some(err);
                }
            }
        }
    }

    pub(crate) fn clear_loaded_model_state(&mut self) {
        let provider = self.ai_settings.selected_provider;
        if let Some(config) = selected_provider_config_mut(&mut self.ai_settings) {
            config.available_models.clear();
        }
        clear_last_selected_model_for_provider(&mut self.ai_settings, provider);
        self.ai_configuration.selected_model_id = None;
        self.ai_configuration.selected_model_label = AI_LABEL_SELECT_MODEL.to_string();
    }

    pub(crate) fn set_selected_ai_model(&mut self, model_id: String) {
        set_selected_model(&mut self.ai_settings, &mut self.ai_configuration, model_id);
        self.persist_ai_settings();
    }

    fn set_ai_no_canonical_run_status(&mut self) {
        eprintln!("INFO: ai triage skipped reason=no_eligible_active_canonical_run");
        self.state.ai_state.last_error = Some(AI_CANONICAL_RUN_REQUIRED_MESSAGE.to_string());
    }

    fn current_canonical_preview_plan(&self) -> Option<chamrisk_core::models::UpdatePlan> {
        self.state
            .current_run
            .as_ref()
            .and_then(|run| run.zypper_plan.clone())
            .or_else(|| self.state.update_plan.clone())
    }

    pub(crate) fn selection_from_triage_state(&self) -> tasks::UpdateRunSelection {
        let prefer_packman = self.state.execution_selection.packman_preference
            && self
                .state
                .triage_repos
                .iter()
                .any(|repo| repo.to_ascii_lowercase().contains("packman"));
        tasks::UpdateRunSelection {
            snapshot_before_update: self.state.execution_selection.snapshot_before_update,
            zypper_dup: self.state.execution_selection.zypper_dup,
            prefer_packman,
            flatpak: self.state.execution_selection.flatpaks,
            journal_vacuum: self.state.execution_selection.journal_vacuum,
            mode: "apply".to_string(),
            risk_filter: format!("{:?}", self.state.risk_filter).to_ascii_lowercase(),
            repos: self.state.triage_repos.clone(),
        }
    }

    fn persist_cached_ai_assessment_to_run_with_store(
        &mut self,
        run_id: &str,
        store: &ReportStore,
    ) {
        let Some(risk) = self.state.ai_state.assessment_risk.clone() else {
            return;
        };
        let Some(summary) = self.state.ai_state.assessment_summary.clone() else {
            return;
        };
        let assessment = chamrisk_ops::ai::AiAssessment { summary, risk };
        if let Err(err) =
            chamrisk_ops::ai::persist_assessment_snapshot_for_run(store, run_id, &assessment)
        {
            self.state.ai_state.last_error = Some(format!(
                "AI triage result could not be attached to the execution run: {err}"
            ));
        }
    }

    fn ensure_master_run_for_selection_with_store(
        &mut self,
        selection: &tasks::UpdateRunSelection,
        plan: Option<&chamrisk_core::models::UpdatePlan>,
        store: Option<&ReportStore>,
    ) -> Option<String> {
        if let Some(run_id) = self
            .state
            .current_run
            .as_ref()
            .and_then(|run| run.run_id.clone())
        {
            return Some(run_id);
        }

        let created_run_id = match store {
            Some(store) => {
                let run_id =
                    tasks::create_master_run_with_optional_plan_in_store(store, selection, plan)
                        .ok()?;
                self.persist_cached_ai_assessment_to_run_with_store(&run_id, store);
                run_id
            }
            None => {
                let store = ReportStore::new().ok()?;
                let run_id =
                    tasks::create_master_run_with_optional_plan_in_store(&store, selection, plan)
                        .ok()?;
                self.persist_cached_ai_assessment_to_run_with_store(&run_id, &store);
                run_id
            }
        };

        if let Some(run) = self.state.current_run.as_mut() {
            run.run_id = Some(created_run_id.clone());
        } else {
            self.state.begin_updates_run_with_existing_master_run(
                created_run_id.clone(),
                selection.zypper_dup || selection.prefer_packman,
            );
            if let Some(plan) = plan.cloned() {
                if let Some(run) = self.state.current_run.as_mut() {
                    run.zypper_plan = Some(plan);
                }
            }
        }

        Some(created_run_id)
    }

    fn clear_stale_canonical_run_context_if_matching(&mut self, run_id: &str) {
        let should_clear_current = self
            .state
            .current_run
            .as_ref()
            .and_then(|run| run.run_id.as_deref())
            == Some(run_id);
        if should_clear_current {
            self.state.current_run = None;
        }
        self.state.clear_loaded_canonical_run_id_if_matching(run_id);
    }

    fn eligible_canonical_ai_run_id_with_store(
        &mut self,
        run_id: &str,
        store: &ReportStore,
    ) -> Result<Option<String>, String> {
        match store.ai_persistence_eligibility(run_id)? {
            AiPersistenceEligibility::EligibleOpenRun => Ok(Some(run_id.to_string())),
            AiPersistenceEligibility::MissingRun => {
                eprintln!("INFO: ai triage skipped run_id={run_id} reason=no_canonical_run_row");
                self.clear_stale_canonical_run_context_if_matching(run_id);
                Ok(None)
            }
            AiPersistenceEligibility::ClosedRun => {
                eprintln!("INFO: ai triage skipped run_id={run_id} reason=run_closed");
                self.clear_stale_canonical_run_context_if_matching(run_id);
                Ok(None)
            }
        }
    }

    fn active_canonical_ai_run_id_with_store(
        &mut self,
        store: &ReportStore,
    ) -> Result<Option<String>, String> {
        let run_id = self
            .state
            .current_run
            .as_ref()
            .and_then(|run| run.run_id.clone())
            .or_else(|| self.state.loaded_canonical_run_id.clone());
        match run_id {
            Some(run_id) => self.eligible_canonical_ai_run_id_with_store(&run_id, store),
            None => Ok(None),
        }
    }

    fn has_valid_sudo_session(&self) -> bool {
        self.sudo_session.sudo_validated && self.sudo_session.sudo_password.is_some()
    }

    fn open_sudo_modal(&mut self, action: Option<PendingAction>) {
        if let Some(action) = action {
            self.sudo_session.pending_privileged_action = Some(action);
        }
        self.sudo_session.password_input.clear();
        self.sudo_session.startup_prompt_active = false;
        self.sudo_session.show_sudo_modal = true;
        self.sudo_session.last_auth_error = None;
    }

    fn invalidate_sudo_session(&mut self, error: Option<String>) {
        self.sudo_session.sudo_password = None;
        self.sudo_session.sudo_validated = false;
        self.sudo_session.password_input.clear();
        self.sudo_session.last_auth_error = error;
    }

    fn handle_sudo_confirm(&mut self) {
        if self.sudo_session.password_input.trim().is_empty() {
            self.sudo_session.last_auth_error =
                Some("Enter your sudo password to continue.".to_string());
            return;
        }

        let password = self.sudo_session.password_input.clone();
        match tasks::validate_sudo_password(&password) {
            Ok(()) => {
                self.sudo_session.sudo_password = Some(password);
                self.sudo_session.sudo_validated = true;
                self.sudo_session.last_auth_error = None;
                self.sudo_session.password_input.clear();
                self.sudo_session.show_sudo_modal = false;
                self.sudo_session.startup_prompt_active = false;

                let pending = self.sudo_session.pending_privileged_action.take();
                if let Some(action) = pending {
                    self.queue_or_run(action);
                }
            }
            Err(_) => {
                self.invalidate_sudo_session(Some(
                    "Authentication failed. Please try again.".to_string(),
                ));
                self.sudo_session.show_sudo_modal = true;
            }
        }
    }

    fn handle_sudo_skip(&mut self) {
        self.sudo_session.password_input.clear();
        self.sudo_session.last_auth_error = None;
        self.sudo_session.pending_privileged_action = None;
        self.sudo_session.show_sudo_modal = false;
        self.sudo_session.startup_prompt_active = false;
    }

    fn handle_sudo_cancel(&mut self, ctx: &egui::Context) {
        let had_pending_action = self.sudo_session.pending_privileged_action.is_some();
        let startup_prompt_active = self.sudo_session.startup_prompt_active;
        self.sudo_session.password_input.clear();
        self.sudo_session.last_auth_error = None;
        self.sudo_session.pending_privileged_action = None;
        self.sudo_session.show_sudo_modal = false;
        self.sudo_session.startup_prompt_active = false;
        if !had_pending_action
            && startup_prompt_active
            && self.sudo_session.sudo_password.is_none()
            && !self.sudo_session.sudo_validated
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn is_sudo_auth_failure(text: &str) -> bool {
        let text = text.to_ascii_lowercase();
        text.contains("incorrect password")
            || text.contains("sorry, try again")
            || text.contains("authentication failed")
    }

    fn log_execution_request_ignored(&mut self) {
        let message = "Run request ignored: execution already in progress";
        eprintln!("INFO: {message}");
        self.state.updates_log.push(format!("INFO: {message}"));
    }

    fn queue_or_run(&mut self, action: PendingAction) {
        if matches!(action, PendingAction::RunSelectedExecution { .. })
            && self.state.active_execution
        {
            self.log_execution_request_ignored();
            return;
        }
        if !self.settings.legal.disclaimer_acknowledged {
            if matches!(action, PendingAction::RefreshPreview) {
                self.refresh_preview_requested = false;
            }
            self.pending_action = None;
            self.state.active_tab = Tab::About;
            self.legal_status = Some(
                "Review and acknowledge the disclaimer before running maintenance actions."
                    .to_string(),
            );
            return;
        }
        if action.requires_sudo() && !self.has_valid_sudo_session() {
            self.open_sudo_modal(Some(action));
            return;
        }
        if self.settings.behavior.confirm_before_execution
            && !matches!(action, PendingAction::PrepareSystemWorkbookExport)
        {
            self.pending_action = Some(action);
        } else {
            self.execute_action(action);
        }
    }

    fn confirm_pending_action(&mut self) {
        if let Some(action) = self.pending_action.take() {
            self.execute_action(action);
        }
    }

    fn cancel_pending_action(&mut self) {
        if matches!(self.pending_action, Some(PendingAction::RefreshPreview)) {
            self.refresh_preview_requested = false;
        }
        self.pending_action = None;
    }

    pub(crate) fn acknowledge_disclaimer(&mut self) {
        if self.settings.legal.disclaimer_acknowledged {
            return;
        }
        self.settings.legal.disclaimer_acknowledged = true;
        self.legal_status = None;
        self.persist_settings();
    }

    fn pending_action_title_for(&self, action: &PendingAction) -> &'static str {
        match action {
            PendingAction::RefreshHealth => "Refresh health checks?",
            PendingAction::RefreshPreview => "Run updates preview?",
            PendingAction::RunSelectedExecution { .. } => "Run selected maintenance tasks?",
            PendingAction::BtrfsSnapshot => "Create a Btrfs snapshot?",
            PendingAction::BtrfsScrub => "Start a Btrfs scrub?",
            PendingAction::BtrfsListSnapshots => "List Btrfs snapshots?",
            PendingAction::RefreshPackageIndex => "Refresh package index?",
            PendingAction::SearchPackages { .. } => "Run package search?",
            PendingAction::PreviewPackageTransaction { .. } => "Build package transaction preview?",
            PendingAction::ApplyPackageTransaction { .. } => "Apply package transaction?",
            PendingAction::RefreshPackageLocks => "Refresh package locks?",
            PendingAction::AddPackageLock { .. } => "Add package lock?",
            PendingAction::RemovePackageLock { .. } => "Remove package lock?",
            PendingAction::CleanPackageLocks => "Clean useless package locks?",
            PendingAction::RunAiTriage { .. } => "Run AI triage?",
            PendingAction::PrepareSystemWorkbookExport => "Export system workbook?",
        }
    }

    fn pending_action_title(&self) -> Option<&'static str> {
        self.pending_action
            .as_ref()
            .map(|action| self.pending_action_title_for(action))
    }

    fn pending_action_detail(&self) -> Option<String> {
        self.pending_action.as_ref().map(|action| match action {
            PendingAction::RefreshHealth => "Collects current system health data.".to_string(),
            PendingAction::RefreshPreview => "Runs the existing zypper preview flow.".to_string(),
            PendingAction::RunSelectedExecution { selection } => format!(
                "Snapshot: {}  zypper dup: {}  Packman: {}  Flatpak: {}  Journal vacuum: {}",
                yes_no(selection.snapshot_before_update),
                yes_no(selection.zypper_dup),
                yes_no(selection.prefer_packman),
                yes_no(selection.flatpak),
                yes_no(selection.journal_vacuum)
            ),
            PendingAction::BtrfsSnapshot => "Creates a manual Btrfs snapshot.".to_string(),
            PendingAction::BtrfsScrub => "Starts a filesystem scrub.".to_string(),
            PendingAction::BtrfsListSnapshots => {
                "Lists snapshots using the existing Btrfs command path.".to_string()
            }
            PendingAction::RefreshPackageIndex => {
                "Rebuilds the package index from the current system.".to_string()
            }
            PendingAction::SearchPackages {
                term,
                installed_only,
            } => format!(
                "Search term: {}  Installed only: {}",
                if term.trim().is_empty() {
                    "(empty)"
                } else {
                    term.trim()
                },
                yes_no(*installed_only)
            ),
            PendingAction::PreviewPackageTransaction { marks } => {
                format!(
                    "Builds a preview for {} marked package change(s).",
                    marks.len()
                )
            }
            PendingAction::ApplyPackageTransaction { marks, dry_run } => format!(
                "Applies {} marked package change(s). Dry-run: {}",
                marks.len(),
                yes_no(*dry_run)
            ),
            PendingAction::RefreshPackageLocks => {
                "Reads the current package lock list.".to_string()
            }
            PendingAction::AddPackageLock { package_name } => {
                format!("Adds a lock for {package_name}.")
            }
            PendingAction::RemovePackageLock { lock_ref } => {
                format!("Removes lock {lock_ref}.")
            }
            PendingAction::CleanPackageLocks => "Removes obsolete package locks.".to_string(),
            PendingAction::RunAiTriage { .. } => {
                "Sends the current update plan to the configured AI triage path.".to_string()
            }
            PendingAction::PrepareSystemWorkbookExport => {
                "Collects current machine state and writes a standalone workbook.".to_string()
            }
        })
    }

    fn execute_action(&mut self, action: PendingAction) {
        let clear_session_password =
            action.requires_sudo() && !matches!(action, PendingAction::PrepareSystemWorkbookExport);
        match action {
            PendingAction::RefreshHealth => self.refresh_health(),
            PendingAction::RefreshPreview => {
                self.state.triage_preview_status = chamrisk_ui::app::TriagePreviewStatus::Updating;
                self.state.preview_running = true;
                self.state.ai_state.last_error = None;
                self.state.ai_state.assessment_risk = None;
                self.state.ai_state.assessment_summary = None;
                self.state.ai_state.preflight_ok = false;
                self.state.begin_updates_run(true);
                tasks::preview_dup(self.tx.clone(), self.sudo_option());
            }
            PendingAction::RunSelectedExecution { selection } => {
                if !self.state.try_begin_execution() {
                    self.log_execution_request_ignored();
                    return;
                }
                self.open_execution_runner_modal();
                let zypper_requested = selection.zypper_dup || selection.prefer_packman;
                let preview_plan = self.current_canonical_preview_plan();
                let existing_master_run_id = self.ensure_master_run_for_selection_with_store(
                    &selection,
                    preview_plan.as_ref(),
                    None,
                );
                if let Some(run_id) = existing_master_run_id.clone() {
                    self.state
                        .begin_updates_run_with_existing_master_run(run_id, zypper_requested);
                } else {
                    self.state.begin_updates_run(zypper_requested);
                }
                let run_id = tasks::run_updates_plan_with_selection_and_return_run_id(
                    self.tx.clone(),
                    selection,
                    existing_master_run_id,
                    self.sudo_option(),
                );
                if run_id.is_none() {
                    self.state
                        .updates_log
                        .push("ERROR: Maintenance run could not be started".to_string());
                    self.state.finish_execution();
                    self.finish_execution_runner_modal_if_needed(
                        "Maintenance run could not be started.".to_string(),
                    );
                    return;
                }
                if let (Some(run), Some(run_id)) = (self.state.current_run.as_mut(), run_id) {
                    eprintln!(
                        "INFO: workflow.master_run.activate run_id={run_id} source=execution"
                    );
                    run.run_id = Some(run_id);
                }
                self.history_dirty = true;
            }
            PendingAction::BtrfsSnapshot => {
                tasks::btrfs_manual_snapshot(self.tx.clone(), self.sudo_option());
            }
            PendingAction::BtrfsScrub => {
                tasks::btrfs_scrub(self.tx.clone(), self.sudo_option());
            }
            PendingAction::BtrfsListSnapshots => {
                tasks::btrfs_list_snapshots(self.tx.clone(), self.sudo_option());
            }
            PendingAction::RefreshPackageIndex => {
                self.state.package_manager.busy = true;
                self.state.package_manager.last_error = None;
                let runner = self.runner.clone();
                let tx = self.tx.clone();
                std::thread::spawn(move || match tasks::build_package_index(&runner) {
                    Ok(rows) => {
                        let _ = tx.send(OpsEvent::PackageIndex(rows));
                    }
                    Err(err) => {
                        let _ = tx.send(OpsEvent::Error(format!("PKG_SEARCH: {err}")));
                    }
                });
            }
            PendingAction::SearchPackages {
                term,
                installed_only,
            } => {
                self.state.package_manager.busy = true;
                self.state.package_manager.last_error = None;
                let runner = self.runner.clone();
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    match tasks::search_packages(&runner, &term, installed_only) {
                        Ok(rows) => {
                            let _ = tx.send(OpsEvent::PackageIndex(rows));
                        }
                        Err(err) => {
                            let _ = tx.send(OpsEvent::Error(format!("PKG_SEARCH: {err}")));
                        }
                    }
                });
            }
            PendingAction::PreviewPackageTransaction { marks } => {
                self.state.package_manager.busy_preview = true;
                self.state.package_manager.preview_error = None;
                self.state.package_manager.preview_plan = None;
                let runner = self.runner.clone();
                let tx = self.tx.clone();
                std::thread::spawn(move || match tasks::preview_transaction(&runner, &marks) {
                    Ok(plan) => {
                        let _ = tx.send(OpsEvent::UpdatePlan(plan));
                    }
                    Err(err) => {
                        let _ = tx.send(OpsEvent::Error(format!("PKG_PREVIEW: {err}")));
                    }
                });
            }
            PendingAction::ApplyPackageTransaction { marks, dry_run } => {
                self.state.package_manager.busy_apply = true;
                self.state.package_manager.apply_error = None;
                let tx = self.tx.clone();
                let sudo = self.sudo_option();
                std::thread::spawn(move || {
                    tasks::apply_transaction(tx, &marks, dry_run, sudo);
                });
            }
            PendingAction::RefreshPackageLocks => {
                self.state.package_manager.locks_busy = true;
                self.state.package_manager.locks_error = None;
                let runner = self.runner.clone();
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    tasks::list_package_locks(tx, &runner);
                });
            }
            PendingAction::AddPackageLock { package_name } => {
                self.state.package_manager.locks_busy = true;
                self.state.package_manager.locks_error = None;
                let tx = self.tx.clone();
                let sudo = self.sudo_option();
                std::thread::spawn(move || {
                    tasks::add_package_lock(tx, &package_name, sudo);
                });
            }
            PendingAction::RemovePackageLock { lock_ref } => {
                self.state.package_manager.locks_busy = true;
                self.state.package_manager.locks_error = None;
                let tx = self.tx.clone();
                let sudo = self.sudo_option();
                std::thread::spawn(move || {
                    tasks::remove_package_lock(tx, &lock_ref, sudo);
                });
            }
            PendingAction::CleanPackageLocks => {
                self.state.package_manager.locks_busy = true;
                self.state.package_manager.locks_error = None;
                let tx = self.tx.clone();
                let sudo = self.sudo_option();
                std::thread::spawn(move || {
                    tasks::clean_package_locks(tx, sudo);
                });
            }
            PendingAction::RunAiTriage { payload, run_id } => {
                if !ai_enabled(&self.ai_settings) {
                    self.state.ai_state.last_error =
                        Some(AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE.to_string());
                } else if matches!(
                    ai_ux_state(&self.ai_settings, &self.ai_configuration),
                    AiUxState::NoKeyConfigured
                ) {
                    self.state.ai_state.last_error =
                        Some(AI_TRIAGE_DISABLED_NO_KEY_MESSAGE.to_string());
                } else if self.state.ai_state.enabled {
                    let eligible_run_id = if let Some(run_id) = run_id {
                        match ReportStore::new() {
                            Ok(store) => {
                                match self.eligible_canonical_ai_run_id_with_store(&run_id, &store)
                                {
                                    Ok(Some(run_id)) => Some(run_id),
                                    Ok(None) => {
                                        self.set_ai_no_canonical_run_status();
                                        return;
                                    }
                                    Err(err) => {
                                        self.state.ai_state.last_error = Some(format!(
                                            "AI triage could not verify the active canonical run: {err}"
                                        ));
                                        return;
                                    }
                                }
                            }
                            Err(err) => {
                                self.state.ai_state.last_error = Some(format!(
                                    "AI triage could not verify the active canonical run: {err}"
                                ));
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    let endpoint = "https://api.openai.com".to_string();
                    let api_key = None;
                    ai_preflight_and_assess(
                        &endpoint,
                        &payload,
                        api_key,
                        eligible_run_id,
                        self.tx.clone(),
                    );
                } else {
                    self.state.ai_state.last_error =
                        Some("AI triage is disabled; continuing without triage".to_string());
                }
            }
            PendingAction::PrepareSystemWorkbookExport => {
                self.system_workbook_export.show_warning_modal = true;
                self.system_workbook_export.status = None;
            }
        }
        if clear_session_password && !self.sudo_session.remember_for_session {
            self.invalidate_sudo_session(None);
        }
    }

    pub(crate) fn request_refresh_health(&mut self) {
        self.queue_or_run(PendingAction::RefreshHealth);
    }

    pub(crate) fn refresh_preview_in_progress(&self) -> bool {
        self.refresh_preview_requested
    }

    pub(crate) fn request_refresh_preview(&mut self) {
        self.refresh_preview_requested = true;
        self.queue_or_run(PendingAction::RefreshPreview);
    }

    pub(crate) fn request_run_selected_execution(&mut self, selection: tasks::UpdateRunSelection) {
        self.queue_or_run(PendingAction::RunSelectedExecution { selection });
    }

    pub(crate) fn request_btrfs_snapshot(&mut self) {
        self.queue_or_run(PendingAction::BtrfsSnapshot);
    }

    pub(crate) fn request_btrfs_scrub(&mut self) {
        self.queue_or_run(PendingAction::BtrfsScrub);
    }

    pub(crate) fn request_btrfs_list_snapshots(&mut self) {
        self.queue_or_run(PendingAction::BtrfsListSnapshots);
    }

    pub(crate) fn request_refresh_package_index(&mut self) {
        self.queue_or_run(PendingAction::RefreshPackageIndex);
    }

    pub(crate) fn request_search_packages(&mut self, term: String, installed_only: bool) {
        self.queue_or_run(PendingAction::SearchPackages {
            term,
            installed_only,
        });
    }

    pub(crate) fn request_preview_package_transaction(
        &mut self,
        marks: std::collections::HashMap<String, PackageAction>,
    ) {
        self.queue_or_run(PendingAction::PreviewPackageTransaction { marks });
    }

    pub(crate) fn request_apply_package_transaction(
        &mut self,
        marks: std::collections::HashMap<String, PackageAction>,
        dry_run: bool,
    ) {
        self.queue_or_run(PendingAction::ApplyPackageTransaction { marks, dry_run });
    }

    pub(crate) fn request_refresh_package_locks(&mut self) {
        self.queue_or_run(PendingAction::RefreshPackageLocks);
    }

    pub(crate) fn request_add_package_lock(&mut self, package_name: String) {
        self.queue_or_run(PendingAction::AddPackageLock { package_name });
    }

    pub(crate) fn request_remove_package_lock(&mut self, lock_ref: String) {
        self.queue_or_run(PendingAction::RemovePackageLock { lock_ref });
    }

    pub(crate) fn request_clean_package_locks(&mut self) {
        self.queue_or_run(PendingAction::CleanPackageLocks);
    }

    pub(crate) fn request_ai_triage(&mut self, payload: String, run_id: Option<String>) {
        self.queue_or_run(PendingAction::RunAiTriage { payload, run_id });
    }

    pub(crate) fn request_ai_triage_for_active_run(&mut self, payload: String) {
        match ReportStore::new() {
            Ok(store) => self.request_ai_triage_for_active_run_with_store(payload, &store),
            Err(err) => {
                self.state.ai_state.last_error = Some(format!(
                    "AI triage could not verify the active canonical run: {err}"
                ));
            }
        }
    }

    fn request_ai_triage_for_active_run_with_store(
        &mut self,
        payload: String,
        store: &ReportStore,
    ) {
        if !ai_enabled(&self.ai_settings) {
            self.state.ai_state.last_error =
                Some(AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE.to_string());
            return;
        }
        if matches!(
            ai_ux_state(&self.ai_settings, &self.ai_configuration),
            AiUxState::NoKeyConfigured
        ) {
            self.state.ai_state.last_error = Some(AI_TRIAGE_DISABLED_NO_KEY_MESSAGE.to_string());
            return;
        }

        let run_id = match self.active_canonical_ai_run_id_with_store(store) {
            Ok(Some(run_id)) => Some(run_id),
            Ok(None) => {
                if self.current_canonical_preview_plan().is_none() {
                    self.set_ai_no_canonical_run_status();
                    return;
                }
                None
            }
            Err(err) => {
                self.state.ai_state.last_error = Some(format!(
                    "AI triage could not verify the active canonical run: {err}"
                ));
                return;
            }
        };

        self.request_ai_triage(payload, run_id);
    }

    pub(crate) fn request_system_workbook_export(&mut self) {
        if self.system_workbook_export.running {
            return;
        }
        if !self.ensure_valid_sudo_session_for_system_workbook() {
            return;
        }
        self.queue_or_run(PendingAction::PrepareSystemWorkbookExport);
    }

    #[cfg(not(test))]
    fn ensure_valid_sudo_session_for_system_workbook(&mut self) -> bool {
        if self.has_valid_sudo_session() {
            if let Some(password) = self.sudo_session.sudo_password.clone() {
                if tasks::validate_sudo_password(&password).is_err() {
                    self.invalidate_sudo_session(Some(
                        "Authentication failed. Please try again.".to_string(),
                    ));
                    self.open_sudo_modal(Some(PendingAction::PrepareSystemWorkbookExport));
                    return false;
                }
            }
        }

        true
    }

    #[cfg(test)]
    fn ensure_valid_sudo_session_for_system_workbook(&mut self) -> bool {
        true
    }

    fn cancel_system_workbook_export(&mut self) {
        self.system_workbook_export.show_warning_modal = false;
        if !self.system_workbook_export.running {
            self.system_workbook_export.status = None;
        }
    }

    fn confirm_system_workbook_export(&mut self) {
        self.system_workbook_export.show_warning_modal = false;

        let output_path = match self.prompt_for_system_workbook_path() {
            Some(path) => path,
            None => {
                self.system_workbook_export.status =
                    Some("System workbook export cancelled".to_string());
                return;
            }
        };

        self.start_system_workbook_export(output_path);
    }

    fn prompt_for_system_workbook_path(&mut self) -> Option<PathBuf> {
        let default_path =
            default_workbook_path(self.settings.reports.default_export_location.as_deref());
        let file_name = default_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("system-workbook.xlsx")
            .to_string();

        let mut dialog = rfd::FileDialog::new().set_file_name(&file_name);
        if let Some(path) = self.settings.reports.default_export_location.as_deref() {
            dialog = dialog.set_directory(path);
        }

        let path = dialog.save_file()?;
        self.set_default_report_export_location(&path);
        Some(path)
    }

    fn start_system_workbook_export(&mut self, output_path: PathBuf) {
        self.system_workbook_export.running = true;
        self.system_workbook_export.status = Some("System workbook export started".to_string());
        let tx = self.tx.clone();
        let sudo = self.sudo_option();
        if !self.sudo_session.remember_for_session {
            self.invalidate_sudo_session(None);
        }
        std::thread::spawn(move || {
            tasks::export_system_workbook(tx, output_path, sudo);
        });
    }

    pub(crate) fn apply_and_persist_settings(
        &mut self,
        ctx: &egui::Context,
        previous: &AppSettings,
    ) {
        self.apply_settings_to_ctx(ctx);
        if previous.history.retention_days != self.settings.history.retention_days {
            self.prune_history();
            self.refresh_history();
        }
        if previous.behavior.logs_expanded_by_default
            != self.settings.behavior.logs_expanded_by_default
        {
            self.console_open = self.settings.behavior.logs_expanded_by_default;
        }
        if !self.settings.behavior.remember_last_tab {
            self.settings.session.last_tab = None;
        }
        self.persist_settings();
    }

    fn prune_history(&mut self) {
        match ReportStore::new().and_then(|store| {
            store.prune_older_than(i64::from(self.settings.history.retention_days))
        }) {
            Ok(()) => {}
            Err(err) => {
                self.history_status = Some(format!("History prune failed: {err}"));
            }
        }
    }

    pub(crate) fn set_default_report_export_location(&mut self, path: &Path) {
        let Some(parent) = path.parent() else {
            return;
        };

        let next = Some(parent.to_path_buf());
        if self.settings.reports.default_export_location == next {
            return;
        }

        self.settings.reports.default_export_location = next;
        self.settings_export_path_input = parent.display().to_string();
        self.persist_settings();
    }

    pub(crate) fn validate_export_path_input(&self) -> Result<Option<PathBuf>, String> {
        let trimmed = self.settings_export_path_input.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let path = PathBuf::from(trimmed);
        if path.exists() && !path.is_dir() {
            return Err("Default report export location must be a directory".to_string());
        }

        if !path.exists() {
            return Err("Default report export location does not exist".to_string());
        }

        Ok(Some(path))
    }

    fn maybe_auto_export_completed_updates_run(
        &mut self,
        summary: &chamrisk_ops::runner::RunSummary,
    ) {
        if !self.settings.reports.auto_save_report_after_updates_run {
            return;
        }
        if !summary.verdict.eq_ignore_ascii_case("PASS") {
            return;
        }

        let Some(run_id) = summary.process_run.as_ref().map(|run| run.run_id.as_str()) else {
            self.export_status =
                Some("Auto-save report skipped: completed run had no canonical run id".to_string());
            return;
        };

        tabs::reports::auto_export_report_for_run(self, run_id);
    }

    fn maybe_auto_export_completed_updates_run_with_store(
        &mut self,
        summary: &chamrisk_ops::runner::RunSummary,
        store: &ReportStore,
    ) {
        if !self.settings.reports.auto_save_report_after_updates_run {
            return;
        }
        if !summary.verdict.eq_ignore_ascii_case("PASS") {
            return;
        }

        let Some(run_id) = summary.process_run.as_ref().map(|run| run.run_id.as_str()) else {
            self.export_status =
                Some("Auto-save report skipped: completed run had no canonical run id".to_string());
            return;
        };

        match tabs::reports::auto_export_report_for_run_with_store(
            store,
            run_id,
            self.settings.reports.default_export_location.as_deref(),
            self.system_info.as_ref(),
        ) {
            Ok(path) => {
                self.export_status = Some(format!("Auto-saved report to {}", path.display()));
            }
            Err(err) => {
                self.export_status = Some(err);
            }
        }
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.rx.try_recv() {
            if matches!(&event, Event::Error(_) | Event::UpdatePlan(_))
                || matches!(
                    &event,
                    Event::CommandResult {
                        operation: OperationKind::UpdatesZypperPreview,
                        ..
                    }
                )
            {
                self.refresh_preview_requested = false;
            }
            if matches!(event, OpsEvent::RunSummary(_)) {
                self.history_dirty = true;
            }
            match event {
                Event::Error(line) => {
                    if Self::is_sudo_auth_failure(&line) {
                        self.invalidate_sudo_session(Some(
                            "Authentication failed. Please try again.".to_string(),
                        ));
                    }
                    self.state.apply_ops_event(Event::Error(line));
                }
                Event::CommandResult { operation, result } => {
                    if Self::is_sudo_auth_failure(&result.stderr) {
                        self.invalidate_sudo_session(Some(
                            "Authentication failed. Please try again.".to_string(),
                        ));
                    }
                    self.state
                        .apply_ops_event(Event::CommandResult { operation, result });
                }
                Event::HealthReport(report) => {
                    self.health_state.pulse = Some(report.pulse.clone());
                    self.health_state.report = Some(report);
                    self.health_state.running = false;
                }
                Event::SystemPulse(pulse) => {
                    self.health_state.pulse = Some(pulse);
                }
                Event::TelemetryUpdate(incoming_telemetry) => {
                    self.telemetry = incoming_telemetry;
                }
                Event::UpdatePhase(phase) => {
                    if phase == "Idle" {
                        self.refresh_preview_requested = false;
                    }
                    if self.state.active_execution && phase != "Idle" {
                        self.execution_runner_modal.mark_started();
                    }
                    self.update_status.phase = phase.clone();
                    self.update_status.active = phase != "Idle";
                    if phase == "Updating" {
                        self.ensure_execution_progress_total();
                    }
                    if phase == "Idle"
                        && self.state.active_execution
                        && self.execution_runner_modal.started
                    {
                        self.state.finish_execution();
                        let outcome = self.fallback_execution_outcome_from_state();
                        self.finish_execution_runner_modal_if_needed(outcome);
                    }
                }
                Event::UpdateProgress {
                    package,
                    processed,
                    total,
                } => {
                    if self.state.active_execution {
                        self.execution_runner_modal.mark_started();
                    }
                    self.update_status.current_package = package;
                    self.update_status.processed = processed;
                    self.update_status.total = total;
                    self.update_status.exact_progress = true;
                    self.update_status.active = true;
                }
                Event::SystemWorkbookExportProgress(message) => {
                    self.system_workbook_export.running = true;
                    self.system_workbook_export.status = Some(message);
                }
                Event::SystemWorkbookExportCompleted { path } => {
                    self.system_workbook_export.running = false;
                    self.system_workbook_export.status =
                        Some(format!("System workbook exported to {}", path.display()));
                    self.state.show_info_dialog(
                        "System workbook export",
                        format!("Exported workbook to {}", path.display()),
                    );
                }
                Event::SystemWorkbookExportFailed(message) => {
                    self.system_workbook_export.running = false;
                    self.system_workbook_export.status =
                        Some(format!("System workbook export failed: {message}"));
                    self.state.show_info_dialog(
                        "System workbook export",
                        format!("Export failed: {message}"),
                    );
                }
                Event::RunSummary(summary) => {
                    if self.state.active_execution {
                        self.execution_runner_modal.mark_started();
                    }
                    self.update_status.phase = "Idle".to_string();
                    self.update_status.active = false;
                    let auto_export_summary = summary.clone();
                    let updates_run_completed = self.state.current_run.is_some();
                    let modal_outcome = Self::completion_outcome_from_summary(&summary);
                    self.state.apply_ops_event(Event::RunSummary(summary));
                    self.finish_execution_runner_modal_if_needed(modal_outcome);
                    if updates_run_completed {
                        self.maybe_auto_export_completed_updates_run(&auto_export_summary);
                    }
                    self.health_state.running = true;
                    spawn_health_check(self.tx.clone());
                }
                other => {
                    if let Event::Structured(event) = &other {
                        if matches!(
                            event.kind,
                            chamrisk_ops::events::OpsEventKind::PreviewResult { .. }
                        ) {
                            self.refresh_preview_requested = false;
                        }
                        if self.state.active_execution {
                            match &event.kind {
                                chamrisk_ops::events::OpsEventKind::RunStart
                                | chamrisk_ops::events::OpsEventKind::PreviewStart
                                | chamrisk_ops::events::OpsEventKind::ApplyStart
                                | chamrisk_ops::events::OpsEventKind::ApplyResult { .. }
                                | chamrisk_ops::events::OpsEventKind::PackageInstalled { .. }
                                | chamrisk_ops::events::OpsEventKind::PackageRemoved { .. }
                                | chamrisk_ops::events::OpsEventKind::PackageUpgraded { .. } => {
                                    self.execution_runner_modal.mark_started();
                                }
                                _ => {}
                            }
                        }
                        match &event.kind {
                            chamrisk_ops::events::OpsEventKind::ApplyStart => {
                                self.ensure_execution_progress_total();
                            }
                            chamrisk_ops::events::OpsEventKind::PackageInstalled {
                                name, ..
                            }
                            | chamrisk_ops::events::OpsEventKind::PackageRemoved { name, .. }
                            | chamrisk_ops::events::OpsEventKind::PackageUpgraded {
                                name, ..
                            } => {
                                self.advance_execution_progress_from_package_event(name);
                            }
                            _ => {}
                        }
                    }
                    self.state.apply_ops_event(other);
                }
            }
            ctx.request_repaint();
        }
    }

    fn sudo_option(&self) -> Option<String> {
        self.sudo_session.sudo_password.clone()
    }

    pub(crate) fn refresh_history(&mut self) {
        let store = match ReportStore::new() {
            Ok(store) => store,
            Err(err) => {
                self.history_runs.clear();
                self.history_events.clear();
                self.history_selected_run_id = None;
                self.history_status = Some(format!("History unavailable: {err}"));
                self.history_dirty = false;
                return;
            }
        };
        self.refresh_history_with_store(&store);
    }

    fn refresh_history_with_store(&mut self, store: &ReportStore) {
        if let Err(err) = store.prune_preview_only_runs() {
            self.history_runs.clear();
            self.history_events.clear();
            self.history_packages.clear();
            self.history_selected_run_id = None;
            self.history_package_selected = None;
            self.history_status = Some(format!("History unavailable: {err}"));
            self.history_dirty = false;
            return;
        }

        match store.list_runs(50) {
            Ok(runs) => {
                let previous = self.history_selected_run_id.clone();
                self.history_runs = runs;
                self.history_status = None;

                let selected = previous
                    .filter(|run_id| self.history_runs.iter().any(|run| &run.run_id == run_id))
                    .or_else(|| self.history_runs.first().map(|run| run.run_id.clone()));

                self.history_selected_run_id = selected.clone();
                match selected {
                    Some(run_id) => {
                        self.history_events = store.load_events(&run_id).unwrap_or_default();
                        self.history_packages = store.load_packages(&run_id).unwrap_or_default();
                    }
                    None => {
                        self.history_events = Vec::new();
                        self.history_packages = Vec::new();
                    }
                };
                self.history_package_selected = None;
            }
            Err(err) => {
                self.history_runs.clear();
                self.history_events.clear();
                self.history_packages.clear();
                self.history_selected_run_id = None;
                self.history_package_selected = None;
                self.history_status = Some(format!("History unavailable: {err}"));
            }
        }

        self.history_dirty = false;
    }

    pub(crate) fn ensure_history_loaded(&mut self) {
        if self.history_dirty {
            self.refresh_history();
        }
    }

    pub(crate) fn refresh_health(&mut self) {
        self.health_state.running = true;
        spawn_health_check(self.tx.clone());
    }

    pub(crate) fn select_history_run(&mut self, run_id: String) {
        let same_selection = self.history_selected_run_id.as_deref() == Some(run_id.as_str());
        let same_loaded_context =
            self.state.loaded_canonical_run_id.as_deref() == Some(run_id.as_str());
        if same_selection && same_loaded_context {
            return;
        }

        match ReportStore::new() {
            Ok(store) => self.select_history_run_with_store(run_id, &store),
            Err(err) => {
                self.history_selected_run_id = Some(run_id);
                self.history_events.clear();
                self.history_packages.clear();
                self.history_package_selected = None;
                self.history_status = Some(format!("Could not load events: {err}"));
            }
        }
    }

    fn select_history_run_with_store(&mut self, run_id: String, store: &ReportStore) {
        self.history_selected_run_id = Some(run_id.clone());
        self.state.restore_loaded_canonical_run_id(run_id.clone());
        match store.load_events(&run_id) {
            Ok(events) => {
                self.history_events = events;
                self.history_packages = store.load_packages(&run_id).unwrap_or_default();
                self.history_package_selected = None;
                self.history_status = None;
            }
            Err(err) => {
                self.history_events.clear();
                self.history_packages.clear();
                self.history_package_selected = None;
                self.state
                    .clear_loaded_canonical_run_id_if_matching(&run_id);
                self.history_status = Some(format!("Could not load events: {err}"));
            }
        }
    }
}

fn default_secret_ref_for_provider(provider: AiProviderKind) -> &'static str {
    match provider {
        AiProviderKind::NoneSelected => "",
        AiProviderKind::OpenAi => "openai_default",
        AiProviderKind::Anthropic => "anthropic_default",
        AiProviderKind::Custom => "custom_default",
    }
}

fn selected_provider_config(ai_settings: &AiSettings) -> Option<&AiProviderConfig> {
    provider_config_for_kind(ai_settings, ai_settings.selected_provider)
}

fn provider_config_for_kind(
    ai_settings: &AiSettings,
    provider: AiProviderKind,
) -> Option<&AiProviderConfig> {
    ai_settings
        .provider_configs
        .iter()
        .find(|config| config.metadata.kind == provider)
}

fn provider_config_for_kind_mut(
    ai_settings: &mut AiSettings,
    provider: AiProviderKind,
) -> Option<&mut AiProviderConfig> {
    ai_settings
        .provider_configs
        .iter_mut()
        .find(|config| config.metadata.kind == provider)
}

fn selected_provider_config_mut(ai_settings: &mut AiSettings) -> Option<&mut AiProviderConfig> {
    provider_config_for_kind_mut(ai_settings, ai_settings.selected_provider)
}

pub(crate) fn ai_enabled(ai_settings: &AiSettings) -> bool {
    ai_settings.selected_provider != AiProviderKind::NoneSelected
}

fn ai_provider_is_available(ai_settings: &AiSettings) -> bool {
    if !ai_enabled(ai_settings) {
        return false;
    }
    selected_provider_config(ai_settings)
        .map(|config| config.enabled && provider_for_config(config).is_some())
        .unwrap_or(false)
}

fn ai_key_source_configured(
    ai_settings: &AiSettings,
    ai_configuration: &AiConfigurationUiState,
) -> bool {
    if !ai_configuration.draft_api_key.trim().is_empty() {
        return true;
    }

    selected_provider_config(ai_settings)
        .map(|config| {
            config
                .connection
                .api_key_file_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
                || config
                    .connection
                    .api_key_env_var
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some()
        })
        .unwrap_or(false)
}

fn ai_selected_model_is_valid(
    ai_settings: &AiSettings,
    ai_configuration: &AiConfigurationUiState,
) -> bool {
    let Some(selected_model_id) = ai_configuration.selected_model_id.as_deref() else {
        return false;
    };
    selected_provider_config(ai_settings)
        .map(|config| {
            config
                .available_models
                .iter()
                .any(|model| model.id == selected_model_id)
        })
        .unwrap_or(false)
}

pub(crate) fn ai_ux_state(
    ai_settings: &AiSettings,
    ai_configuration: &AiConfigurationUiState,
) -> AiUxState {
    if !ai_provider_is_available(ai_settings) {
        return AiUxState::NoProvider;
    }
    if !ai_key_source_configured(ai_settings, ai_configuration) {
        return AiUxState::NoKeyConfigured;
    }
    let Some(config) = selected_provider_config(ai_settings) else {
        return AiUxState::NoProvider;
    };
    if config.available_models.is_empty() {
        return AiUxState::ModelsUnavailable;
    }
    if ai_configuration.selected_model_id.is_none()
        || !ai_selected_model_is_valid(ai_settings, ai_configuration)
    {
        return AiUxState::ModelNotSelected;
    }
    match ai_configuration.connection_status.as_str() {
        AI_LABEL_AVAILABLE => AiUxState::Ready,
        AI_LABEL_NOT_AVAILABLE => AiUxState::NotAvailable,
        _ => AiUxState::NotTested,
    }
}

fn remembered_model_id(ai_settings: &AiSettings, provider: AiProviderKind) -> Option<String> {
    ai_settings
        .last_selected_model_by_provider
        .iter()
        .find(|(kind, _)| *kind == provider)
        .map(|(_, model_id)| model_id.clone())
}

fn set_last_selected_model_for_provider(
    ai_settings: &mut AiSettings,
    provider: AiProviderKind,
    model_id: Option<String>,
) {
    ai_settings
        .last_selected_model_by_provider
        .retain(|(kind, _)| *kind != provider);
    if let Some(model_id) = model_id {
        ai_settings
            .last_selected_model_by_provider
            .push((provider, model_id));
    }
}

fn clear_last_selected_model_for_provider(ai_settings: &mut AiSettings, provider: AiProviderKind) {
    set_last_selected_model_for_provider(ai_settings, provider, None);
}

fn resolve_selected_model_id(ai_settings: &AiSettings) -> Option<String> {
    let provider = ai_settings.selected_provider;
    let config = selected_provider_config(ai_settings)?;
    let remembered = remembered_model_id(ai_settings, provider);
    if let Some(remembered) = remembered {
        if config
            .available_models
            .iter()
            .any(|model| model.id == remembered)
        {
            return Some(remembered);
        }
        return None;
    }
    config
        .available_models
        .first()
        .map(|model| model.id.clone())
}

fn selected_model_label_for_settings(
    ai_settings: &AiSettings,
    selected_model_id: Option<&str>,
) -> String {
    let Some(config) = selected_provider_config(ai_settings) else {
        return AI_LABEL_SELECT_MODEL.to_string();
    };
    if let Some(selected_model_id) = selected_model_id {
        if let Some(model) = config
            .available_models
            .iter()
            .find(|model| model.id == selected_model_id)
        {
            return model.display_name.clone();
        }
    }
    config
        .available_models
        .first()
        .map(|model| model.display_name.clone())
        .unwrap_or_else(|| AI_LABEL_SELECT_MODEL.to_string())
}

fn apply_loaded_models(
    ai_settings: &mut AiSettings,
    ai_configuration: &mut AiConfigurationUiState,
    models: Vec<AiModelDescriptor>,
) {
    let provider = ai_settings.selected_provider;
    if let Some(config) = selected_provider_config_mut(ai_settings) {
        config.available_models = models;
    }
    let selected_model_id = resolve_selected_model_id(ai_settings);
    set_last_selected_model_for_provider(ai_settings, provider, selected_model_id.clone());
    ai_configuration.selected_model_id = selected_model_id.clone();
    ai_configuration.selected_model_label =
        selected_model_label_for_settings(ai_settings, selected_model_id.as_deref());
}

fn set_selected_model(
    ai_settings: &mut AiSettings,
    ai_configuration: &mut AiConfigurationUiState,
    model_id: String,
) {
    let provider = ai_settings.selected_provider;
    set_last_selected_model_for_provider(ai_settings, provider, Some(model_id.clone()));
    ai_configuration.selected_model_id = Some(model_id.clone());
    ai_configuration.selected_model_label =
        selected_model_label_for_settings(ai_settings, Some(model_id.as_str()));
}

fn resolve_ai_test_api_key<R, E>(
    config: &AiProviderConfig,
    ai_configuration: &AiConfigurationUiState,
    resolver: &R,
    env_lookup: E,
) -> Result<Option<String>, String>
where
    R: SecretResolver,
    E: FnOnce(&str) -> Option<String>,
{
    if let Some(draft_key) =
        Some(ai_configuration.draft_api_key.trim()).filter(|value| !value.is_empty())
    {
        return Ok(Some(draft_key.to_string()));
    }

    if let Some(env_var) = config
        .connection
        .api_key_env_var
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(value) = env_lookup(env_var) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
    }

    let Some(secret_ref) = config
        .connection
        .api_key_file_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    resolver.read_secret(secret_ref).map(|value| {
        value
            .map(|secret| secret.trim().to_string())
            .filter(|secret| !secret.is_empty())
    })
}

#[cfg(test)]
fn test_ai_provider_connection<R, F>(
    ai_settings: &AiSettings,
    ai_configuration: &AiConfigurationUiState,
    resolver: &R,
    tester: F,
) -> Result<String, String>
where
    R: SecretResolver,
    F: FnOnce(
        &AiProviderConfig,
        Option<&str>,
    ) -> Result<(bool, Option<String>, Option<Vec<AiModelDescriptor>>), String>,
{
    test_ai_provider_connection_with_env(
        ai_settings,
        ai_configuration,
        resolver,
        |_name| None,
        tester,
    )
    .map(|(status, _detail, _models)| status)
}

fn test_ai_provider_connection_with_env<R, E, F>(
    ai_settings: &AiSettings,
    ai_configuration: &AiConfigurationUiState,
    resolver: &R,
    env_lookup: E,
    tester: F,
) -> Result<(String, Option<String>, Option<Vec<AiModelDescriptor>>), String>
where
    R: SecretResolver,
    E: FnOnce(&str) -> Option<String>,
    F: FnOnce(
        &AiProviderConfig,
        Option<&str>,
    ) -> Result<(bool, Option<String>, Option<Vec<AiModelDescriptor>>), String>,
{
    let config = selected_provider_config(ai_settings).ok_or_else(|| {
        format!(
            "selected AI provider is not configured: {:?}",
            ai_settings.selected_provider
        )
    })?;
    let resolved_api_key = resolve_ai_test_api_key(config, ai_configuration, resolver, env_lookup)?;
    if resolved_api_key.is_none() {
        return Ok((
            AI_LABEL_NOT_TESTED.to_string(),
            Some(AI_NO_KEY_CONFIGURED_DETAIL.to_string()),
            None,
        ));
    }
    let (available, detail, models) = tester(config, resolved_api_key.as_deref())?;
    Ok((
        if available {
            AI_LABEL_AVAILABLE.to_string()
        } else {
            AI_LABEL_NOT_AVAILABLE.to_string()
        },
        detail,
        models,
    ))
}

fn ensure_selected_provider_secret_ref(ai_settings: &mut AiSettings) -> Result<String, String> {
    let provider = ai_settings.selected_provider;
    if provider == AiProviderKind::NoneSelected {
        return Err("no AI provider selected".to_string());
    }
    let config = provider_config_for_kind_mut(ai_settings, provider)
        .ok_or_else(|| format!("selected AI provider is not configured: {provider:?}"))?;

    if config
        .connection
        .api_key_file_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        config.connection.api_key_file_name =
            Some(default_secret_ref_for_provider(provider).to_string());
    }

    config
        .connection
        .api_key_file_name
        .clone()
        .ok_or_else(|| format!("selected AI provider has no secret ref: {provider:?}"))
}

fn selected_provider_secret_ref_for_settings(
    ai_settings: &AiSettings,
    provider: AiProviderKind,
) -> Option<String> {
    ai_settings
        .provider_configs
        .iter()
        .find(|config| config.metadata.kind == provider)
        .and_then(|config| config.connection.api_key_file_name.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

struct StorageMigrationPlan {
    old_secret_ref: String,
    notice: Option<String>,
}

fn migrate_secret_between_resolvers<RFrom, RTo>(
    from_resolver: &RFrom,
    to_resolver: &RTo,
    old_secret_ref: &str,
    new_secret_ref: &str,
) -> Result<Option<StorageMigrationPlan>, String>
where
    RFrom: SecretResolver,
    RTo: SecretResolver,
{
    let existing = from_resolver.read_secret(old_secret_ref)?;
    let Some(secret) = existing
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(Some(StorageMigrationPlan {
            old_secret_ref: old_secret_ref.to_string(),
            notice: Some(AI_STORAGE_MIGRATION_REENTER_MESSAGE.to_string()),
        }));
    };

    to_resolver.write_secret(new_secret_ref, &secret)?;
    Ok(Some(StorageMigrationPlan {
        old_secret_ref: old_secret_ref.to_string(),
        notice: Some(
            "Storage location updated. Your saved API key was moved successfully.".to_string(),
        ),
    }))
}

fn persist_ai_configuration<RPrev, R, F>(
    previous_settings: &AiSettings,
    previous_resolver: Option<&RPrev>,
    ai_settings: &mut AiSettings,
    ai_configuration: &mut AiConfigurationUiState,
    resolver: &R,
    save_settings_fn: F,
) -> Result<Option<String>, String>
where
    RPrev: SecretResolver,
    R: SecretResolver,
    F: FnOnce(&AiSettings) -> Result<(), String>,
{
    let trimmed_key = ai_configuration.draft_api_key.trim().to_string();
    let storage_mode_changed = previous_settings.storage_mode != ai_settings.storage_mode;
    let selected_provider = ai_settings.selected_provider;
    let mut migration_plan = None;
    let mut notice = None;

    if storage_mode_changed
        && selected_provider != AiProviderKind::NoneSelected
        && trimmed_key.is_empty()
        && previous_settings.selected_provider == selected_provider
    {
        if let Some(old_secret_ref) =
            selected_provider_secret_ref_for_settings(previous_settings, selected_provider)
        {
            let new_secret_ref = ensure_selected_provider_secret_ref(ai_settings)?;
            let previous_resolver = previous_resolver.ok_or_else(|| {
                "could not migrate the stored API key to the new storage mode. Re-enter the API key to finish switching storage mode.".to_string()
            })?;
            migration_plan = migrate_secret_between_resolvers(
                previous_resolver,
                resolver,
                &old_secret_ref,
                &new_secret_ref,
            )
            .map_err(|err| {
                format!(
                    "could not migrate the stored API key to the new storage mode: {err}. Re-enter the API key to finish switching storage mode."
                )
            })?;
            if let Some(plan) = &migration_plan {
                notice = plan.notice.clone();
            }
        }
    }

    if !trimmed_key.is_empty() {
        let secret_ref = ensure_selected_provider_secret_ref(ai_settings)?;
        resolver.write_secret(&secret_ref, &trimmed_key)?;
        if storage_mode_changed
            && selected_provider != AiProviderKind::NoneSelected
            && previous_settings.selected_provider == selected_provider
        {
            if let Some(old_secret_ref) =
                selected_provider_secret_ref_for_settings(previous_settings, selected_provider)
            {
                migration_plan = Some(StorageMigrationPlan {
                    old_secret_ref,
                    notice: Some(
                        "Storage location updated. Your API key was saved in the new location."
                            .to_string(),
                    ),
                });
                notice = migration_plan.as_ref().and_then(|plan| plan.notice.clone());
            }
        }
    }

    save_settings_fn(ai_settings)?;
    if let Some(plan) = migration_plan {
        let Some(old_resolver) = previous_resolver else {
            ai_configuration.draft_api_key.clear();
            return Ok(Some(format!(
                "{} Old stored API key could not be removed automatically.",
                notice
                    .clone()
                    .unwrap_or_else(|| "Storage location updated.".to_string())
            )));
        };
        if let Err(err) = old_resolver.delete_secret(&plan.old_secret_ref) {
            notice = Some(format!(
                "{} Old stored API key could not be removed: {err}",
                notice
                    .clone()
                    .unwrap_or_else(|| "Storage location updated.".to_string())
            ));
        }
    }
    ai_configuration.draft_api_key.clear();
    Ok(notice)
}

impl eframe::App for MaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events(ctx);
        ctx.request_repaint_after(Duration::from_secs(1));
        let sudo_modal_open = self.sudo_session.show_sudo_modal;
        let execution_modal_open = self.execution_runner_modal.visible;
        let ui_blocked = sudo_modal_open || execution_modal_open;

        if !self.state.btrfs_available && self.state.active_tab == Tab::Btrfs {
            self.state.active_tab = Tab::Health;
        }

        if self.state.ai_state.enabled && !self.state.ai_state.preflight_ok {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.state.package_manager.busy || self.state.package_manager.busy_preview {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.state.preview_running {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if self.execution_runner_modal.visible {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        if ctx.input(|i| i.modifiers.ctrl && !i.modifiers.shift && i.key_pressed(egui::Key::Q)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if !ui_blocked
            && ctx.input(|i| i.modifiers.ctrl && !i.modifiers.shift && i.key_pressed(egui::Key::R))
        {
            self.request_refresh_preview();
        }
        if !ui_blocked && ctx.input(|i| i.key_pressed(egui::Key::L) && i.modifiers.ctrl) {
            self.console_open = !self.console_open;
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_enabled_ui(!ui_blocked, |ui| {
                ui.horizontal(|ui| {
                    brand_wordmark(ui);
                    ui.add_space(10.0);
                    tab_button(ui, &mut self.state.active_tab, Tab::Health, "Health");
                    tab_button(ui, &mut self.state.active_tab, Tab::TriageAi, "Triage & AI");
                    tab_button(ui, &mut self.state.active_tab, Tab::Reports, "Reports");
                    if self.state.btrfs_available {
                        tab_button(ui, &mut self.state.active_tab, Tab::Btrfs, "Btrfs");
                    }
                    tab_button(
                        ui,
                        &mut self.state.active_tab,
                        Tab::PackageManager,
                        "Package Manager",
                    );
                    tab_button(
                        ui,
                        &mut self.state.active_tab,
                        Tab::Configuration,
                        "Configuration",
                    );
                    tab_button(ui, &mut self.state.active_tab, Tab::About, "About");
                    if nav_button(ui, self.console_open, "Logs").clicked() {
                        self.console_open = !self.console_open;
                    }
                });
                ui.horizontal(|ui| {
                    let status = if self.has_valid_sudo_session() {
                        "Sudo: ready for this session"
                    } else {
                        "Sudo: not set"
                    };
                    ui.label(status);
                    if ui.button("Enter sudo password").clicked() {
                        self.open_sudo_modal(None);
                    }
                });
            });
        });

        if !self.settings.legal.disclaimer_acknowledged {
            egui::TopBottomPanel::top("disclaimer_acknowledgement").show(ctx, |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.strong(ACKNOWLEDGEMENT_TITLE);
                        ui.label(DISCLAIMER_TEXT.trim());
                        ui.horizontal(|ui| {
                            if ui.button("Acknowledge").clicked() {
                                self.acknowledge_disclaimer();
                            }
                            if ui.button("Review in About").clicked() {
                                self.state.active_tab = Tab::About;
                            }
                        });
                    });
                });
            });
        }

        if let Some(title) = self.pending_action_title() {
            let detail = self.pending_action_detail().unwrap_or_default();
            egui::TopBottomPanel::top("execution_confirmation").show(ctx, |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(title);
                        if !detail.is_empty() {
                            ui.label(detail);
                        }
                        if ui.button("Confirm").clicked() {
                            self.confirm_pending_action();
                        }
                        if ui.button("Cancel").clicked() {
                            self.cancel_pending_action();
                        }
                    });
                });
            });
        }

        let health_tab_active = matches!(self.state.active_tab, Tab::Health);
        if health_tab_active && !self.was_health_tab_active && !self.health_state.running {
            if self.suppress_initial_health_refresh {
                self.suppress_initial_health_refresh = false;
            } else {
                self.refresh_health();
            }
        }
        self.was_health_tab_active = health_tab_active;

        if self.health_state.last_update.elapsed() > Duration::from_secs(30) {
            spawn_system_pulse(self.tx.clone());
            self.health_state.last_update = Instant::now();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!ui_blocked, |ui| match self.state.active_tab {
                Tab::Health => tabs::health::show(ui, self),
                Tab::TriageAi => tabs::triage_ai::ui(self, ctx, ui),
                Tab::Reports => tabs::reports::ui(self, ctx, ui),
                Tab::Btrfs => tabs::btrfs::ui(self, ctx, ui),
                Tab::PackageManager => tabs::package_manager::ui(self, ctx, ui),
                Tab::Configuration => tabs::settings::ui(self, ctx, ui),
                Tab::About => tabs::about::ui(self, ctx, ui),
            });
        });

        if self.console_open {
            egui::TopBottomPanel::bottom("log_console")
                .resizable(true)
                .default_height(self.console_height)
                .show(ctx, |ui| {
                    ui.add_enabled_ui(!ui_blocked, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Logs");

                            if ui.button("Export log").clicked() {
                                tabs::reports::export_updates_log(self);
                            }

                            if ui.button("Clear").clicked() {
                                self.state.logs.clear();
                            }

                            if ui.button("Close").clicked() {
                                self.console_open = false;
                            }
                        });

                        ui.separator();

                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                render_log_table(ui, &self.state.logs);
                            });
                    });
                });
        }

        self.show_execution_runner_modal(ctx);

        if sudo_modal_open {
            let pending_label = self
                .sudo_session
                .pending_privileged_action
                .as_ref()
                .map(|action| self.pending_action_title_for(action));
            let is_startup_prompt = self.sudo_session.startup_prompt_active;
            egui::Window::new("Sudo Password")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.set_min_width(420.0);
                    ui.label("This app can perform privileged maintenance tasks. You may enter your sudo password now, or continue and provide it only when required.");
                    if let Some(label) = pending_label {
                        ui.add_space(6.0);
                        ui.label(format!("Pending action: {label}"));
                    }
                    ui.add_space(8.0);
                    ui.label("Sudo password");
                    let password_input = ui.add(
                        egui::TextEdit::singleline(&mut self.sudo_session.password_input)
                            .password(true)
                            .desired_width(320.0),
                    );
                    password_input.request_focus();
                    ui.checkbox(
                        &mut self.sudo_session.remember_for_session,
                        "Remember for this session",
                    );
                    if let Some(error) = &self.sudo_session.last_auth_error {
                        ui.add_space(6.0);
                        ui.colored_label(egui::Color32::YELLOW, error);
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            self.handle_sudo_confirm();
                        }
                        if ui.button("Skip for now").clicked() {
                            self.handle_sudo_skip();
                        }
                        if ui.button("Cancel").clicked() {
                            if is_startup_prompt {
                                self.handle_sudo_cancel(ctx);
                            } else {
                                self.sudo_session.pending_privileged_action = None;
                                self.sudo_session.show_sudo_modal = false;
                                self.sudo_session.startup_prompt_active = false;
                                self.sudo_session.last_auth_error = None;
                                self.sudo_session.password_input.clear();
                            }
                        }
                    });
                });
        }

        if let Some(dialog) = self.state.info_dialog.clone() {
            let title = dialog.title;
            let message = dialog.message;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.set_min_width(320.0);
                    ui.label(message);
                    ui.add_space(8.0);
                    if ui.button("OK").clicked() {
                        self.state.dismiss_info_dialog();
                    }
                });
        }

        if self.system_workbook_export.show_warning_modal {
            egui::Window::new("System workbook export")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.set_min_width(360.0);
                    ui.label("This may take time while system information is collected.");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            self.confirm_system_workbook_export();
                        }
                        if ui.button("Cancel").clicked() {
                            self.cancel_system_workbook_export();
                        }
                    });
                });
        }

        if self.state.active_tab != self.last_persisted_tab {
            self.last_persisted_tab = self.state.active_tab;
            self.persist_settings();
        }
    }
}

fn spawn_health_check(tx: Sender<Event>) {
    thread::spawn(move || {
        let report = collect_health_report();
        tx.send(Event::HealthReport(report)).ok();
    });
}

fn spawn_system_pulse(tx: Sender<Event>) {
    thread::spawn(move || {
        let pulse = collect_system_pulse();
        tx.send(Event::SystemPulse(pulse)).ok();
    });
}

fn spawn_telemetry_worker(tx: Sender<Event>) {
    thread::spawn(move || {
        let mut previous_cpu_sample = read_cpu_stat_sample();
        loop {
            let current_cpu_sample = read_cpu_stat_sample();
            let cpu_percent = match (previous_cpu_sample, current_cpu_sample) {
                (Some(previous), Some(current)) => {
                    cpu_percent_from_samples(previous, current).unwrap_or(0.0)
                }
                _ => 0.0,
            };
            previous_cpu_sample = current_cpu_sample;

            let pulse = collect_system_pulse();
            let telemetry = SystemTelemetry {
                cpu_percent,
                mem_used_gb: pulse.mem_used_gb,
                mem_total_gb: pulse.mem_total_gb,
                root_fs_percent: (pulse.root_disk_ratio * 100.0).clamp(0.0, 100.0),
            };
            if tx.send(Event::TelemetryUpdate(telemetry)).is_err() {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

#[derive(Clone, Copy)]
struct CpuStatSample {
    total: u64,
    idle: u64,
}

fn read_cpu_stat_sample() -> Option<CpuStatSample> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let mut fields = line.split_whitespace();
    let _cpu_label = fields.next()?;
    let values = fields
        .take(10)
        .map(|value| value.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;

    let total = values.iter().sum();
    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);

    Some(CpuStatSample { total, idle })
}

fn cpu_percent_from_samples(previous: CpuStatSample, current: CpuStatSample) -> Option<f32> {
    let delta_total = current.total.saturating_sub(previous.total);
    if delta_total == 0 {
        return None;
    }

    let delta_idle = current.idle.saturating_sub(previous.idle);
    let usage = (delta_total.saturating_sub(delta_idle)) as f32 / delta_total as f32;
    Some((usage * 100.0).clamp(0.0, 100.0))
}

pub(crate) fn yes_no(v: bool) -> &'static str {
    if v {
        "Yes"
    } else {
        "No"
    }
}

/// Categorise packages like your Python script: stable buckets that help AI + UI.
fn category_for(pkg_name: &str) -> &'static str {
    let n = pkg_name.to_lowercase();

    if n.starts_with("kernel")
        || n.contains("dracut")
        || n.contains("grub")
        || n.contains("systemd-boot")
        || n.contains("shim")
        || n.contains("mokutil")
    {
        "Kernel & Boot"
    } else if n.contains("mesa")
        || n.contains("nvidia")
        || n.contains("vulkan")
        || n.contains("libdrm")
        || n.contains("xf86")
    {
        "Graphics"
    } else if n.contains("ffmpeg")
        || n.contains("libav")
        || n.contains("pipewire")
        || n.contains("pulseaudio")
        || n.contains("gstreamer")
        || n.contains("libheif")
        || n.contains("openh264")
        || n.contains("codec")
    {
        "Multimedia"
    } else if n.contains("glibc")
        || n.contains("systemd")
        || n.contains("openssl")
        || n.contains("dbus")
        || n.contains("util-linux")
        || n.contains("rpm")
        || n.contains("zypper")
        || n.contains("sudo")
    {
        "Core System"
    } else if n.contains("plasma")
        || n.contains("kwin")
        || n.contains("kde")
        || n.contains("gnome")
        || n.contains("gtk")
        || n.contains("qt")
    {
        "Desktop"
    } else {
        "Other"
    }
}

pub(crate) fn reboot_recommended_from_plan(
    changes: &[chamrisk_core::models::PackageChange],
) -> bool {
    changes.iter().any(|c| {
        let n = c.name.to_lowercase();
        n.starts_with("kernel")
            || n.starts_with("systemd")
            || n.starts_with("glibc")
            || n.starts_with("dbus")
            || n.starts_with("udev")
            || n.starts_with("linux-firmware")
    })
}

pub(crate) fn count_kernel_core(
    changes: &[chamrisk_core::models::PackageChange],
) -> (usize, usize) {
    let mut kernel = 0;
    let mut core = 0;

    for c in changes {
        let cat = category_for(&c.name);
        if cat == "Kernel & Boot" {
            kernel += 1;
        }
        if cat == "Core System" {
            core += 1;
        }
    }

    (kernel, core)
}

/// Build ONE payload that makes the model treat the update as a single “upgrade event”
/// and provides signals so it doesn’t use “if/might” politics.
pub(crate) fn build_ai_payload_from_plan(
    changes: &[chamrisk_core::models::PackageChange],
    snapshot_selected: bool,
    packman_preference_selected: bool,
    reboot_recommended: bool,
    kernel_count: usize,
    core_count: usize,
) -> String {
    let total = changes.len();
    let canonical_risk = assess_risk(
        &changes
            .iter()
            .map(package_change_as_update)
            .collect::<Vec<_>>(),
    );
    let recommendation_themes =
        build_recommendation_themes(changes, reboot_recommended, canonical_risk.level);

    let repos: Vec<String> = {
        let mut v: Vec<String> = changes.iter().filter_map(|c| c.repo.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let has_packman = repos.iter().any(|r| r.to_lowercase().contains("packman"));

    // Bucket into categories
    let mut buckets: BTreeMap<&'static str, Vec<&chamrisk_core::models::PackageChange>> =
        BTreeMap::new();
    for c in changes {
        buckets.entry(category_for(&c.name)).or_default().push(c);
    }

    let categories_json: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(cat, items)| {
            let pkgs: Vec<serde_json::Value> = items
                .into_iter()
                .map(|c| {
                    json!({
                        "name": c.name,
                        "action": format!("{:?}", c.action),
                        "from": c.from.as_deref().unwrap_or(""),
                        "to": c.to.as_deref().unwrap_or(""),
                        "repo": c.repo.as_deref().unwrap_or(""),
                        "vendor": c.vendor.as_deref().unwrap_or(""),
                        "arch": c.arch.as_deref().unwrap_or(""),
                        "kind": c.kind.as_deref().unwrap_or("")
                    })
                })
                .collect();

            json!({
                "category": cat,
                "count": pkgs.len(),
                "packages": pkgs
            })
        })
        .collect();

    json!({
        "package_count": total,
        "context": {
            "distro": "openSUSE Tumbleweed",
            "operation": "zypper_dup_preview",
            "generated_at": Utc::now().to_rfc3339()
        },
        "plan_summary": {
            "total_packages": total,
            "repositories": repos,
            "has_packman": has_packman,
            "kernel_updates": kernel_count,
            "core_system_updates": core_count
        },
        "canonical_risk": {
            // Canonical transaction risk comes from core::risk::assess_risk().
            "level": format!("{:?}", canonical_risk.level),
            "score_sum": canonical_risk.score_sum,
            "score_max": canonical_risk.score_max,
            "reasons": canonical_risk.reasons
        },
        "recommendation_themes": recommendation_themes,
        "signals": {
            "snapshot_selected": snapshot_selected,
            "packman_preference_selected": packman_preference_selected,
            "reboot_recommended": reboot_recommended
        },
        "categories": categories_json,
        "request": {
            "goal": "Minimise risk of applying the full update plan",
            "output_format": "Exactly 6 lines only: line 1 is Risk: Green|Amber|Red; lines 2-6 are actions numbered 1) through 5).",
            "constraints": [
                "Do not add commentary or extra lines.",
                "Do not use these words in actions: careful, validate, consider, ensure, might, warrant.",
                "Do not mention vendor unless vendor-change data is explicitly present.",
                "Use the signals provided (snapshot_selected, reboot_recommended, packman flags).",
                "Use recommendation_themes as the primary source for the runbook.",
                "Suppress irrelevant checks when their package families are absent.",
                "Line 2 must be Pre-update safeguards.",
                "Line 3 must be Update execution.",
                "Line 4 must be Post-reboot core validation.",
                "Line 5 must be Post-reboot functional validation.",
                "Line 6 must be Optional deeper checks."
            ],
            "include": [
                "confirm whether snapshot is already selected; if not, instruct to enable it",
                "packman guidance when packman is present (repo mixing/origin conflicts)",
                "explicit reboot guidance based on reboot_recommended",
                "canonical_risk: use level and reasons as the base risk signal",
                "recommendation_themes: derive each runbook phase from affected package families only",
                "produce a practical cautious-desktop runbook, not generic advice"
            ]
        }
    }).to_string()
}

fn package_change_as_update(change: &PackageChange) -> PackageUpdate {
    PackageUpdate {
        name: change.name.clone(),
        action: change.action.clone(),
        current_version: change.from.clone(),
        new_version: change.to.clone(),
        arch: change.arch.clone(),
        repository: change.repo.clone(),
        vendor: change.vendor.clone(),
        vendor_group: VendorGroup::Unknown,
        vendor_change: change_field_has_transition(change.vendor.as_deref())
            || change.action == UpdateAction::VendorChange,
        repo_change: change_field_has_transition(change.repo.as_deref())
            || change.action == UpdateAction::RepoChange,
    }
}

fn change_field_has_transition(value: Option<&str>) -> bool {
    value.map(|s| s.contains("->")).unwrap_or(false)
}

fn build_recommendation_themes(
    changes: &[PackageChange],
    reboot_recommended: bool,
    risk_level: RiskLevel,
) -> serde_json::Value {
    let families = detected_package_families(changes);
    let has_system_services = families.contains("system-services");
    let has_boot_chain = families.contains("boot-chain");
    let has_runtime_libs = families.contains("runtime-libs");
    let has_graphics = families.contains("graphics-session");
    let has_networking = families.contains("networking");
    let has_media = families.contains("media-audio");
    let has_codec = families.contains("codec-image");
    let mut pre_update = Vec::new();
    let mut update_execution = Vec::new();
    let mut post_reboot_core = Vec::new();
    let mut post_reboot_functional = Vec::new();
    let mut optional_deeper = Vec::new();

    match risk_level {
        RiskLevel::High => {
            if has_system_services || has_boot_chain || has_runtime_libs {
                pre_update.push(
                    "Create a fresh Btrfs snapshot before this core-system update.".to_string(),
                );
                pre_update.push(
                    "Plan a reboot window and avoid starting the update if you need the machine right away."
                        .to_string(),
                );
            } else {
                pre_update.push(
                    "Make sure you can roll back easily before this higher-risk update."
                        .to_string(),
                );
            }

            update_execution.push(
                "Run the update in one session. Stop and review if the solver proposes unexpected removals or vendor/repository changes."
                    .to_string(),
            );
            if has_boot_chain {
                update_execution.push(
                    "Check the proposed kernel, initramfs, and bootloader changes before you confirm."
                        .to_string(),
                );
            }

            if has_system_services || has_boot_chain {
                post_reboot_core.push(
                    "Reboot immediately after the update completes and confirm the system boots normally.".to_string(),
                );
            } else {
                post_reboot_core.push(
                    "Confirm the system returns cleanly to the desktop after the update."
                        .to_string(),
                );
            }
            if has_system_services {
                post_reboot_core.push(
                    "Run `systemctl --failed` and review boot errors with `journalctl -b -p err`."
                        .to_string(),
                );
                post_reboot_functional.push(
                    "Check that input, storage, and network devices are detected normally."
                        .to_string(),
                );
            }
            if has_boot_chain {
                post_reboot_core.push(
                    "Confirm the bootloader menu appears and the updated entry boots cleanly."
                        .to_string(),
                );
                post_reboot_core.push(
                    "Confirm the initramfs hands off cleanly with no emergency shell or long boot delay."
                        .to_string(),
                );
            }
            if has_runtime_libs {
                post_reboot_functional.push(
                    "Launch several regularly used GUI and CLI applications. Watch for runtime or linker regressions."
                        .to_string(),
                );
                post_reboot_functional.push(
                    "Open a terminal and at least one browser or editor. Confirm they start normally."
                        .to_string(),
                );
            }
            if has_graphics {
                post_reboot_functional.push(
                    "Log out and back in to confirm the graphical session starts normally."
                        .to_string(),
                );
                post_reboot_functional.push(
                    "Check display acceleration, multi-monitor output, and window compositing."
                        .to_string(),
                );
            }
            if has_networking {
                post_reboot_functional.push(
                    "Check wired or wireless connectivity. Confirm DHCP, DNS resolution, and reconnect behaviour."
                        .to_string(),
                );
            }
            if has_media {
                post_reboot_functional.push(
                    "Play a short audio and video sample. Confirm media playback and device routing."
                        .to_string(),
                );
            }
            if has_codec {
                optional_deeper.push(
                    "Open a HEIF, AVIF, or other affected media sample in the default viewer."
                        .to_string(),
                );
            }
            if has_boot_chain || has_system_services {
                optional_deeper.push(
                    "Review the boot journal if anything behaves differently after the restart."
                        .to_string(),
                );
            }
        }
        RiskLevel::Medium => {
            if reboot_recommended || has_system_services || has_boot_chain {
                pre_update
                    .push("Save your work and plan for a reboot after the update.".to_string());
            }

            update_execution.push(
                "Run the update in one session. Stop if the solver proposes unexpected removals."
                    .to_string(),
            );

            if has_system_services {
                post_reboot_core.push(
                    "Reboot after the update. Then run `systemctl --failed` and `journalctl -b -p err`."
                        .to_string(),
                );
                post_reboot_functional.push(
                    "Confirm login still works. Check that devices are detected normally after the restart."
                        .to_string(),
                );
            } else if has_boot_chain {
                post_reboot_core.push(
                    "Reboot after the update and confirm the updated entry boots cleanly."
                        .to_string(),
                );
            } else {
                post_reboot_core
                    .push("Confirm the system returns cleanly after the update.".to_string());
            }

            if has_runtime_libs {
                post_reboot_functional.push(
                    "Launch a browser, terminal, and one daily-use application. Watch for runtime or linker regressions."
                        .to_string(),
                );
            }
            if has_graphics {
                post_reboot_functional.push(
                    "Log out and back in. Confirm display acceleration and compositing still work."
                        .to_string(),
                );
            }
            if has_networking {
                post_reboot_functional.push(
                    "Check connectivity on your usual network. Confirm DNS resolution and reconnect behaviour."
                        .to_string(),
                );
            }
            if has_media {
                post_reboot_functional.push(
                    "Play a short audio or video sample to confirm media playback still works."
                        .to_string(),
                );
            }
            if has_codec {
                optional_deeper.push(
                    "Open one affected image or media sample if you rely on that format regularly."
                        .to_string(),
                );
            }
        }
        RiskLevel::Low => {
            update_execution.push(
                "Run the update normally and stop only if something unexpected appears."
                    .to_string(),
            );
            if reboot_recommended {
                post_reboot_core.push(
                    "Reboot after the update and confirm the session comes back cleanly."
                        .to_string(),
                );
            } else {
                post_reboot_core
                    .push("Confirm the system comes back cleanly after the update.".to_string());
            }

            if has_runtime_libs {
                post_reboot_functional.push(
                    "Launch one GUI application and one terminal tool. Check for obvious runtime issues."
                        .to_string(),
                );
            } else if has_graphics {
                post_reboot_functional.push(
                    "Log out and back in once to confirm the desktop renders normally.".to_string(),
                );
            } else if has_networking {
                post_reboot_functional.push(
                    "Do a quick connectivity and DNS check on your usual network.".to_string(),
                );
            } else if has_media {
                post_reboot_functional.push(
                    "Play a short audio or video sample if you use that stack regularly."
                        .to_string(),
                );
            } else {
                post_reboot_functional
                    .push("Run a brief login, network, and app-launch sanity check.".to_string());
            }
            optional_deeper.push(
                "No deeper checks needed unless something behaves differently after the update."
                    .to_string(),
            );
        }
    }

    if post_reboot_core.is_empty() {
        post_reboot_core.push("Confirm the system returns cleanly after the update.".to_string());
    }

    if post_reboot_functional.is_empty() {
        post_reboot_functional.push(match risk_level {
            RiskLevel::Low => "Run a brief login, network, and app-launch sanity check.".to_string(),
            RiskLevel::Medium => {
                "Run the most relevant daily-use workflow once to confirm the updated area still works."
                    .to_string()
            }
            RiskLevel::High => {
                "Repeat the most important daily-use workflow after the reboot."
                    .to_string()
            }
        });
    }

    if optional_deeper.is_empty() {
        optional_deeper.push(match risk_level {
            RiskLevel::Low => {
                "No deeper checks needed unless something behaves differently after the update."
                    .to_string()
            }
            RiskLevel::Medium => {
                "If anything looks off, repeat the affected workflow once and check the relevant logs."
                    .to_string()
            }
            RiskLevel::High => {
                "If anything looks off, re-check logs and repeat the most affected workflow once more."
                    .to_string()
            }
        });
    }

    pre_update.dedup();
    update_execution.dedup();
    post_reboot_core.dedup();
    post_reboot_functional.dedup();
    optional_deeper.dedup();

    json!({
        "families": families.into_iter().collect::<Vec<_>>(),
        "risk_level": format!("{:?}", risk_level),
        "pre_update_safeguards": pre_update,
        "update_execution": update_execution,
        "post_reboot_core_validation": post_reboot_core,
        "post_reboot_functional_validation": post_reboot_functional,
        "optional_deeper_checks": optional_deeper,
    })
}

#[cfg(test)]
mod system_workbook_export_tests {
    use super::*;
    use chamrisk_core::models::{CommandResult, UpdatePlan};
    use chamrisk_ops::report_store::ReportStore;
    use chamrisk_ui::app::RiskFilter;
    use std::sync::mpsc::channel;
    use tempfile::tempdir;

    fn test_app() -> MaintenanceApp {
        let (tx, rx) = channel();
        let mut settings = AppSettings::default();
        settings.legal.disclaimer_acknowledged = true;
        let mut ai_settings = chamrisk_ui::default_ai_settings();
        ai_settings.selected_provider = AiProviderKind::OpenAi;

        MaintenanceApp {
            state: AppState::default(),
            settings,
            ai_settings,
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
            sudo_session: SudoSessionState {
                show_sudo_modal: false,
                startup_prompt_active: false,
                ..SudoSessionState::default()
            },
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
            refresh_preview_requested: false,
            system_dark_mode: false,
            suppress_initial_health_refresh: false,
            last_persisted_tab: Tab::Health,
            was_health_tab_active: false,
        }
    }

    fn test_report_store() -> (tempfile::TempDir, ReportStore) {
        let temp = tempdir().expect("tempdir");
        let store =
            ReportStore::with_db_path(temp.path().join("reports.sqlite")).expect("report store");
        (temp, store)
    }

    fn successful_run_summary(run_id: &str) -> chamrisk_ops::runner::RunSummary {
        chamrisk_ops::runner::RunSummary {
            verdict: "PASS".to_string(),
            attempted: 1,
            installed: 1,
            failed: 0,
            unaccounted: 0,
            process_run: Some(chamrisk_core::models::ProcessRun {
                run_id: run_id.to_string(),
                backend: chamrisk_core::models::PackageBackend::Zypper,
                command: "zypper".to_string(),
                args: Vec::new(),
                started_at_utc: "0".to_string(),
                ended_at_utc: Some("1".to_string()),
                duration_ms: Some(1),
                events: Vec::new(),
                summary: chamrisk_core::models::ProcessSummary {
                    process_name: "zypper".to_string(),
                    process_type: "update".to_string(),
                    status: chamrisk_core::models::ProcessStatus::Success,
                    reboot_recommended: false,
                    test_required: false,
                    summary_line: "Completed with exit code 0".to_string(),
                    exit_code: Some(0),
                    confidence: chamrisk_core::models::Confidence::Medium,
                    error_category: None,
                },
            }),
            reconcile: Some(chamrisk_core::models::ReconcileResult {
                run_id: run_id.to_string(),
                total_planned: 1,
                matched_success: 1,
                matched_failed: 0,
                skipped: 0,
                not_attempted: 0,
                ambiguous: 0,
                items: Vec::new(),
            }),
        }
    }

    fn ai_test_change(name: &str, action: UpdateAction) -> PackageChange {
        PackageChange {
            name: name.to_string(),
            arch: None,
            action,
            from: None,
            to: None,
            repo: None,
            vendor: None,
            kind: None,
        }
    }

    fn test_preview_plan() -> UpdatePlan {
        UpdatePlan {
            changes: vec![ai_test_change("mesa", UpdateAction::Upgrade)],
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
        }
    }

    #[test]
    fn system_workbook_export_click_opens_warning_modal_after_sudo_is_ready() {
        let mut app = test_app();
        app.sudo_session.sudo_password = Some("pw".to_string());
        app.sudo_session.sudo_validated = true;

        app.request_system_workbook_export();

        assert!(app.system_workbook_export.show_warning_modal);
        assert!(!app.system_workbook_export.running);
        assert!(!app.sudo_session.show_sudo_modal);
    }

    #[test]
    fn system_workbook_export_cancel_path_aborts_cleanly() {
        let mut app = test_app();
        app.sudo_session.sudo_password = Some("pw".to_string());
        app.sudo_session.sudo_validated = true;
        app.request_system_workbook_export();

        app.cancel_system_workbook_export();

        assert!(!app.system_workbook_export.show_warning_modal);
        assert!(!app.system_workbook_export.running);
        assert!(app.system_workbook_export.status.is_none());
    }

    #[test]
    fn system_workbook_export_sudo_cancel_aborts_before_warning_modal() {
        let mut app = test_app();
        let ctx = egui::Context::default();

        app.request_system_workbook_export();

        assert!(app.sudo_session.show_sudo_modal);
        assert!(matches!(
            app.sudo_session.pending_privileged_action,
            Some(PendingAction::PrepareSystemWorkbookExport)
        ));

        app.handle_sudo_cancel(&ctx);

        assert!(!app.sudo_session.show_sudo_modal);
        assert!(app.sudo_session.pending_privileged_action.is_none());
        assert!(!app.system_workbook_export.show_warning_modal);
        assert!(!app.system_workbook_export.running);
    }

    #[test]
    fn system_workbook_export_does_not_require_preloaded_tab_state() {
        let mut app = test_app();
        app.sudo_session.sudo_password = Some("pw".to_string());
        app.sudo_session.sudo_validated = true;
        assert!(app.state.btrfs_snapshots.is_empty());
        assert!(app.state.package_manager.rows.is_empty());

        app.request_system_workbook_export();

        assert!(app.system_workbook_export.show_warning_modal);
    }

    #[test]
    fn request_ai_triage_uses_explicit_run_id_without_reading_current_run_state() {
        let mut app = test_app();
        app.state.ai_state.enabled = false;
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.run_id = Some("stale-run-id".to_string());
        }

        app.request_ai_triage("{}".to_string(), Some("canonical-run-id".to_string()));
        assert!(matches!(
            app.pending_action.as_ref(),
            Some(PendingAction::RunAiTriage { run_id: Some(run_id), .. }) if run_id == "canonical-run-id"
        ));

        app.confirm_pending_action();

        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some("AI triage is disabled; continuing without triage")
        );
    }

    #[test]
    fn request_ai_triage_with_no_provider_selected_exits_cleanly() {
        let mut app = test_app();
        app.ai_settings.selected_provider = AiProviderKind::NoneSelected;

        app.request_ai_triage("{}".to_string(), Some("canonical-run-id".to_string()));
        app.confirm_pending_action();

        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE)
        );
    }

    #[test]
    fn clicking_ai_triage_without_active_canonical_run_does_not_create_run() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(super::AI_CANONICAL_RUN_REQUIRED_MESSAGE)
        );
        assert!(store.list_runs(10).expect("list runs").is_empty());
    }

    #[test]
    fn clicking_ai_triage_with_no_provider_selected_is_neutral() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
            .expect("start run");
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.run_id = Some(run_id);
        }
        app.ai_settings.selected_provider = AiProviderKind::NoneSelected;

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE)
        );
        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn clicking_ai_triage_with_no_key_configured_is_neutral() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
            .expect("start run");
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.run_id = Some(run_id);
        }
        app.ai_settings.selected_provider = AiProviderKind::OpenAi;
        app.ai_settings.provider_configs[0]
            .connection
            .api_key_file_name = None;
        app.ai_settings.provider_configs[0]
            .connection
            .api_key_env_var = None;

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(AI_TRIAGE_DISABLED_NO_KEY_MESSAGE)
        );
        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn clicking_ai_triage_with_no_provider_and_preview_plan_does_not_create_master_run() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.ai_settings.selected_provider = AiProviderKind::NoneSelected;
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.zypper_plan = Some(test_preview_plan());
        }

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(AI_TRIAGE_DISABLED_NO_PROVIDER_MESSAGE)
        );
        assert!(store.list_runs(10).expect("list runs").is_empty());
    }

    #[test]
    fn clicking_ai_triage_with_preview_plan_queues_ephemeral_assessment_without_history_row() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.zypper_plan = Some(test_preview_plan());
        }

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(matches!(
            app.pending_action.as_ref(),
            Some(PendingAction::RunAiTriage { run_id: None, .. })
        ));
        assert!(store.list_runs(10).expect("list runs").is_empty());
        assert_eq!(
            app.state
                .current_run
                .as_ref()
                .and_then(|run| run.run_id.as_deref()),
            None
        );
    }

    #[test]
    fn triage_execution_selection_maps_to_requested_tasks() {
        let mut app = test_app();
        app.state.execution_selection.snapshot_before_update = false;
        app.state.execution_selection.zypper_dup = false;
        app.state.execution_selection.packman_preference = true;
        app.state.execution_selection.flatpaks = true;
        app.state.execution_selection.journal_vacuum = true;
        app.state.risk_filter = RiskFilter::Amber;
        app.state.triage_repos = vec!["repo-oss".to_string(), "Packman Essentials".to_string()];

        let selection = app.selection_from_triage_state();

        assert!(!selection.snapshot_before_update);
        assert!(!selection.zypper_dup);
        assert!(selection.prefer_packman);
        assert!(selection.flatpak);
        assert!(selection.journal_vacuum);
        assert_eq!(selection.risk_filter, "amber");
        assert_eq!(selection.repos.len(), 2);
    }

    #[test]
    fn execution_request_from_triage_queues_selected_maintenance_tasks() {
        let mut app = test_app();
        app.settings.behavior.confirm_before_execution = true;
        app.sudo_session.sudo_password = Some("pw".to_string());
        app.sudo_session.sudo_validated = true;
        app.state.execution_selection.zypper_dup = false;
        app.state.execution_selection.packman_preference = false;
        app.state.execution_selection.flatpaks = true;
        app.state.execution_selection.journal_vacuum = true;

        let selection = app.selection_from_triage_state();
        app.request_run_selected_execution(selection);

        match app.pending_action.as_ref() {
            Some(PendingAction::RunSelectedExecution { selection }) => {
                assert!(!selection.zypper_dup);
                assert!(!selection.prefer_packman);
                assert!(selection.flatpak);
                assert!(selection.journal_vacuum);
            }
            _ => panic!("expected queued execution request"),
        }
    }

    #[test]
    fn execution_request_is_ignored_while_execution_is_active() {
        let mut app = test_app();
        app.settings.behavior.confirm_before_execution = true;
        app.sudo_session.sudo_password = Some("pw".to_string());
        app.sudo_session.sudo_validated = true;
        app.state.active_execution = true;

        app.request_run_selected_execution(app.selection_from_triage_state());

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.updates_log.last().map(String::as_str),
            Some("INFO: Run request ignored: execution already in progress")
        );
    }

    #[test]
    fn execute_action_ignores_duplicate_execution_even_if_called_directly() {
        let mut app = test_app();
        app.state.active_execution = true;

        app.execute_action(PendingAction::RunSelectedExecution {
            selection: app.selection_from_triage_state(),
        });

        assert!(app.state.active_execution);
        assert!(app.state.current_run.is_none());
        assert_eq!(
            app.state.updates_log.last().map(String::as_str),
            Some("INFO: Run request ignored: execution already in progress")
        );
    }

    #[test]
    fn execution_start_opens_runner_modal_immediately() {
        let mut app = test_app();
        app.open_execution_runner_modal();

        assert!(app.execution_runner_modal.visible);
        assert!(app.execution_runner_modal.final_outcome.is_none());
        assert_eq!(app.update_status, UpdateStatus::default());
    }

    #[test]
    fn update_phase_idle_releases_execution_guard_without_run_summary() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        assert!(app.state.try_begin_execution());
        app.open_execution_runner_modal();
        app.state.begin_updates_run(true);
        assert!(app.state.current_run.is_some());
        app.tx
            .send(Event::UpdatePhase("Updating".to_string()))
            .expect("send updating phase");

        app.tx
            .send(Event::UpdatePhase("Idle".to_string()))
            .expect("send idle phase");
        app.drain_events(&ctx);

        assert!(!app.state.active_execution);
        assert!(app.state.current_run.is_none());
        assert!(app.execution_runner_modal.visible);
        assert_eq!(
            app.execution_runner_modal.final_outcome.as_deref(),
            Some("Maintenance run finished.")
        );
    }

    #[test]
    fn stale_idle_does_not_complete_execution_before_run_activity_starts() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        assert!(app.state.try_begin_execution());
        app.open_execution_runner_modal();
        app.state.begin_updates_run(true);

        app.tx
            .send(Event::UpdatePhase("Idle".to_string()))
            .expect("send stale idle");
        app.drain_events(&ctx);

        assert!(app.state.active_execution);
        assert!(app.state.current_run.is_some());
        assert!(app.execution_runner_modal.visible);
        assert!(app.execution_runner_modal.final_outcome.is_none());
    }

    #[test]
    fn run_summary_completes_runner_modal_with_success_outcome() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        app.execution_runner_modal.open_for_run();
        assert!(app.state.try_begin_execution());
        app.state.begin_updates_run(true);

        app.tx
            .send(Event::RunSummary(successful_run_summary("run-123")))
            .expect("send summary");
        app.drain_events(&ctx);

        assert!(!app.state.active_execution);
        assert!(app.execution_runner_modal.visible);
        assert_eq!(
            app.execution_runner_modal.final_outcome.as_deref(),
            Some("Maintenance run completed successfully.")
        );
    }

    #[test]
    fn update_progress_event_preserves_exact_package_counts() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        app.execution_runner_modal.open_for_run();
        assert!(app.state.try_begin_execution());

        app.tx
            .send(Event::UpdateProgress {
                package: "ffmpeg-8".to_string(),
                processed: 7,
                total: 18,
            })
            .expect("send exact progress");
        app.drain_events(&ctx);

        assert_eq!(app.update_status.current_package, "ffmpeg-8");
        assert_eq!(app.update_status.processed, 7);
        assert_eq!(app.update_status.total, 18);
        assert!(app.update_status.exact_progress);
    }

    #[test]
    fn package_events_derive_progress_from_cached_plan_when_exact_counts_are_missing() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        app.execution_runner_modal.open_for_run();
        assert!(app.state.try_begin_execution());
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.zypper_plan = Some(test_preview_plan());
        }

        app.tx
            .send(Event::Structured(
                chamrisk_ops::events::OpsEvent::from_kind(
                    chamrisk_ops::events::OpsEventKind::ApplyStart,
                ),
            ))
            .expect("send apply start");
        app.tx
            .send(Event::Structured(
                chamrisk_ops::events::OpsEvent::from_kind(
                    chamrisk_ops::events::OpsEventKind::PackageUpgraded {
                        name: "ffmpeg-8".to_string(),
                        from: None,
                        to: None,
                        repo: None,
                        arch: None,
                    },
                ),
            ))
            .expect("send package event");
        app.drain_events(&ctx);

        assert_eq!(app.update_status.current_package, "ffmpeg-8");
        assert_eq!(app.update_status.processed, 1);
        assert_eq!(app.update_status.total, 1);
        assert!(!app.update_status.exact_progress);
    }

    #[test]
    fn failure_path_finishes_in_recoverable_state() {
        let mut app = test_app();
        let ctx = egui::Context::default();
        app.execution_runner_modal.open_for_run();
        assert!(app.state.try_begin_execution());
        app.state.begin_updates_run(true);
        app.tx
            .send(Event::Structured(
                chamrisk_ops::events::OpsEvent::from_kind(
                    chamrisk_ops::events::OpsEventKind::RunStart,
                ),
            ))
            .expect("send run start");

        app.tx
            .send(Event::Error("backend failed".to_string()))
            .expect("send error");
        app.tx
            .send(Event::UpdatePhase("Idle".to_string()))
            .expect("send idle");
        app.drain_events(&ctx);

        assert!(!app.state.active_execution);
        assert!(app.state.current_run.is_none());
        assert!(app.execution_runner_modal.visible);
        assert_eq!(
            app.execution_runner_modal.final_outcome.as_deref(),
            Some("Maintenance run failed. ERROR: backend failed")
        );

        app.execution_runner_modal.dismiss();
        assert!(!app.execution_runner_modal.visible);
        assert!(app.state.try_begin_execution());
    }

    #[test]
    fn dismissing_completed_modal_and_starting_new_run_resets_progress_state() {
        let mut app = test_app();
        app.update_status.current_package = "stale-package".to_string();
        app.update_status.processed = 9;
        app.update_status.total = 12;
        app.update_status.exact_progress = true;
        app.execution_runner_modal
            .finish("Maintenance run completed successfully.".to_string());

        app.execution_runner_modal.dismiss();
        app.open_execution_runner_modal();

        assert!(app.execution_runner_modal.visible);
        assert!(app.execution_runner_modal.final_outcome.is_none());
        assert_eq!(app.update_status, UpdateStatus::default());
    }

    #[test]
    fn modal_ok_becomes_enabled_as_soon_as_final_outcome_exists() {
        let mut app = test_app();
        app.state.active_execution = true;
        app.execution_runner_modal
            .finish("Maintenance run completed successfully.".to_string());

        assert!(app.execution_modal_ok_enabled());
    }

    #[test]
    fn refresh_preview_can_be_requested_with_no_provider_selected() {
        let mut app = test_app();
        app.ai_settings.selected_provider = AiProviderKind::NoneSelected;

        app.request_refresh_preview();

        assert!(matches!(
            app.pending_action,
            Some(PendingAction::RefreshPreview)
        ));
    }

    #[test]
    fn loaded_rows_without_canonical_run_context_keep_ai_triage_blocked() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;
        app.state
            .set_changes(vec![ai_test_change("mesa", UpdateAction::Upgrade)]);

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(super::AI_CANONICAL_RUN_REQUIRED_MESSAGE)
        );
        assert!(store.list_runs(10).expect("list runs").is_empty());
    }

    #[test]
    fn loaded_valid_canonical_run_enables_ai_triage_without_creating_phantom_rows() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;
        app.state
            .set_changes(vec![ai_test_change("mesa", UpdateAction::Upgrade)]);
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
            .expect("start run");

        app.select_history_run_with_store(run_id.clone(), &store);
        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(matches!(
            app.pending_action.as_ref(),
            Some(PendingAction::RunAiTriage { run_id: Some(queued_run_id), .. }) if queued_run_id == &run_id
        ));
        assert_eq!(
            app.state.loaded_canonical_run_id.as_deref(),
            Some(run_id.as_str())
        );
        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
    }

    #[test]
    fn closed_runs_are_not_reused_as_active_ai_targets() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;
        app.state
            .set_changes(vec![ai_test_change("mesa", UpdateAction::Upgrade)]);
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
            .expect("start run");
        store
            .finish_run(&run_id, 1, "PASS", 0, 0, 0, 0)
            .expect("finish run");

        app.select_history_run_with_store(run_id.clone(), &store);
        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(app.pending_action.is_none());
        assert_eq!(
            app.state.ai_state.last_error.as_deref(),
            Some(super::AI_CANONICAL_RUN_REQUIRED_MESSAGE)
        );
        assert!(app.state.current_run.is_none());
        assert!(app.state.loaded_canonical_run_id.is_none());
    }

    #[test]
    fn valid_active_run_is_used_without_creating_a_phantom_run() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.state.ai_state.enabled = true;
        app.state.begin_updates_run(true);
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
            .expect("start run");
        if let Some(run) = app.state.current_run.as_mut() {
            run.run_id = Some(run_id.clone());
        }

        app.request_ai_triage_for_active_run_with_store("{}".to_string(), &store);

        assert!(matches!(
            app.pending_action.as_ref(),
            Some(PendingAction::RunAiTriage { run_id: Some(queued_run_id), .. }) if queued_run_id == &run_id
        ));
        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
    }

    #[test]
    fn creating_execution_run_attaches_cached_ai_result_to_master_run() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        let selection = app.selection_from_triage_state();
        let plan = test_preview_plan();
        app.state.ai_state.assessment_risk = Some("Amber".to_string());
        app.state.ai_state.assessment_summary =
            Some("1) Review snapshot\n2) Proceed carefully".to_string());
        app.state.begin_updates_run(true);
        if let Some(run) = app.state.current_run.as_mut() {
            run.zypper_plan = Some(plan.clone());
        }

        let run_id = app
            .ensure_master_run_for_selection_with_store(&selection, Some(&plan), Some(&store))
            .expect("create master run");

        let assessment = store
            .load_ai_assessment(&run_id)
            .expect("load AI assessment")
            .expect("persisted AI assessment");
        assert_eq!(assessment.run_id, run_id);
        assert_eq!(assessment.risk_level.as_deref(), Some("Amber"));
        let runs = store.list_runs(10).expect("list runs");
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn refresh_history_prunes_preview_only_rows_from_updates_tab() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        let preview_run = store
            .start_run(
                r#"{"snapshot_before_update":false,"zypper_dup":true,"prefer_packman":false,"flatpak":false,"journal_vacuum":false,"mode":"preview","risk_filter":"all","repos":[]}"#,
                env!("CARGO_PKG_VERSION"),
            )
            .expect("start preview run");
        store
            .append_event(
                &preview_run,
                "zypper",
                "info",
                "preview.result",
                r#"{"packages":0}"#,
                "Preview result with 0 package(s)",
            )
            .expect("append preview event");

        let execution_run = store
            .start_run(
                r#"{"zypper_dup":true,"mode":"apply"}"#,
                env!("CARGO_PKG_VERSION"),
            )
            .expect("start execution run");
        store
            .finish_run(&execution_run, 1_000, "PASS", 1, 1, 0, 0)
            .expect("finish execution run");

        app.refresh_history_with_store(&store);

        assert_eq!(app.history_runs.len(), 1);
        assert_eq!(app.history_runs[0].run_id, execution_run);
        assert!(store
            .list_runs(10)
            .expect("list runs")
            .iter()
            .all(|run| run.run_id != preview_run));
    }

    #[test]
    fn auto_export_disabled_does_not_write_report() {
        let mut app = test_app();
        let (temp, store) = test_report_store();
        let export_dir = temp.path().join("exports-disabled");
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        app.settings.reports.auto_save_report_after_updates_run = false;
        app.settings.reports.default_export_location = Some(export_dir.clone());
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
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

        app.maybe_auto_export_completed_updates_run_with_store(
            &successful_run_summary(&run_id),
            &store,
        );

        assert!(app.export_status.is_none());
        assert!(std::fs::read_dir(&export_dir)
            .expect("read export dir")
            .filter_map(Result::ok)
            .all(|entry| entry.path().extension().and_then(|ext| ext.to_str()) != Some("odt")));
    }

    #[test]
    fn auto_export_enabled_without_default_location_sets_clean_status() {
        let mut app = test_app();
        let (_temp, store) = test_report_store();
        app.settings.reports.auto_save_report_after_updates_run = true;
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
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

        app.maybe_auto_export_completed_updates_run_with_store(
            &successful_run_summary(&run_id),
            &store,
        );

        assert_eq!(
            app.export_status.as_deref(),
            Some("Auto-save report skipped: no default report export location is configured")
        );
    }

    #[test]
    fn auto_export_enabled_uses_canonical_run_id_and_writes_report() {
        let mut app = test_app();
        let (temp, store) = test_report_store();
        let export_dir = temp.path().join("exports-enabled");
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        app.settings.reports.auto_save_report_after_updates_run = true;
        app.settings.reports.default_export_location = Some(export_dir.clone());
        let run_id = store
            .start_run("{\"zypper_dup\":true}", env!("CARGO_PKG_VERSION"))
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

        app.maybe_auto_export_completed_updates_run_with_store(
            &successful_run_summary(&run_id),
            &store,
        );

        let exported = std::fs::read_dir(&export_dir)
            .expect("read temp dir")
            .filter_map(Result::ok)
            .find(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("odt"))
            .expect("auto-saved report");
        assert!(exported
            .file_name()
            .to_string_lossy()
            .contains("chamrisk-report-"));
        let expected_status = format!("Auto-saved report to {}", exported.path().display());
        assert_eq!(app.export_status.as_deref(), Some(expected_status.as_str()));
    }
}

#[cfg(test)]
mod ai_configuration_tests {
    use super::{
        default_secret_ref_for_provider, persist_ai_configuration, test_ai_provider_connection,
        AiConfigurationUiState, ExecutionRunnerModalState, MaintenanceApp, AI_LABEL_SELECT_MODEL,
    };
    use crate::{HealthState, SystemWorkbookExportState};
    use chamrisk_core::ai::{AiModelDescriptor, AiProviderKind, SecretResolver};
    use chamrisk_ops::health::SystemTelemetry;
    use chamrisk_ops::runner::Runner;
    use chamrisk_ui::ai_settings::default_ai_settings;
    use chamrisk_ui::app::{SortState, UpdateStatus};
    use chamrisk_ui::settings::AppSettings;
    use chamrisk_ui::{MaintenanceApp as AppState, Tab};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::mpsc::channel;
    use std::time::Instant;
    use tempfile::tempdir;

    #[derive(Default)]
    struct TestSecretResolver {
        secrets: RefCell<HashMap<String, String>>,
        fail_read: RefCell<Option<String>>,
        fail_write: RefCell<Option<String>>,
        fail_delete: RefCell<Option<String>>,
    }

    impl SecretResolver for TestSecretResolver {
        fn read_secret(&self, secret_ref: &str) -> Result<Option<String>, String> {
            if let Some(err) = self.fail_read.borrow().clone() {
                return Err(err);
            }
            Ok(self.secrets.borrow().get(secret_ref).cloned())
        }

        fn write_secret(&self, secret_ref: &str, secret_value: &str) -> Result<(), String> {
            if let Some(err) = self.fail_write.borrow().clone() {
                return Err(err);
            }
            self.secrets
                .borrow_mut()
                .insert(secret_ref.to_string(), secret_value.to_string());
            Ok(())
        }

        fn delete_secret(&self, secret_ref: &str) -> Result<(), String> {
            if let Some(err) = self.fail_delete.borrow().clone() {
                return Err(err);
            }
            self.secrets.borrow_mut().remove(secret_ref);
            Ok(())
        }
    }

    struct PanicSecretResolver;

    impl SecretResolver for PanicSecretResolver {
        fn read_secret(&self, _secret_ref: &str) -> Result<Option<String>, String> {
            panic!("secret lookup should not be touched")
        }

        fn write_secret(&self, _secret_ref: &str, _secret_value: &str) -> Result<(), String> {
            panic!("secret write should not be touched")
        }

        fn delete_secret(&self, _secret_ref: &str) -> Result<(), String> {
            panic!("secret delete should not be touched")
        }
    }

    fn test_app() -> MaintenanceApp {
        let (tx, rx) = channel();
        let mut ai_settings = default_ai_settings();
        ai_settings.selected_provider = AiProviderKind::OpenAi;
        MaintenanceApp {
            state: AppState::default(),
            settings: AppSettings::default(),
            ai_settings,
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
            refresh_preview_requested: false,
            system_dark_mode: false,
            suppress_initial_health_refresh: false,
            last_persisted_tab: Tab::Health,
            was_health_tab_active: false,
        }
    }

    #[test]
    fn provider_selection_persists_to_ai_settings_json() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("ai_settings.json");
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        let mut ui_state = AiConfigurationUiState::default();

        persist_ai_configuration(
            &default_ai_settings(),
            None::<&TestSecretResolver>,
            &mut settings,
            &mut ui_state,
            &resolver,
            |saved| {
                let payload = serde_json::to_string_pretty(saved).expect("serialize ai settings");
                fs::write(&path, payload).map_err(|err| format!("write ai settings: {err}"))
            },
        )
        .expect("persist ai configuration");

        let raw = fs::read_to_string(&path).expect("read ai settings");
        let loaded: chamrisk_core::ai::AiSettings =
            serde_json::from_str(&raw).expect("deserialize ai settings");

        assert_eq!(loaded.selected_provider, AiProviderKind::Anthropic);
    }

    #[test]
    fn no_provider_connection_test_skips_secret_lookup() {
        let settings = default_ai_settings();
        let ui_state = AiConfigurationUiState::default();

        let err = super::test_ai_provider_connection_with_env(
            &settings,
            &ui_state,
            &PanicSecretResolver,
            |_name| None,
            |_config, _key| panic!("provider test should not run without a selected provider"),
        )
        .expect_err("no provider should short-circuit");

        assert!(err.contains("selected AI provider is not configured"));
    }

    #[test]
    fn selecting_no_provider_clears_selected_model_state() {
        let mut app = test_app();
        app.ai_configuration.selected_model_id = Some("gpt-4.1".to_string());
        app.ai_configuration.selected_model_label = "GPT-4.1".to_string();
        app.ai_configuration.draft_api_key = "sk-test".to_string();

        app.set_selected_ai_provider(AiProviderKind::NoneSelected);

        assert_eq!(
            app.ai_settings.selected_provider,
            AiProviderKind::NoneSelected
        );
        assert!(app.ai_configuration.draft_api_key.is_empty());
        assert!(app.ai_configuration.selected_model_id.is_none());
        assert_eq!(
            app.ai_configuration.selected_model_label,
            AI_LABEL_SELECT_MODEL
        );
    }

    #[test]
    fn api_key_save_creates_secret_ref_and_keeps_secret_out_of_json() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("ai_settings.json");
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].connection.api_key_file_name = None;
        let mut ui_state = AiConfigurationUiState {
            draft_api_key: "sk-test-12345678901234567890".to_string(),
            ..AiConfigurationUiState::default()
        };

        persist_ai_configuration(
            &default_ai_settings(),
            None::<&TestSecretResolver>,
            &mut settings,
            &mut ui_state,
            &resolver,
            |saved| {
                let payload = serde_json::to_string_pretty(saved).expect("serialize ai settings");
                fs::write(&path, payload).map_err(|err| format!("write ai settings: {err}"))
            },
        )
        .expect("persist ai configuration");

        let secret_ref = settings.provider_configs[0]
            .connection
            .api_key_file_name
            .as_deref();
        assert_eq!(
            secret_ref,
            Some(default_secret_ref_for_provider(AiProviderKind::OpenAi))
        );
        assert_eq!(
            resolver
                .read_secret(default_secret_ref_for_provider(AiProviderKind::OpenAi))
                .expect("read secret")
                .as_deref(),
            Some("sk-test-12345678901234567890")
        );

        let raw = fs::read_to_string(&path).expect("read ai settings");
        assert!(!raw.contains("sk-test-12345678901234567890"));
        assert!(raw.contains("openai_default"));
        assert!(ui_state.draft_api_key.is_empty());
    }

    #[test]
    fn anthropic_api_key_save_uses_anthropic_secret_ref() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("ai_settings.json");
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        settings.provider_configs[1].connection.api_key_file_name = None;
        let mut ui_state = AiConfigurationUiState {
            draft_api_key: "sk-ant-test-12345678901234567890".to_string(),
            ..AiConfigurationUiState::default()
        };

        persist_ai_configuration(
            &default_ai_settings(),
            None::<&TestSecretResolver>,
            &mut settings,
            &mut ui_state,
            &resolver,
            |saved| {
                let payload = serde_json::to_string_pretty(saved).expect("serialize ai settings");
                fs::write(&path, payload).map_err(|err| format!("write ai settings: {err}"))
            },
        )
        .expect("persist ai configuration");

        assert_eq!(
            settings.provider_configs[1]
                .connection
                .api_key_file_name
                .as_deref(),
            Some(default_secret_ref_for_provider(AiProviderKind::Anthropic))
        );
        assert_eq!(
            resolver
                .read_secret(default_secret_ref_for_provider(AiProviderKind::Anthropic))
                .expect("read anthropic secret")
                .as_deref(),
            Some("sk-ant-test-12345678901234567890")
        );
        let raw = fs::read_to_string(&path).expect("read ai settings");
        assert!(!raw.contains("sk-ant-test-12345678901234567890"));
        assert!(raw.contains("anthropic_default"));
    }

    #[test]
    fn storage_mode_change_migrates_existing_key_and_removes_old_copy_after_success() {
        let mut previous_settings = default_ai_settings();
        previous_settings.selected_provider = AiProviderKind::OpenAi;
        let old_resolver = TestSecretResolver::default();
        old_resolver
            .write_secret("openai_default", "sk-migrate-test-1234567890")
            .expect("write old secret");
        let new_resolver = TestSecretResolver::default();
        let mut settings = previous_settings.clone();
        settings.storage_mode = chamrisk_core::ai::AiSecretStorageMode::LocalFileStorage;
        let mut ui_state = AiConfigurationUiState::default();

        let notice = persist_ai_configuration(
            &previous_settings,
            Some(&old_resolver),
            &mut settings,
            &mut ui_state,
            &new_resolver,
            |_saved| Ok(()),
        )
        .expect("persist after migration");

        assert_eq!(
            new_resolver
                .read_secret("openai_default")
                .expect("read migrated secret")
                .as_deref(),
            Some("sk-migrate-test-1234567890")
        );
        assert_eq!(
            old_resolver
                .read_secret("openai_default")
                .expect("read old secret after migration"),
            None
        );
        assert_eq!(
            notice.as_deref(),
            Some("Storage location updated. Your saved API key was moved successfully.")
        );
    }

    #[test]
    fn failed_storage_mode_migration_keeps_existing_key_in_old_backend() {
        let mut previous_settings = default_ai_settings();
        previous_settings.selected_provider = AiProviderKind::OpenAi;
        let old_resolver = TestSecretResolver::default();
        old_resolver
            .write_secret("openai_default", "sk-migrate-test-1234567890")
            .expect("write old secret");
        let new_resolver = TestSecretResolver::default();
        *new_resolver.fail_write.borrow_mut() = Some("new backend unavailable".to_string());
        let mut settings = previous_settings.clone();
        settings.storage_mode = chamrisk_core::ai::AiSecretStorageMode::LocalFileStorage;
        let mut ui_state = AiConfigurationUiState::default();

        let err = persist_ai_configuration(
            &previous_settings,
            Some(&old_resolver),
            &mut settings,
            &mut ui_state,
            &new_resolver,
            |_saved| Ok(()),
        )
        .expect_err("migration should fail");

        assert!(err.contains("could not migrate the stored API key"));
        assert_eq!(
            old_resolver
                .read_secret("openai_default")
                .expect("read old secret after failure")
                .as_deref(),
            Some("sk-migrate-test-1234567890")
        );
        assert_eq!(
            new_resolver
                .read_secret("openai_default")
                .expect("read new secret after failure"),
            None
        );
    }

    #[test]
    fn reload_keeps_masked_key_field_empty_while_preserving_secret_ref() {
        let mut app = test_app();
        app.ai_settings.provider_configs[0]
            .connection
            .api_key_file_name = Some("openai_default".to_string());
        app.ai_configuration.draft_api_key = "should clear".to_string();

        let reloaded_settings = app.ai_settings.clone();
        app.ai_settings = reloaded_settings;
        app.ai_configuration = AiConfigurationUiState::default();
        app.sync_ai_configuration_ui();

        assert!(app.ai_configuration.draft_api_key.is_empty());
        assert_eq!(
            app.ai_settings.provider_configs[0]
                .connection
                .api_key_file_name
                .as_deref(),
            Some("openai_default")
        );
    }

    #[test]
    fn selecting_anthropic_resets_connection_status_and_loads_its_saved_model_state() {
        let mut app = test_app();
        app.ai_settings.provider_configs[0].available_models = vec![AiModelDescriptor {
            id: "gpt-4.1".to_string(),
            display_name: "GPT-4.1".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        app.ai_settings.provider_configs[1].available_models = vec![AiModelDescriptor {
            id: "claude-3-7-sonnet-latest".to_string(),
            display_name: "Claude 3.7 Sonnet".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: false,
        }];
        app.ai_settings.last_selected_model_by_provider = vec![
            (AiProviderKind::OpenAi, "gpt-4.1".to_string()),
            (
                AiProviderKind::Anthropic,
                "claude-3-7-sonnet-latest".to_string(),
            ),
        ];
        app.ai_configuration.connection_status = "Available".to_string();
        app.ai_configuration.draft_api_key = "sk-should-clear".to_string();
        app.ai_configuration.selected_model_id = Some("gpt-4.1".to_string());
        app.ai_configuration.selected_model_label = "GPT-4.1".to_string();

        app.set_selected_ai_provider(AiProviderKind::Anthropic);

        assert_eq!(app.ai_settings.selected_provider, AiProviderKind::Anthropic);
        assert_eq!(app.ai_configuration.connection_status, "Not checked yet");
        assert!(app.ai_configuration.draft_api_key.is_empty());
        assert_eq!(
            app.ai_configuration.selected_model_id.as_deref(),
            Some("claude-3-7-sonnet-latest")
        );
        assert_eq!(
            app.ai_configuration.selected_model_label,
            "Claude 3.7 Sonnet"
        );
        assert_eq!(
            app.ai_settings.provider_configs[1].available_models.len(),
            1
        );
    }

    #[test]
    fn connection_test_success_status_path_returns_available() {
        let temp = tempdir().expect("tempdir");
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState {
            draft_api_key: "sk-valid-test-key-1234567890".to_string(),
            ..AiConfigurationUiState::default()
        };

        let status = test_ai_provider_connection(&settings, &ui_state, &resolver, |config, key| {
            assert_eq!(config.metadata.kind, AiProviderKind::OpenAi);
            assert_eq!(key, Some("sk-valid-test-key-1234567890"));
            Ok((true, None, None))
        })
        .expect("successful status");

        assert_eq!(status, "Available");
    }

    #[test]
    fn connection_test_failure_status_path_returns_not_available() {
        let temp = tempdir().expect("tempdir");
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState {
            draft_api_key: "sk-valid-test-key-1234567890".to_string(),
            ..AiConfigurationUiState::default()
        };

        let status =
            test_ai_provider_connection(&settings, &ui_state, &resolver, |_config, _key| {
                Ok((false, None, None))
            })
            .expect("status");

        assert_eq!(status, "Connection check failed");
    }

    #[test]
    fn connection_test_failure_detail_is_preserved() {
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState {
            draft_api_key: "sk-valid-test-key-1234567890".to_string(),
            ..AiConfigurationUiState::default()
        };

        let (status, detail, models) = super::test_ai_provider_connection_with_env(
            &settings,
            &ui_state,
            &resolver,
            |_name| None,
            |_config, _key| Ok((false, Some("Authentication failed".to_string()), None)),
        )
        .expect("status with detail");

        assert_eq!(status, "Connection check failed");
        assert_eq!(detail.as_deref(), Some("Authentication failed"));
        assert!(models.is_none());
    }

    #[test]
    fn connection_test_broken_backend_returns_real_error() {
        let resolver = TestSecretResolver::default();
        *resolver.fail_read.borrow_mut() = Some("secure secret store unavailable".to_string());
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState::default();

        let err = super::test_ai_provider_connection_with_env(
            &settings,
            &ui_state,
            &resolver,
            |_name| None,
            |_config, _key| panic!("provider test should not run when secret lookup fails"),
        )
        .expect_err("broken backend should be a real error");

        assert!(err.contains("secure secret store unavailable"));
    }

    #[test]
    fn connection_test_missing_key_path_returns_error() {
        let resolver = TestSecretResolver::default();
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState::default();

        let (status, detail, models) = super::test_ai_provider_connection_with_env(
            &settings,
            &ui_state,
            &resolver,
            |_name| None,
            |_config, _key| panic!("tester should not run without a configured key"),
        )
        .expect("missing key should be neutral");

        assert_eq!(status, super::AI_LABEL_NOT_TESTED);
        assert_eq!(
            detail.as_deref(),
            Some("Add an API key to enable AI triage for this provider.")
        );
        assert!(models.is_none());
    }

    #[test]
    fn connection_test_uses_stored_secret_when_no_draft_key_is_present() {
        let temp = tempdir().expect("tempdir");
        let resolver = TestSecretResolver::default();
        resolver
            .write_secret("openai_default", "sk-stored-test-key-1234567890")
            .expect("write secret");
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let ui_state = AiConfigurationUiState::default();

        let status = test_ai_provider_connection(&settings, &ui_state, &resolver, |config, key| {
            assert_eq!(config.metadata.kind, AiProviderKind::OpenAi);
            assert_eq!(key, Some("sk-stored-test-key-1234567890"));
            Ok((true, None, None))
        })
        .expect("status");

        assert_eq!(status, "Available");
    }

    #[test]
    fn anthropic_connection_test_uses_selected_provider_and_populates_models() {
        let temp = tempdir().expect("tempdir");
        let resolver = TestSecretResolver::default();
        resolver
            .write_secret("anthropic_default", "sk-ant-stored-test-key-1234567890")
            .expect("write anthropic secret");
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        let ui_state = AiConfigurationUiState::default();

        let (status, _detail, models) = super::test_ai_provider_connection_with_env(
            &settings,
            &ui_state,
            &resolver,
            |_name| None,
            |config, key| {
                assert_eq!(config.metadata.kind, AiProviderKind::Anthropic);
                assert_eq!(key, Some("sk-ant-stored-test-key-1234567890"));
                Ok((
                    true,
                    None,
                    Some(vec![AiModelDescriptor {
                        id: "claude-3-7-sonnet-latest".to_string(),
                        display_name: "Claude 3.7 Sonnet".to_string(),
                        context_window_tokens: None,
                        supports_streaming: false,
                        supports_json_mode: false,
                    }]),
                ))
            },
        )
        .expect("anthropic status");

        assert_eq!(status, "Available");
        assert_eq!(models.expect("models").len(), 1);
    }

    #[test]
    fn ai_ux_state_reports_missing_key_cleanly() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].connection.api_key_file_name = None;
        settings.provider_configs[0].connection.api_key_env_var = None;
        let ui_state = AiConfigurationUiState::default();

        assert_eq!(
            super::ai_ux_state(&settings, &ui_state),
            super::AiUxState::NoKeyConfigured
        );
    }

    #[test]
    fn ai_ux_state_reports_stale_selected_model_as_not_selected() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].available_models = vec![AiModelDescriptor {
            id: "gpt-4.1-mini".to_string(),
            display_name: "GPT-4.1 Mini".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        let ui_state = AiConfigurationUiState {
            connection_status: super::AI_LABEL_AVAILABLE.to_string(),
            selected_model_id: Some("missing-model".to_string()),
            selected_model_label: "Missing".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            super::ai_ux_state(&settings, &ui_state),
            super::AiUxState::ModelNotSelected
        );
    }

    #[test]
    fn ai_ux_state_reports_ready_when_provider_key_connection_and_model_are_valid() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].available_models = vec![AiModelDescriptor {
            id: "gpt-4.1-mini".to_string(),
            display_name: "GPT-4.1 Mini".to_string(),
            context_window_tokens: None,
            supports_streaming: false,
            supports_json_mode: true,
        }];
        let ui_state = AiConfigurationUiState {
            connection_status: super::AI_LABEL_AVAILABLE.to_string(),
            selected_model_id: Some("gpt-4.1-mini".to_string()),
            selected_model_label: "GPT-4.1 Mini".to_string(),
            ..AiConfigurationUiState::default()
        };

        assert_eq!(
            super::ai_ux_state(&settings, &ui_state),
            super::AiUxState::Ready
        );
    }

    #[test]
    fn apply_loaded_models_prefers_last_selected_model_on_reload() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.last_selected_model_by_provider =
            vec![(AiProviderKind::OpenAi, "gpt-4.1".to_string())];
        settings.provider_configs[0].available_models = vec![
            AiModelDescriptor {
                id: "gpt-4.1-mini".to_string(),
                display_name: "GPT-4.1 Mini".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
            AiModelDescriptor {
                id: "gpt-4.1".to_string(),
                display_name: "GPT-4.1".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
        ];
        let mut ui_state = AiConfigurationUiState::default();

        let selected_model_id = super::resolve_selected_model_id(&settings);
        ui_state.selected_model_id = selected_model_id.clone();
        ui_state.selected_model_label =
            super::selected_model_label_for_settings(&settings, selected_model_id.as_deref());

        assert_eq!(ui_state.selected_model_id.as_deref(), Some("gpt-4.1"));
        assert_eq!(ui_state.selected_model_label, "GPT-4.1");
    }

    #[test]
    fn set_selected_model_persists_last_selected_model_for_provider() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].available_models = vec![
            AiModelDescriptor {
                id: "gpt-4.1-mini".to_string(),
                display_name: "GPT-4.1 Mini".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
            AiModelDescriptor {
                id: "gpt-4.1".to_string(),
                display_name: "GPT-4.1".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
        ];
        let mut ui_state = AiConfigurationUiState::default();

        super::set_selected_model(&mut settings, &mut ui_state, "gpt-4.1".to_string());

        assert_eq!(
            settings.last_selected_model_by_provider,
            vec![(AiProviderKind::OpenAi, "gpt-4.1".to_string())]
        );
        assert_eq!(ui_state.selected_model_id.as_deref(), Some("gpt-4.1"));
        assert_eq!(ui_state.selected_model_label, "GPT-4.1");
    }

    #[test]
    fn anthropic_selected_model_persists_for_anthropic_provider() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::Anthropic;
        settings.provider_configs[1].available_models = vec![
            AiModelDescriptor {
                id: "claude-3-5-haiku-latest".to_string(),
                display_name: "Claude 3.5 Haiku".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            },
            AiModelDescriptor {
                id: "claude-3-7-sonnet-latest".to_string(),
                display_name: "Claude 3.7 Sonnet".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: false,
            },
        ];
        let mut ui_state = AiConfigurationUiState::default();

        super::set_selected_model(
            &mut settings,
            &mut ui_state,
            "claude-3-7-sonnet-latest".to_string(),
        );

        assert_eq!(
            settings.last_selected_model_by_provider,
            vec![(
                AiProviderKind::Anthropic,
                "claude-3-7-sonnet-latest".to_string(),
            )]
        );
        assert_eq!(
            ui_state.selected_model_id.as_deref(),
            Some("claude-3-7-sonnet-latest")
        );
        assert_eq!(ui_state.selected_model_label, "Claude 3.7 Sonnet");
    }

    #[test]
    fn apply_loaded_models_replaces_seeded_default_with_fetched_model_list() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        let mut ui_state = AiConfigurationUiState::default();

        super::apply_loaded_models(
            &mut settings,
            &mut ui_state,
            vec![
                AiModelDescriptor {
                    id: "gpt-4.1".to_string(),
                    display_name: "GPT-4.1".to_string(),
                    context_window_tokens: None,
                    supports_streaming: false,
                    supports_json_mode: true,
                },
                AiModelDescriptor {
                    id: "gpt-4.1-mini".to_string(),
                    display_name: "GPT-4.1 Mini".to_string(),
                    context_window_tokens: None,
                    supports_streaming: false,
                    supports_json_mode: true,
                },
            ],
        );

        assert_eq!(settings.provider_configs[0].available_models.len(), 2);
        assert_eq!(
            settings.provider_configs[0]
                .available_models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["gpt-4.1", "gpt-4.1-mini"]
        );
    }

    #[test]
    fn clear_loaded_model_state_removes_seeded_default_after_fetch_failure() {
        let mut app = test_app();
        app.ai_configuration.selected_model_id = Some("gpt-4.1-mini".to_string());
        app.ai_configuration.selected_model_label = "GPT-4.1 Mini".to_string();

        app.clear_loaded_model_state();

        assert!(app.ai_settings.provider_configs[0]
            .available_models
            .is_empty());
        assert!(app.ai_configuration.selected_model_id.is_none());
        assert_eq!(
            app.ai_configuration.selected_model_label,
            super::AI_LABEL_SELECT_MODEL
        );
    }

    #[test]
    fn selected_model_persistence_keeps_full_available_options_list() {
        let mut settings = default_ai_settings();
        settings.selected_provider = AiProviderKind::OpenAi;
        settings.provider_configs[0].available_models = vec![
            AiModelDescriptor {
                id: "gpt-4.1-mini".to_string(),
                display_name: "GPT-4.1 Mini".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
            AiModelDescriptor {
                id: "gpt-4.1".to_string(),
                display_name: "GPT-4.1".to_string(),
                context_window_tokens: None,
                supports_streaming: false,
                supports_json_mode: true,
            },
        ];
        let mut ui_state = AiConfigurationUiState::default();

        super::set_selected_model(&mut settings, &mut ui_state, "gpt-4.1".to_string());

        assert_eq!(settings.provider_configs[0].available_models.len(), 2);
        assert_eq!(ui_state.selected_model_id.as_deref(), Some("gpt-4.1"));
    }

    #[test]
    fn selected_model_label_defaults_to_empty_state_without_models() {
        let mut settings = default_ai_settings();
        settings.provider_configs[0].available_models.clear();

        assert_eq!(super::resolve_selected_model_id(&settings), None);
        assert_eq!(
            super::selected_model_label_for_settings(&settings, None),
            super::AI_LABEL_SELECT_MODEL
        );
    }
}

fn detected_package_families(changes: &[PackageChange]) -> BTreeSet<&'static str> {
    let mut families = BTreeSet::new();

    for change in changes {
        let name = change.name.as_str();
        if is_system_services_package(name) {
            families.insert("system-services");
        }
        if is_boot_chain_package(name) {
            families.insert("boot-chain");
        }
        if is_runtime_lib_package(name) {
            families.insert("runtime-libs");
        }
        if is_graphics_session_package(name) {
            families.insert("graphics-session");
        }
        if is_networking_package(name) {
            families.insert("networking");
        }
        if is_audio_media_package(name) {
            families.insert("media-audio");
        }
        if is_codec_image_package(name) {
            families.insert("codec-image");
        }
    }

    families
}

fn is_system_services_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("systemd") || lower.starts_with("libsystemd") || lower == "udev"
}

fn is_boot_chain_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("kernel")
        || lower.starts_with("dracut")
        || lower.starts_with("grub2")
        || lower.starts_with("shim")
        || lower.starts_with("mokutil")
}

fn is_runtime_lib_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("glibc")
        || lower.starts_with("libstdc++")
        || lower.starts_with("gcc")
        || lower.starts_with("clang")
}

fn is_graphics_session_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("xorg")
        || lower.starts_with("mesa")
        || lower.starts_with("wayland")
        || lower.starts_with("kwin")
        || lower.starts_with("nvidia")
}

fn is_networking_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("networkmanager")
        || lower.starts_with("wicked")
        || lower.starts_with("nftables")
        || lower.starts_with("iptables")
        || lower.starts_with("firewalld")
}

fn is_audio_media_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("pipewire")
        || lower.contains("pulseaudio")
        || lower.contains("gstreamer")
        || lower.contains("ffmpeg")
        || lower.contains("libav")
}

fn is_codec_image_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("codec")
        || lower.contains("libheif")
        || lower.contains("heif")
        || lower.contains("avif")
        || lower.contains("openh264")
}
#[derive(Clone)]
pub(crate) struct Row {
    index: usize,
    risk: Risk,
    recon: String,
    name: String,
    action: String,
    from: String,
    to: String,
    repo: String,
    vendor: String,
    arch: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Risk {
    Red,
    Amber,
    Green,
}

fn risk_badge(ui: &mut Ui, risk: Risk) {
    let (label, bg) = match risk {
        Risk::Red => ("Red", egui::Color32::from_rgb(180, 60, 60)),
        Risk::Amber => ("Amber", egui::Color32::from_rgb(190, 140, 40)),
        Risk::Green => ("Green", egui::Color32::from_rgb(70, 160, 90)),
    };

    let text = egui::RichText::new(label)
        .color(egui::Color32::WHITE)
        .strong();

    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.label(text);
        });
}

fn sortable_header(ui: &mut Ui, title: &str, col: SortCol, sort: &mut SortState) -> bool {
    let mut t = title.to_string();
    if sort.col == col {
        t.push(' ');
        t.push(if sort.asc { '▲' } else { '▼' });
    }
    let clicked = ui
        .add(egui::Label::new(egui::RichText::new(t).strong()).sense(egui::Sense::click()))
        .clicked();
    if clicked {
        if sort.col == col {
            sort.asc = !sort.asc;
        } else {
            sort.col = col;
            sort.asc = true;
        }
    }
    clicked
}

pub(crate) fn packages_table(
    ui: &mut Ui,
    rows: &mut [Row],
    sort: &mut SortState,
    selected: &mut Option<usize>,
    table_height: f32,
    allow_name_selection: bool,
) {
    let risk_value = |risk: Risk| match risk {
        Risk::Red => 0_u8,
        Risk::Amber => 1,
        Risk::Green => 2,
    };

    rows.sort_by(|a, b| {
        let ord = match sort.col {
            SortCol::Risk => risk_value(a.risk).cmp(&risk_value(b.risk)),
            SortCol::Result => a.recon.cmp(&b.recon),
            SortCol::Name => {
                let a_name = a.name.to_lowercase();
                let b_name = b.name.to_lowercase();
                a_name.cmp(&b_name).then_with(|| a.name.cmp(&b.name))
            }
            SortCol::Action => a.action.cmp(&b.action),
            SortCol::From => a.from.cmp(&b.from),
            SortCol::To => a.to.cmp(&b.to),
            SortCol::Repo => a.repo.cmp(&b.repo),
            SortCol::Vendor => a.vendor.cmp(&b.vendor),
            SortCol::Arch => a.arch.cmp(&b.arch),
        };
        if sort.asc {
            ord
        } else {
            ord.reverse()
        }
    });

    let row_height = ui.text_style_height(&TextStyle::Body) + 10.0;
    let table_h = table_height.max(0.0);
    let content_w = 64.0 + 58.0 + 220.0 + 92.0 + 140.0 + 140.0 + 140.0 + 140.0 + 78.0;

    egui::ScrollArea::horizontal()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            ui.set_min_width(content_w);

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .vscroll(true)
                .min_scrolled_height(table_h)
                .max_scroll_height(table_h)
                // 1 Risk
                .column(Column::exact(64.0))
                // 2 Result
                .column(Column::exact(58.0))
                // 3 Name
                .column(Column::exact(220.0))
                // 4 Action
                .column(Column::exact(92.0))
                // 5 From
                .column(Column::exact(140.0))
                // 6 To
                .column(Column::exact(140.0))
                // 7 Repo
                .column(Column::exact(140.0))
                // 8 Vendor
                .column(Column::exact(140.0))
                // 9 Arch
                .column(Column::exact(78.0))
                .header(row_height, |mut header| {
                    header.col(|ui| {
                        sortable_header(ui, "Risk", SortCol::Risk, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Result", SortCol::Result, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Name", SortCol::Name, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Action", SortCol::Action, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "From", SortCol::From, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "To", SortCol::To, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Repo", SortCol::Repo, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Vendor", SortCol::Vendor, sort);
                    });
                    header.col(|ui| {
                        sortable_header(ui, "Arch", SortCol::Arch, sort);
                    });
                })
                .body(|mut body| {
                    for r in rows.iter() {
                        body.row(row_height, |mut row| {
                            let is_sel = allow_name_selection && *selected == Some(r.index);

                            // 1 Risk badge
                            row.col(|ui| {
                                risk_badge(ui, r.risk);
                            });

                            // 2 Result badge
                            row.col(|ui| {
                                let rid = format!("plan-{}", r.index);
                                let txt = if r.recon.is_empty() {
                                    "".to_string()
                                } else {
                                    r.recon.clone()
                                };
                                ui.label(txt).on_hover_text(rid);
                            });

                            // 3 Name (selectable)
                            row.col(|ui| {
                                if allow_name_selection {
                                    let resp = ui.selectable_label(is_sel, &r.name);
                                    if resp.clicked() {
                                        *selected = Some(r.index);
                                    }
                                    if resp.hovered()
                                        && ui.is_rect_visible(resp.rect)
                                        && r.name.len() > 28
                                    {
                                        resp.on_hover_text(&r.name);
                                    }
                                } else {
                                    let resp = ui.label(&r.name);
                                    if resp.hovered()
                                        && ui.is_rect_visible(resp.rect)
                                        && r.name.len() > 28
                                    {
                                        resp.on_hover_text(&r.name);
                                    }
                                }
                            });

                            // 4 Action
                            row.col(|ui| {
                                ui.label(&r.action);
                            });

                            // 5 From
                            row.col(|ui| {
                                let resp = ui.label(egui::RichText::new(&r.from).monospace());
                                if resp.hovered() {
                                    resp.on_hover_text(&r.from);
                                }
                            });

                            // 6 To
                            row.col(|ui| {
                                let resp = ui.label(egui::RichText::new(&r.to).monospace());
                                if resp.hovered() {
                                    resp.on_hover_text(&r.to);
                                }
                            });

                            // 7 Repo
                            row.col(|ui| {
                                ui.label(&r.repo);
                            });

                            // 8 Vendor
                            row.col(|ui| {
                                ui.label(&r.vendor);
                            });

                            // 9 Arch (right aligned)
                            row.col(|ui| {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(&r.arch);
                                });
                            });
                        });
                    }
                });
        });
}

fn tab_button(ui: &mut egui::Ui, active_tab: &mut Tab, tab: Tab, label: &str) {
    if nav_button(ui, *active_tab == tab, label).clicked() {
        *active_tab = tab;
    }
}

fn nav_button(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let visuals = ui.visuals();
    let text = if selected {
        egui::RichText::new(label)
            .color(egui::Color32::WHITE)
            .strong()
    } else {
        egui::RichText::new(label).strong()
    };

    let mut button = egui::Button::new(text)
        .rounding(egui::Rounding::same(6.0))
        .stroke(visuals.widgets.inactive.bg_stroke);

    if selected {
        button = button.fill(visuals.selection.bg_fill);
    }

    ui.add(button)
}

fn render_log_table(ui: &mut Ui, logs: &[LogEntry]) {
    TableBuilder::new(ui)
        .striped(true)
        .column(Column::exact(90.0))
        .column(Column::exact(80.0))
        .column(Column::exact(110.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.label("Time");
            });
            header.col(|ui| {
                ui.label("Level");
            });
            header.col(|ui| {
                ui.label("Stage");
            });
            header.col(|ui| {
                ui.label("Message");
            });
        })
        .body(|mut body| {
            for log in logs {
                body.row(18.0, |mut row| {
                    row.col(|ui| {
                        ui.label(&log.timestamp);
                    });
                    row.col(|ui| match log.level {
                        LogLevel::Info => {
                            ui.label("INFO");
                        }
                        LogLevel::Warn => {
                            ui.colored_label(egui::Color32::YELLOW, "WARN");
                        }
                        LogLevel::Error => {
                            ui.colored_label(egui::Color32::RED, "ERROR");
                        }
                    });
                    row.col(|ui| {
                        ui.label(format!("{:?}", log.stage));
                    });
                    row.col(|ui| {
                        ui.label(&log.message);
                    });
                });
            }
        });
}

pub(crate) fn toggle_mark(
    marks: &mut std::collections::HashMap<String, PackageAction>,
    name: &str,
    action: PackageAction,
) {
    if marks.get(name) == Some(&action) {
        marks.remove(name);
    } else {
        marks.insert(name.to_string(), action);
    }
}

#[cfg(test)]
mod tests {
    use super::build_ai_payload_from_plan;
    use chamrisk_core::models::{PackageChange, UpdateAction};
    use chamrisk_core::risk::assess_risk;
    use serde_json::Value;

    fn change(name: &str, action: UpdateAction) -> PackageChange {
        PackageChange {
            name: name.to_string(),
            arch: Some("x86_64".to_string()),
            action,
            from: Some("1.0.0".to_string()),
            to: Some("1.0.1".to_string()),
            repo: Some("repo-oss".to_string()),
            vendor: Some("openSUSE".to_string()),
            kind: Some("package".to_string()),
        }
    }

    fn themes_for(
        changes: &[PackageChange],
        reboot_recommended: bool,
        kernel_count: usize,
        core_count: usize,
    ) -> Value {
        let payload = build_ai_payload_from_plan(
            changes,
            true,
            false,
            reboot_recommended,
            kernel_count,
            core_count,
        );
        let value: Value = serde_json::from_str(&payload).unwrap();
        value["recommendation_themes"].clone()
    }

    #[test]
    fn ai_payload_includes_canonical_risk_fields_from_core_engine() {
        let changes = vec![
            change("systemd", UpdateAction::Upgrade),
            change("kernel-default", UpdateAction::Upgrade),
        ];

        let payload = build_ai_payload_from_plan(&changes, true, false, true, 1, 2);
        let value: Value = serde_json::from_str(&payload).unwrap();
        let canonical = &value["canonical_risk"];
        let expected = assess_risk(
            &changes
                .iter()
                .map(super::package_change_as_update)
                .collect::<Vec<_>>(),
        );

        assert_eq!(canonical["level"], Value::String("High".to_string()));
        assert_eq!(canonical["score_sum"], Value::from(expected.score_sum));
        assert_eq!(canonical["score_max"], Value::from(expected.score_max));
        assert_eq!(
            canonical["reasons"].as_array().unwrap().len(),
            expected.reasons.len()
        );
        assert_eq!(
            canonical["reasons"][0],
            Value::String(expected.reasons[0].clone())
        );
    }

    #[test]
    fn ai_payload_marks_systemd_upgrade_as_at_least_medium() {
        let changes = vec![change("systemd", UpdateAction::Upgrade)];

        let payload = build_ai_payload_from_plan(&changes, true, false, false, 0, 1);
        let value: Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            value["canonical_risk"]["level"],
            Value::String("Medium".to_string())
        );
    }

    #[test]
    fn ai_payload_marks_systemd_and_kernel_transaction_as_high() {
        let changes = vec![
            change("systemd", UpdateAction::Upgrade),
            change("kernel-default", UpdateAction::Upgrade),
        ];

        let payload = build_ai_payload_from_plan(&changes, true, false, true, 1, 2);
        let value: Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(
            value["canonical_risk"]["level"],
            Value::String("High".to_string())
        );
        assert!(value["canonical_risk"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|reason| reason.contains("systemd-family + kernel")));
    }

    #[test]
    fn ai_payload_recommendations_follow_system_service_and_boot_families() {
        let changes = vec![
            change("systemd", UpdateAction::Upgrade),
            change("kernel-default", UpdateAction::Upgrade),
        ];

        let themes = themes_for(&changes, true, 1, 2);

        assert_eq!(themes["risk_level"], Value::String("High".to_string()));
        assert!(themes["families"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|family| family == "system-services"));
        assert!(themes["families"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|family| family == "boot-chain"));
        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("systemctl --failed")));
        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("bootloader menu")));
        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("journalctl -b -p err")));
        assert!(themes["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("snapshot") || item.contains("reboot window")));
    }

    #[test]
    fn ai_payload_suppresses_irrelevant_media_checks_for_runtime_updates() {
        let changes = vec![change("glibc", UpdateAction::Upgrade)];

        let themes = themes_for(&changes, false, 0, 1);

        assert!(!themes["families"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|family| family == "media-audio" || family == "codec-image"));
        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("browser, terminal, and one daily-use app")));
    }

    #[test]
    fn ai_payload_keeps_amber_runbook_targeted() {
        let changes = vec![change("glibc", UpdateAction::Upgrade)];

        let themes = themes_for(&changes, true, 0, 1);

        assert_eq!(themes["risk_level"], Value::String("Medium".to_string()));
        assert!(themes["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("reboot")));
        assert!(!themes["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("snapshot")));
        assert_eq!(themes["update_execution"].as_array().unwrap().len(), 1);
        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("browser, terminal, and one daily-use app")));
    }

    #[test]
    fn ai_payload_keeps_green_runbook_short_and_generic() {
        let changes = vec![change("nano", UpdateAction::Upgrade)];

        let themes = themes_for(&changes, false, 0, 0);

        assert_eq!(themes["risk_level"], Value::String("Low".to_string()));
        assert!(themes["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            themes["post_reboot_functional_validation"][0],
            Value::String("Run a brief login, network, and app-launch sanity check.".to_string())
        );
        assert_eq!(
            themes["optional_deeper_checks"][0],
            Value::String(
                "No deeper checks needed unless something behaves differently after the update."
                    .to_string()
            )
        );
    }

    #[test]
    fn red_core_system_transaction_generates_full_runbook() {
        let changes = vec![
            change("systemd", UpdateAction::Upgrade),
            change("kernel-default", UpdateAction::Upgrade),
            change("glibc", UpdateAction::Upgrade),
        ];

        let themes = themes_for(&changes, true, 1, 3);

        assert!(!themes["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!themes["update_execution"].as_array().unwrap().is_empty());
        assert!(!themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!themes["optional_deeper_checks"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn systemd_updates_include_service_and_device_validation() {
        let changes = vec![change("libsystemd0", UpdateAction::Upgrade)];

        let themes = themes_for(&changes, true, 0, 1);

        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("systemctl --failed")));
        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("journalctl -b -p err")));
        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("device")));
    }

    #[test]
    fn graphics_updates_include_session_validation() {
        let changes = vec![
            change("mesa", UpdateAction::Upgrade),
            change("kwin", UpdateAction::Upgrade),
        ];

        let themes = themes_for(&changes, false, 0, 0);

        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("Log out and back in")));
        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("display acceleration")));
    }

    #[test]
    fn runtime_library_updates_include_runtime_regression_checks() {
        let changes = vec![
            change("glibc", UpdateAction::Upgrade),
            change("libstdc++6", UpdateAction::Upgrade),
        ];

        let themes = themes_for(&changes, false, 0, 2);

        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("runtime or linker regressions")));
        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("browser") || item.contains("GUI app")));
    }

    #[test]
    fn media_stack_updates_include_audio_media_validation() {
        let changes = vec![
            change("pipewire", UpdateAction::Upgrade),
            change("gstreamer", UpdateAction::Upgrade),
        ];

        let themes = themes_for(&changes, false, 0, 0);

        assert!(themes["post_reboot_functional_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("audio") || item.contains("video")));
    }

    #[test]
    fn amber_output_is_shorter_and_more_targeted_than_red() {
        let amber = themes_for(&[change("glibc", UpdateAction::Upgrade)], true, 0, 1);
        let red = themes_for(
            &[
                change("systemd", UpdateAction::Upgrade),
                change("kernel-default", UpdateAction::Upgrade),
                change("glibc", UpdateAction::Upgrade),
            ],
            true,
            1,
            3,
        );

        let amber_total = amber["pre_update_safeguards"].as_array().unwrap().len()
            + amber["update_execution"].as_array().unwrap().len()
            + amber["post_reboot_core_validation"]
                .as_array()
                .unwrap()
                .len()
            + amber["post_reboot_functional_validation"]
                .as_array()
                .unwrap()
                .len()
            + amber["optional_deeper_checks"].as_array().unwrap().len();
        let red_total = red["pre_update_safeguards"].as_array().unwrap().len()
            + red["update_execution"].as_array().unwrap().len()
            + red["post_reboot_core_validation"].as_array().unwrap().len()
            + red["post_reboot_functional_validation"]
                .as_array()
                .unwrap()
                .len()
            + red["optional_deeper_checks"].as_array().unwrap().len();

        assert!(red_total > amber_total);
        assert!(!amber["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("snapshot")));
        assert!(red["pre_update_safeguards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("snapshot")));
    }

    #[test]
    fn journal_check_uses_err_not_err_alert_range() {
        let themes = themes_for(&[change("systemd", UpdateAction::Upgrade)], true, 0, 1);

        assert!(themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("journalctl -b -p err")));
        assert!(!themes["post_reboot_core_validation"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .any(|item| item.contains("err..alert")));
    }
}
