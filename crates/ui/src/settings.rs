use crate::app::Tab;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const SETTINGS_FILE_NAME: &str = "ui_settings.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

impl ThemePreference {
    pub fn label(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutDensity {
    Compact,
    Comfortable,
}

impl LayoutDensity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Compact => "Compact",
            Self::Comfortable => "Comfortable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccentColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl AccentColor {
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppearanceSettings {
    pub theme: ThemePreference,
    pub accent_color: AccentColor,
    pub font_size: f32,
    pub density: LayoutDensity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorSettings {
    pub remember_last_tab: bool,
    pub auto_refresh_on_launch: bool,
    pub logs_expanded_by_default: bool,
    pub confirm_before_execution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistorySettings {
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSettings {
    pub default_export_location: Option<PathBuf>,
    pub auto_save_report_after_updates_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalSettings {
    pub disclaimer_acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionSettings {
    pub last_tab: Option<Tab>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSettings {
    pub appearance: AppearanceSettings,
    pub behavior: BehaviorSettings,
    pub history: HistorySettings,
    pub reports: ReportSettings,
    pub legal: LegalSettings,
    pub session: SessionSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            appearance: AppearanceSettings {
                theme: ThemePreference::System,
                accent_color: AccentColor::new(72, 133, 237, 255),
                font_size: 14.0,
                density: LayoutDensity::Comfortable,
            },
            behavior: BehaviorSettings {
                remember_last_tab: true,
                auto_refresh_on_launch: false,
                logs_expanded_by_default: false,
                confirm_before_execution: true,
            },
            history: HistorySettings { retention_days: 90 },
            reports: ReportSettings {
                default_export_location: None,
                auto_save_report_after_updates_run: false,
            },
            legal: LegalSettings {
                disclaimer_acknowledged: false,
            },
            session: SessionSettings::default(),
        }
    }
}

impl AppSettings {
    fn from_value(value: &Value) -> Self {
        let mut settings = Self::default();
        let Some(root) = value.as_object() else {
            return settings;
        };

        if let Some(appearance) = root.get("appearance").and_then(Value::as_object) {
            if let Some(theme) = appearance.get("theme").and_then(Value::as_str) {
                settings.appearance.theme = match theme {
                    "system" => ThemePreference::System,
                    "light" => ThemePreference::Light,
                    "dark" => ThemePreference::Dark,
                    _ => settings.appearance.theme,
                };
            }

            if let Some(color) = appearance.get("accent_color").and_then(Value::as_object) {
                settings.appearance.accent_color = AccentColor {
                    r: color
                        .get("r")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(settings.appearance.accent_color.r),
                    g: color
                        .get("g")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(settings.appearance.accent_color.g),
                    b: color
                        .get("b")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(settings.appearance.accent_color.b),
                    a: color
                        .get("a")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(settings.appearance.accent_color.a),
                };
            }

            if let Some(font_size) = appearance.get("font_size").and_then(Value::as_f64) {
                let font_size = font_size as f32;
                if (10.0..=24.0).contains(&font_size) {
                    settings.appearance.font_size = font_size;
                }
            }

            if let Some(density) = appearance.get("density").and_then(Value::as_str) {
                settings.appearance.density = match density {
                    "compact" => LayoutDensity::Compact,
                    "comfortable" => LayoutDensity::Comfortable,
                    _ => settings.appearance.density,
                };
            }
        }

        if let Some(behavior) = root.get("behavior").and_then(Value::as_object) {
            if let Some(value) = behavior.get("remember_last_tab").and_then(Value::as_bool) {
                settings.behavior.remember_last_tab = value;
            }
            if let Some(value) = behavior
                .get("auto_refresh_on_launch")
                .and_then(Value::as_bool)
            {
                settings.behavior.auto_refresh_on_launch = value;
            }
            if let Some(value) = behavior
                .get("logs_expanded_by_default")
                .and_then(Value::as_bool)
            {
                settings.behavior.logs_expanded_by_default = value;
            }
            if let Some(value) = behavior
                .get("confirm_before_execution")
                .and_then(Value::as_bool)
            {
                settings.behavior.confirm_before_execution = value;
            }
        }

        if let Some(history) = root.get("history").and_then(Value::as_object) {
            if let Some(retention_days) = history
                .get("retention_days")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
            {
                if (1..=3650).contains(&retention_days) {
                    settings.history.retention_days = retention_days;
                }
            }
        }

        if let Some(reports) = root.get("reports").and_then(Value::as_object) {
            if let Some(path) = reports
                .get("default_export_location")
                .and_then(Value::as_str)
                .map(str::trim)
            {
                settings.reports.default_export_location = if path.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(path))
                };
            }
            if let Some(value) = reports
                .get("auto_save_report_after_updates_run")
                .and_then(Value::as_bool)
            {
                settings.reports.auto_save_report_after_updates_run = value;
            }
        }

        if let Some(legal) = root.get("legal").and_then(Value::as_object) {
            if let Some(value) = legal
                .get("disclaimer_acknowledged")
                .and_then(Value::as_bool)
            {
                settings.legal.disclaimer_acknowledged = value;
            }
        }

        if let Some(session) = root.get("session").and_then(Value::as_object) {
            if let Some(tab) = session.get("last_tab").and_then(Value::as_str) {
                settings.session.last_tab = match tab {
                    "health" => Some(Tab::Health),
                    "triage_ai" => Some(Tab::TriageAi),
                    "reports" | "updates" => Some(Tab::Reports),
                    "btrfs" => Some(Tab::Btrfs),
                    "package_manager" => Some(Tab::PackageManager),
                    "configuration" => Some(Tab::Configuration),
                    "about" => Some(Tab::About),
                    _ => settings.session.last_tab,
                };
            }
        }

        settings
    }
}

pub fn config_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(PathBuf::from(home).join(".config").join("chamrisk"))
}

pub fn settings_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join(SETTINGS_FILE_NAME))
}

pub fn load_settings() -> AppSettings {
    let Ok(path) = settings_path() else {
        return AppSettings::default();
    };

    let Ok(raw) = fs::read_to_string(path) else {
        return AppSettings::default();
    };

    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return AppSettings::default();
    };

    AppSettings::from_value(&value)
}

pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let path = settings_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("settings path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create settings dir {}: {err}", parent.display()))?;
    let payload = serde_json::to_string_pretty(settings)
        .map_err(|err| format!("failed to serialize settings: {err}"))?;
    fs::write(&path, payload)
        .map_err(|err| format!("failed to write settings file {}: {err}", path.display()))
}

pub fn path_to_string(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_when_payload_is_not_an_object() {
        let settings = AppSettings::from_value(&json!("invalid"));
        assert_eq!(settings, AppSettings::default());
    }

    #[test]
    fn keeps_defaults_for_missing_or_invalid_fields() {
        let settings = AppSettings::from_value(&json!({
            "appearance": {
                "theme": "dark",
                "font_size": "large",
                "density": "invalid"
            },
            "behavior": {
                "remember_last_tab": false
            },
            "history": {
                "retention_days": 0
            },
            "reports": {
                "default_export_location": "/tmp/reports",
                "auto_save_report_after_updates_run": true
            },
            "legal": {
                "disclaimer_acknowledged": true
            },
            "session": {
                "last_tab": "reports"
            }
        }));

        assert_eq!(settings.appearance.theme, ThemePreference::Dark);
        assert_eq!(
            settings.appearance.font_size,
            AppSettings::default().appearance.font_size
        );
        assert_eq!(
            settings.appearance.density,
            AppSettings::default().appearance.density
        );
        assert!(!settings.behavior.remember_last_tab);
        assert_eq!(settings.history.retention_days, 90);
        assert_eq!(
            settings.reports.default_export_location,
            Some(PathBuf::from("/tmp/reports"))
        );
        assert!(settings.reports.auto_save_report_after_updates_run);
        assert!(settings.legal.disclaimer_acknowledged);
        assert_eq!(settings.session.last_tab, Some(Tab::Reports));
    }

    #[test]
    fn legacy_updates_last_tab_still_maps_to_reports() {
        let settings = AppSettings::from_value(&json!({
            "session": {
                "last_tab": "updates"
            }
        }));

        assert_eq!(settings.session.last_tab, Some(Tab::Reports));
    }

    #[test]
    fn report_auto_save_setting_round_trips_through_json() {
        let mut settings = AppSettings::default();
        settings.reports.auto_save_report_after_updates_run = true;

        let value = serde_json::to_value(&settings).expect("serialize settings");
        let loaded = AppSettings::from_value(&value);

        assert!(loaded.reports.auto_save_report_after_updates_run);
    }
}
