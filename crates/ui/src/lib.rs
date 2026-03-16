pub mod about;
pub mod ai_settings;
pub mod app;
pub mod branding;
pub mod settings;

pub use ai_settings::{ai_settings_path, default_ai_settings, load_ai_settings, save_ai_settings};
pub use app::{AppEvent, LogEntry, LogLevel, LogStage, MaintenanceApp, Tab};
pub use settings::{
    save_settings, AccentColor, AppSettings, AppearanceSettings, BehaviorSettings, HistorySettings,
    LayoutDensity, LegalSettings, ReportSettings, SessionSettings, ThemePreference,
};
