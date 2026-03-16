// models/triage.rs
use crate::models::PackageBackend;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedAction {
    Install,
    Remove,
    Update,
    Upgrade,
    Downgrade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriagePackage {
    pub triage_id: String,         // stable UI/reference id
    pub backend: PackageBackend,   // Zypper / Dnf / Pacman / Flatpak (later)
    pub package_name: String,      // display/original
    pub package_name_norm: String, // canonical for matching
    pub arch: Option<String>,      // x86_64, noarch, etc
    pub planned_action: PlannedAction,
    pub planned_from_version: Option<String>,
    pub planned_to_version: Option<String>,
    pub selected: bool,              // user selected for execution
    pub source_repo: Option<String>, // repo alias if known
}
