// models.rs (REPLACE ENTIRE FILE CONTENT WITH THIS)

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAction {
    Install,
    Upgrade,
    Downgrade,
    Remove,
    VendorChange,
    RepoChange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorGroup {
    Official,
    Packman,
    ThirdParty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageUpdate {
    pub name: String,
    pub action: UpdateAction,
    pub current_version: Option<String>,
    pub new_version: Option<String>,
    pub arch: Option<String>,
    pub repository: Option<String>,
    pub vendor: Option<String>, // <-- ADDED
    pub vendor_group: VendorGroup,
    pub vendor_change: bool,
    pub repo_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageChange {
    pub name: String,
    pub arch: Option<String>,
    pub action: UpdateAction,
    pub from: Option<String>,
    pub to: Option<String>,
    pub repo: Option<String>,
    pub vendor: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub changes: Vec<PackageChange>,
    pub command: Vec<String>,
    pub result: CommandResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRow {
    pub name: String,
    pub installed_version: Option<String>,
    pub available_version: Option<String>,
    pub repository: Option<String>,
    pub arch: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLock {
    pub lock_id: Option<String>,
    pub name: String,
    pub match_type: Option<String>,
    pub repository: Option<String>,
    pub comment: Option<String>,
    pub raw_entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryRow {
    pub alias: String,
    pub name: String,
    pub enabled: Option<bool>,
    pub gpg_check: Option<bool>,
    pub refresh: Option<bool>,
    pub priority: Option<String>,
    pub uri: Option<String>,
    pub repo_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSnapshotRow {
    pub snapshot_id: String,
    pub is_current: bool,
    pub snapshot_type: String,
    pub pre_number: Option<String>,
    pub date: String,
    pub user: String,
    pub used_space: String,
    pub cleanup: String,
    pub description: String,
    pub userdata: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageAction {
    Install,
    Upgrade,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMark {
    pub name: String,
    pub action: PackageAction,
}
