use crate::health::filesystem;
use chamrisk_core::zypper::{parse_packages_xml, parse_repositories_xml};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Ok,
    Warn,
    Error,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub name: String,
    pub message: String,
    pub recommendation: Option<String>,
}

pub fn check_boot_space() -> HealthCheckResult {
    if let Some(usage) = filesystem::boot_partition_usage() {
        let percent = usage.used_percent;
        let status = if percent < 70 {
            HealthStatus::Ok
        } else if percent <= 85 {
            HealthStatus::Warn
        } else {
            HealthStatus::Error
        };

        return HealthCheckResult {
            name: "Boot Partition".to_string(),
            status,
            message: format!("{percent}% used ({})", usage.mount_point),
            recommendation: Some("Consider cleaning old kernels if usage exceeds 85%".to_string()),
        };
    }

    HealthCheckResult {
        name: "Boot Partition".to_string(),
        status: HealthStatus::Ok,
        message: "Boot partition not detected".to_string(),
        recommendation: None,
    }
}

pub fn check_orphans() -> HealthCheckResult {
    let output = match Command::new("zypper")
        .arg("--xmlout")
        .arg("packages")
        .arg("--orphaned")
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return HealthCheckResult {
                name: "Orphaned Packages".to_string(),
                status: HealthStatus::Warn,
                message: "Unable to check orphaned packages".to_string(),
                recommendation: Some("Review and remove unused packages".to_string()),
            };
        }
    };

    if !output.status.success() {
        return HealthCheckResult {
            name: "Orphaned Packages".to_string(),
            status: HealthStatus::Warn,
            message: "Unable to check orphaned packages".to_string(),
            recommendation: Some("Review and remove unused packages".to_string()),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = parse_packages_xml(&stdout)
        .map(|rows| rows.len())
        .unwrap_or(0);

    let status = if count == 0 {
        HealthStatus::Ok
    } else if count <= 10 {
        HealthStatus::Warn
    } else {
        HealthStatus::Error
    };

    HealthCheckResult {
        name: "Orphaned Packages".to_string(),
        status,
        message: format!("{count} orphaned packages detected"),
        recommendation: Some("Review and remove unused packages".to_string()),
    }
}

pub fn check_repositories() -> HealthCheckResult {
    let output = match Command::new("zypper")
        .arg("--xmlout")
        .arg("lr")
        .arg("-d")
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return HealthCheckResult {
                name: "Repository Configuration".to_string(),
                status: HealthStatus::Warn,
                message: "Unable to inspect repositories".to_string(),
                recommendation: Some("Review repository setup with `zypper lr -d`".to_string()),
            };
        }
    };

    if !output.status.success() {
        return HealthCheckResult {
            name: "Repository Configuration".to_string(),
            status: HealthStatus::Warn,
            message: "Unable to inspect repositories".to_string(),
            recommendation: Some("Review repository setup with `zypper lr -d`".to_string()),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let rows = match parse_repositories_xml(&stdout) {
        Ok(rows) if !rows.is_empty() => rows,
        _ => {
            return HealthCheckResult {
                name: "Repository Configuration".to_string(),
                status: HealthStatus::Warn,
                message: "Unable to inspect repositories".to_string(),
                recommendation: Some("Review repository setup with `zypper lr -d`".to_string()),
            };
        }
    };

    let mut seen_names = std::collections::HashSet::new();
    let mut duplicate_names = 0usize;
    let mut disabled_repos = 0usize;
    let mut packman_repos = 0usize;
    let mut active_repos = 0usize;

    for row in rows {
        let repo_name = if !row.name.is_empty() {
            row.name
        } else {
            row.alias
        };
        let repo_name_lc = repo_name.to_ascii_lowercase();
        let enabled = row.enabled.unwrap_or(true);

        if enabled {
            active_repos += 1;
        } else {
            disabled_repos += 1;
        }

        if repo_name_lc.contains("packman") {
            packman_repos += 1;
        }

        if !repo_name.is_empty() && !seen_names.insert(repo_name_lc) {
            duplicate_names += 1;
        }
    }

    let has_duplicate_packman = packman_repos > 1;
    let status = if has_duplicate_packman {
        HealthStatus::Error
    } else if disabled_repos > 0 {
        HealthStatus::Warn
    } else {
        HealthStatus::Ok
    };

    let message = if has_duplicate_packman {
        format!("{active_repos} repositories active, {packman_repos} Packman repos detected")
    } else if disabled_repos > 0 {
        format!("{active_repos} repositories active, {disabled_repos} disabled")
    } else if duplicate_names > 0 {
        format!("{active_repos} repositories active, {duplicate_names} duplicate names found")
    } else {
        format!("{active_repos} repositories active, Packman configured correctly")
    };

    let recommendation = if has_duplicate_packman {
        Some("Remove duplicate Packman repositories and keep a single correct entry.".to_string())
    } else if disabled_repos > 0 {
        Some(
            "Review disabled repositories and enable required ones with `zypper mr -e`."
                .to_string(),
        )
    } else {
        None
    };

    HealthCheckResult {
        name: "Repository Configuration".to_string(),
        status,
        message,
        recommendation,
    }
}

pub fn collect_health_checks() -> Vec<HealthCheckResult> {
    let btrfs_enabled = root_filesystem_is_btrfs();

    vec![
        check_boot_space(),
        check_orphans(),
        check_repositories(),
        check_btrfs_enabled(btrfs_enabled),
        check_btrfs_root_lineage(btrfs_enabled),
    ]
}

pub fn root_filesystem_is_btrfs() -> bool {
    let output = match run_command_with_timeout("findmnt", &["-no", "FSTYPE", "/"], 250) {
        Ok(output) => output,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .eq_ignore_ascii_case("btrfs")
}

fn check_btrfs_enabled(enabled: bool) -> HealthCheckResult {
    if enabled {
        HealthCheckResult {
            name: "Btrfs Enabled".to_string(),
            status: HealthStatus::Ok,
            message: "Yes".to_string(),
            recommendation: None,
        }
    } else {
        HealthCheckResult {
            name: "Btrfs Enabled".to_string(),
            status: HealthStatus::Warn,
            message: "Consider Enabling Btrfs Snapshots".to_string(),
            recommendation: Some("Enable Btrfs snapshots for safer rollback points".to_string()),
        }
    }
}

fn check_btrfs_root_lineage(btrfs_enabled: bool) -> HealthCheckResult {
    if !btrfs_enabled {
        return HealthCheckResult {
            name: "Btrfs Root Lineage".to_string(),
            status: HealthStatus::Unknown,
            message: "Unable to determine Btrfs root lineage.".to_string(),
            recommendation: Some(
                "Root mount information could not be parsed, or this system is not using a detectable Snapper-style Btrfs layout."
                    .to_string(),
            ),
        };
    }

    let options = match run_command_with_timeout("findmnt", &["-no", "OPTIONS", "/"], 250) {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout).to_string(),
        _ => {
            return HealthCheckResult {
                name: "Btrfs Root Lineage".to_string(),
                status: HealthStatus::Unknown,
                message: "Unable to determine Btrfs root lineage.".to_string(),
                recommendation: Some(
                    "Root mount information could not be parsed, or this system is not using a detectable Snapper-style Btrfs layout."
                        .to_string(),
                ),
            }
        }
    };

    let subvol = match parse_subvol_from_mount_options(&options) {
        Some(subvol) => subvol,
        None => {
            return HealthCheckResult {
                name: "Btrfs Root Lineage".to_string(),
                status: HealthStatus::Unknown,
                message: "Unable to determine Btrfs root lineage.".to_string(),
                recommendation: Some(
                    "Root mount information could not be parsed, or this system is not using a detectable Snapper-style Btrfs layout."
                        .to_string(),
                ),
            }
        }
    };

    if is_snapshot_backed_subvolume(&subvol) {
        return HealthCheckResult {
            name: "Btrfs Root Lineage".to_string(),
            status: HealthStatus::Warn,
            message: "System is booted from a snapshot-backed Btrfs root.".to_string(),
            recommendation: Some(
                "You appear to be running from a rollback-created or snapshot-backed root subvolume. Updates may still work, but root lineage is branched and recovery history may be harder to reason about."
                    .to_string(),
            ),
        };
    }

    HealthCheckResult {
        name: "Btrfs Root Lineage".to_string(),
        status: HealthStatus::Ok,
        message: "System is booted from normal Btrfs root.".to_string(),
        recommendation: Some(
            "Current root mount does not appear to be snapshot-backed.".to_string(),
        ),
    }
}

fn parse_subvol_from_mount_options(options: &str) -> Option<String> {
    let mut subvols = options
        .trim()
        .split(',')
        .filter_map(|entry| entry.trim().strip_prefix("subvol="))
        .map(ToOwned::to_owned);
    let subvol = subvols.next()?;

    if subvols.next().is_some() {
        return None;
    }

    if subvol.is_empty() {
        None
    } else {
        Some(subvol)
    }
}

fn is_snapshot_backed_subvolume(subvol: &str) -> bool {
    let subvol_normalized = subvol.trim();
    subvol_normalized.contains(".snapshots/") && subvol_normalized.contains("/snapshot")
}

fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    timeout_ms: u64,
) -> Result<Output, std::io::Error> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match child.try_wait()? {
            Some(_) => return child.wait_with_output(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("command timed out: {program}"),
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_snapshot_backed_subvolume, parse_subvol_from_mount_options};

    #[test]
    fn parses_subvol_from_mount_options() {
        let options = "rw,relatime,ssd,space_cache=v2,subvolid=259,subvol=/@";
        assert_eq!(
            parse_subvol_from_mount_options(options),
            Some("/@".to_string())
        );
    }

    #[test]
    fn parse_subvol_returns_none_for_missing_or_ambiguous_subvol() {
        assert_eq!(
            parse_subvol_from_mount_options("rw,relatime,subvolid=259"),
            None
        );
        assert_eq!(
            parse_subvol_from_mount_options("rw,subvol=/@,subvol=/.snapshots/1/snapshot"),
            None
        );
    }

    #[test]
    fn detects_snapshot_backed_subvolumes() {
        assert!(is_snapshot_backed_subvolume("/.snapshots/1022/snapshot"));
        assert!(!is_snapshot_backed_subvolume("/@"));
    }
}
