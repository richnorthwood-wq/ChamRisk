use std::collections::HashMap;
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub architecture: String,
    pub cpu_model: String,
    pub memory_gb: u64,
    pub uptime_seconds: u64,
}

pub fn collect_system_info() -> SystemInfo {
    let (os_name, os_version) = read_os_release();

    SystemInfo {
        os_name,
        os_version,
        kernel: run_uname("-r"),
        architecture: run_uname("-m"),
        cpu_model: read_cpu_model(),
        memory_gb: read_memory_gb(),
        uptime_seconds: read_uptime_seconds(),
    }
}

pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }

    if parts.is_empty() {
        "0m".to_string()
    } else {
        parts.join(" ")
    }
}

fn read_os_release() -> (String, String) {
    let contents = match fs::read_to_string("/etc/os-release") {
        Ok(contents) => contents,
        Err(_) => return (unknown(), unknown()),
    };

    let map = parse_os_release_map(&contents);
    let os_name = resolve_os_name(&map);
    let os_version = resolve_os_version(&map);

    (os_name, os_version)
}

fn parse_os_release_map(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            let value = unquote_os_release(value);
            if value.is_empty() {
                return None;
            }
            Some((key.to_string(), value))
        })
        .collect()
}

fn resolve_os_name(map: &HashMap<String, String>) -> String {
    if let Some(pretty) = map.get("PRETTY_NAME") {
        return pretty.clone();
    }

    if let (Some(name), Some(version)) = (map.get("NAME"), map.get("VERSION")) {
        return format!("{name} {version}");
    }

    if let Some(name) = map.get("NAME") {
        return name.clone();
    }

    unknown()
}

fn resolve_os_version(map: &HashMap<String, String>) -> String {
    for key in ["VERSION", "VERSION_ID", "BUILD_ID", "IMAGE_VERSION"] {
        if let Some(value) = map.get(key) {
            if !value.trim().is_empty() {
                return value.clone();
            }
        }
    }

    unknown()
}

fn unquote_os_release(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].to_string();
    }

    trimmed.to_string()
}

fn run_uname(flag: &str) -> String {
    Command::new("uname")
        .arg(flag)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(unknown)
}

fn read_cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.trim() == "model name" {
                    let model = value.trim();
                    if model.is_empty() {
                        None
                    } else {
                        Some(model.to_string())
                    }
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(unknown)
}

fn read_memory_gb() -> u64 {
    let memtotal_kib = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let rest = line.strip_prefix("MemTotal:")?;
                rest.split_whitespace().next()?.parse::<u64>().ok()
            })
        })
        .unwrap_or(0);

    memtotal_kib / 1_048_576
}

fn read_uptime_seconds() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| {
            contents
                .split_whitespace()
                .next()
                .and_then(|seconds| seconds.parse::<f64>().ok())
        })
        .map(|seconds| seconds.max(0.0) as u64)
        .unwrap_or(0)
}

fn unknown() -> String {
    "Unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::{format_uptime, parse_os_release_map, resolve_os_name, resolve_os_version};

    #[test]
    fn formats_uptime_as_days_hours_minutes() {
        assert_eq!(format_uptime(3_600), "1h");
        assert_eq!(format_uptime(90_000), "1d 1h");
        assert_eq!(format_uptime(172_800), "2d");
    }

    #[test]
    fn os_release_version_prefers_version_and_falls_back_to_version_id() {
        let with_version = parse_os_release_map(
            r#"
NAME="openSUSE Tumbleweed"
VERSION="2026-03-12"
VERSION_ID="20260312"
"#,
        );
        let with_version_id_only = parse_os_release_map(
            r#"
NAME="openSUSE Tumbleweed"
VERSION_ID="20260312"
"#,
        );

        assert_eq!(resolve_os_version(&with_version), "2026-03-12");
        assert_eq!(resolve_os_version(&with_version_id_only), "20260312");
    }

    #[test]
    fn os_release_name_prefers_pretty_name() {
        let map = parse_os_release_map(
            r#"
NAME="openSUSE"
VERSION_ID="20260312"
PRETTY_NAME="openSUSE Tumbleweed 20260312"
"#,
        );

        assert_eq!(resolve_os_name(&map), "openSUSE Tumbleweed 20260312");
    }
}
