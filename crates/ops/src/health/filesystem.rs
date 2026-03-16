use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemUsage {
    pub mount_point: String,
    pub used_percent: u8,
}

impl FilesystemUsage {
    pub fn used_ratio(&self) -> f32 {
        (f32::from(self.used_percent) / 100.0).clamp(0.0, 1.0)
    }
}

pub fn root_usage() -> Option<FilesystemUsage> {
    usage_for_mount("/")
}

pub fn boot_partition_usage() -> Option<FilesystemUsage> {
    usage_for_mount("/boot/efi").or_else(|| usage_for_mount("/boot"))
}

fn usage_for_mount(path: &str) -> Option<FilesystemUsage> {
    if !is_exact_mount_point(path) {
        return None;
    }

    let output = Command::new("df").arg("-P").arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let used_percent = stdout
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(4))
        .and_then(|value| value.trim_end_matches('%').parse::<u8>().ok())?;

    Some(FilesystemUsage {
        mount_point: path.to_string(),
        used_percent,
    })
}

fn is_exact_mount_point(path: &str) -> bool {
    let output = match Command::new("findmnt")
        .arg("-n")
        .arg("-o")
        .arg("TARGET")
        .arg("--target")
        .arg(path)
        .output()
    {
        Ok(output) => output,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    String::from_utf8_lossy(&output.stdout).trim() == path
}
