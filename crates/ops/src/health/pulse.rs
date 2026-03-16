use crate::health::filesystem;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SystemTelemetry {
    pub cpu_percent: f32,
    pub mem_used_gb: f32,
    pub mem_total_gb: f32,
    pub root_fs_percent: f32,
}

impl Default for SystemTelemetry {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            mem_used_gb: 0.0,
            mem_total_gb: 0.0,
            root_fs_percent: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemPulse {
    pub cpu_load: f32,
    pub mem_used_gb: f32,
    pub mem_total_gb: f32,
    pub mem_ratio: f32,
    pub root_disk_ratio: f32,
    pub efi_ratio: Option<f32>,
    pub efi_mount_point: Option<String>,
}

impl SystemPulse {
    pub fn collect() -> Option<Self> {
        let raw_load = read_cpu_load()?;
        let cpu_cores = (num_cpus::get().max(1)) as f32;
        let cpu_load = (raw_load / cpu_cores).clamp(0.0, 1.0);

        let (mem_used_gb, mem_total_gb, mem_ratio) = read_memory()?;
        let root_disk_ratio = filesystem::root_usage()?.used_ratio();
        let efi_usage = filesystem::boot_partition_usage();
        let efi_ratio = efi_usage.as_ref().map(|usage| usage.used_ratio());
        let efi_mount_point = efi_usage.map(|usage| usage.mount_point);

        Some(Self {
            cpu_load,
            mem_used_gb,
            mem_total_gb,
            mem_ratio,
            root_disk_ratio,
            efi_ratio,
            efi_mount_point,
        })
    }
}

pub fn collect_system_pulse() -> SystemPulse {
    SystemPulse::collect().unwrap_or(SystemPulse {
        cpu_load: 0.0,
        mem_used_gb: 0.0,
        mem_total_gb: 0.0,
        mem_ratio: 0.0,
        root_disk_ratio: 0.0,
        efi_ratio: None,
        efi_mount_point: None,
    })
}

fn read_cpu_load() -> Option<f32> {
    let loadavg = fs::read_to_string("/proc/loadavg").ok()?;
    loadavg.split_whitespace().next()?.parse::<f32>().ok()
}

fn read_memory() -> Option<(f32, f32, f32)> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kib: Option<f32> = None;
    let mut available_kib: Option<f32> = None;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kib = parse_kib_value(line);
        } else if line.starts_with("MemAvailable:") {
            available_kib = parse_kib_value(line);
        }
    }

    let total_kib = total_kib?;
    let available_kib = available_kib?;
    if total_kib <= 0.0 {
        return None;
    }

    let used_kib = (total_kib - available_kib).max(0.0);
    let mem_used_gb = used_kib / 1_048_576.0;
    let mem_total_gb = total_kib / 1_048_576.0;
    let mem_ratio = (used_kib / total_kib).clamp(0.0, 1.0);

    Some((mem_used_gb, mem_total_gb, mem_ratio))
}

fn parse_kib_value(line: &str) -> Option<f32> {
    line.split_whitespace().nth(1)?.parse::<f32>().ok()
}
