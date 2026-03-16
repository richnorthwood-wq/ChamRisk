pub mod checks;
pub mod filesystem;
pub mod pulse;
pub mod system_info;

pub use checks::{root_filesystem_is_btrfs, HealthCheckResult, HealthStatus};
pub use pulse::{collect_system_pulse, SystemPulse, SystemTelemetry};
pub use system_info::{collect_system_info, format_uptime, SystemInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallStatus {
    Green,
    Amber,
    Red,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthReport {
    pub pulse: SystemPulse,
    pub checks: Vec<HealthCheckResult>,
    pub overall_status: OverallStatus,
}

pub fn collect_health_report() -> HealthReport {
    let checks = checks::collect_health_checks();
    let overall_status = compute_overall_status(&checks);

    HealthReport {
        pulse: pulse::collect_system_pulse(),
        checks,
        overall_status,
    }
}

fn compute_overall_status(checks: &[HealthCheckResult]) -> OverallStatus {
    if checks
        .iter()
        .any(|check| check.status == HealthStatus::Error)
    {
        OverallStatus::Red
    } else if checks
        .iter()
        .any(|check| matches!(check.status, HealthStatus::Warn | HealthStatus::Unknown))
    {
        OverallStatus::Amber
    } else {
        OverallStatus::Green
    }
}
