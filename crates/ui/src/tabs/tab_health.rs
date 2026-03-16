use crate::{ui_text::metric_value, MaintenanceApp};
use chamrisk_ops::health::{format_uptime, HealthReport, HealthStatus, SystemInfo, SystemPulse};
use eframe::egui;

struct Metric {
    ratio: f32,
    text: String,
    show_percentage: bool,
}

pub fn show(ui: &mut egui::Ui, app: &mut MaintenanceApp) {
    ui.horizontal(|ui| {
        ui.heading("Health");
        if ui.button("Refresh Health").clicked() {
            app.request_refresh_health();
        }
        if ui
            .add_enabled(
                !app.system_workbook_export.running,
                egui::Button::new("Export system workbook"),
            )
            .clicked()
        {
            app.request_system_workbook_export();
        }
    });
    if app.system_workbook_export.running {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.label(
                app.system_workbook_export
                    .status
                    .as_deref()
                    .unwrap_or("Exporting system workbook..."),
            );
        });
    } else if let Some(status) = &app.system_workbook_export.status {
        ui.label(status);
    }
    render_system_overview(ui, app.system_info.as_ref());
    render_package_locks_advisory(ui, app.state.package_manager.locks.len());
    ui.add_space(10.0);

    if app.health_state.running && app.health_state.report.is_none() {
        ui.label("Running health checks...");
    }

    ui.columns(2, |columns| {
        columns[0].set_min_width(280.0);
        columns[0].vertical(|ui| {
            ui.label("System Pulse");
            egui::Frame::group(ui.style()).show(ui, |ui| {
                if let Some(pulse) = &app.health_state.pulse {
                    render_system_pulse(ui, pulse);
                } else {
                    ui.label("System pulse unavailable.");
                }
            });
        });

        columns[1].set_min_width(320.0);
        columns[1].vertical(|ui| {
            ui.label("Maintenance Health");
            egui::Frame::group(ui.style()).show(ui, |ui| {
                if let Some(report) = &app.health_state.report {
                    render_health_report(ui, report);
                } else {
                    ui.label("No health report available yet.");
                }
            });
        });
    });
}

fn render_package_locks_advisory(ui: &mut egui::Ui, lock_count: usize) {
    ui.add_space(6.0);
    ui.label("Package Locks");
    ui.group(|ui| {
        ui.label(egui::RichText::new(format!("{lock_count} locked package(s)")).strong());
        if lock_count > 0 {
            ui.label(
                "Review locked packages periodically to avoid stale pins and dependency issues.",
            );
        }
    });
}

fn render_system_overview(ui: &mut egui::Ui, system_info: Option<&SystemInfo>) {
    ui.label("System Overview");

    let os = system_info.map(|i| i.os_name.as_str()).unwrap_or("Unknown");
    let kernel = system_info.map(|i| i.kernel.as_str()).unwrap_or("Unknown");
    let architecture = system_info
        .map(|i| i.architecture.as_str())
        .unwrap_or("Unknown");
    let cpu = system_info
        .map(|i| i.cpu_model.as_str())
        .unwrap_or("Unknown");
    let memory = system_info
        .map(|i| {
            if i.memory_gb == 0 {
                "Unknown".to_string()
            } else {
                format!("{} GB", i.memory_gb)
            }
        })
        .unwrap_or_else(|| "Unknown".to_string());
    let uptime = system_info
        .map(|i| {
            if i.uptime_seconds == 0 {
                "Unknown".to_string()
            } else {
                format_uptime(i.uptime_seconds)
            }
        })
        .unwrap_or_else(|| "Unknown".to_string());

    ui.columns(3, |columns| {
        columns[0].vertical(|ui| info_box(ui, "OS", os));
        columns[1].vertical(|ui| info_box(ui, "Kernel", kernel));
        columns[2].vertical(|ui| info_box(ui, "Architecture", architecture));
    });

    ui.add_space(6.0);
    ui.columns(3, |columns| {
        columns[0].vertical(|ui| info_box(ui, "CPU", cpu));
        columns[1].vertical(|ui| info_box(ui, "Memory", &memory));
        columns[2].vertical(|ui| info_box(ui, "Uptime", &uptime));
    });
}

fn info_box(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.group(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(label).weak());
            ui.label(egui::RichText::new(value).strong());
        });
    });
}

fn render_health_report(ui: &mut egui::Ui, report: &HealthReport) {
    for check in &report.checks {
        ui.horizontal_wrapped(|ui| {
            let icon = status_icon(check.status);
            let color = status_color(check.status);
            ui.colored_label(color, icon);
            ui.strong(&check.name);
            ui.label(&check.message);
        });
        if let Some(recommendation) = check.recommendation.as_deref() {
            ui.label(
                egui::RichText::new(format!("Recommendation: {recommendation}"))
                    .small()
                    .italics(),
            );
        }
        ui.add_space(6.0);
    }
}

fn render_system_pulse(ui: &mut egui::Ui, pulse: &SystemPulse) {
    let cpu = cpu_load_metric(pulse);
    ui.label("CPU average load");
    render_metric_bar(ui, cpu);

    ui.add_space(6.0);
    let memory = memory_usage_metric(pulse);
    ui.label("Memory usage");
    render_metric_bar(ui, memory);

    ui.add_space(6.0);
    let root = filesystem_usage_metric(pulse, false);
    ui.label("Root filesystem");
    render_metric_bar(ui, root);

    ui.add_space(6.0);
    let efi = filesystem_usage_metric(pulse, true);
    ui.label("/boot/efi");
    render_metric_bar(ui, efi);
}

fn status_icon(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Ok => "[OK]",
        HealthStatus::Warn => "[!]",
        HealthStatus::Error => "[X]",
        HealthStatus::Unknown => "[?]",
    }
}

fn status_color(status: HealthStatus) -> egui::Color32 {
    match status {
        HealthStatus::Ok => egui::Color32::GREEN,
        HealthStatus::Warn => egui::Color32::YELLOW,
        HealthStatus::Error => egui::Color32::RED,
        HealthStatus::Unknown => egui::Color32::LIGHT_GRAY,
    }
}

fn cpu_load_metric(pulse: &SystemPulse) -> Metric {
    let ratio = pulse.cpu_load.clamp(0.0, 1.0);
    Metric {
        ratio,
        text: format!("{:.0}%", ratio * 100.0),
        show_percentage: true,
    }
}

fn memory_usage_metric(pulse: &SystemPulse) -> Metric {
    Metric {
        ratio: pulse.mem_ratio.clamp(0.0, 1.0),
        text: format!("{:.1} / {:.1} GiB", pulse.mem_used_gb, pulse.mem_total_gb),
        show_percentage: true,
    }
}

fn filesystem_usage_metric(pulse: &SystemPulse, efi: bool) -> Metric {
    if efi {
        if let Some(ratio) = pulse.efi_ratio {
            let ratio = ratio.clamp(0.0, 1.0);
            let text = if let Some(mount_point) = pulse.efi_mount_point.as_deref() {
                format!("{:.0}% used ({mount_point})", ratio * 100.0)
            } else {
                format!("{:.0}% used", ratio * 100.0)
            };
            return Metric {
                ratio,
                text,
                show_percentage: true,
            };
        }

        return Metric {
            ratio: 0.0,
            text: "Not mounted".to_string(),
            show_percentage: false,
        };
    }

    let ratio = pulse.root_disk_ratio.clamp(0.0, 1.0);
    Metric {
        ratio,
        text: format!("{:.0}% used", ratio * 100.0),
        show_percentage: true,
    }
}

fn render_metric_bar(ui: &mut egui::Ui, metric: Metric) {
    let bar = egui::ProgressBar::new(metric.ratio).text(metric_value(metric.text));
    if metric.show_percentage {
        ui.add(bar.show_percentage());
    } else {
        ui.add(bar);
    }
}
