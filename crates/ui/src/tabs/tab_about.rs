use crate::legal_ui::notice_panel;
use crate::MaintenanceApp;
use chamrisk_ui::about::{
    ACKNOWLEDGEMENT_TITLE, AI_DISCLAIMER_TEXT, AI_DISCLAIMER_TITLE, APP_DISPLAY_NAME, COPYRIGHT,
    DISCLAIMER_TEXT, LICENSE_NAME, LICENSE_SUMMARY, THIRD_PARTY_TEXT,
};
use chamrisk_ui::branding::eye_mark;
use eframe::egui;

pub fn ui(app: &mut MaintenanceApp, _ctx: &egui::Context, ui: &mut egui::Ui) {
    ui.heading("About / Legal");
    ui.add_space(6.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            eye_mark(ui, 40.0);
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.heading(APP_DISPLAY_NAME);
                ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                ui.label(COPYRIGHT);
            });
        });
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("License");
        ui.label(LICENSE_NAME);
        ui.add_space(4.0);
        ui.label(LICENSE_SUMMARY.trim());
    });

    ui.add_space(8.0);

    notice_panel(ui, AI_DISCLAIMER_TITLE, AI_DISCLAIMER_TEXT);

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading("Third-Party Acknowledgements");
        ui.label(THIRD_PARTY_TEXT.trim());
    });

    ui.add_space(8.0);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading(ACKNOWLEDGEMENT_TITLE);
        ui.label(format!(
            "Status: {}",
            if app.settings.legal.disclaimer_acknowledged {
                "Acknowledged"
            } else {
                "Not yet acknowledged"
            }
        ));
        ui.add_space(4.0);
        ui.label(DISCLAIMER_TEXT.trim());
        if !app.settings.legal.disclaimer_acknowledged && ui.button("Acknowledge").clicked() {
            app.acknowledge_disclaimer();
        }
        if let Some(status) = &app.legal_status {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::YELLOW, status);
        }
    });
}
