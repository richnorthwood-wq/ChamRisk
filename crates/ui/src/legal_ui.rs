use eframe::egui;

pub(crate) fn notice_panel(ui: &mut egui::Ui, title: &str, body: &str) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.heading(title);
        ui.label(body.trim());
    });
}
