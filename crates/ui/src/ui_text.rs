use eframe::egui;

pub(crate) fn metric_value(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into())
        .color(egui::Color32::WHITE)
        .strong()
        .size(18.0)
}
