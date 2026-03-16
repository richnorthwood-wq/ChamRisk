use eframe::egui::{self, vec2, Color32, Pos2, Response, Sense, Shape, Stroke, Ui};

pub fn eye_mark(ui: &mut Ui, size: f32) -> Response {
    let desired = vec2(size, size * 0.62);
    let (rect, response) = ui.allocate_exact_size(desired, Sense::hover());
    if !ui.is_rect_visible(rect) {
        return response;
    }

    let visuals = ui.visuals();
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let rx = rect.width() * 0.5;
    let ry = rect.height() * 0.5;

    let stroke_color = visuals.widgets.noninteractive.fg_stroke.color;
    let fill_color = if visuals.dark_mode {
        Color32::from_rgba_unmultiplied(94, 159, 128, 34)
    } else {
        Color32::from_rgba_unmultiplied(64, 108, 84, 24)
    };
    let iris_color = if visuals.dark_mode {
        Color32::from_rgba_unmultiplied(154, 200, 110, 120)
    } else {
        Color32::from_rgba_unmultiplied(93, 139, 74, 110)
    };
    let pupil_color = visuals.window_fill().gamma_multiply(0.55);
    let ring_stroke = Stroke::new(1.0, stroke_color.gamma_multiply(0.55));
    let outline = Stroke::new(1.2, stroke_color.gamma_multiply(0.75));

    let mut eye_points = Vec::with_capacity(34);
    for i in 0..=16 {
        let t = i as f32 / 16.0;
        let x = rect.left() + rect.width() * t;
        let k = 1.0 - ((t * 2.0) - 1.0).abs().powf(1.6);
        let y = center.y - (ry * 0.88 * k);
        eye_points.push(Pos2::new(x, y));
    }
    for i in (0..=16).rev() {
        let t = i as f32 / 16.0;
        let x = rect.left() + rect.width() * t;
        let k = 1.0 - ((t * 2.0) - 1.0).abs().powf(1.6);
        let y = center.y + (ry * 0.88 * k);
        eye_points.push(Pos2::new(x, y));
    }
    painter.add(Shape::convex_polygon(eye_points, fill_color, outline));

    painter.circle_filled(
        center,
        ry * 0.72,
        visuals.extreme_bg_color.gamma_multiply(0.55),
    );
    painter.circle_filled(center, ry * 0.52, iris_color);
    painter.circle_stroke(center, ry * 0.52, ring_stroke);
    painter.circle_filled(center, ry * 0.26, pupil_color);

    let highlight = Pos2::new(center.x + rx * 0.16, center.y - ry * 0.22);
    painter.circle_filled(
        highlight,
        ry * 0.1,
        Color32::from_rgba_unmultiplied(255, 255, 255, if visuals.dark_mode { 84 } else { 96 }),
    );

    response
}

pub fn brand_wordmark(ui: &mut Ui) {
    ui.horizontal(|ui| {
        eye_mark(ui, 24.0);
        ui.add_space(4.0);
        ui.label(egui::RichText::new("ChamRisk").strong());
    });
}
