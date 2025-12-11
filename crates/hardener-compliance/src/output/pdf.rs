//! PDF report formatter.
//!
//! Produces PDF compliance reports using the krilla library.

use crate::output::ReportFormatter;
use crate::report::ComplianceReport;
use hardener_common::types::ControlStatus;
use krilla::geom::{PathBuilder, Point};
use krilla::num::NormalizedF32;
use krilla::page::PageSettings;
use krilla::paint::{Fill, FillRule};
use krilla::text::{Font, TextDirection};
use krilla::{Document, color};
use std::collections::BTreeMap;

/// Embedded font data (NotoSans).
const FONT_DATA: &[u8] = include_bytes!("../fonts/NotoSans-Regular.ttf");
const FONT_BOLD_DATA: &[u8] = include_bytes!("../fonts/NotoSans-Bold.ttf");

/// Page dimensions (A4 in points: 595 × 842).
const PAGE_WIDTH: f32 = 595.0;
const PAGE_HEIGHT: f32 = 842.0;

/// Margins.
const MARGIN_LEFT: f32 = 50.0;
const MARGIN_TOP: f32 = 50.0;
const MARGIN_BOTTOM: f32 = 50.0;

/// Content width.
const CONTENT_WIDTH: f32 = PAGE_WIDTH - MARGIN_LEFT - 50.0;

/// Font sizes.
const TITLE_SIZE: f32 = 24.0;
const HEADING_SIZE: f32 = 16.0;
const BODY_SIZE: f32 = 10.0;
const SMALL_SIZE: f32 = 8.0;

/// Line heights (multiplier of font size).
const LINE_HEIGHT: f32 = 1.4;

/// Colours (RGB).
fn colour_black() -> color::rgb::Color {
    color::rgb::Color::new(0, 0, 0)
}

fn colour_dark_grey() -> color::rgb::Color {
    color::rgb::Color::new(51, 51, 51)
}

fn colour_medium_grey() -> color::rgb::Color {
    color::rgb::Color::new(127, 140, 141)
}

fn colour_pass() -> color::rgb::Color {
    color::rgb::Color::new(39, 174, 96)
}

fn colour_fail() -> color::rgb::Color {
    color::rgb::Color::new(231, 76, 60)
}

fn colour_warning() -> color::rgb::Color {
    color::rgb::Color::new(241, 196, 15)
}

fn colour_na() -> color::rgb::Color {
    color::rgb::Color::new(149, 165, 166)
}

fn colour_blue() -> color::rgb::Color {
    color::rgb::Color::new(52, 152, 219)
}

fn colour_light_grey() -> color::rgb::Color {
    color::rgb::Color::new(236, 240, 241)
}

/// Formats compliance reports as PDF.
pub struct PdfFormatter;

impl PdfFormatter {
    /// Creates a new PdfFormatter.
    pub fn new() -> PdfFormatter {
        PdfFormatter
    }
}

impl Default for PdfFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportFormatter for PdfFormatter {
    fn format(&self, report: &ComplianceReport) -> String {
        let pdf_bytes = generate_pdf(report);

        // The ReportFormatter trait returns a String, but PDF is binary.
        // We return raw bytes converted to a String for file writing.
        // Each byte is preserved as-is (ISO-8859-1 / Latin-1 encoding).
        pdf_bytes.into_iter().map(|b| b as char).collect()
    }
}

/// Tracks current Y position during PDF generation.
struct YTracker {
    current_y: f32,
}

impl YTracker {
    fn new() -> Self {
        Self {
            current_y: MARGIN_TOP,
        }
    }

    /// Resets Y position for a new page.
    fn reset(&mut self) {
        self.current_y = MARGIN_TOP;
    }

    /// Checks if we need a new page.
    fn needs_new_page(&self, needed: f32) -> bool {
        self.current_y + needed > PAGE_HEIGHT - MARGIN_BOTTOM
    }

    /// Advances Y position by the specified amount.
    fn advance(&mut self, amount: f32) {
        self.current_y += amount;
    }

    /// Returns current Y position.
    fn y(&self) -> f32 {
        self.current_y
    }
}

/// Generates a PDF document from a compliance report.
fn generate_pdf(report: &ComplianceReport) -> Vec<u8> {
    let font_regular = Font::new(FONT_DATA.to_vec().into(), 0).expect(
        "Failed to load regular font - ensure NotoSans-Regular.ttf is
  present",
    );
    let font_bold = Font::new(FONT_BOLD_DATA.to_vec().into(), 0).expect(
        "Failed to load bold font - ensure NotoSans-Bold.ttf is
  present",
    );

    let mut document = Document::new();
    let mut y = YTracker::new();

    // Group controls by section for organised output
    let mut sections: BTreeMap<&str, Vec<&crate::report::ControlResult>> = BTreeMap::new();
    for control in &report.report_controls {
        sections
            .entry(control.control_section.as_str())
            .or_default()
            .push(control);
    }

    // Sort sections by their first control ID (numerical order) rather than alphabetically
    let mut sections_vec: Vec<_> = sections.into_iter().collect();
    sections_vec.sort_by(|a, b| {
        let empty = String::new();
        let id_a = a.1.first().map(|c| c.control_id.as_str()).unwrap_or(&empty);
        let id_b = b.1.first().map(|c| c.control_id.as_str()).unwrap_or(&empty);
        compare_control_ids(id_a, id_b)
    });

    // Start first page
    let mut page = document.start_page_with(PageSettings::new(PAGE_WIDTH, PAGE_HEIGHT));
    let mut surface = page.surface();

    // === Title ===
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    let title = format!("{} Compliance Report", report.report_framework.full_name());
    surface.draw_text(
        Point::from_xy(MARGIN_LEFT, y.y() + TITLE_SIZE),
        font_bold.clone(),
        TITLE_SIZE,
        &title,
        false,
        TextDirection::LeftToRight,
    );
    y.advance(TITLE_SIZE * LINE_HEIGHT + 5.0);

    // === Framework description (subtitle) ===
    surface.set_fill(Some(Fill {
        paint: colour_medium_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    let description = report.report_framework.description();
    surface.draw_text(
        Point::from_xy(MARGIN_LEFT, y.y() + BODY_SIZE),
        font_regular.clone(),
        BODY_SIZE,
        description,
        false,
        TextDirection::LeftToRight,
    );
    y.advance(BODY_SIZE * LINE_HEIGHT + 10.0);

    // === Generated timestamp ===
    let generated = format!(
        "Generated: {}",
        report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    surface.draw_text(
        Point::from_xy(MARGIN_LEFT, y.y() + SMALL_SIZE),
        font_regular.clone(),
        SMALL_SIZE,
        &generated,
        false,
        TextDirection::LeftToRight,
    );
    y.advance(SMALL_SIZE * LINE_HEIGHT + 20.0);

    // === Summary Box ===
    draw_summary_box(&mut surface, &mut y, report, &font_regular, &font_bold);
    y.advance(30.0);

    // === Controls by Section ===
    for (section_name, controls) in &sections_vec {
        // Check if we need a new page for the section header
        if y.needs_new_page(HEADING_SIZE * LINE_HEIGHT + BODY_SIZE * LINE_HEIGHT * 3.0) {
            surface.finish();
            page.finish();
            y.reset();
            page = document.start_page_with(PageSettings::new(PAGE_WIDTH, PAGE_HEIGHT));
            surface = page.surface();
        }

        // Section header
        surface.set_fill(Some(Fill {
            paint: colour_dark_grey().into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));

        surface.draw_text(
            Point::from_xy(MARGIN_LEFT, y.y() + HEADING_SIZE),
            font_bold.clone(),
            HEADING_SIZE,
            section_name,
            false,
            TextDirection::LeftToRight,
        );
        y.advance(HEADING_SIZE * LINE_HEIGHT + 5.0);

        // Draw line under section header
        draw_horizontal_line(&mut surface, y.y(), colour_blue());
        y.advance(10.0);

        // Column headers
        surface.set_fill(Some(Fill {
            paint: colour_medium_grey().into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));

        surface.draw_text(
            Point::from_xy(MARGIN_LEFT, y.y() + SMALL_SIZE),
            font_bold.clone(),
            SMALL_SIZE,
            "Control",
            false,
            TextDirection::LeftToRight,
        );

        surface.draw_text(
            Point::from_xy(MARGIN_LEFT + 60.0, y.y() + SMALL_SIZE),
            font_bold.clone(),
            SMALL_SIZE,
            "Status",
            false,
            TextDirection::LeftToRight,
        );

        surface.draw_text(
            Point::from_xy(MARGIN_LEFT + 120.0, y.y() + SMALL_SIZE),
            font_bold.clone(),
            SMALL_SIZE,
            "Description",
            false,
            TextDirection::LeftToRight,
        );

        y.advance(SMALL_SIZE * LINE_HEIGHT + 5.0);

        // Controls in this section
        for control in controls {
            // Check if we need a new page
            let control_height = BODY_SIZE * LINE_HEIGHT * 2.0
                + if control.control_status == ControlStatus::Fail {
                    control.control_findings.len() as f32 * BODY_SIZE * LINE_HEIGHT
                } else {
                    0.0
                };

            if y.needs_new_page(control_height) {
                surface.finish();
                page.finish();
                y.reset();
                page = document.start_page_with(PageSettings::new(PAGE_WIDTH, PAGE_HEIGHT));
                surface = page.surface();
            }

            draw_control(&mut surface, &mut y, control, &font_regular, &font_bold);
        }

        y.advance(15.0);
    }

    // === Footer on last page ===
    surface.set_fill(Some(Fill {
        paint: colour_medium_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    let footer_y = PAGE_HEIGHT - MARGIN_BOTTOM + 20.0;
    draw_horizontal_line(&mut surface, footer_y - 10.0, colour_light_grey());

    surface.draw_text(
        Point::from_xy(MARGIN_LEFT, footer_y),
        font_regular.clone(),
        SMALL_SIZE,
        "Generated by Linux System Hardener",
        false,
        TextDirection::LeftToRight,
    );

    surface.finish();
    page.finish();

    document.finish().expect("Failed to generate PDF")
}

/// Draws the summary box with score and statistics.
fn draw_summary_box(
    surface: &mut krilla::surface::Surface,
    y: &mut YTracker,
    report: &ComplianceReport,
    font_regular: &Font,
    font_bold: &Font,
) {
    let box_height = 80.0;
    let start_y = y.y();

    // Draw background rectangle
    let mut pb = PathBuilder::new();
    pb.move_to(MARGIN_LEFT, start_y);
    pb.line_to(MARGIN_LEFT + CONTENT_WIDTH, start_y);
    pb.line_to(MARGIN_LEFT + CONTENT_WIDTH, start_y + box_height);
    pb.line_to(MARGIN_LEFT, start_y + box_height);
    pb.close();

    if let Some(path) = pb.finish() {
        surface.set_fill(Some(Fill {
            paint: colour_light_grey().into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));
        surface.draw_path(&path);
    }

    // "Summary" heading
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    surface.draw_text(
        Point::from_xy(MARGIN_LEFT + 15.0, start_y + 25.0),
        font_bold.clone(),
        HEADING_SIZE,
        "Summary",
        false,
        TextDirection::LeftToRight,
    );

    // Score percentage (large, coloured)
    let score = report.report_summary.summary_score_percentage;
    let score_colour = if score >= 80.0 {
        colour_pass()
    } else if score >= 50.0 {
        colour_warning()
    } else {
        colour_fail()
    };

    surface.set_fill(Some(Fill {
        paint: score_colour.into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    let score_text = format!("{:.1}%", score);
    surface.draw_text(
        Point::from_xy(MARGIN_LEFT + 15.0, start_y + 55.0),
        font_bold.clone(),
        24.0,
        &score_text,
        false,
        TextDirection::LeftToRight,
    );

    // Statistics on the right side
    let stats_x = MARGIN_LEFT + 150.0;

    // Passing
    surface.set_fill(Some(Fill {
        paint: colour_pass().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));
    let passing_text = format!("Passing: {}", report.report_summary.summary_passing);
    surface.draw_text(
        Point::from_xy(stats_x, start_y + 30.0),
        font_regular.clone(),
        BODY_SIZE,
        &passing_text,
        false,
        TextDirection::LeftToRight,
    );

    // Failing
    surface.set_fill(Some(Fill {
        paint: colour_fail().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));
    let failing_text = format!("Failing: {}", report.report_summary.summary_failing);
    surface.draw_text(
        Point::from_xy(stats_x, start_y + 45.0),
        font_regular.clone(),
        BODY_SIZE,
        &failing_text,
        false,
        TextDirection::LeftToRight,
    );

    // Not Applicable (if any)
    if report.report_summary.summary_not_applicable > 0 {
        surface.set_fill(Some(Fill {
            paint: colour_na().into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));
        let na_text = format!("N/A: {}", report.report_summary.summary_not_applicable);
        surface.draw_text(
            Point::from_xy(stats_x, start_y + 60.0),
            font_regular.clone(),
            BODY_SIZE,
            &na_text,
            false,
            TextDirection::LeftToRight,
        );
    }

    // Manual Review (if any)
    if report.report_summary.summary_manual_review > 0 {
        surface.set_fill(Some(Fill {
            paint: colour_warning().into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));
        let manual_text = format!("Manual: {}", report.report_summary.summary_manual_review);
        surface.draw_text(
            Point::from_xy(stats_x + 100.0, start_y + 30.0),
            font_regular.clone(),
            BODY_SIZE,
            &manual_text,
            false,
            TextDirection::LeftToRight,
        );
    }

    // Total
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));
    let total_text = format!("Total: {}", report.report_summary.summary_total_controls);
    surface.draw_text(
        Point::from_xy(stats_x + 100.0, start_y + 45.0),
        font_regular.clone(),
        BODY_SIZE,
        &total_text,
        false,
        TextDirection::LeftToRight,
    );

    y.advance(box_height);
}

/// Draws a single control entry.
fn draw_control(
    surface: &mut krilla::surface::Surface,
    y: &mut YTracker,
    control: &crate::report::ControlResult,
    font_regular: &Font,
    font_bold: &Font,
) {
    let (status_text, status_colour) = match control.control_status {
        ControlStatus::Pass => ("PASS", colour_pass()),
        ControlStatus::Fail => ("FAIL", colour_fail()),
        ControlStatus::NotApplicable => ("N/A", colour_na()),
        ControlStatus::ManualReview => ("MANUAL", colour_warning()),
    };

    // Control ID
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    surface.draw_text(
        Point::from_xy(MARGIN_LEFT, y.y() + BODY_SIZE),
        font_bold.clone(),
        BODY_SIZE,
        &control.control_id,
        false,
        TextDirection::LeftToRight,
    );

    // Status badge
    surface.set_fill(Some(Fill {
        paint: status_colour.into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    surface.draw_text(
        Point::from_xy(MARGIN_LEFT + 60.0, y.y() + BODY_SIZE),
        font_bold.clone(),
        BODY_SIZE,
        status_text,
        false,
        TextDirection::LeftToRight,
    );

    // Control title
    surface.set_fill(Some(Fill {
        paint: colour_black().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    // Truncate title if too long
    let title = truncate_string(&control.control_title, 70);

    surface.draw_text(
        Point::from_xy(MARGIN_LEFT + 120.0, y.y() + BODY_SIZE),
        font_regular.clone(),
        BODY_SIZE,
        &title,
        false,
        TextDirection::LeftToRight,
    );

    y.advance(BODY_SIZE * LINE_HEIGHT);

    // Show findings for failed controls
    if control.control_status == ControlStatus::Fail && !control.control_findings.is_empty() {
        y.advance(BODY_SIZE * LINE_HEIGHT * 0.5);
        for finding in &control.control_findings {
            surface.set_fill(Some(Fill {
                paint: colour_fail().into(),
                opacity: NormalizedF32::new(0.8).unwrap(),
                rule: FillRule::default(),
            }));

            let finding_text = format!(
                " -> [{}] {}",
                finding.finding_severity,
                truncate_string(&finding.finding_title, 60)
            );

            surface.draw_text(
                Point::from_xy(MARGIN_LEFT + 120.0, y.y() + SMALL_SIZE),
                font_bold.clone(),
                SMALL_SIZE,
                &finding_text,
                false,
                TextDirection::LeftToRight,
            );

            y.advance(BODY_SIZE * LINE_HEIGHT);
        }
    }
}

/// Draws a horizontal line across the content area.
fn draw_horizontal_line(surface: &mut krilla::surface::Surface, y: f32, colour: color::rgb::Color) {
    // Draw a thin rectangle as a line
    let mut rect_pb = PathBuilder::new();
    rect_pb.move_to(MARGIN_LEFT, y);
    rect_pb.line_to(MARGIN_LEFT + CONTENT_WIDTH, y);
    rect_pb.line_to(MARGIN_LEFT + CONTENT_WIDTH, y + 1.0);
    rect_pb.line_to(MARGIN_LEFT, y + 1.0);
    rect_pb.close();

    if let Some(rect_path) = rect_pb.finish() {
        surface.set_fill(Some(Fill {
            paint: colour.into(),
            opacity: NormalizedF32::ONE,
            rule: FillRule::default(),
        }));
        surface.draw_path(&rect_path);
    }
}

/// Truncates a string to the specified length, adding ellipsis if needed.
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

/// Compares two control IDs numerically (e.g., "1.5.1" < "1.5.2" < "1.5.10").
fn compare_control_ids(a: &str, b: &str) -> std::cmp::Ordering {
    let parts_a: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let parts_b: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();

    for (pa, pb) in parts_a.iter().zip(parts_b.iter()) {
        match pa.cmp(pb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    parts_a.len().cmp(&parts_b.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ComplianceReport, ComplianceSummary, ControlResult};
    use chrono::Utc;
    use hardener_common::types::ComplianceFramework;

    #[test]
    fn test_pdf_formatter_creates_output() {
        let report = ComplianceReport {
            report_framework: ComplianceFramework::CIS,
            report_generated_at: Utc::now(),
            report_controls: vec![
                ControlResult {
                    control_id: "1.5.1".to_string(),
                    control_title: "Ensure ASLR is enabled".to_string(),
                    control_section: "Initial Setup".to_string(),
                    control_status: ControlStatus::Pass,
                    control_findings: vec![],
                },
                ControlResult {
                    control_id: "1.5.2".to_string(),
                    control_title: "Ensure ptrace is restricted".to_string(),
                    control_section: "Initial Setup".to_string(),
                    control_status: ControlStatus::Fail,
                    control_findings: vec![],
                },
            ],
            report_summary: ComplianceSummary {
                summary_total_controls: 2,
                summary_passing: 1,
                summary_failing: 1,
                summary_not_applicable: 0,
                summary_manual_review: 0,
                summary_score_percentage: 50.0,
            },
        };

        let formatter = PdfFormatter::new();
        let output = formatter.format(&report);

        // PDF files start with %PDF-
        assert!(output.starts_with("%PDF-"), "Output should be a valid PDF");
        assert!(output.len() > 1000, "PDF should have substantial content");
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(
            truncate_string("this is a longer string", 10),
            "this is a ..."
        );
    }

    #[test]
    fn test_pdf_formatter_default() {
        let _formatter = PdfFormatter;
    }
}
