//! PDF report formatter.
//!
//! Produces PDF compliance reports using the krilla library.

use super::{exclusion_note, group_controls_by_section, report_title};
use crate::output::ReportFormatter;
use crate::report::ComplianceReport;
use hardener_common::text::truncate_string;
use hardener_common::types::ControlStatus;
use krilla::geom::{PathBuilder, Point};
use krilla::num::NormalizedF32;
use krilla::page::PageSettings;
use krilla::paint::{Fill, FillRule};
use krilla::text::{Font, TextDirection};
use krilla::{Document, color};

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

/// Characters per line when wrapping prose at [`SMALL_SIZE`].
///
/// NotoSans averages a little under half its point size per character, so 100
/// characters of 8pt text stays inside [`CONTENT_WIDTH`] with room to spare.
/// Deliberately conservative: krilla gives no measured advance here, and a
/// short line is a cosmetic flaw where an over-long one runs off the page.
const WRAP_CHARS: usize = 100;

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

    fn format_bytes(&self, report: &ComplianceReport) -> Vec<u8> {
        generate_pdf(report)
    }

    /// One document carrying every report, rather than the default's
    /// UTF-8 encoding of concatenated Latin-1 page streams, which no PDF
    /// reader could open.
    fn format_all_bytes(&self, reports: &[ComplianceReport]) -> Vec<u8> {
        generate_pdf_all(reports)
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
    generate_pdf_all(std::slice::from_ref(report))
}

/// Renders every report into one document, each framework starting a new page.
///
/// The multi-report case is the one every real consumer takes: the CLI, the
/// report wizard and the desktop all select a set of frameworks and export
/// once. Until this existed all five call sites rendered `reports[0]` and
/// dropped the rest with nothing said, while the same selection through the
/// text, JSON, CSV and HTML renderers carried every framework.
///
/// An empty slice yields a document with no pages rather than a panic, which
/// `an_empty_set_renders_without_panicking` pins. No caller refuses the
/// export first, so that is the behaviour an operator selecting no framework
/// gets: a contentless file instead of the index-out-of-bounds `reports[0]`
/// gave them. Refusing it with a reason is a separate decision, and belongs
/// in the callers where a reason can be worded.
fn generate_pdf_all(reports: &[ComplianceReport]) -> Vec<u8> {
    let font_regular = Font::new(FONT_DATA.to_vec().into(), 0).expect(
        "Failed to load regular font - ensure NotoSans-Regular.ttf is
  present",
    );
    let font_bold = Font::new(FONT_BOLD_DATA.to_vec().into(), 0).expect(
        "Failed to load bold font - ensure NotoSans-Bold.ttf is
  present",
    );

    let mut document = Document::new();
    for report in reports {
        draw_report(&mut document, report, &font_regular, &font_bold);
    }

    document.finish().expect("Failed to generate PDF")
}

/// Appends one report's pages to `document`.
///
/// The vertical tracker is per report, so each one opens its own first page
/// and carries its own footer, which is what keeps two frameworks from
/// running into each other mid-page.
fn draw_report(
    document: &mut Document,
    report: &ComplianceReport,
    font_regular: &Font,
    font_bold: &Font,
) {
    let mut y = YTracker::new();

    let sections_vec = group_controls_by_section(report);

    // Start first page
    let mut page = document.start_page_with(PageSettings::new(PAGE_WIDTH, PAGE_HEIGHT));
    let mut surface = page.surface();

    // === Title ===
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));

    let title = report_title(report);
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
    draw_summary_box(&mut surface, &mut y, report, font_regular, font_bold);
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
                + control.control_findings.len() as f32 * BODY_SIZE * LINE_HEIGHT;

            if y.needs_new_page(control_height) {
                surface.finish();
                page.finish();
                y.reset();
                page = document.start_page_with(PageSettings::new(PAGE_WIDTH, PAGE_HEIGHT));
                surface = page.surface();
            }

            draw_control(&mut surface, &mut y, control, font_regular, font_bold);
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
        "Generated by Linux Hardener",
        false,
        TextDirection::LeftToRight,
    );

    surface.finish();
    page.finish();
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

    // Directly under the box holding the figure, because it is that figure the
    // sentence qualifies. The PDF is the artefact an auditor is handed, and it
    // used to state a score whose denominator a human had reduced with no
    // sentence anywhere saying so. `Total` in the box above is the catalogue
    // size and does not move on exclusion, which is the conflation this
    // resolves.
    let Some(note) = exclusion_note(&report.report_summary) else {
        return;
    };
    surface.set_fill(Some(Fill {
        paint: colour_dark_grey().into(),
        opacity: NormalizedF32::ONE,
        rule: FillRule::default(),
    }));
    y.advance(SMALL_SIZE);
    for line in wrap_text(&note, WRAP_CHARS) {
        surface.draw_text(
            Point::from_xy(MARGIN_LEFT, y.y() + SMALL_SIZE),
            font_regular.clone(),
            SMALL_SIZE,
            &line,
            false,
            TextDirection::LeftToRight,
        );
        y.advance(SMALL_SIZE * LINE_HEIGHT);
    }
}

/// Breaks `text` into lines of at most `max_chars` characters, splitting on
/// whitespace.
///
/// A word longer than `max_chars` gets a line of its own rather than being
/// cut: everything reaching this is prose the report composed, so an over-long
/// word means a control id or a hostname, and a truncated identifier is worse
/// than an over-long line.
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match lines.last_mut() {
            Some(line) if line.chars().count() + 1 + word.chars().count() <= max_chars => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_string()),
        }
    }
    lines
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

    // Show the evidence behind the status. A control carrying only excepted
    // findings passes, but the documented deviations are still listed (in the
    // neutral colour, not the failure red) so the pass is not mistaken for a
    // clean one.
    if !control.control_findings.is_empty() {
        y.advance(BODY_SIZE * LINE_HEIGHT * 0.5);
        for finding in &control.control_findings {
            let excepted = finding.is_policy_excepted();
            surface.set_fill(Some(Fill {
                paint: if excepted {
                    colour_dark_grey().into()
                } else {
                    colour_fail().into()
                },
                opacity: NormalizedF32::new(0.8).expect("0.8 is always in [0.0, 1.0]"),
                rule: FillRule::default(),
            }));

            let finding_text = format!(
                " -> [{}] {}",
                finding.evidence_label(),
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

#[cfg(test)]
mod tests;
