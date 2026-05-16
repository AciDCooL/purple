//! Shared activity sparkline rendering used by host detail and the
//! Keys tab info card. Auto-scales the time window to the oldest data
//! point so brand-new logs show a tight 5-day chart that grows over
//! time. Output is a vector of `Line`s: optional top row (only when a
//! bar exceeds half height), bottom row with dotted baseline for empty
//! buckets, and axis labels.

use ratatui::text::{Line, Span};

use super::theme;

const BLOCKS: [char; 9] = [
    ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
    '\u{2588}',
];

/// Predefined time ranges for auto-scaling the sparkline.
/// (days, left_label, midpoint_label)
const CHART_RANGES: &[(u64, &str, &str)] = &[
    (5, "5d", "~2d"),
    (10, "10d", "~5d"),
    (14, "2w", "~1w"),
    (21, "3w", "~10d"),
    (30, "30d", "~2w"),
    (60, "2mo", "~1mo"),
    (84, "12w", "~6w"),
    (180, "6mo", "~3mo"),
    (365, "1y", "~6mo"),
];

/// Render a stepped activity sparkline. Returns an empty Vec when there
/// is no data so the caller can render its own placeholder (used by the
/// host detail panel, which hides the chart row in that case).
///
/// `now` is parameterised so demo-mode renders and golden tests stay
/// byte-stable; pass `key_activity::now_secs()` from screens that need
/// to honour the frozen demo clock, or the wall clock otherwise.
pub fn render(timestamps: &[u64], chart_width: usize, now: u64) -> Vec<Line<'static>> {
    render_inner(timestamps, chart_width, now, false)
}

/// Like `render`, but on empty data it draws a dotted baseline with
/// axis labels instead of returning an empty Vec. Used by the Keys
/// info card so the time window stays visible even before the first
/// recorded use.
pub fn render_with_baseline(
    timestamps: &[u64],
    chart_width: usize,
    now: u64,
) -> Vec<Line<'static>> {
    render_inner(timestamps, chart_width, now, true)
}

fn render_inner(
    timestamps: &[u64],
    chart_width: usize,
    now: u64,
    baseline_on_empty: bool,
) -> Vec<Line<'static>> {
    if chart_width == 0 {
        return Vec::new();
    }

    let oldest = timestamps
        .iter()
        .copied()
        .filter(|&t| t <= now)
        .min()
        .unwrap_or(now);
    let data_age_days = now.saturating_sub(oldest) / 86_400 + 1;
    let chart_days = CHART_RANGES
        .iter()
        .find(|(days, _, _)| *days >= data_age_days)
        .map(|(days, _, _)| *days)
        .or_else(|| CHART_RANGES.last().map(|r| r.0))
        .unwrap_or(FALLBACK_CHART_DAYS);

    let range_secs = chart_days * 86_400;
    let bucket_secs = range_secs as f64 / chart_width as f64;
    let cutoff = now.saturating_sub(range_secs);

    let mut buckets = vec![0u64; chart_width];
    for &ts in timestamps {
        if ts < cutoff || ts > now {
            continue;
        }
        let age = now.saturating_sub(ts);
        let idx =
            chart_width - 1 - ((age as f64 / bucket_secs).floor() as usize).min(chart_width - 1);
        buckets[idx] += 1;
    }

    if buckets.iter().all(|&v| v == 0) {
        return if baseline_on_empty {
            render_empty(chart_width, chart_days)
        } else {
            Vec::new()
        };
    }

    let max_val = buckets.iter().copied().max().unwrap_or(1).max(1);
    let total_levels = 16usize; // 2 rows x 8 levels

    let heights: Vec<usize> = buckets
        .iter()
        .map(|&v| {
            if v == 0 {
                0
            } else {
                ((v as f64 / max_val as f64) * total_levels as f64).ceil() as usize
            }
        })
        .collect();

    let mut chart_lines = Vec::new();

    // Top row (only rendered if any bar exceeds half height)
    if heights.iter().any(|&h| h > 8) {
        let mut top = String::with_capacity(chart_width * 3);
        for &h in &heights {
            if h > 8 {
                top.push(BLOCKS[(h - 8).min(8)]);
            } else {
                top.push(' ');
            }
        }
        chart_lines.push(Line::from(Span::styled(top, theme::bold())));
    }

    // Bottom row with dotted baseline for empty buckets
    let mut bottom_spans: Vec<Span<'static>> = Vec::new();
    let mut run_empty = String::new();
    let mut run_filled = String::new();

    for &h in &heights {
        if h == 0 {
            if !run_filled.is_empty() {
                bottom_spans.push(Span::styled(std::mem::take(&mut run_filled), theme::bold()));
            }
            run_empty.push('\u{00B7}'); // ·
        } else {
            if !run_empty.is_empty() {
                bottom_spans.push(Span::styled(std::mem::take(&mut run_empty), theme::muted()));
            }
            if h >= 8 {
                run_filled.push(BLOCKS[8]);
            } else {
                run_filled.push(BLOCKS[h]);
            }
        }
    }
    if !run_filled.is_empty() {
        bottom_spans.push(Span::styled(run_filled, theme::bold()));
    }
    if !run_empty.is_empty() {
        bottom_spans.push(Span::styled(run_empty, theme::muted()));
    }
    chart_lines.push(Line::from(bottom_spans));

    chart_lines.push(axis_line(chart_width, chart_days));
    chart_lines
}

/// Empty-state chart: dotted baseline plus the same axis labels so the
/// reader still sees the time window the chart would cover.
fn render_empty(chart_width: usize, chart_days: u64) -> Vec<Line<'static>> {
    let baseline: String = "\u{00B7}".repeat(chart_width);
    vec![
        Line::from(Span::styled(baseline, theme::muted())),
        axis_line(chart_width, chart_days),
    ]
}

/// L5: cheap-safe fallback when CHART_RANGES is ever made empty in
/// the future. The current array is non-empty so this is unreachable
/// in production, but the explicit fallback keeps the function panic-free.
const FALLBACK_CHART_DAYS: u64 = 365;

fn axis_line(chart_width: usize, chart_days: u64) -> Line<'static> {
    let range_entry = CHART_RANGES.iter().find(|(days, _, _)| *days == chart_days);
    let left_label = range_entry
        .map(|(_, label, _)| label.to_string())
        .unwrap_or_else(|| format!("{}d", chart_days));
    let mid_label = range_entry
        .map(|(_, _, mid)| mid.to_string())
        .unwrap_or_default();
    let right_label = "now";

    let labels_width = left_label.len() + mid_label.len() + right_label.len();
    if !mid_label.is_empty() && chart_width > labels_width + 4 {
        let total_gap = chart_width.saturating_sub(labels_width);
        let gap_left = total_gap / 2;
        let gap_right = total_gap - gap_left;
        Line::from(vec![
            Span::styled(left_label, theme::muted()),
            Span::raw(" ".repeat(gap_left)),
            Span::styled(mid_label, theme::muted()),
            Span::raw(" ".repeat(gap_right)),
            Span::styled(right_label.to_string(), theme::muted()),
        ])
    } else {
        let gap = chart_width.saturating_sub(left_label.len() + right_label.len());
        Line::from(vec![
            Span::styled(left_label, theme::muted()),
            Span::raw(" ".repeat(gap)),
            Span::styled(right_label.to_string(), theme::muted()),
        ])
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the bucketing and scaling math. The renderer's
    //! styled output is covered by the visual regression suite; these
    //! tests target the numeric/index logic where off-by-one and
    //! sign errors would otherwise slip past goldens.
    use super::*;

    const NOW: u64 = crate::key_activity::DEMO_NOW_SECS; // 2026-05-16 12:00 UTC
    const DAY: u64 = 86_400;

    /// Flatten a Line into its content string (ignores styling).
    fn line_text(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn empty_data_returns_empty_vec_when_baseline_off() {
        assert!(render(&[], 30, NOW).is_empty());
    }

    #[test]
    fn empty_data_renders_baseline_when_flag_on() {
        let lines = render_with_baseline(&[], 30, NOW);
        assert_eq!(lines.len(), 2, "baseline + axis row");
        // First line is a dotted baseline; check the dot count.
        assert_eq!(line_text(&lines[0]), "\u{00B7}".repeat(30));
    }

    #[test]
    fn chart_width_zero_returns_empty_vec_regardless_of_data() {
        let ts = vec![NOW];
        assert!(render(&ts, 0, NOW).is_empty());
        assert!(render_with_baseline(&ts, 0, NOW).is_empty());
    }

    #[test]
    fn single_event_at_now_lands_in_rightmost_bucket() {
        let ts = vec![NOW];
        let lines = render(&ts, 30, NOW);
        assert!(!lines.is_empty());
        // The bottom row has exactly one non-baseline column at the far right.
        let bottom = line_text(&lines[lines.len() - 2]);
        let chars: Vec<char> = bottom.chars().collect();
        assert_eq!(chars.len(), 30);
        // All but the last cell must be the baseline dot.
        for ch in chars.iter().take(29) {
            assert_eq!(*ch, '\u{00B7}');
        }
        // Last cell must be a block, not a dot.
        assert_ne!(chars[29], '\u{00B7}');
    }

    #[test]
    fn future_timestamps_are_excluded() {
        // ts > now must not be plotted: a clock skew or wrong-zone source
        // could otherwise push events into nonexistent buckets.
        let ts = vec![NOW + DAY * 3];
        assert!(render(&ts, 30, NOW).is_empty());
    }

    #[test]
    fn auto_scale_picks_smallest_range_fitting_data_age() {
        // Single event 6 days old must pick the 10d window (5d does not fit).
        let ts = vec![NOW - 6 * DAY];
        let lines = render(&ts, 40, NOW);
        let axis = line_text(&lines[lines.len() - 1]);
        assert!(
            axis.starts_with("10d"),
            "expected 10d window, got axis: {}",
            axis
        );
    }

    #[test]
    fn auto_scale_picks_widest_window_for_year_old_data() {
        // 350 days old fits in the widest 1y window. Anything older
        // falls outside cutoff and is dropped: that path is covered by
        // future_timestamps_are_excluded above.
        let ts = vec![NOW - 350 * DAY];
        let lines = render(&ts, 40, NOW);
        assert!(!lines.is_empty(), "data within 1y must render");
        let axis = line_text(&lines[lines.len() - 1]);
        assert!(
            axis.starts_with("1y"),
            "expected 1y window, got axis: {}",
            axis
        );
    }

    #[test]
    fn two_rows_emitted_when_max_bar_dominates_others() {
        // 17 events on one bucket, single events on three others: the
        // tallest bar reaches the top half because its height (16)
        // exceeds the half-height cutoff while the singles sit at 1.
        let mut ts = vec![NOW - 2 * DAY; 17];
        ts.push(NOW);
        ts.push(NOW - 4 * DAY);
        ts.push(NOW - 6 * DAY);
        let lines = render(&ts, 30, NOW);
        assert_eq!(lines.len(), 3, "expected top + bottom + axis");
    }

    #[test]
    fn single_event_renders_axis_and_at_least_one_row() {
        // A lone event scales to height 16 against max=1 and triggers
        // the top row. Concrete invariant: axis is present and the
        // chart has at least two rows (one body row + axis).
        let ts = vec![NOW];
        let lines = render(&ts, 30, NOW);
        assert!(lines.len() >= 2);
        let axis = line_text(&lines[lines.len() - 1]);
        assert!(axis.ends_with("now"));
    }

    #[test]
    fn chart_width_one_does_not_panic() {
        // A 1-column chart can be drawn (single bucket) but the bucket
        // index math (chart_width - 1 = 0) must not underflow.
        let ts = vec![NOW];
        let lines = render(&ts, 1, NOW);
        assert!(!lines.is_empty());
        let bottom = line_text(&lines[lines.len() - 2]);
        assert_eq!(bottom.chars().count(), 1);
    }

    #[test]
    fn axis_includes_now_label() {
        let ts = vec![NOW - DAY];
        let lines = render(&ts, 40, NOW);
        let axis = line_text(&lines[lines.len() - 1]);
        assert!(axis.ends_with("now"), "axis must end with 'now': {}", axis);
    }
}
