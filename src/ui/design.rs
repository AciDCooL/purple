//! Design system tokens and reusable component builders.
//!
//! This module centralizes spacing, overlay sizing, toast, timeout, icon and
//! list rendering constants that are shared across UI modules. It also exposes
//! block component builders, layout helpers, a `Footer` builder and a small
//! set of render helpers so individual screens can stay short and consistent.
//!
//! The goal is to keep design intent in one place and have screens reference
//! these helpers instead of duplicating border, title or footer wiring.
//!
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};

use super::theme;
use crate::app::App;

// ---------------------------------------------------------------------------
// Spacing tokens
// ---------------------------------------------------------------------------

/// Two-space gap used between footer action entries.
pub const FOOTER_GAP: &str = "  ";
/// Gap between columns in list rows.
pub const COL_GAP: u16 = 2;

/// Lowercase "purple." wordmark in Unicode box-drawing, 5 rows × 20 cols.
/// Trailing `▪` on row 3 renders in `theme::logo_dot` (cyan).
pub const LOGO: [&str; 5] = [
    "             ╮      ",
    "╭─╮╷ ╷╭─ ╭─╮ │ ╭─╮  ",
    "│ ││ ││  │ │ │ ├─╯  ",
    "├─╯╰─╯╵  ├─╯╶┴╴╰─╴ ▪",
    "╵        ╵          ",
];

/// Column range of the trailing dot glyph. `logo_line` slices on this
/// range to recolour the dot independently of the word body.
pub const LOGO_DOT_COL_START: usize = 19;
pub const LOGO_DOT_COL_END: usize = 20;

/// Build logo row `i` as three spans (word / dot / padding) so callers
/// can keep their existing alignment logic.
pub fn logo_line(
    i: usize,
    word_style: ratatui::style::Style,
    dot_style: ratatui::style::Style,
) -> ratatui::text::Line<'static> {
    use ratatui::text::Span;
    let chars: Vec<char> = LOGO[i].chars().collect();
    let before: String = chars
        .get(..LOGO_DOT_COL_START)
        .unwrap_or(&[])
        .iter()
        .collect();
    let dot: String = chars
        .get(LOGO_DOT_COL_START..LOGO_DOT_COL_END.min(chars.len()))
        .unwrap_or(&[])
        .iter()
        .collect();
    let after: String = chars
        .get(LOGO_DOT_COL_END..)
        .unwrap_or(&[])
        .iter()
        .collect();
    ratatui::text::Line::from(vec![
        Span::styled(before, word_style),
        Span::styled(dot, dot_style),
        Span::styled(after, word_style),
    ])
}

// ---------------------------------------------------------------------------
// Overlay sizing tokens
// ---------------------------------------------------------------------------

/// Default overlay width percentage.
pub const OVERLAY_W: u16 = 70;
/// Default overlay height percentage.
pub const OVERLAY_H: u16 = 80;
/// Minimum width for picker overlays. All pickers (Password Source,
/// Select Key, Vault SSH Role, ProxyJump, tag picker, theme picker, etc.)
/// share this single sizing range so they look identical regardless of
/// which form field opened them.
pub const PICKER_MIN_W: u16 = 60;
/// Maximum width for picker overlays.
pub const PICKER_MAX_W: u16 = 72;
/// Maximum height (incl. borders) for picker overlays. Pickers grow with
/// item count up to this cap, then scroll.
pub const PICKER_MAX_H: u16 = 18;

// ---------------------------------------------------------------------------
// Toast tokens
// ---------------------------------------------------------------------------

/// Toast horizontal inset from the right edge.
pub const TOAST_INSET_X: u16 = 2;
/// Toast vertical inset from the bottom edge.
pub const TOAST_INSET_Y: u16 = 2;

// ---------------------------------------------------------------------------
// Timeout tokens (millisecond-based, tick-rate-independent)
// ---------------------------------------------------------------------------

/// Minimum milliseconds before a Success or Info message clears (2.5s).
/// Effective timeout is `max(TIMEOUT_MIN_MS, words * MS_PER_WORD)`.
pub const TIMEOUT_MIN_MS: u64 = 2500;
/// Minimum milliseconds before a Warning message clears (4s).
pub const TIMEOUT_MIN_WARNING_MS: u64 = 4000;
/// Per-word reading-time budget in milliseconds (750ms/word, matching
/// peripheral reading speed for short status strings competing with the
/// primary task).
pub const MS_PER_WORD: u64 = 750;
/// Cap on word count for length-proportional timeout. 30 words at
/// 750ms/word = 22.5s maximum for any non-sticky toast.
pub const WORD_CAP: usize = 30;
/// Maximum number of queued toast messages. Three matches Linear/Stripe
/// toast stack patterns; more than 3 stacked toasts is itself a UX signal
/// of a system problem and dropping older ones is preferable to clutter.
pub const TOAST_QUEUE_MAX: usize = 3;

// ---------------------------------------------------------------------------
// Status indicator tokens
// ---------------------------------------------------------------------------

/// Online status glyph (U+25CF, filled circle).
pub const ICON_ONLINE: &str = "\u{25CF}";
/// Success glyph (U+2713, check mark). Also used as the toast success glyph.
pub const ICON_SUCCESS: &str = "\u{2713}";
/// Warning glyph (U+26A0, warning sign). Also used as the toast warning glyph.
pub const ICON_WARNING: &str = "\u{26A0}";
/// Error glyph (U+2716, heavy multiplication X). Distinct from the
/// warning sign so the user can tell at a glance whether something is
/// recoverable (warning) or has gone wrong (error).
pub const ICON_ERROR: &str = "\u{2716}";
/// Paused / restarting container glyph (U+25D0, left half-filled circle).
/// Used for transitional states where the container is neither cleanly
/// running nor cleanly stopped.
pub const ICON_PAUSED: &str = "\u{25D0}";
/// Stopped / inactive container glyph (U+25CB, empty circle). Used for
/// "exited cleanly" and for unknown / not-yet-seen states.
pub const ICON_STOPPED: &str = "\u{25CB}";
/// Slow ping glyph (U+25B2, up-pointing triangle). Used in the Linked
/// Hosts list to mark hosts that responded but exceeded the slow-ping
/// threshold.
pub const ICON_SLOW: &str = "\u{25B2}";
/// Pending / unknown status glyph (U+00B7, middle dot). Used for
/// "checking now" and "not yet probed" rows where neither online nor
/// offline applies yet.
pub const ICON_PENDING: &str = "\u{00B7}";
/// Target / destination glyph (U+25C9, fisheye). Marks the final hop in a
/// ProxyJump ladder and the container/host that is currently selected as
/// the navigation target in a tree view.
pub const ICON_TARGET: &str = "\u{25C9}";

// ---------------------------------------------------------------------------
// Route / tree glyphs
// ---------------------------------------------------------------------------

/// Dotted vertical glyph (U+250A) for the connecting line between hops in a
/// ProxyJump ladder rendered in detail panels.
pub const ROUTE_BRANCH: &str = "\u{250A}";

// ---------------------------------------------------------------------------
// Container state mapping (single source of truth)
// ---------------------------------------------------------------------------

/// True when the container `state` field reports a running container.
/// Single source of truth shared by detail panels, overlays and the
/// containers overview so all surfaces classify the same state identically.
pub fn is_container_running(state: &str) -> bool {
    state.eq_ignore_ascii_case("running")
}

/// Extract the integer in `Exited (N)` from a docker `Status` string.
/// Returns `None` when the prefix is absent or the captured slice does not
/// parse as an integer. Podman emits an empty status; callers should fall
/// back to inspect-cache exit code in that case.
pub fn parse_container_exit_code(status: &str) -> Option<i32> {
    let prefix = "Exited (";
    let start = status.find(prefix)?;
    let after = &status[start + prefix.len()..];
    let end = after.find(')')?;
    after[..end].parse().ok()
}

/// Canonical mapping from container state to (icon, style).
///
/// Every consumer of container state (host detail panel, per-host overlay,
/// containers overview tab) must route through this helper so a single
/// container shows the same glyph and colour everywhere. Pre-rules audit
/// found 3 distinct ad-hoc mappings producing divergent visuals across the
/// same container; this helper closes that gap.
///
/// Arguments:
/// - `state`: docker/podman `state` field (`running`, `exited`, `dead`, etc.)
/// - `health`: docker health (`healthy`, `unhealthy`, `starting`) when known
/// - `status`: docker `Status` string (e.g. `Exited (137) 2 minutes ago`)
/// - `inspect_exit_code`: fallback exit code from inspect cache (podman path)
/// - `spinner_tick`: spinner counter for the pulsing running-dot
///
/// Pass `None`/empty/0 for fields the caller does not have; the helper
/// degrades gracefully (e.g. running container without spinner_tick still
/// renders, just without pulsing animation contribution).
pub fn container_state_style(
    state: &str,
    health: Option<&str>,
    status: &str,
    inspect_exit_code: Option<i32>,
    spinner_tick: u64,
) -> (&'static str, ratatui::style::Style) {
    if is_container_running(state) {
        return match health {
            Some("unhealthy") => (ICON_ONLINE, theme::error()),
            Some("starting") => (ICON_ONLINE, theme::warning()),
            _ => (ICON_ONLINE, theme::online_dot_pulsing(spinner_tick)),
        };
    }
    match state {
        "dead" => (ICON_ERROR, theme::error()),
        "exited" | "stopped" => {
            let exit_code = parse_container_exit_code(status).or(inspect_exit_code);
            match exit_code {
                Some(code) if code != 0 => (ICON_ERROR, theme::warning()),
                _ => (ICON_STOPPED, theme::muted()),
            }
        }
        "paused" | "restarting" => (ICON_PAUSED, theme::warning()),
        _ => (ICON_STOPPED, theme::muted()),
    }
}

// ---------------------------------------------------------------------------
// List rendering tokens
// ---------------------------------------------------------------------------

/// Default list-row highlight prefix (two spaces).
pub const LIST_HIGHLIGHT: &str = "  ";
/// Host list highlight prefix (U+258C, left half block).
pub const HOST_HIGHLIGHT: &str = "\u{258C}";

// ---------------------------------------------------------------------------
// Detail panel tokens
// ---------------------------------------------------------------------------

/// Detail panel section label column width.
pub const SECTION_LABEL_W: u16 = 14;

// ---------------------------------------------------------------------------
// Dim background tokens
// ---------------------------------------------------------------------------

/// RGB triple used for dim-background text.
pub const DIM_FG_RGB: (u8, u8, u8) = (70, 70, 70);

// ---------------------------------------------------------------------------
// Block component builders
// ---------------------------------------------------------------------------

/// Standard overlay block: rounded border, brand title, accent border.
pub fn overlay_block(title: &str) -> Block<'static> {
    overlay_block_line(Line::from(Span::styled(
        format!(" {title} "),
        theme::brand(),
    )))
}

/// Overlay block variant accepting a pre-built compound title `Line`.
/// Use when the caller needs multi-span titles that `overlay_block(&str)`
/// cannot express. Border style, border type and borders match `overlay_block`.
pub fn overlay_block_line(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border_dim())
        .title(title)
}

/// Overlay block with the search-active purple border. Mirrors
/// `search_block_line` for overlays — use on overlays whose body
/// hosts a `/` search so the border switches to purple while the
/// search is open (same affordance as the host list border switch).
pub fn search_overlay_block_line(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border_search())
        .title(title)
}

/// Plain overlay block: rounded border, dim border, NO title. Use for
/// unique dialogs (e.g. welcome screen) where the block carries no title
/// and the content itself supplies visual hierarchy.
pub fn plain_overlay_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border_dim())
}

/// Danger overlay block: rounded border, danger title, danger border.
/// Use for destructive confirmations (delete, purge).
pub fn danger_block(title: &str) -> Block<'static> {
    danger_block_line(Line::from(Span::styled(
        format!(" {title} "),
        theme::danger(),
    )))
}

/// Danger block variant accepting a pre-built compound title `Line`.
pub fn danger_block_line(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border_danger())
        .title(title)
}

/// Main block accepting a pre-built compound title `Line`.
/// All main-screen blocks (host list, top navigation bar) compose their
/// title spans manually and pass them in here, so a string-only convenience
/// constructor is intentionally absent.
pub fn main_block_line(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(title)
}

/// Search-active block accepting a pre-built compound title `Line`.
/// Mirrors `main_block_line` but with the search border style.
pub fn search_block_line(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::border_search())
        .title(title)
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

/// Overlay area: percentage width with a fixed height clamped to terminal.
pub fn overlay_area(frame: &Frame, w_pct: u16, h_pct: u16, height: u16) -> Rect {
    let area = frame.area();
    // Start from a percentage-based rectangle, then clamp the vertical extent
    // to the caller-requested height so narrow terminals still show a usable
    // overlay without stretching vertically.
    let pct_area = super::centered_rect(w_pct, h_pct, area);
    super::centered_rect_fixed(pct_area.width, height.min(pct_area.height), area)
}

/// Form footer positioned directly below the block border.
///
/// All overlays use this — there is no longer an "inside the block + spacer"
/// alternative. Form screens, list/picker overlays and detail overlays
/// alike render their action footer at this fixed external position so the
/// keycaps strip lines up consistently across every screen.
///
/// **Note:** Prefer `render_overlay_footer` over this helper. `form_footer`
/// only computes the Rect; `render_overlay_footer` also renders a `Clear`
/// widget over the footer row so it does not show through to the screen
/// behind the overlay (e.g. the host list when a picker is open).
pub fn form_footer(block_area: Rect, block_height: u16) -> Rect {
    Rect::new(
        block_area.x,
        block_area.y + block_height,
        block_area.width,
        1,
    )
}

/// Compute the external footer Rect for an overlay block, render `Clear`
/// over it so the row underneath the overlay does not bleed through, and
/// return the footer Rect for the caller to render the footer spans into.
pub fn render_overlay_footer(frame: &mut Frame, block_area: Rect) -> Rect {
    let footer_area = form_footer(block_area, block_area.height);
    frame.render_widget(Clear, footer_area);
    footer_area
}

/// Form divider Y position for the given index.
pub fn form_divider_y(inner: Rect, index: usize) -> u16 {
    inner.y + (index as u16) * 2
}

/// Picker overlay width clamped to `[PICKER_MIN_W, PICKER_MAX_W]`.
///
/// Canonical formula used by all picker overlays (ProxyJump, Vault role,
/// Password source). `super::picker_overlay_width` delegates here.
pub fn picker_width(frame: &Frame) -> u16 {
    frame.area().width.clamp(PICKER_MIN_W, PICKER_MAX_W)
}

// ---------------------------------------------------------------------------
// Footer builder
// ---------------------------------------------------------------------------

/// Builder for action footers. Inserts `FOOTER_GAP` between entries only.
pub struct Footer {
    spans: Vec<Span<'static>>,
}

impl Footer {
    /// Create an empty footer.
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    /// Add a primary action (semantic marker for the default action).
    #[allow(deprecated)]
    pub fn primary(mut self, key: &str, label: &str) -> Self {
        if !self.spans.is_empty() {
            self.spans.push(Span::raw(FOOTER_GAP));
        }
        let [k, l] = super::footer_primary(key, label);
        self.spans.push(k);
        self.spans.push(l);
        self
    }

    /// Add a secondary action.
    pub fn action(mut self, key: &str, label: &str) -> Self {
        if !self.spans.is_empty() {
            self.spans.push(Span::raw(FOOTER_GAP));
        }
        let [k, l] = super::footer_action(key, label);
        self.spans.push(k);
        self.spans.push(l);
        self
    }

    /// Render in an overlay footer (status right-aligned if present).
    pub fn render_with_status(self, frame: &mut Frame, area: Rect, app: &App) {
        super::render_footer_with_status(frame, area, self.spans, app);
    }

    /// Convert the accumulated spans into a single `Line`.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_line(self) -> Line<'static> {
        Line::from(self.spans)
    }

    /// Raw spans for screens with custom footer rendering.
    pub fn into_spans(self) -> Vec<Span<'static>> {
        self.spans
    }
}

impl Default for Footer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// 2-space-indented muted line. Single source of truth for the
/// indent + muted style pattern shared by `render_empty`, `render_loading`
/// and `empty_line`.
fn muted_line(message: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(message.to_string(), theme::muted()),
    ])
}

/// Render a 2-space-indented message with the muted style.
fn render_muted_message(frame: &mut Frame, area: Rect, message: &str) {
    frame.render_widget(Paragraph::new(muted_line(message)), area);
}

/// Render an empty-state message with 2-space indent and muted style.
pub fn render_empty(frame: &mut Frame, area: Rect, message: &str) {
    render_muted_message(frame, area, message);
}

/// Render a loading message with 2-space indent and muted style.
pub fn render_loading(frame: &mut Frame, area: Rect, message: &str) {
    render_muted_message(frame, area, message);
}

/// Render an error message with 2-space indent and error style.
pub fn render_error(frame: &mut Frame, area: Rect, message: &str) {
    let line = Line::from(vec![
        Span::raw("  "),
        Span::styled(message.to_string(), theme::error()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Inline section divider below section headers.
/// Renders as indented dashes in muted style.
pub fn section_divider() -> Line<'static> {
    Line::from(Span::styled("  ────────────────────────", theme::muted()))
}

// ---------------------------------------------------------------------------
// Content-level helpers
// ---------------------------------------------------------------------------

/// Column-width padding formula (usize variant for list screens).
pub fn padded_usize(w: usize) -> usize {
    if w == 0 { 0 } else { w + w / 10 + 1 }
}

/// 3-space prefix for column headers (aligns with highlight_symbol + leading space).
pub const COLUMN_HEADER_PREFIX: &str = "   ";

/// Inter-column gap as string.
pub const COL_GAP_STR: &str = "  ";

/// Key-value line: muted label (left-padded to width) + bold value.
pub fn kv_line(label: &str, value: &str, label_width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<width$}", label, width = label_width),
            theme::muted(),
        ),
        Span::styled(value.to_string(), theme::bold()),
    ])
}

/// Key-value label width for overlay detail screens (host_detail, key_detail).
pub const KV_LABEL_WIDE: usize = 22;

/// Content section header + divider pair.
pub fn content_section(label: &str) -> [Line<'static>; 2] {
    [
        Line::from(vec![
            Span::raw("  "),
            Span::styled(label.to_string(), theme::section_header()),
        ]),
        section_divider(),
    ]
}

/// Empty state with action hint: `"  message  \[key\]  action"`
pub fn render_empty_with_hint(
    frame: &mut Frame,
    area: Rect,
    message: &str,
    key: &str,
    action: &str,
) {
    let line = Line::from(vec![
        Span::raw("  "),
        Span::styled(message.to_string(), theme::muted()),
        Span::raw("  "),
        Span::styled(format!(" {} ", key), theme::footer_key()),
        Span::styled(format!(" {}", action), theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// Body-content area inside an overlay block. Inset 1 char left so
/// paragraphs align with field-content rows (which sit at `inner.x + 1`)
/// and the divider labels (which start with a leading space). Use this
/// instead of `Rect::new(inner.x, ...)` for any prose inside an overlay.
///
/// Currently no overlay renders body prose alongside form dividers — the
/// label-migration form proved the field labels are enough by themselves —
/// but keep this helper available so the next screen that needs body text
/// gets the inset for free.
#[allow(dead_code)]
pub fn body_text_area(inner: Rect, y: u16, height: u16) -> Rect {
    Rect::new(
        inner.x.saturating_add(1),
        y,
        inner.width.saturating_sub(1),
        height,
    )
}

// ---------------------------------------------------------------------------
// Body breathing room (prevents text from touching the inner-right border)
// ---------------------------------------------------------------------------

/// Right-side breathing room inside any block that hosts text content.
/// Without this margin `ratatui` writes the last glyph flush against
/// the right `│`, which reads as a layout bug even when the text fits.
/// Left-side padding is provided by the existing per-line convention
/// (lines start with `Span::raw("  ")` or `format!("  ...")`); this
/// helper only fixes the asymmetric right edge.
pub const BODY_RIGHT_PAD: u16 = 2;

/// Safe content area inside an overlay block. Insets `block_area` by the
/// 1-char block border on every side plus `BODY_RIGHT_PAD` on the right
/// only, so wrapped paragraphs and ASCII art rendered into the returned
/// `Rect` never touch the inner-right border.
///
/// Use whenever you would otherwise pass `Block::inner(area)` to
/// `frame.render_widget(Paragraph::new(...), inner)`. The
/// [`render_body`] and [`render_body_wrapped`] helpers do this for you;
/// reach for `body_area` directly only when the caller needs the rect
/// for custom rendering (e.g. List + Paragraph in the same block).
pub fn body_area(block_area: Rect) -> Rect {
    let inner_x = block_area.x.saturating_add(1);
    let inner_y = block_area.y.saturating_add(1);
    let inner_w = block_area.width.saturating_sub(2);
    let inner_h = block_area.height.saturating_sub(2);
    let pad_x = BODY_RIGHT_PAD.min(inner_w);
    Rect::new(inner_x, inner_y, inner_w.saturating_sub(pad_x), inner_h)
}

/// Render the block, then render `lines` into [`body_area`] of that
/// block. Lines render verbatim (no wrap) so long text is hard-truncated
/// by ratatui. Use for dialogs whose content is composed of pre-formatted
/// single-line rows (key-value lists, identity rows, glyph rows).
///
/// Caller is responsible for keeping individual lines within
/// `body_area(block_area).width`; reach for [`render_body_wrapped`] when
/// long prose may overflow and should wrap, or [`ellipsize`] when a
/// single value (alias, image, path) must clip with `…`.
#[allow(dead_code)]
pub fn render_body<'a>(
    frame: &mut Frame,
    block_area: Rect,
    block: Block<'a>,
    lines: Vec<Line<'a>>,
) {
    frame.render_widget(block, block_area);
    frame.render_widget(Paragraph::new(lines), body_area(block_area));
}

/// Render the block, then render `lines` into [`body_area`] of that
/// block with word-wrapping enabled. Long prose wraps to additional
/// rows; `trim: false` preserves leading indentation on continuation
/// lines so multi-paragraph bodies keep their "  " prefix.
///
/// Use for confirm dialogs, help body text, and any block whose content
/// includes full sentences. The 2-char right margin guarantees wrapped
/// continuation lines never touch the inner border.
pub fn render_body_wrapped<'a>(
    frame: &mut Frame,
    block_area: Rect,
    block: Block<'a>,
    lines: Vec<Line<'a>>,
) {
    use ratatui::widgets::Wrap;
    frame.render_widget(block, block_area);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        body_area(block_area),
    );
}

// ---------------------------------------------------------------------------
// Tab-level empty state (one card, no duplicate messages across panels)
// ---------------------------------------------------------------------------

/// Copy bundle for a tab's empty state. Each tab (Containers, Tunnels,
/// Keys, and any future Hosts/empty surface) constructs one of these
/// and hands it to [`render_tab_empty`], which composes the bordered
/// card inside the existing outer block.
///
/// - `card_title` appears in the inner card's top border (e.g. "Containers").
/// - `headline` is the one-line bold statement of what is missing.
/// - `explainer` is a one or two sentence muted paragraph that names
///   the cause (cache not yet populated, no key files, etc.). Wrap is
///   handled internally; pass the unwrapped text.
/// - `hints` is a list of `(key, action)` pairs rendered as keycap rows
///   below the explainer. Empty slice renders no hints.
pub struct TabEmpty<'a> {
    pub card_title: &'a str,
    pub headline: &'a str,
    pub explainer: &'a str,
    pub hints: &'a [(&'a str, &'a str)],
}

/// Render an inner empty-state card centred horizontally inside `area`.
/// Caller is responsible for the outer block (e.g. the existing
/// `main_block_line` with the row-count title) — that outer frame is
/// preserved so the empty state reads as a state OF the tab, not as a
/// replacement screen.
///
/// Width: clamped to `[40, 78]` columns so the card never hugs the
/// outer border on a 200-col terminal and never overflows on a narrow
/// one. When `area.width` is below 44 the card collapses to a single
/// 2-space-indented line via [`render_empty_with_hint`] using the first
/// hint as the affordance — graceful degradation without a new code
/// path on the caller side.
pub fn render_tab_empty(frame: &mut Frame, area: Rect, e: &TabEmpty) {
    use unicode_width::UnicodeWidthStr;

    // Graceful degradation on narrow terminals: drop the card chrome,
    // render the headline as a single muted-with-hint line.
    if area.width < 44 || area.height < 8 {
        if let Some((key, action)) = e.hints.first() {
            render_empty_with_hint(frame, area, e.headline, key, action);
        } else {
            render_empty(frame, area, e.headline);
        }
        return;
    }

    let body = body_area(area);
    let card_w_max = 78u16.min(body.width.saturating_sub(2));
    let card_w_min = 40u16;
    let card_w = card_w_max.max(card_w_min).min(body.width);
    let card_x = body.x + (body.width.saturating_sub(card_w)) / 2;

    // Compose the card contents: blank, headline, blank, explainer
    // (wrapped), blank, hints. Compute the row count so the card
    // height matches the content exactly — no trailing whitespace.
    let inner_card_w = card_w as usize;
    let prose_w = inner_card_w.saturating_sub(4); // border (2) + 2-col padding
    let mut card_lines: Vec<Line<'static>> = Vec::new();
    section_open(&mut card_lines, e.card_title, inner_card_w);

    // Open the body of the card with a blank inner row so the headline
    // does not crowd the top border.
    section_line(&mut card_lines, vec![Span::raw("")], inner_card_w);
    section_line(
        &mut card_lines,
        vec![
            Span::raw("  "),
            Span::styled(e.headline.to_string(), theme::bold()),
        ],
        inner_card_w,
    );

    // Explainer: wrap with 2-space indent on every continuation row.
    if !e.explainer.is_empty() {
        section_line(&mut card_lines, vec![Span::raw("")], inner_card_w);
        for row in wrap_indented(e.explainer, "  ", prose_w) {
            section_line(
                &mut card_lines,
                vec![Span::styled(row, theme::muted())],
                inner_card_w,
            );
        }
    }

    if !e.hints.is_empty() {
        section_line(&mut card_lines, vec![Span::raw("")], inner_card_w);
        // Right-align the keycap glyphs in a small column so every hint
        // line reads as a single visual list, regardless of key length.
        let key_w = e.hints.iter().map(|(k, _)| k.width()).max().unwrap_or(1);
        for (key, action) in e.hints {
            let key_pad = format!("  {:>width$}  ", key, width = key_w);
            section_line(
                &mut card_lines,
                vec![
                    Span::styled(key_pad, theme::accent_bold()),
                    Span::styled(action.to_string(), theme::muted()),
                ],
                inner_card_w,
            );
        }
    }

    // Close the card with a blank inner row + the bottom border.
    section_line(&mut card_lines, vec![Span::raw("")], inner_card_w);
    section_close(&mut card_lines, inner_card_w);

    // Centre vertically: leave equal blank rows above and below within
    // the body area (≥ 0).
    let card_h = card_lines.len() as u16;
    let top_pad = body.height.saturating_sub(card_h) / 2;
    let card_y = body.y + top_pad;
    let card_rect = Rect::new(card_x, card_y, card_w, card_h.min(body.height));
    frame.render_widget(Paragraph::new(card_lines), card_rect);
}

/// Render a bordered placeholder for the detail panel that sits next to
/// an empty tab. Draws only the block frame — no text — so the caller
/// can keep both panels visible without re-introducing the
/// double-message bug. Use when the layout reserves a detail panel
/// area but there are no rows to populate it.
pub fn render_tab_empty_detail(frame: &mut Frame, detail_area: Rect) {
    frame.render_widget(main_block_line(Line::default()), detail_area);
}

/// Word-wrap `text` to lines whose display width is at most
/// `max_width`, prepending `indent` to **every** output line — the
/// first and every continuation. Ratatui's `Wrap { trim: false }`
/// preserves leading whitespace on the source line but emits
/// continuation rows flush-left, which breaks the visual indent of a
/// multi-line body paragraph (e.g. a long host-list preview wraps to a
/// second row with no indent and no longer reads as a single block).
///
/// Words longer than `max_width - indent.width()` are hard-broken at
/// the column boundary so the wrapper never loops. Empty input returns
/// an empty vec; zero `max_width` returns an empty vec rather than
/// looping. The breakable character is the ASCII space; tabs and
/// non-breaking spaces are treated as part of a word.
pub fn wrap_indented(text: &str, indent: &str, max_width: usize) -> Vec<String> {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if text.is_empty() || max_width == 0 {
        return Vec::new();
    }
    let indent_w = indent.width();
    if indent_w >= max_width {
        // Indent eats the entire width — fall back to no indent so the
        // caller still gets readable output rather than infinite recursion.
        return wrap_indented(text, "", max_width);
    }
    let content_max = max_width - indent_w;
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_w = 0usize;
    let push_current = |out: &mut Vec<String>, current: &mut String, current_w: &mut usize| {
        if !current.is_empty() {
            out.push(format!("{}{}", indent, current));
            current.clear();
            *current_w = 0;
        }
    };
    for word in text.split(' ') {
        let word_w = word.width();
        if word_w == 0 {
            // empty word from a double space — emit a single space if room
            if current_w < content_max {
                current.push(' ');
                current_w += 1;
            }
            continue;
        }
        // Word doesn't fit on the current line.
        if current_w > 0 && current_w + 1 + word_w > content_max {
            push_current(&mut out, &mut current, &mut current_w);
        }
        // Word longer than the available content width: hard-break.
        if word_w > content_max {
            push_current(&mut out, &mut current, &mut current_w);
            let mut chunk = String::new();
            let mut chunk_w = 0usize;
            for ch in word.chars() {
                let cw = UnicodeWidthChar::width(ch).unwrap_or(0);
                if chunk_w + cw > content_max {
                    out.push(format!("{}{}", indent, chunk));
                    chunk.clear();
                    chunk_w = 0;
                }
                chunk.push(ch);
                chunk_w += cw;
            }
            if !chunk.is_empty() {
                current = chunk;
                current_w = chunk_w;
            }
            continue;
        }
        if current_w > 0 {
            current.push(' ');
            current_w += 1;
        }
        current.push_str(word);
        current_w += word_w;
    }
    push_current(&mut out, &mut current, &mut current_w);
    out
}

/// Build a `Vec<Line>` from `text` wrapped to `max_width` with `indent`
/// applied to every continuation row. Each line carries `style`. Use
/// instead of building a single long `Line::from(Span::styled(text,
/// style))` and relying on `Wrap { trim: false }`, which only indents
/// the first row.
pub fn wrap_body_lines(
    text: &str,
    indent: &str,
    max_width: usize,
    style: ratatui::style::Style,
) -> Vec<Line<'static>> {
    wrap_indented(text, indent, max_width)
        .into_iter()
        .map(|s| Line::from(Span::styled(s, style)))
        .collect()
}

/// Truncate `text` to at most `max_width` display columns. If the text
/// is longer, the last column is replaced with `…` so the reader can
/// tell that data was cut. `max_width` must be ≥ 1; the helper is a
/// no-op when `text` already fits.
///
/// Use for single-line cells where wrapping is not an option (host
/// alias columns, image names, path fragments). The single-character
/// ellipsis `…` matches the convention used by `ssh -G` output and
/// most modern terminal lists; do not introduce ASCII `...` for the
/// same purpose — it consumes 3 display columns where `…` consumes 1.
#[allow(dead_code)]
pub fn ellipsize(text: &str, max_width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    if max_width == 0 {
        return String::new();
    }
    if text.width() <= max_width {
        return text.to_string();
    }
    if max_width == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut width = 0usize;
    for ch in text.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + cw + 1 > max_width {
            break;
        }
        width += cw;
        out.push(ch);
    }
    out.push('…');
    out
}

/// Right-arrow glyph for picker fields.
pub const PICKER_ARROW: &str = "\u{25B8}";

/// Space-bar glyph for toggle fields.
pub const TOGGLE_HINT: &str = "\u{2423}";

/// Down-pointing triangle for an expanded tree node (multi-config provider).
pub const TREE_EXPANDED: &str = "\u{25BE}";

/// Down-pointing triangle reused as a column-header descending-sort
/// indicator (e.g. "LAST ▾"). Same glyph as `TREE_EXPANDED` but exposed
/// under a sort-specific name so column headers don't grep as tree code.
pub const SORT_DESC: &str = "\u{25BE}";

/// Right-pointing triangle for a collapsed tree node (multi-config provider).
pub const TREE_COLLAPSED: &str = "\u{25B8}";

/// L-shaped branch glyph for the last-child leaf row under an expanded tree node.
pub const TREE_BRANCH: &str = "\u{2514}";

/// Empty-state line for embedding in Paragraphs that render inside a block.
/// Same visual output as `render_empty()` but returns a composable `Line`.
pub fn empty_line(message: &str) -> Line<'static> {
    muted_line(message)
}

// ---------------------------------------------------------------------------
// Keyboard interaction primitives
// ---------------------------------------------------------------------------
//
// These helpers are the single source of truth for keyboard interaction
// patterns in purple. The CI script `scripts/check-keybindings.sh` enforces
// that handler and screen code uses these helpers instead of building footers
// or routing keys ad hoc.

/// Field kind for dynamic form footer hints.
///
/// Drives the `Space` action label in [`form_save_footer`]:
/// - `Text`: Space inserts a literal space character. No hint shown.
/// - `Toggle`: Space flips a boolean. Footer shows "Space toggle".
/// - `Picker`: Space opens a selection picker. Footer shows "Space pick".
///
/// **Invariant**: Enter ALWAYS submits the form regardless of `FieldKind`.
/// Pickers and toggles are reached via Space only, never via Enter.
/// `scripts/check-keybindings.sh` enforces this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Text input field. Space inserts a literal character.
    Text,
    /// Boolean toggle (e.g. VerifyTls, AutoSync). Space flips the value.
    Toggle,
    /// Picker field (e.g. IdentityFile, ProxyJump). Space opens the picker.
    Picker,
}

/// Form mode for dynamic footer rendering.
///
/// Forms with progressive disclosure (host form, provider form) start
/// `Collapsed` showing only required fields. The footer hints `\u{2193} more
/// options` so the user can expand. After expansion the footer flips to
/// `Expanded(kind)` and shows the appropriate per-field hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFooterMode {
    /// Required fields only. Down arrow expands to optional fields.
    Collapsed,
    /// All fields visible. Field kind determines the Space hint.
    Expanded(FieldKind),
}

/// Standard form save footer with dynamic hints based on focused field.
///
/// Renders one of:
/// - Collapsed:                `Enter save | \u{2193} more options | Esc cancel`
/// - Expanded + Text field:    `Enter save | Tab next | Esc cancel`
/// - Expanded + Toggle field:  `Enter save | Space toggle | Tab next | Esc cancel`
/// - Expanded + Picker field:  `Enter save | Space pick | Tab next | Esc cancel`
///
/// **Why this helper exists**: it codifies the rule that Enter is always the
/// save action, and that Space is the universal field-action key. Screens
/// must call this instead of building form footers ad hoc.
pub fn form_save_footer(mode: FormFooterMode) -> Footer {
    use crate::messages::footer as f;
    let mut footer = Footer::new().primary("Enter", f::ENTER_SAVE);
    match mode {
        FormFooterMode::Collapsed => {
            footer = footer.action("\u{2193}", " more options ");
        }
        FormFooterMode::Expanded(FieldKind::Text) => {
            footer = footer.action("Tab", f::TAB_NEXT);
        }
        FormFooterMode::Expanded(FieldKind::Toggle) => {
            footer = footer
                .action("Space", f::SPACE_TOGGLE)
                .action("Tab", f::TAB_NEXT);
        }
        FormFooterMode::Expanded(FieldKind::Picker) => {
            footer = footer
                .action("Space", f::SPACE_PICK)
                .action("Tab", f::TAB_NEXT);
        }
    }
    footer.action("Esc", f::ESC_CANCEL)
}

/// Footer for a destructive confirmation. Action-specific verbs both sides.
///
/// Stakes test: if cancelling by mistake loses irrecoverable work, use
/// action verbs (e.g. `delete/keep`, `sign/skip`, `purge/keep`). The
/// asymmetry helps users read the dialog as a choice between two outcomes,
/// not "did I press the right key?".
///
/// Both `n` and `Esc` cancel (the contract enforced by
/// `handler::route_confirm_key`); the footer advertises them as `n/Esc` so
/// the visible UI matches the actual key set.
///
/// Examples:
/// - `confirm_footer_destructive("delete", "keep")` for delete confirms
/// - `confirm_footer_destructive("sign", "skip")` for vault sign
/// - `confirm_footer_destructive("purge", "keep")` for purge stale
pub fn confirm_footer_destructive(yes_verb: &str, no_verb: &str) -> Footer {
    Footer::new()
        .primary("y", &format!(" {} ", yes_verb))
        .action("n/Esc", &format!(" {}", no_verb))
}

/// Footer for the standard discard-changes confirmation in any form.
///
/// Discarding form changes is a benign confirmation: users can re-enter the
/// data. We still use action verbs (`discard`/`keep`) instead of `yes/no`
/// because the noun-verb pairing is more informative than a bare affirmative.
pub fn discard_footer() -> Footer {
    confirm_footer_destructive("discard", "keep")
}

/// Render a centred destructive-confirm popup over whatever is on
/// screen. Use for inline `pending_delete`-style confirms (deleting a
/// tunnel rule from the tunnels overlay, removing a snippet from the
/// picker, dropping a provider config) so the affordance reads as a
/// modal popup with the rest of the design-system confirms (host
/// delete, vault sign, container restart) instead of a footer-line
/// prompt under the parent overlay. Footer renders the action-verb
/// pair below the popup's bottom border.
///
/// `title` appears in the danger block's top border.
/// `body_question` is the single-line question rendered with `theme::bold()`.
/// `body_detail` is an optional muted second-row sentence; pass `""` to
/// skip and let the popup collapse to a 5-row dialog.
pub fn render_destructive_popup(
    frame: &mut Frame,
    title: &str,
    body_question: &str,
    body_detail: &str,
    yes_verb: &str,
    no_verb: &str,
    app: &App,
) {
    let has_detail = !body_detail.is_empty();
    // 52-col wide matches confirm_dialog (single-alias host delete).
    // Height: border (2) + blank + question + (blank + detail) + blank = 6 or 8.
    let height: u16 = if has_detail { 7 } else { 5 };
    let area = super::centered_rect_fixed(56, height, frame.area());
    frame.render_widget(Clear, area);

    let block = danger_block(title);
    let mut text: Vec<Line<'static>> = vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {}", body_question), theme::bold())),
    ];
    if has_detail {
        text.push(Line::from(""));
        text.push(Line::from(Span::styled(
            format!("  {}", body_detail),
            theme::muted(),
        )));
    }
    render_body_wrapped(frame, area, block, text);

    let footer_area = render_overlay_footer(frame, area);
    let footer = confirm_footer_destructive(yes_verb, no_verb).to_line();
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.extend(footer.spans);
    super::render_footer_with_status(frame, footer_area, spans, app);
}

/// Render the standard "Discard changes?" footer with prompt prefix.
///
/// Single source of truth for the discard prompt across every editable
/// surface (host form, tunnel form, snippet form, provider form, snippet
/// param form, bulk tag editor). Renders below the block via
/// `render_overlay_footer`. Callers must compute `footer_area` first via
/// [`render_overlay_footer`] and pass it in.
pub fn render_discard_prompt(frame: &mut Frame, footer_area: Rect, app: &App) {
    let mut spans = vec![Span::styled(" Discard changes? ", theme::error())];
    spans.extend(discard_footer().into_spans());
    super::render_footer_with_status(frame, footer_area, spans, app);
}

// ---------------------------------------------------------------------------
// Section card primitives
// ---------------------------------------------------------------------------
//
// Bordered "section cards" with title in the top border. Shared by host
// detail and container detail so both panels read as siblings.

/// Box-drawing characters for section cards. Match the rounded-border look
/// used everywhere else in the TUI.
pub const BOX_TL: &str = "\u{256D}";
pub const BOX_TR: &str = "\u{256E}";
pub const BOX_BL: &str = "\u{2570}";
pub const BOX_BR: &str = "\u{256F}";
pub const BOX_H: &str = "\u{2500}";
pub const BOX_V: &str = "\u{2502}";

/// Push the opening line of a section card: ╭─ TITLE ───╮
pub fn section_open(lines: &mut Vec<Line<'static>>, title: &str, width: usize) {
    use unicode_width::UnicodeWidthStr;
    let border_prefix = format!("{}{} ", BOX_TL, BOX_H);
    let title_suffix = " ";
    let prefix_width = border_prefix.width() + title.width() + title_suffix.width();
    let fill = width.saturating_sub(prefix_width).saturating_sub(1);
    lines.push(Line::from(vec![
        Span::styled(border_prefix, theme::border()),
        Span::styled(title.to_string(), theme::bold()),
        Span::styled(title_suffix, theme::border()),
        Span::styled(BOX_H.repeat(fill), theme::border()),
        Span::styled(BOX_TR, theme::border()),
    ]));
}

/// Push the opening line of a section card without a title: ╭───────╮
pub fn section_open_notitle(lines: &mut Vec<Line<'static>>, width: usize) {
    let fill = width.saturating_sub(2);
    lines.push(Line::from(vec![
        Span::styled(BOX_TL, theme::border()),
        Span::styled(BOX_H.repeat(fill), theme::border()),
        Span::styled(BOX_TR, theme::border()),
    ]));
}

/// Push a content row wrapped in box side characters: │ <spans...> │
pub fn section_line(lines: &mut Vec<Line<'static>>, spans: Vec<Span<'static>>, width: usize) {
    use unicode_width::UnicodeWidthStr;
    let mut full_spans: Vec<Span<'static>> =
        vec![Span::styled(format!("{} ", BOX_V), theme::border())];
    let content_width: usize = full_spans.iter().map(|s| s.content.width()).sum::<usize>()
        + spans.iter().map(|s| s.content.width()).sum::<usize>();
    full_spans.extend(spans);
    let closing_offset = 1;
    let padding = width
        .saturating_sub(content_width)
        .saturating_sub(closing_offset);
    if padding > 0 {
        full_spans.push(Span::raw(" ".repeat(padding)));
    }
    full_spans.push(Span::styled(BOX_V, theme::border()));
    lines.push(Line::from(full_spans));
}

/// Push the closing line of a section card: ╰───────╯
pub fn section_close(lines: &mut Vec<Line<'static>>, width: usize) {
    let fill = width.saturating_sub(2);
    lines.push(Line::from(vec![
        Span::styled(BOX_BL, theme::border()),
        Span::styled(BOX_H.repeat(fill), theme::border()),
        Span::styled(BOX_BR, theme::border()),
    ]));
}

/// Empty bordered line used to stretch the last card on a panel. Renders
/// as `│              │` so the close-border stays anchored to the panel
/// bottom regardless of how much content the cards above produced.
pub fn section_empty_line(width: usize) -> Line<'static> {
    let fill = width.saturating_sub(2);
    Line::from(vec![
        Span::styled(BOX_V, theme::border()),
        Span::raw(" ".repeat(fill)),
        Span::styled(BOX_V, theme::border()),
    ])
}

/// Pad the line list so the LAST `section_close` row sits at row index
/// `available_rows - 1`. Inserts empty bordered lines just before that
/// close so the trailing card stretches without breaking its frame.
/// No-op when the lines already fill or exceed `available_rows`.
pub fn stretch_last_card(lines: &mut Vec<Line<'static>>, available_rows: usize, box_width: usize) {
    if lines.len() >= available_rows {
        return;
    }
    let extra = available_rows - lines.len();
    let last_close = lines.iter().rposition(|line| {
        line.spans
            .first()
            .map(|s| s.content.starts_with(BOX_BL))
            .unwrap_or(false)
    });
    let Some(idx) = last_close else {
        return;
    };
    for _ in 0..extra {
        lines.insert(idx, section_empty_line(box_width));
    }
}

/// Push a label+value field row inside a section card. Truncates the value
/// when it exceeds `max_value_width`. Pass `0` to disable truncation.
pub fn section_field(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &str,
    max_value_width: usize,
    box_width: usize,
) {
    use unicode_width::UnicodeWidthStr;
    let display = if max_value_width > 0 && value.width() > max_value_width {
        super::truncate(value, max_value_width)
    } else {
        value.to_string()
    };
    let spans = vec![
        Span::styled(
            format!("{:<width$}", label, width = SECTION_LABEL_W as usize),
            theme::muted(),
        ),
        Span::styled(display, theme::bold()),
    ];
    section_line(lines, spans, box_width);
}

/// Push a label+value field row with a custom value style (e.g. warning,
/// error, online dot). Otherwise identical to `section_field`.
pub fn section_field_styled(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &str,
    value_style: ratatui::style::Style,
    max_value_width: usize,
    box_width: usize,
) {
    use unicode_width::UnicodeWidthStr;
    let display = if max_value_width > 0 && value.width() > max_value_width {
        super::truncate(value, max_value_width)
    } else {
        value.to_string()
    };
    let spans = vec![
        Span::styled(
            format!("{:<width$}", label, width = SECTION_LABEL_W as usize),
            theme::muted(),
        ),
        Span::styled(display, value_style),
    ];
    section_line(lines, spans, box_width);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::widgets::Widget;

    fn make_app() -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::ssh_config::model::SshConfigFile {
            elements: crate::ssh_config::model::SshConfigFile::parse_content(""),
            path: dir.path().join("test_design"),
            crlf: false,
            bom: false,
        };
        (App::new(config), dir)
    }

    fn buffer_contains(buf: &Buffer, needle: &str) -> bool {
        for y in 0..buf.area.height {
            let mut row = String::new();
            for x in 0..buf.area.width {
                row.push_str(buf[(x, y)].symbol());
            }
            if row.contains(needle) {
                return true;
            }
        }
        false
    }

    fn render_block_title(block: Block<'static>, title: &str) -> bool {
        let area = Rect::new(0, 0, 30, 5);
        let mut buf = Buffer::empty(area);
        block.render(area, &mut buf);
        buffer_contains(&buf, title)
    }

    #[test]
    fn overlay_block_title_is_padded() {
        assert!(render_block_title(overlay_block("Hello"), " Hello "));
    }

    #[test]
    fn danger_block_title_is_padded() {
        assert!(render_block_title(danger_block("Delete"), " Delete "));
    }

    #[test]
    fn overlay_area_stays_within_frame() {
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let rect = overlay_area(frame, 70, 80, 20);
                let area = frame.area();
                assert!(rect.x >= area.x);
                assert!(rect.y >= area.y);
                assert!(rect.x + rect.width <= area.x + area.width);
                assert!(rect.y + rect.height <= area.y + area.height);
                assert!(rect.height <= 20);
            })
            .unwrap();
    }

    #[test]
    fn form_footer_sits_directly_below_block() {
        let block_area = Rect::new(5, 2, 30, 8);
        let rect = form_footer(block_area, 8);
        assert_eq!(rect.x, 5);
        assert_eq!(rect.y, 10);
        assert_eq!(rect.width, 30);
        assert_eq!(rect.height, 1);
    }

    #[test]
    fn form_divider_y_steps_by_two() {
        let inner = Rect::new(2, 3, 20, 10);
        assert_eq!(form_divider_y(inner, 0), 3);
        assert_eq!(form_divider_y(inner, 1), 5);
        assert_eq!(form_divider_y(inner, 2), 7);
    }

    #[test]
    fn footer_builder_inserts_gaps_between_entries_only() {
        let spans = Footer::new()
            .primary("Enter", "save")
            .action("Esc", "cancel")
            .action("Tab", "next")
            .into_spans();
        // primary (2) + gap (1) + action (2) + gap (1) + action (2) = 8
        assert_eq!(spans.len(), 8);
        assert_eq!(spans[2].content, FOOTER_GAP);
        assert_eq!(spans[5].content, FOOTER_GAP);
    }

    #[test]
    fn empty_footer_has_no_spans() {
        assert!(Footer::new().into_spans().is_empty());
    }

    #[test]
    fn footer_to_line_preserves_span_count() {
        let footer = Footer::new()
            .primary("Enter", "save")
            .action("Esc", "cancel");
        let spans_len = {
            let clone = Footer::new()
                .primary("Enter", "save")
                .action("Esc", "cancel");
            clone.into_spans().len()
        };
        let line = footer.to_line();
        assert_eq!(line.spans.len(), spans_len);
    }

    #[test]
    fn picker_width_is_clamped() {
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let w = picker_width(frame);
                assert!(w >= PICKER_MIN_W);
                assert!(w <= PICKER_MAX_W);
            })
            .unwrap();
    }

    #[test]
    fn picker_width_clamps_narrow_terminal_to_min() {
        let backend = TestBackend::new(30, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                assert_eq!(picker_width(frame), PICKER_MIN_W);
            })
            .unwrap();
    }

    #[test]
    fn picker_width_clamps_wide_terminal_to_max() {
        let backend = TestBackend::new(200, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                assert_eq!(picker_width(frame), PICKER_MAX_W);
            })
            .unwrap();
    }

    #[test]
    fn picker_width_passes_midrange_through() {
        // PICKER_MIN_W (60) < 66 < PICKER_MAX_W (72), so passes through unclamped.
        let backend = TestBackend::new(66, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                assert_eq!(picker_width(frame), 66);
            })
            .unwrap();
    }

    #[test]
    fn plain_overlay_block_has_no_title() {
        // Render the block into a small buffer and verify the top border row
        // contains only rounded glyphs and horizontal lines (no injected title
        // characters from a helper).
        let area = Rect::new(0, 0, 20, 3);
        let mut buf = Buffer::empty(area);
        plain_overlay_block().render(area, &mut buf);
        let mut top = String::new();
        for x in 0..area.width {
            top.push_str(buf[(x, 0)].symbol());
        }
        assert!(top.starts_with('\u{256D}'));
        assert!(top.ends_with('\u{256E}'));
        // All inner chars should be box-drawing horizontals.
        for ch in top.chars().skip(1).take((area.width as usize) - 2) {
            assert_eq!(ch, '\u{2500}');
        }
    }

    #[test]
    fn section_divider_contains_dashes() {
        let line = section_divider();
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("────"),
            "section divider should contain dash characters"
        );
    }

    #[test]
    fn padded_usize_matches_expected_values() {
        assert_eq!(padded_usize(0), 0);
        assert_eq!(padded_usize(10), 12);
        assert_eq!(padded_usize(20), 23);
    }

    #[test]
    fn kv_line_format_has_two_spans() {
        let line = kv_line("Label", "Value", KV_LABEL_WIDE);
        assert_eq!(line.spans.len(), 2);
        let label_text = &line.spans[0].content;
        assert!(
            label_text.starts_with("  "),
            "label should be 2-space indented"
        );
        assert!(label_text.contains("Label"));
        assert_eq!(line.spans[1].content.as_ref(), "Value");
    }

    #[test]
    fn kv_line_label_is_padded_to_width() {
        let line = kv_line("X", "Y", 22);
        let label = &line.spans[0].content;
        // 2-space indent + 22-char padded label = 24 total
        assert_eq!(label.len(), 24);
    }

    #[test]
    fn content_section_returns_header_and_divider() {
        let [header, divider] = content_section("Directives");
        let h_text: String = header.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(h_text.contains("Directives"));
        let d_text: String = divider.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(d_text.contains("────"));
    }

    #[test]
    fn render_empty_with_hint_does_not_panic() {
        let backend = TestBackend::new(60, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 60, 1);
                render_empty_with_hint(frame, area, "No tags yet.", "+", "add");
            })
            .unwrap();
    }

    #[test]
    fn column_header_prefix_is_three_spaces() {
        assert_eq!(COLUMN_HEADER_PREFIX, "   ");
        assert_eq!(COLUMN_HEADER_PREFIX.len(), 3);
    }

    #[test]
    fn col_gap_str_is_two_spaces() {
        assert_eq!(COL_GAP_STR, "  ");
        assert_eq!(COL_GAP_STR.len(), 2);
    }

    #[test]
    fn picker_arrow_renders_as_single_glyph() {
        // The grep check in scripts/check-design-system.sh enforces that the
        // literal "\u{25B8}" only appears in design.rs. The test here
        // guards a different invariant: PICKER_ARROW must be a single
        // non-whitespace grapheme so it lines up in form fields.
        assert_eq!(PICKER_ARROW.chars().count(), 1);
        assert!(!PICKER_ARROW.starts_with(char::is_whitespace));
    }

    #[test]
    fn toggle_hint_renders_as_single_glyph() {
        assert_eq!(TOGGLE_HINT.chars().count(), 1);
        assert!(!TOGGLE_HINT.starts_with(char::is_whitespace));
    }

    #[test]
    fn empty_line_has_indent_and_muted_style() {
        let line = empty_line("No results.");
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[0].content.as_ref(), "  ");
        assert_eq!(line.spans[1].content.as_ref(), "No results.");
    }

    #[test]
    fn render_empty_loading_error_do_not_panic() {
        let backend = TestBackend::new(40, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 40, 1);
                render_empty(frame, area, "no hosts");
                render_loading(frame, area, "loading...");
                render_error(frame, area, "something broke");
            })
            .unwrap();
    }

    #[test]
    fn footer_render_with_status_does_not_panic() {
        let (app, _dir) = make_app();
        let backend = TestBackend::new(60, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 60, 1);
                Footer::new()
                    .primary("Enter", "save")
                    .action("Esc", "cancel")
                    .render_with_status(frame, area, &app);
            })
            .unwrap();
    }

    fn footer_text(footer: Footer) -> String {
        footer
            .into_spans()
            .iter()
            .map(|s| s.content.as_ref())
            .collect()
    }

    #[test]
    fn form_save_footer_collapsed_shows_more_options() {
        let text = footer_text(form_save_footer(FormFooterMode::Collapsed));
        assert!(text.contains("Enter"));
        assert!(text.contains("save"));
        assert!(text.contains("more options"));
        assert!(text.contains("Esc"));
        assert!(text.contains("cancel"));
        // Collapsed mode never advertises Space.
        assert!(!text.contains("Space"));
    }

    #[test]
    fn form_save_footer_expanded_text_omits_space_hint() {
        let text = footer_text(form_save_footer(FormFooterMode::Expanded(FieldKind::Text)));
        assert!(text.contains("Enter"));
        assert!(text.contains("save"));
        assert!(text.contains("Tab"));
        assert!(text.contains("Esc"));
        // Text fields: Space is a literal character, not a hint.
        assert!(!text.contains("Space"));
    }

    #[test]
    fn form_save_footer_expanded_toggle_shows_space_toggle() {
        let text = footer_text(form_save_footer(FormFooterMode::Expanded(
            FieldKind::Toggle,
        )));
        assert!(text.contains("Space"));
        assert!(text.contains("toggle"));
        // Should not advertise picker on a toggle field.
        assert!(!text.contains("pick"));
    }

    #[test]
    fn form_save_footer_expanded_picker_shows_space_pick() {
        let text = footer_text(form_save_footer(FormFooterMode::Expanded(
            FieldKind::Picker,
        )));
        assert!(text.contains("Space"));
        assert!(text.contains("pick"));
        // Should not advertise toggle on a picker field.
        assert!(!text.contains("toggle"));
    }

    #[test]
    fn confirm_footer_destructive_uses_action_verbs() {
        let text = footer_text(confirm_footer_destructive("delete", "keep"));
        assert!(text.contains("y"));
        assert!(text.contains("delete"));
        assert!(text.contains("n/Esc"));
        assert!(text.contains("keep"));
        // Destructive footer must not contain generic yes/no labels.
        assert!(!text.contains("yes"));
        assert!(!text.contains(" no"));
    }

    #[test]
    fn confirm_footers_advertise_n_alongside_esc() {
        // route_confirm_key accepts y/Y, n/N, Esc. The footer must advertise
        // both n and Esc to keep the visible UI in sync with the key contract.
        for footer_text_str in [
            footer_text(confirm_footer_destructive("delete", "keep")),
            footer_text(discard_footer()),
        ] {
            assert!(
                footer_text_str.contains("n/Esc"),
                "footer must show both n and Esc as cancel keys: {}",
                footer_text_str
            );
        }
    }

    #[test]
    fn discard_footer_uses_discard_keep_verbs() {
        let text = footer_text(discard_footer());
        assert!(text.contains("discard"));
        assert!(text.contains("keep"));
    }

    #[test]
    fn is_container_running_is_case_insensitive() {
        assert!(is_container_running("running"));
        assert!(is_container_running("Running"));
        assert!(is_container_running("RUNNING"));
        assert!(!is_container_running("exited"));
        assert!(!is_container_running("paused"));
        assert!(!is_container_running(""));
    }

    #[test]
    fn parse_container_exit_code_extracts_docker_format() {
        assert_eq!(
            parse_container_exit_code("Exited (0) 2 minutes ago"),
            Some(0)
        );
        assert_eq!(
            parse_container_exit_code("Exited (137) just now"),
            Some(137)
        );
        assert_eq!(parse_container_exit_code("Up 5 minutes"), None);
        assert_eq!(parse_container_exit_code(""), None);
        assert_eq!(parse_container_exit_code("Exited (abc) bad"), None);
    }

    #[test]
    fn container_state_style_running_uses_online_icon() {
        let (icon, _) = container_state_style("running", None, "", None, 0);
        assert_eq!(icon, ICON_ONLINE);
    }

    #[test]
    fn container_state_style_dead_uses_error_icon() {
        let (icon, _) = container_state_style("dead", None, "", None, 0);
        assert_eq!(icon, ICON_ERROR);
    }

    #[test]
    fn container_state_style_paused_uses_paused_icon() {
        let (icon, _) = container_state_style("paused", None, "", None, 0);
        assert_eq!(icon, ICON_PAUSED);
        let (icon, _) = container_state_style("restarting", None, "", None, 0);
        assert_eq!(icon, ICON_PAUSED);
    }

    #[test]
    fn container_state_style_clean_exit_uses_stopped_icon() {
        let (icon, _) = container_state_style("exited", None, "Exited (0) ago", None, 0);
        assert_eq!(icon, ICON_STOPPED);
        // No exit code at all also reads as clean.
        let (icon, _) = container_state_style("exited", None, "", None, 0);
        assert_eq!(icon, ICON_STOPPED);
    }

    #[test]
    fn container_state_style_nonzero_exit_uses_error_icon() {
        let (icon, _) = container_state_style("exited", None, "Exited (137) ago", None, 0);
        assert_eq!(icon, ICON_ERROR);
        // Podman fallback path via inspect cache.
        let (icon, _) = container_state_style("stopped", None, "", Some(1), 0);
        assert_eq!(icon, ICON_ERROR);
    }

    #[test]
    fn container_state_style_unknown_state_falls_back_to_stopped() {
        let (icon, _) = container_state_style("created", None, "", None, 0);
        assert_eq!(icon, ICON_STOPPED);
        let (icon, _) = container_state_style("removing", None, "", None, 0);
        assert_eq!(icon, ICON_STOPPED);
    }

    #[test]
    fn container_state_style_running_with_unhealthy_uses_error_style() {
        let (_, style) = container_state_style("running", Some("unhealthy"), "", None, 0);
        // theme::error() in ANSI 16 mode is Red foreground.
        assert!(style.fg.is_some());
    }

    #[test]
    fn body_area_insets_block_border_plus_right_margin() {
        let block_area = Rect::new(10, 5, 40, 12);
        let body = body_area(block_area);
        // Border (1) only on left, border (1) + BODY_RIGHT_PAD (2) on right.
        assert_eq!(body.x, 11);
        assert_eq!(body.width, 40 - 2 - BODY_RIGHT_PAD);
        // Vertical: border only, no padding (block.inner equivalent).
        assert_eq!(body.y, 6);
        assert_eq!(body.height, 10);
    }

    #[test]
    fn body_area_collapses_safely_in_tiny_blocks() {
        // A 1x1 block has no room for margins; body_area must not panic
        // and must return a zero-sized rect inside the bounds.
        let body = body_area(Rect::new(0, 0, 1, 1));
        assert_eq!(body.width, 0);
        assert_eq!(body.height, 0);
    }

    #[test]
    fn ellipsize_returns_text_unchanged_when_it_fits() {
        assert_eq!(ellipsize("hello", 10), "hello");
        assert_eq!(ellipsize("hello", 5), "hello");
    }

    #[test]
    fn ellipsize_appends_single_glyph_when_text_overflows() {
        assert_eq!(ellipsize("hello world", 8), "hello w…");
    }

    #[test]
    fn ellipsize_handles_extreme_widths() {
        assert_eq!(ellipsize("hello", 0), "");
        assert_eq!(ellipsize("hello", 1), "…");
        assert_eq!(ellipsize("", 5), "");
    }

    #[test]
    fn wrap_indented_keeps_prefix_on_continuation_rows() {
        let text = "alpha beta gamma delta epsilon zeta eta theta iota kappa";
        let rows = wrap_indented(text, "  ", 18);
        assert!(rows.len() > 1, "long text must wrap");
        for row in &rows {
            assert!(row.starts_with("  "), "every row keeps indent: {row:?}");
            assert!(row.len() <= 18 + 2, "row exceeds budget: {row:?}");
        }
    }

    #[test]
    fn wrap_indented_hard_breaks_oversized_words() {
        let text = "ohabsurdlylongwordthatdoesnotfit ok";
        let rows = wrap_indented(text, "  ", 10);
        assert!(rows.len() >= 2);
        // Every row still carries the indent and stays within budget.
        for row in &rows {
            assert!(row.starts_with("  "));
        }
    }

    #[test]
    fn wrap_indented_returns_empty_for_zero_inputs() {
        assert!(wrap_indented("", "  ", 10).is_empty());
        assert!(wrap_indented("hi", "  ", 0).is_empty());
    }

    #[test]
    fn tab_empty_falls_back_to_single_line_on_narrow_areas() {
        // Below 44 cols wide, render_tab_empty should NOT panic — it
        // should fall back to the single-line render_empty_with_hint
        // path. Render to a tiny rect and assert no panic + content.
        let backend = ratatui::backend::TestBackend::new(40, 6);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let e = TabEmpty {
                    card_title: "X",
                    headline: "Cache is empty.",
                    explainer: "Nothing yet.",
                    hints: &[("R", "refresh")],
                };
                render_tab_empty(frame, Rect::new(0, 0, 40, 6), &e);
            })
            .unwrap();
    }

    #[test]
    fn tab_empty_card_renders_on_wide_areas() {
        let backend = ratatui::backend::TestBackend::new(100, 20);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let e = TabEmpty {
                    card_title: "Containers",
                    headline: "No containers cached yet.",
                    explainer: "Containers are fetched per host on demand and cached locally.",
                    hints: &[("Enter", "open a shell"), ("R", "refresh hosts")],
                };
                render_tab_empty(frame, Rect::new(0, 0, 100, 20), &e);
            })
            .unwrap();
    }

    #[test]
    fn ellipsize_respects_unicode_display_width() {
        // CJK characters take 2 display columns each.
        let s = "東京京都大阪";
        // Six glyphs × 2 cols each = 12 cols. Budget 9 → fit 4 glyphs (8 cols) + ellipsis.
        let out = ellipsize(s, 9);
        assert!(out.ends_with('…'));
        let inner = &out[..out.len() - '…'.len_utf8()];
        assert!(unicode_width::UnicodeWidthStr::width(inner) <= 8);
    }
}
