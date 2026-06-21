//! Native full-screen REPL built on `ratatui` + `crossterm`.
//!
//! A scrollback transcript above an editable input line. Each submitted line is
//! evaluated by the shared [`Engine`], so this is purely presentation — the same
//! engine a future `ratzilla` (browser) frontend would render.
//!
//! The input line is a real editor: a cursor moves through the text and the keys
//! are decoded by the configured [`Keybindings`] scheme — [`emacs`] (also
//! `native`) or modal [`vi`]. Kill/yank flows through the system clipboard (see
//! [`apply`] and [`clipboard`]). Enter submits, PgUp/PgDn scroll the transcript,
//! Ctrl-C quits.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::clipboard;
use ikigai_engine::config::Keybindings;
use ikigai_engine::{Action, CacheStats, Engine, Entry, HELP};

/// How many transcript lines PgUp/PgDn move.
const SCROLL_STEP: u16 = 5;

/// Run the TUI to completion, restoring the terminal on the way out.
pub fn run(engine: Engine, keys: Keybindings) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &engine, keys);
    ratatui::restore();
    result
}

/// One decoded input action — what a key press means, independent of which
/// keybinding scheme produced it. `Submit` and `Quit` are control flow; the rest
/// edit the line or move through history/scrollback and are applied by [`edit`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Edit {
    Insert(char),
    DeleteLeft,  // backspace
    DeleteRight, // delete the char under the cursor
    Left,
    Right,
    WordLeft,
    WordRight,
    Home,
    End,
    KillToEnd,   // cut from the cursor to the end of the line into the kill buffer
    KillToStart, // cut from the start of the line to the cursor into the kill buffer
    SetMark,     // mark the cursor as one end of a region
    Copy,        // copy the region (mark…cursor) into the kill buffer
    Cut,         // cut the region into the kill buffer, or the previous word if no mark
    Yank,        // insert (paste) the kill buffer at the cursor
    HistoryPrev,
    HistoryNext,
    ScrollUp,
    ScrollDown,
    Clear, // empty the line
    // vi mode switches and operators (no-ops under other schemes).
    ViInsert,                // enter Insert mode at the cursor (`i`)
    ViAppend,                // enter Insert mode one char right (`a`)
    ViInsertHome,            // jump to the start and enter Insert (`I`)
    ViAppendEnd,             // jump to the end and enter Insert (`A`)
    ViChangeToEnd,           // kill to the end of the line and enter Insert (`C`)
    ViNormal,                // leave Insert for Normal mode (`Esc`)
    ViWordFwd,               // `w` — move to the start of the next word
    ViWordEnd,               // `e` — move onto the end of the word
    ViOperator(ViOp),        // `d`/`c`/`y` — begin operator-pending
    ViMotionApply(ViMotion), // a motion in operator-pending — apply the operator
    Submit,
    Quit,
    Ignore,
}

/// The current mode of a vi-style input line.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum ViMode {
    /// Typing inserts text; `Esc` switches to [`Normal`](ViMode::Normal). A fresh
    /// line starts here (like `set -o vi` in a shell), so plain typing just works.
    #[default]
    Insert,
    /// Keys move the cursor and edit; `i`/`a`/`A`/`I`/`C` switch to Insert.
    Normal,
    /// After `d`/`c`/`y`, waiting for a motion (or the doubled operator) to define
    /// the range to operate on.
    Operator(ViOp),
}

/// A vi operator awaiting a motion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ViOp {
    Delete,
    Change,
    Yank,
}

impl ViOp {
    /// The key that starts this operator — and, pressed again, means "the whole
    /// line" (`dd` / `cc` / `yy`).
    fn key(self) -> char {
        match self {
            ViOp::Delete => 'd',
            ViOp::Change => 'c',
            ViOp::Yank => 'y',
        }
    }
}

/// A motion that, paired with an operator, defines the byte range to act on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ViMotion {
    WordFwd,   // `w` — to the start of the next word
    WordBack,  // `b` — to the start of the previous word
    WordEnd,   // `e` — through the end of the word
    LineStart, // `0`
    LineEnd,   // `$`
    WholeLine, // the doubled operator
}

/// Mutable UI state: the input buffer and cursor, the transcript, and history.
#[derive(Default)]
struct State {
    input: String,
    /// Byte offset of the cursor within `input`, always on a `char` boundary.
    cursor: usize,
    /// The most recent killed/copied text — yanked back by `Ctrl-Y`. Persists
    /// across lines, so you can cut on one line and paste on another.
    kill: String,
    /// The mark (a byte offset) set by `Ctrl-Space`; with the cursor it bounds
    /// the region that copy/cut act on. Cleared by any edit to the text.
    mark: Option<usize>,
    keys: Keybindings,
    /// The vi sub-mode (only meaningful when `keys` is [`Keybindings::Vi`]).
    vi_mode: ViMode,
    transcript: Vec<Entry>,
    history: Vec<String>,
    /// Index into `history` while browsing with Up/Down; `None` = editing fresh.
    history_pos: Option<usize>,
    /// Lines scrolled up from the bottom; `0` = pinned to the latest output.
    scroll_back: u16,
}

impl State {
    /// The active region as sorted byte offsets `(lo, hi)`, or `None` when no
    /// mark is set. The mark is clamped to the current length, defending against
    /// a stale offset even though edits clear it.
    fn region(&self) -> Option<(usize, usize)> {
        let mark = self.mark?.min(self.input.len());
        Some((mark.min(self.cursor), mark.max(self.cursor)))
    }
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    engine: &Engine,
    keys: Keybindings,
) -> io::Result<()> {
    let mut state = State {
        keys,
        ..State::default()
    };
    loop {
        terminal.draw(|frame| draw(frame, &state))?;
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match decode(key, &state) {
                Edit::Quit => return Ok(()),
                // `submit` evaluates the line and reports whether to quit.
                Edit::Submit if submit(&mut state, engine) => return Ok(()),
                Edit::Submit => {}
                action => apply(&mut state, action),
            }
        }
    }
}

/// Decode a key press into an [`Edit`] under the active scheme, given the state
/// the decoding depends on (whether the line is empty for Emacs; the vi mode).
fn decode(key: KeyEvent, state: &State) -> Edit {
    match state.keys {
        // `Native` is the platform's terminal default, which is Emacs everywhere.
        Keybindings::Emacs | Keybindings::Native => emacs(key, state.input.is_empty()),
        Keybindings::Vi => vi(key, state.vi_mode),
    }
}

/// Modal vi bindings: Normal mode moves and edits, Insert mode types. A fresh
/// line starts in Insert (so typing works immediately); `Esc` enters Normal.
fn vi(key: KeyEvent, mode: ViMode) -> Edit {
    match mode {
        ViMode::Insert => vi_insert(key),
        ViMode::Normal => vi_normal(key),
        ViMode::Operator(op) => vi_pending(key, op),
    }
}

/// vi Insert mode: type text, with a few readline conveniences; `Esc` → Normal.
fn vi_insert(key: KeyEvent) -> Edit {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Esc => Edit::ViNormal,
        KeyCode::Char('c') if ctrl => Edit::Quit,
        KeyCode::Char('w') if ctrl => Edit::Cut,
        KeyCode::Char('u') if ctrl => Edit::KillToStart,
        KeyCode::Char(c) if !ctrl && !alt => Edit::Insert(c),
        KeyCode::Backspace => Edit::DeleteLeft,
        KeyCode::Delete => Edit::DeleteRight,
        KeyCode::Left => Edit::Left,
        KeyCode::Right => Edit::Right,
        KeyCode::Home => Edit::Home,
        KeyCode::End => Edit::End,
        KeyCode::Up => Edit::HistoryPrev,
        KeyCode::Down => Edit::HistoryNext,
        KeyCode::PageUp => Edit::ScrollUp,
        KeyCode::PageDown => Edit::ScrollDown,
        KeyCode::Enter => Edit::Submit,
        _ => Edit::Ignore,
    }
}

/// vi Normal mode: motions (`h l w b e 0 $`), edits (`x X D C p P`), mode
/// switches (`i a A I`), operators (`d c y` → operator-pending), and history
/// (`j k`). Counts (`3w`) are deferred.
fn vi_normal(key: KeyEvent) -> Edit {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('c') if ctrl => Edit::Quit,
        KeyCode::Char('i') => Edit::ViInsert,
        KeyCode::Char('a') => Edit::ViAppend,
        KeyCode::Char('I') => Edit::ViInsertHome,
        KeyCode::Char('A') => Edit::ViAppendEnd,
        KeyCode::Char('C') => Edit::ViChangeToEnd,
        KeyCode::Char('h') | KeyCode::Left => Edit::Left,
        KeyCode::Char('l') | KeyCode::Right => Edit::Right,
        KeyCode::Char('w') => Edit::ViWordFwd,
        KeyCode::Char('e') => Edit::ViWordEnd,
        KeyCode::Char('b') => Edit::WordLeft,
        KeyCode::Char('0') => Edit::Home,
        KeyCode::Char('$') => Edit::End,
        KeyCode::Char('x') | KeyCode::Delete => Edit::DeleteRight,
        KeyCode::Char('X') => Edit::DeleteLeft,
        KeyCode::Char('D') => Edit::KillToEnd,
        KeyCode::Char('d') => Edit::ViOperator(ViOp::Delete),
        KeyCode::Char('c') => Edit::ViOperator(ViOp::Change),
        KeyCode::Char('y') => Edit::ViOperator(ViOp::Yank),
        KeyCode::Char('p') | KeyCode::Char('P') => Edit::Yank,
        KeyCode::Char('j') | KeyCode::Down => Edit::HistoryNext,
        KeyCode::Char('k') | KeyCode::Up => Edit::HistoryPrev,
        KeyCode::Backspace => Edit::Left, // Normal-mode Backspace moves, not deletes
        KeyCode::PageUp => Edit::ScrollUp,
        KeyCode::PageDown => Edit::ScrollDown,
        KeyCode::Enter => Edit::Submit,
        _ => Edit::Ignore,
    }
}

/// vi operator-pending: after `d`/`c`/`y`, a motion (`w b e 0 $`) or the doubled
/// operator (`dd`/`cc`/`yy` = the whole line) selects the range. Anything else
/// cancels back to Normal.
fn vi_pending(key: KeyEvent, op: ViOp) -> Edit {
    match key.code {
        KeyCode::Char(c) if c == op.key() => Edit::ViMotionApply(ViMotion::WholeLine),
        KeyCode::Char('w') => Edit::ViMotionApply(ViMotion::WordFwd),
        KeyCode::Char('b') => Edit::ViMotionApply(ViMotion::WordBack),
        KeyCode::Char('e') => Edit::ViMotionApply(ViMotion::WordEnd),
        KeyCode::Char('0') => Edit::ViMotionApply(ViMotion::LineStart),
        KeyCode::Char('$') => Edit::ViMotionApply(ViMotion::LineEnd),
        _ => Edit::ViNormal, // unknown motion (or Esc) cancels the operator
    }
}

/// Emacs / readline bindings. Arrow keys, Home/End, Delete, and Backspace work
/// too, so muscle memory from either world lands.
fn emacs(key: KeyEvent, input_empty: bool) -> Edit {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('c') if ctrl => Edit::Quit,
        // Readline convention: delete-forward, but EOF (quit) on an empty line.
        KeyCode::Char('d') if ctrl => {
            if input_empty {
                Edit::Quit
            } else {
                Edit::DeleteRight
            }
        }
        KeyCode::Char('a') if ctrl => Edit::Home,
        KeyCode::Char('e') if ctrl => Edit::End,
        KeyCode::Char('f') if ctrl => Edit::Right,
        KeyCode::Char('b') if ctrl => Edit::Left,
        KeyCode::Char('f') if alt => Edit::WordRight,
        KeyCode::Char('b') if alt => Edit::WordLeft,
        KeyCode::Char('p') if ctrl => Edit::HistoryPrev,
        KeyCode::Char('n') if ctrl => Edit::HistoryNext,
        KeyCode::Char('k') if ctrl => Edit::KillToEnd,
        KeyCode::Char('u') if ctrl => Edit::KillToStart,
        KeyCode::Char('w') if ctrl => Edit::Cut,
        KeyCode::Char('w') if alt => Edit::Copy,
        KeyCode::Char('y') if ctrl => Edit::Yank,
        // Set the mark. Terminals report Ctrl-Space inconsistently — as Ctrl-`@`,
        // a control space, or NUL — so accept all three.
        KeyCode::Char('@') if ctrl => Edit::SetMark,
        KeyCode::Char(' ') if ctrl => Edit::SetMark,
        KeyCode::Null => Edit::SetMark,
        KeyCode::Char(c) if !ctrl && !alt => Edit::Insert(c),
        KeyCode::Backspace => Edit::DeleteLeft,
        KeyCode::Delete => Edit::DeleteRight,
        KeyCode::Left => Edit::Left,
        KeyCode::Right => Edit::Right,
        KeyCode::Home => Edit::Home,
        KeyCode::End => Edit::End,
        KeyCode::Up => Edit::HistoryPrev,
        KeyCode::Down => Edit::HistoryNext,
        KeyCode::PageUp => Edit::ScrollUp,
        KeyCode::PageDown => Edit::ScrollDown,
        KeyCode::Esc => Edit::Clear,
        KeyCode::Enter => Edit::Submit,
        _ => Edit::Ignore,
    }
}

/// Apply an editing action, keeping the kill buffer in sync with the system
/// clipboard around the pure [`edit`]: a yank pulls the clipboard in first, and
/// any change to the kill buffer is pushed back out. Best-effort — with no
/// clipboard tool present, the in-process buffer is used (see [`clipboard`]).
fn apply(state: &mut State, action: Edit) {
    if action == Edit::Yank {
        if let Some(text) = clipboard::paste() {
            state.kill = text;
        }
    }
    let before = state.kill.clone();
    edit(state, action);
    if state.kill != before {
        clipboard::copy(&state.kill);
    }
}

/// Apply a line-editing action to the state. `Submit`/`Quit` are handled by the
/// caller (control flow); everything else mutates the buffer, cursor, history
/// browsing, scrollback, or vi mode here. Pure (no I/O) so it is fully testable;
/// clipboard sync lives in [`apply`].
fn edit(state: &mut State, action: Edit) {
    // Any edit to the text invalidates the mark (its byte offset would shift);
    // movement and the mark/copy/cut commands manage it themselves.
    match action {
        Edit::Insert(c) => {
            state.input.insert(state.cursor, c);
            state.cursor += c.len_utf8();
            state.mark = None;
        }
        Edit::DeleteLeft => {
            if state.cursor > 0 {
                let from = prev_boundary(&state.input, state.cursor);
                state.input.replace_range(from..state.cursor, "");
                state.cursor = from;
            }
            state.mark = None;
        }
        Edit::DeleteRight => {
            let to = next_boundary(&state.input, state.cursor);
            state.input.replace_range(state.cursor..to, "");
            state.mark = None;
        }
        Edit::Left => state.cursor = prev_boundary(&state.input, state.cursor),
        Edit::Right => state.cursor = next_boundary(&state.input, state.cursor),
        Edit::WordLeft => state.cursor = word_left(&state.input, state.cursor),
        Edit::WordRight => state.cursor = word_right(&state.input, state.cursor),
        Edit::Home => state.cursor = 0,
        Edit::End => state.cursor = state.input.len(),
        Edit::KillToEnd => kill(state, state.cursor, state.input.len()),
        Edit::KillToStart => kill(state, 0, state.cursor),
        Edit::SetMark => state.mark = Some(state.cursor),
        Edit::Copy => {
            if let Some((lo, hi)) = state.region() {
                state.kill = state.input[lo..hi].to_string();
            }
            state.mark = None;
        }
        Edit::Cut => match state.region() {
            Some((lo, hi)) => kill(state, lo, hi),
            // No region: cut the previous word (readline `Ctrl-W`).
            None => kill(state, word_left(&state.input, state.cursor), state.cursor),
        },
        Edit::Yank => {
            let yanked = state.kill.clone();
            state.input.insert_str(state.cursor, &yanked);
            state.cursor += yanked.len();
            state.mark = None;
        }
        Edit::HistoryPrev => recall(state, -1),
        Edit::HistoryNext => recall(state, 1),
        Edit::ScrollUp => state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP),
        Edit::ScrollDown => state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP),
        Edit::Clear => {
            state.input.clear();
            state.cursor = 0;
            state.mark = None;
        }
        Edit::ViInsert => state.vi_mode = ViMode::Insert,
        Edit::ViNormal => state.vi_mode = ViMode::Normal,
        Edit::ViAppend => {
            state.cursor = next_boundary(&state.input, state.cursor);
            state.vi_mode = ViMode::Insert;
        }
        Edit::ViInsertHome => {
            state.cursor = 0;
            state.vi_mode = ViMode::Insert;
        }
        Edit::ViAppendEnd => {
            state.cursor = state.input.len();
            state.vi_mode = ViMode::Insert;
        }
        Edit::ViChangeToEnd => {
            kill(state, state.cursor, state.input.len());
            state.vi_mode = ViMode::Insert;
        }
        Edit::ViWordFwd => state.cursor = vi_word_forward(&state.input, state.cursor),
        Edit::ViWordEnd => state.cursor = vi_word_end(&state.input, state.cursor),
        Edit::ViOperator(op) => state.vi_mode = ViMode::Operator(op),
        Edit::ViMotionApply(motion) => {
            if let ViMode::Operator(op) = state.vi_mode {
                let (lo, hi) = vi_range(&state.input, state.cursor, op, motion);
                match op {
                    ViOp::Delete => {
                        kill(state, lo, hi);
                        state.vi_mode = ViMode::Normal;
                    }
                    ViOp::Change => {
                        kill(state, lo, hi);
                        state.vi_mode = ViMode::Insert;
                    }
                    ViOp::Yank => {
                        state.kill = state.input[lo..hi].to_string();
                        state.cursor = lo;
                        state.mark = None;
                        state.vi_mode = ViMode::Normal;
                    }
                }
            }
        }
        Edit::Submit | Edit::Quit | Edit::Ignore => {}
    }
}

/// The byte range a vi operator acts on, given the cursor and a motion. Forward
/// motions span `cursor..target`, backward motions `target..cursor`. `cw` is the
/// famous special case — it acts like `ce` (to the end of the word, not the start
/// of the next), so it doesn't swallow the trailing space.
fn vi_range(input: &str, cursor: usize, op: ViOp, motion: ViMotion) -> (usize, usize) {
    match motion {
        ViMotion::WordFwd if matches!(op, ViOp::Change) => (cursor, word_right(input, cursor)),
        ViMotion::WordFwd => (cursor, vi_word_forward(input, cursor)),
        ViMotion::WordEnd => (cursor, word_right(input, cursor)),
        ViMotion::LineEnd => (cursor, input.len()),
        ViMotion::WordBack => (word_left(input, cursor), cursor),
        ViMotion::LineStart => (0, cursor),
        ViMotion::WholeLine => (0, input.len()),
    }
}

/// vi `w`: the start of the next word — skip the current word, then the run of
/// whitespace after it.
fn vi_word_forward(s: &str, cursor: usize) -> usize {
    let next = |i: usize| s[i..].chars().next().map(|c| (i + c.len_utf8(), c));
    let mut i = cursor;
    while let Some((n, c)) = next(i) {
        if c.is_whitespace() {
            break;
        }
        i = n;
    }
    while let Some((n, c)) = next(i) {
        if c.is_whitespace() {
            i = n;
        } else {
            break;
        }
    }
    i
}

/// vi `e`: onto the last character of the word ahead of the cursor.
fn vi_word_end(s: &str, cursor: usize) -> usize {
    let end = word_right(s, cursor);
    if end > cursor {
        prev_boundary(s, end)
    } else {
        cursor
    }
}

/// Move the byte range `lo..hi` of `input` into the kill buffer, leaving the
/// cursor at `lo`. The range must be on `char` boundaries.
fn kill(state: &mut State, lo: usize, hi: usize) {
    state.kill = state.input[lo..hi].to_string();
    state.input.replace_range(lo..hi, "");
    state.cursor = lo;
    state.mark = None;
}

/// Byte offset of the `char` boundary just left of `cursor` (the cursor itself
/// when already at the start).
fn prev_boundary(s: &str, cursor: usize) -> usize {
    s[..cursor]
        .chars()
        .next_back()
        .map_or(cursor, |c| cursor - c.len_utf8())
}

/// Byte offset of the `char` boundary just right of `cursor` (the cursor itself
/// when already at the end).
fn next_boundary(s: &str, cursor: usize) -> usize {
    s[cursor..]
        .chars()
        .next()
        .map_or(cursor, |c| cursor + c.len_utf8())
}

/// Byte offset one word left of `cursor`: skip whitespace, then the word.
fn word_left(s: &str, cursor: usize) -> usize {
    let prev = |i: usize| s[..i].chars().next_back().map(|c| (i - c.len_utf8(), c));
    let mut i = cursor;
    while let Some((p, c)) = prev(i) {
        if c.is_whitespace() {
            i = p;
        } else {
            break;
        }
    }
    while let Some((p, c)) = prev(i) {
        if c.is_whitespace() {
            break;
        }
        i = p;
    }
    i
}

/// Byte offset one word right of `cursor`: skip whitespace, then the word.
fn word_right(s: &str, cursor: usize) -> usize {
    let next = |i: usize| s[i..].chars().next().map(|c| (i + c.len_utf8(), c));
    let mut i = cursor;
    while let Some((n, c)) = next(i) {
        if c.is_whitespace() {
            i = n;
        } else {
            break;
        }
    }
    while let Some((n, c)) = next(i) {
        if c.is_whitespace() {
            break;
        }
        i = n;
    }
    i
}

/// Evaluate the current input line; returns `true` if the REPL should quit.
fn submit(state: &mut State, engine: &Engine) -> bool {
    let line = std::mem::take(&mut state.input);
    state.cursor = 0;
    state.mark = None;
    state.vi_mode = ViMode::default(); // each new line starts in Insert
    state.history_pos = None;
    state.scroll_back = 0;
    if !line.trim().is_empty() {
        state.history.push(line.clone());
    }
    match engine.eval(&line) {
        Action::Quit => return true,
        Action::Help => state.transcript.push(Entry {
            input: line,
            result: Ok(HELP.to_string()),
            cache: CacheStats::default(),
        }),
        Action::Output(entry) => state.transcript.push(entry),
        // Drop the scrollback transcript; `state.history` (line recall) is untouched,
        // and the `clear` line itself was already pushed to it above.
        Action::Clear => state.transcript.clear(),
        Action::Noop => {}
    }
    false
}

/// Step through input history: `dir < 0` older, `dir > 0` newer.
fn recall(state: &mut State, dir: i32) {
    if state.history.is_empty() {
        return;
    }
    let last = state.history.len() - 1;
    let next = match (state.history_pos, dir) {
        (None, d) if d < 0 => Some(last), // first Up → most recent
        (None, _) => None,                // Down with no browsing → stay fresh
        (Some(p), d) if d < 0 => Some(p.saturating_sub(1)),
        (Some(p), _) if p < last => Some(p + 1), // Down → newer
        (Some(_), _) => None,                    // Down past newest → fresh line
    };
    state.history_pos = next;
    state.input = next.map(|p| state.history[p].clone()).unwrap_or_default();
    state.cursor = state.input.len(); // land at the end of the recalled line
    state.mark = None; // the recalled text is a new buffer; any old mark is stale
}

fn draw(frame: &mut Frame, state: &State) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // title
        Constraint::Min(1),    // transcript
        Constraint::Length(3), // input box
    ])
    .split(frame.area());

    let title = Line::from(vec![
        format!("ikigai {} ", env!("CARGO_PKG_VERSION")).bold(),
        "— resource-resolution REPL".into(),
        format!(
            "   (help · quit · ↑↓ history · {} · PgUp/PgDn scroll · Ctrl-C exit)",
            mode_label(state)
        )
        .dim(),
    ]);
    frame.render_widget(Paragraph::new(title), chunks[0]);

    let lines = transcript_lines(&state.transcript);
    let bottom = (lines.len() as u16).saturating_sub(chunks[1].height);
    let scroll_y = bottom.saturating_sub(state.scroll_back);
    frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);

    let input = Paragraph::new(state.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" request "));
    frame.render_widget(input, chunks[2]);
    // Place the cursor at its column — the display width before it — inside the
    // 1-cell border, clamped so a long line can't draw past the box.
    let col = state.input[..state.cursor].chars().count() as u16;
    let cursor_x = (chunks[2].x + 1 + col).min(chunks[2].x + chunks[2].width.saturating_sub(1));
    frame.set_cursor_position(Position::new(cursor_x, chunks[2].y + 1));
}

/// The active scheme (and, for vi, its mode) shown in the title hint — so a vi
/// user can always see whether they're in Normal or Insert.
fn mode_label(state: &State) -> String {
    match state.keys {
        Keybindings::Emacs => "emacs keys".to_string(),
        Keybindings::Native => "native keys".to_string(),
        Keybindings::Vi => {
            let mode = match state.vi_mode {
                ViMode::Insert => "insert".to_string(),
                ViMode::Normal => "normal".to_string(),
                // Operator-pending — show the operator key waiting for a motion.
                ViMode::Operator(op) => format!("normal {}", op.key()),
            };
            format!("vi · {mode}")
        }
    }
}

/// Render the transcript as colored lines: cyan prompt, green output, red errors,
/// with a dim cache-outcome tag (`cached` / `computed` / …) after the prompt.
fn transcript_lines(transcript: &[Entry]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for entry in transcript {
        let mut prompt = vec![format!("ikigai> {}", entry.input).cyan()];
        if let Some(label) = entry.cache.label() {
            prompt.push(format!("  ({label})").dim());
        }
        lines.push(Line::from(prompt));
        match &entry.result {
            Ok(out) => lines.extend(out.lines().map(|l| Line::from(l.to_string().green()))),
            Err(err) => lines.push(Line::from(format!("error: {err}").red())),
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(width: u16, height: u16, state: &State) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, state)).unwrap();
    }

    // The interactive loop can't run headless, but `draw` can — exercise it at
    // edge sizes and with content so the scroll/cursor math can't panic.
    #[test]
    fn draws_without_panicking() {
        let mut state = State::default();
        render(80, 24, &state); // empty, normal size
        render(1, 1, &state); // degenerate: smaller than the layout wants

        state.input = "source urn:fn:toUpper hi".into();
        state.cursor = 7; // cursor mid-line — exercises the cursor-column math
        state.transcript.push(Entry {
            input: "source urn:fn:toUpper hi".into(),
            result: Ok("line one\nline two".into()),
            cache: CacheStats::default(),
        });
        state.transcript.push(Entry {
            input: "source urn:fn:nope".into(),
            result: Err("no endpoint resolved".into()),
            cache: CacheStats::default(),
        });
        render(80, 5, &state); // transcript taller than the area → scrolled
        render(80, 24, &state);

        // A line longer than the input box, cursor at the end → the column clamp
        // must keep the cursor inside the border rather than drawing past it.
        state.input = "x".repeat(200);
        state.cursor = state.input.len();
        render(40, 24, &state);
    }

    fn state_with(input: &str, cursor: usize) -> State {
        State {
            input: input.to_string(),
            cursor,
            ..State::default()
        }
    }

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    #[test]
    fn inserts_and_deletes_at_the_cursor() {
        let mut s = state_with("ac", 1);
        edit(&mut s, Edit::Insert('b'));
        assert_eq!((s.input.as_str(), s.cursor), ("abc", 2));

        edit(&mut s, Edit::Home);
        edit(&mut s, Edit::Right);
        edit(&mut s, Edit::DeleteRight); // remove 'b'
        assert_eq!((s.input.as_str(), s.cursor), ("ac", 1));
        edit(&mut s, Edit::DeleteLeft); // remove 'a'
        assert_eq!((s.input.as_str(), s.cursor), ("c", 0));
        edit(&mut s, Edit::DeleteLeft); // no-op at start
        assert_eq!((s.input.as_str(), s.cursor), ("c", 0));
        edit(&mut s, Edit::End);
        assert_eq!(s.cursor, 1);
    }

    #[test]
    fn kills_to_end_start_and_word_into_the_buffer() {
        let mut s = state_with("foo bar baz", 8);
        edit(&mut s, Edit::KillToEnd);
        assert_eq!(s.input, "foo bar ");
        assert_eq!(s.kill, "baz"); // killed text is yankable

        let mut s = state_with("foo bar", 4);
        edit(&mut s, Edit::KillToStart);
        assert_eq!(
            (s.input.as_str(), s.cursor, s.kill.as_str()),
            ("bar", 0, "foo ")
        );

        // `Cut` with no mark falls back to killing the previous word.
        let mut s = state_with("foo bar", 7);
        edit(&mut s, Edit::Cut);
        assert_eq!(
            (s.input.as_str(), s.cursor, s.kill.as_str()),
            ("foo ", 4, "bar")
        );
    }

    #[test]
    fn yank_pastes_the_kill_buffer_at_the_cursor() {
        let mut s = state_with("foo bar", 7);
        edit(&mut s, Edit::Cut); // kill "bar"
        edit(&mut s, Edit::Home);
        edit(&mut s, Edit::Yank); // paste at the start
        assert_eq!((s.input.as_str(), s.cursor), ("barfoo ", 3));
    }

    #[test]
    fn copy_takes_the_region_without_deleting() {
        let mut s = state_with("hello world", 0);
        edit(&mut s, Edit::SetMark); // mark at 0
        edit(&mut s, Edit::WordRight); // cursor to 5 ("hello")
        edit(&mut s, Edit::Copy);
        assert_eq!(s.input, "hello world"); // unchanged
        assert_eq!(s.kill, "hello");
        assert_eq!(s.mark, None); // region consumed
    }

    #[test]
    fn cut_removes_the_region_when_a_mark_is_set() {
        let mut s = state_with("hello world", 11);
        edit(&mut s, Edit::SetMark); // mark at end
        edit(&mut s, Edit::WordLeft); // cursor to 6 (start of "world")
        edit(&mut s, Edit::Cut);
        assert_eq!(
            (s.input.as_str(), s.cursor, s.kill.as_str()),
            ("hello ", 6, "world")
        );
    }

    #[test]
    fn editing_text_clears_the_mark() {
        let mut s = state_with("abc", 0);
        edit(&mut s, Edit::SetMark);
        edit(&mut s, Edit::Insert('x'));
        assert_eq!(s.mark, None);
        assert!(s.region().is_none());
    }

    #[test]
    fn moves_by_word_over_runs_of_spaces() {
        let mut s = state_with("foo  bar", 0);
        edit(&mut s, Edit::WordRight);
        assert_eq!(s.cursor, 3); // end of "foo"
        edit(&mut s, Edit::WordRight);
        assert_eq!(s.cursor, 8); // end of "bar"
        edit(&mut s, Edit::WordLeft);
        assert_eq!(s.cursor, 5); // start of "bar"
    }

    #[test]
    fn edits_respect_utf8_boundaries() {
        let mut s = state_with("", 0);
        edit(&mut s, Edit::Insert('é')); // two bytes
        assert_eq!(s.cursor, 2);
        edit(&mut s, Edit::Insert('x'));
        assert_eq!((s.input.as_str(), s.cursor), ("éx", 3));
        edit(&mut s, Edit::Left);
        assert_eq!(s.cursor, 2);
        edit(&mut s, Edit::DeleteLeft); // remove the whole 'é'
        assert_eq!((s.input.as_str(), s.cursor), ("x", 0));
    }

    #[test]
    fn emacs_maps_the_core_motions() {
        let c = KeyModifiers::CONTROL;
        let a = KeyModifiers::ALT;
        assert_eq!(emacs(key(KeyCode::Char('a'), c), false), Edit::Home);
        assert_eq!(emacs(key(KeyCode::Char('e'), c), false), Edit::End);
        assert_eq!(emacs(key(KeyCode::Char('f'), c), false), Edit::Right);
        assert_eq!(emacs(key(KeyCode::Char('b'), c), false), Edit::Left);
        assert_eq!(emacs(key(KeyCode::Char('f'), a), false), Edit::WordRight);
        assert_eq!(emacs(key(KeyCode::Char('b'), a), false), Edit::WordLeft);
        assert_eq!(emacs(key(KeyCode::Char('p'), c), false), Edit::HistoryPrev);
        assert_eq!(emacs(key(KeyCode::Char('n'), c), false), Edit::HistoryNext);
        assert_eq!(
            emacs(key(KeyCode::Char('x'), KeyModifiers::NONE), false),
            Edit::Insert('x')
        );
    }

    #[test]
    fn emacs_maps_the_kill_ring() {
        let c = KeyModifiers::CONTROL;
        let a = KeyModifiers::ALT;
        assert_eq!(emacs(key(KeyCode::Char('y'), c), false), Edit::Yank);
        assert_eq!(emacs(key(KeyCode::Char('w'), c), false), Edit::Cut);
        assert_eq!(emacs(key(KeyCode::Char('w'), a), false), Edit::Copy);
        assert_eq!(emacs(key(KeyCode::Char('k'), c), false), Edit::KillToEnd);
        // Ctrl-Space arrives variously across terminals; all set the mark.
        assert_eq!(emacs(key(KeyCode::Char(' '), c), false), Edit::SetMark);
        assert_eq!(emacs(key(KeyCode::Char('@'), c), false), Edit::SetMark);
        assert_eq!(
            emacs(key(KeyCode::Null, KeyModifiers::NONE), false),
            Edit::SetMark
        );
    }

    #[test]
    fn emacs_ctrl_d_is_eof_only_on_an_empty_line() {
        let c = KeyModifiers::CONTROL;
        assert_eq!(emacs(key(KeyCode::Char('d'), c), true), Edit::Quit);
        assert_eq!(emacs(key(KeyCode::Char('d'), c), false), Edit::DeleteRight);
        assert_eq!(emacs(key(KeyCode::Char('c'), c), false), Edit::Quit);
    }

    fn vi_key(c: char) -> KeyEvent {
        key(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn vi_normal_maps_motions_and_edits() {
        use ViMode::Normal;
        assert_eq!(vi(vi_key('h'), Normal), Edit::Left);
        assert_eq!(vi(vi_key('l'), Normal), Edit::Right);
        assert_eq!(vi(vi_key('w'), Normal), Edit::ViWordFwd);
        assert_eq!(vi(vi_key('e'), Normal), Edit::ViWordEnd);
        assert_eq!(vi(vi_key('b'), Normal), Edit::WordLeft);
        assert_eq!(vi(vi_key('0'), Normal), Edit::Home);
        assert_eq!(vi(vi_key('$'), Normal), Edit::End);
        assert_eq!(vi(vi_key('x'), Normal), Edit::DeleteRight);
        assert_eq!(vi(vi_key('X'), Normal), Edit::DeleteLeft);
        assert_eq!(vi(vi_key('D'), Normal), Edit::KillToEnd);
        assert_eq!(vi(vi_key('p'), Normal), Edit::Yank);
        assert_eq!(vi(vi_key('j'), Normal), Edit::HistoryNext);
        assert_eq!(vi(vi_key('k'), Normal), Edit::HistoryPrev);
        // A bare letter in Normal mode edits rather than inserting.
        assert_eq!(vi(vi_key('z'), Normal), Edit::Ignore);
    }

    #[test]
    fn vi_mode_switch_keys_enter_insert() {
        use ViMode::Normal;
        assert_eq!(vi(vi_key('i'), Normal), Edit::ViInsert);
        assert_eq!(vi(vi_key('a'), Normal), Edit::ViAppend);
        assert_eq!(vi(vi_key('I'), Normal), Edit::ViInsertHome);
        assert_eq!(vi(vi_key('A'), Normal), Edit::ViAppendEnd);
        assert_eq!(vi(vi_key('C'), Normal), Edit::ViChangeToEnd);
    }

    #[test]
    fn vi_insert_types_until_escape() {
        use ViMode::Insert;
        assert_eq!(vi(vi_key('x'), Insert), Edit::Insert('x'));
        assert_eq!(
            vi(key(KeyCode::Esc, KeyModifiers::NONE), Insert),
            Edit::ViNormal
        );
        assert_eq!(
            vi(key(KeyCode::Char('w'), KeyModifiers::CONTROL), Insert),
            Edit::Cut
        );
        assert_eq!(
            vi(key(KeyCode::Backspace, KeyModifiers::NONE), Insert),
            Edit::DeleteLeft
        );
    }

    #[test]
    fn vi_mode_transitions_move_and_switch() {
        // `a` appends: cursor steps right, mode becomes Insert.
        let mut s = state_with("ab", 0);
        s.keys = Keybindings::Vi;
        s.vi_mode = ViMode::Normal;
        edit(&mut s, Edit::ViAppend);
        assert_eq!((s.cursor, s.vi_mode), (1, ViMode::Insert));

        // `A` jumps to the end; `I` to the start.
        let mut s = state_with("hello", 2);
        edit(&mut s, Edit::ViAppendEnd);
        assert_eq!((s.cursor, s.vi_mode), (5, ViMode::Insert));
        edit(&mut s, Edit::ViNormal);
        edit(&mut s, Edit::ViInsertHome);
        assert_eq!((s.cursor, s.vi_mode), (0, ViMode::Insert));

        // `C` kills to the end (into the buffer) and enters Insert.
        let mut s = state_with("hello", 2);
        edit(&mut s, Edit::ViChangeToEnd);
        assert_eq!(
            (s.input.as_str(), s.kill.as_str(), s.vi_mode),
            ("he", "llo", ViMode::Insert)
        );
    }

    #[test]
    fn decode_dispatches_by_scheme() {
        // Native behaves as emacs.
        let mut s = State {
            keys: Keybindings::Native,
            ..State::default()
        };
        assert_eq!(
            decode(key(KeyCode::Char('a'), KeyModifiers::CONTROL), &s),
            Edit::Home
        );
        // Vi routes through the current sub-mode.
        s.keys = Keybindings::Vi;
        s.vi_mode = ViMode::Normal;
        assert_eq!(decode(vi_key('x'), &s), Edit::DeleteRight);
        s.vi_mode = ViMode::Insert;
        assert_eq!(decode(vi_key('x'), &s), Edit::Insert('x'));
    }

    /// Drive a sequence of (unmodified) character keys through the real vi
    /// decode→edit path, starting in Normal mode.
    fn vi_keys(input: &str, cursor: usize, chars: &str) -> State {
        let mut s = state_with(input, cursor);
        s.keys = Keybindings::Vi;
        s.vi_mode = ViMode::Normal;
        for ch in chars.chars() {
            let action = decode(vi_key(ch), &s);
            edit(&mut s, action);
        }
        s
    }

    #[test]
    fn vi_operator_pending_decodes_motions() {
        let pending = State {
            keys: Keybindings::Vi,
            vi_mode: ViMode::Operator(ViOp::Delete),
            ..State::default()
        };
        assert_eq!(
            decode(vi_key('d'), &state_normal()),
            Edit::ViOperator(ViOp::Delete)
        );
        assert_eq!(
            decode(vi_key('w'), &pending),
            Edit::ViMotionApply(ViMotion::WordFwd)
        );
        // The doubled operator means the whole line.
        assert_eq!(
            decode(vi_key('d'), &pending),
            Edit::ViMotionApply(ViMotion::WholeLine)
        );
        // An unknown motion cancels back to Normal.
        assert_eq!(decode(vi_key('z'), &pending), Edit::ViNormal);
    }

    fn state_normal() -> State {
        State {
            keys: Keybindings::Vi,
            vi_mode: ViMode::Normal,
            ..State::default()
        }
    }

    #[test]
    fn vi_delete_operator_spans_the_motion() {
        // dw deletes the word and its trailing space; db deletes back a word.
        let s = vi_keys("foo bar", 0, "dw");
        assert_eq!(
            (s.input.as_str(), s.cursor, s.kill.as_str()),
            ("bar", 0, "foo ")
        );
        let s = vi_keys("foo bar", 7, "db");
        assert_eq!((s.input.as_str(), s.kill.as_str()), ("foo ", "bar"));
        // d$ to end of line; dd the whole line.
        let s = vi_keys("hello world", 6, "d$");
        assert_eq!((s.input.as_str(), s.kill.as_str()), ("hello ", "world"));
        let s = vi_keys("hello", 2, "dd");
        assert_eq!((s.input.as_str(), s.kill.as_str()), ("", "hello"));
    }

    #[test]
    fn vi_change_word_acts_like_change_to_end() {
        // The classic quirk: `cw` stops at the word end (like `ce`), not the start
        // of the next word, so it leaves the trailing space — and enters Insert.
        let s = vi_keys("foo bar", 0, "cw");
        assert_eq!(
            (s.input.as_str(), s.kill.as_str(), s.vi_mode),
            (" bar", "foo", ViMode::Insert)
        );
    }

    #[test]
    fn vi_yank_copies_without_deleting() {
        let s = vi_keys("foo bar", 0, "yw");
        assert_eq!(s.input, "foo bar"); // unchanged
        assert_eq!(s.kill, "foo ");
        assert_eq!(s.vi_mode, ViMode::Normal);
    }

    #[test]
    fn vi_operator_then_escape_cancels() {
        let mut s = state_with("hello", 2);
        s.keys = Keybindings::Vi;
        s.vi_mode = ViMode::Normal;
        let enter = decode(vi_key('d'), &s); // enter operator-pending
        edit(&mut s, enter);
        assert_eq!(s.vi_mode, ViMode::Operator(ViOp::Delete));
        let escape = decode(key(KeyCode::Esc, KeyModifiers::NONE), &s);
        edit(&mut s, escape);
        assert_eq!((s.input.as_str(), s.vi_mode), ("hello", ViMode::Normal));
    }

    #[test]
    fn vi_word_motions_move_by_word() {
        // `w` lands on the start of the next word; `e` on the end of the word.
        let s = vi_keys("foo bar", 0, "w");
        assert_eq!(s.cursor, 4);
        let s = vi_keys("foo bar", 0, "e");
        assert_eq!(s.cursor, 2); // last char of "foo"
    }

    #[test]
    fn recall_lands_the_cursor_at_the_end() {
        let mut s = State {
            history: vec!["source x".into()],
            ..State::default()
        };
        edit(&mut s, Edit::HistoryPrev);
        assert_eq!((s.input.as_str(), s.cursor), ("source x", 8));
    }

    #[test]
    fn history_recall_steps_and_clears() {
        let mut state = State {
            history: vec!["a".into(), "b".into()],
            ..State::default()
        };
        recall(&mut state, -1); // first Up → newest
        assert_eq!(state.input, "b");
        recall(&mut state, -1); // older
        assert_eq!(state.input, "a");
        recall(&mut state, 1); // newer
        assert_eq!(state.input, "b");
        recall(&mut state, 1); // past newest → fresh empty line
        assert_eq!(state.input, "");
        assert_eq!(state.history_pos, None);
    }
}
