//! Native full-screen REPL built on `ratatui` + `crossterm`.
//!
//! A scrollback transcript above an editable input line. Each submitted line is
//! evaluated by the shared [`Engine`], so this is purely presentation — the same
//! engine a future `ratzilla` (browser) frontend would render.
//!
//! The input line is a real editor: a cursor moves through the text and the keys
//! are decoded by the configured [`Keybindings`] scheme (Emacs today). See
//! [`emacs`] for the bindings; Enter submits, PgUp/PgDn scroll the transcript,
//! Ctrl-C quits.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ikigai_core::Kernel;
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::config::Keybindings;
use crate::engine::{Action, CacheStats, Engine, Entry, HELP};

/// How many transcript lines PgUp/PgDn move.
const SCROLL_STEP: u16 = 5;

/// Run the TUI to completion, restoring the terminal on the way out.
pub fn run(kernel: Kernel, keys: Keybindings) -> io::Result<()> {
    let engine = Engine::new(kernel);
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
    KillToEnd,    // delete from the cursor to the end of the line
    KillToStart,  // delete from the start of the line to the cursor
    KillWordLeft, // delete the word before the cursor
    HistoryPrev,
    HistoryNext,
    ScrollUp,
    ScrollDown,
    Clear, // empty the line
    Submit,
    Quit,
    Ignore,
}

/// Mutable UI state: the input buffer and cursor, the transcript, and history.
#[derive(Default)]
struct State {
    input: String,
    /// Byte offset of the cursor within `input`, always on a `char` boundary.
    cursor: usize,
    keys: Keybindings,
    transcript: Vec<Entry>,
    history: Vec<String>,
    /// Index into `history` while browsing with Up/Down; `None` = editing fresh.
    history_pos: Option<usize>,
    /// Lines scrolled up from the bottom; `0` = pinned to the latest output.
    scroll_back: u16,
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
            match decode(state.keys, key, state.input.is_empty()) {
                Edit::Quit => return Ok(()),
                // `submit` evaluates the line and reports whether to quit.
                Edit::Submit if submit(&mut state, engine) => return Ok(()),
                Edit::Submit => {}
                action => edit(&mut state, action),
            }
        }
    }
}

/// Decode a key press into an [`Edit`] under the active scheme. `input_empty`
/// lets a scheme make a key context-sensitive (Emacs `Ctrl-D` = quit on an empty
/// line, delete-forward otherwise).
fn decode(keys: Keybindings, key: KeyEvent, input_empty: bool) -> Edit {
    match keys {
        Keybindings::Emacs => emacs(key, input_empty),
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
        KeyCode::Char('w') if ctrl => Edit::KillWordLeft,
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

/// Apply a line-editing action to the state. `Submit`/`Quit` are handled by the
/// caller (control flow); everything else mutates the buffer, cursor, history
/// browsing, or scrollback here.
fn edit(state: &mut State, action: Edit) {
    match action {
        Edit::Insert(c) => {
            state.input.insert(state.cursor, c);
            state.cursor += c.len_utf8();
        }
        Edit::DeleteLeft => {
            if state.cursor > 0 {
                let from = prev_boundary(&state.input, state.cursor);
                state.input.replace_range(from..state.cursor, "");
                state.cursor = from;
            }
        }
        Edit::DeleteRight => {
            let to = next_boundary(&state.input, state.cursor);
            state.input.replace_range(state.cursor..to, "");
        }
        Edit::Left => state.cursor = prev_boundary(&state.input, state.cursor),
        Edit::Right => state.cursor = next_boundary(&state.input, state.cursor),
        Edit::WordLeft => state.cursor = word_left(&state.input, state.cursor),
        Edit::WordRight => state.cursor = word_right(&state.input, state.cursor),
        Edit::Home => state.cursor = 0,
        Edit::End => state.cursor = state.input.len(),
        Edit::KillToEnd => state.input.truncate(state.cursor),
        Edit::KillToStart => {
            state.input.replace_range(0..state.cursor, "");
            state.cursor = 0;
        }
        Edit::KillWordLeft => {
            let from = word_left(&state.input, state.cursor);
            state.input.replace_range(from..state.cursor, "");
            state.cursor = from;
        }
        Edit::HistoryPrev => recall(state, -1),
        Edit::HistoryNext => recall(state, 1),
        Edit::ScrollUp => state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP),
        Edit::ScrollDown => state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP),
        Edit::Clear => {
            state.input.clear();
            state.cursor = 0;
        }
        Edit::Submit | Edit::Quit | Edit::Ignore => {}
    }
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
            "   (help · quit · ↑↓ history · {} keys · PgUp/PgDn scroll · Ctrl-C exit)",
            keymap_name(state.keys)
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

/// The active scheme's short name, shown in the title hint.
fn keymap_name(keys: Keybindings) -> &'static str {
    match keys {
        Keybindings::Emacs => "emacs",
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
    fn kills_to_end_start_and_word() {
        let mut s = state_with("foo bar baz", 8);
        edit(&mut s, Edit::KillToEnd);
        assert_eq!(s.input, "foo bar ");

        let mut s = state_with("foo bar", 4);
        edit(&mut s, Edit::KillToStart);
        assert_eq!((s.input.as_str(), s.cursor), ("bar", 0));

        let mut s = state_with("foo bar", 7);
        edit(&mut s, Edit::KillWordLeft);
        assert_eq!((s.input.as_str(), s.cursor), ("foo ", 4));
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
    fn emacs_ctrl_d_is_eof_only_on_an_empty_line() {
        let c = KeyModifiers::CONTROL;
        assert_eq!(emacs(key(KeyCode::Char('d'), c), true), Edit::Quit);
        assert_eq!(emacs(key(KeyCode::Char('d'), c), false), Edit::DeleteRight);
        assert_eq!(emacs(key(KeyCode::Char('c'), c), false), Edit::Quit);
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
