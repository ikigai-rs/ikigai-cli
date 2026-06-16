//! Native full-screen REPL built on `ratatui` + `crossterm`.
//!
//! A scrollback transcript above an input line. Each submitted line is evaluated
//! by the shared [`Engine`], so this is purely presentation — the same engine a
//! future `ratzilla` (browser) frontend would render. Keys: Enter submits,
//! Up/Down recall history, PgUp/PgDn scroll, Esc clears, Ctrl-C / Ctrl-D quit.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ikigai_core::Kernel;
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::engine::{Action, CacheStats, Engine, Entry, HELP};

/// How many transcript lines PgUp/PgDn move.
const SCROLL_STEP: u16 = 5;

/// Run the TUI to completion, restoring the terminal on the way out.
pub fn run(kernel: Kernel) -> io::Result<()> {
    let engine = Engine::new(kernel);
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &engine);
    ratatui::restore();
    result
}

/// Mutable UI state: the input buffer, the transcript, and input history.
#[derive(Default)]
struct State {
    input: String,
    transcript: Vec<Entry>,
    history: Vec<String>,
    /// Index into `history` while browsing with Up/Down; `None` = editing fresh.
    history_pos: Option<usize>,
    /// Lines scrolled up from the bottom; `0` = pinned to the latest output.
    scroll_back: u16,
}

fn event_loop(terminal: &mut DefaultTerminal, engine: &Engine) -> io::Result<()> {
    let mut state = State::default();
    loop {
        terminal.draw(|frame| draw(frame, &state))?;
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            match key.code {
                KeyCode::Char('c') | KeyCode::Char('d') if ctrl => return Ok(()),
                KeyCode::Char(c) if !ctrl => state.input.push(c),
                KeyCode::Backspace => {
                    state.input.pop();
                }
                KeyCode::Esc => state.input.clear(),
                KeyCode::Up => recall(&mut state, -1),
                KeyCode::Down => recall(&mut state, 1),
                KeyCode::PageUp => {
                    state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP)
                }
                KeyCode::PageDown => {
                    state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP)
                }
                // `submit` evaluates the line for its effects and reports whether
                // the REPL should quit; the bare arm catches the keep-going case.
                KeyCode::Enter if submit(&mut state, engine) => return Ok(()),
                KeyCode::Enter => {}
                _ => {}
            }
        }
    }
}

/// Evaluate the current input line; returns `true` if the REPL should quit.
fn submit(state: &mut State, engine: &Engine) -> bool {
    let line = std::mem::take(&mut state.input);
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
        "   (help · quit · ↑↓ history · PgUp/PgDn scroll · Ctrl-C exit)".dim(),
    ]);
    frame.render_widget(Paragraph::new(title), chunks[0]);

    let lines = transcript_lines(&state.transcript);
    let bottom = (lines.len() as u16).saturating_sub(chunks[1].height);
    let scroll_y = bottom.saturating_sub(state.scroll_back);
    frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);

    let input = Paragraph::new(state.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" request "));
    frame.render_widget(input, chunks[2]);
    // Place the cursor after the typed text (inside the 1-cell border).
    let cursor_x = chunks[2].x + 1 + state.input.chars().count() as u16;
    frame.set_cursor_position(Position::new(cursor_x, chunks[2].y + 1));
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
