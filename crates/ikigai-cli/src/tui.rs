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
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
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
    /// Active tab: `0` = the REPL, `1` = the Docs page (the catalog as text),
    /// `2..=demos.len()+1` = a runbook demo page. Only non-zero when the demo is on
    /// (tabs are shown).
    tab: usize,
    /// The runbook demos, lazily loaded the first time the demo turns on (sourced
    /// as `application/json`). Empty ⇒ no tab bar; the REPL renders as before.
    demos: Vec<DemoData>,
    /// Output of the last step run on the current demo page, shown beneath it.
    demo_out: String,
    /// The Docs page text — the kernel's own catalog (`urn:kernel:catalog`) as
    /// Turtle, the text analog of the browser demo's rendered Catalog page. Loaded
    /// alongside the demos when the demo turns on.
    docs: String,
    /// The Control page text — `urn:data:control` composed (scheduler + cache + time
    /// jobs), the text analog of the browser demo's Control page. Loaded with the demos.
    control: String,
    /// The tab-bar clock `HH:MM`, refreshed each frame from the cacheable `urn:time:now`
    /// (a cache hit within the minute — recomputes only on the minute). Empty until the
    /// first fetch. The colon blinks per second, computed at draw time.
    clock: String,
}

/// One step of a runbook demo, as carried by the `application/json` representation.
struct StepData {
    label: String,
    cmd: String,
    note: String,
}

/// A runbook demo page: its tab label, intro prose, and runnable steps. Parsed from
/// `source urn:runbook:<id> as=application/json`.
struct DemoData {
    label: String,
    intro: String,
    steps: Vec<StepData>,
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
    // Preload persisted command history when persistence is on — the flag is seeded
    // from the sticky on-disk marker, so ↑↓ recall spans prior sessions.
    if ikigai_embedded::history_flag().load(std::sync::atomic::Ordering::Relaxed) {
        state.history = ikigai_embedded::load_history();
    }
    loop {
        // The demo can be toggled at runtime (`demo on|off`, or over the wire via
        // `urn:host:demo`), so reconcile the tab bar with the flag each frame: load
        // the demos the first time it's on, drop them (and any open tab) when it's off.
        let demo_on = ikigai_embedded::demo_flag().load(std::sync::atomic::Ordering::Relaxed);
        if demo_on && state.demos.is_empty() {
            load_demos(&mut state, engine);
        } else if !demo_on && !state.demos.is_empty() {
            state.demos.clear();
            state.docs.clear();
            state.control.clear();
            state.tab = 0;
            state.demo_out.clear();
        }

        // Refresh the tab-bar clock from the cacheable urn:time:now — a cache hit within
        // the minute, so this is cheap every 250ms tick and only recomputes on the minute.
        state.clock = clock_text(engine);

        terminal.draw(|frame| draw(frame, &state))?;
        // Poll rather than block on input, so a demo toggle that arrives without a
        // keypress — `sink urn:host:demo on` over the wire — surfaces (or hides) the
        // tabs on the next tick instead of waiting for the user to press a key.
        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            // Ctrl-C always exits, on any tab (demo pages don't run the editor that
            // would otherwise decode it).
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                return Ok(());
            }
            // With tabs shown, Tab/BackTab cycle them regardless of which tab is up,
            // and a demo page is a browse view (number keys run steps; no text entry).
            if !state.demos.is_empty() {
                let n = state.demos.len() + 3; // REPL, Docs, Control, then one tab per demo
                match key.code {
                    KeyCode::Tab => {
                        state.tab = (state.tab + 1) % n;
                        state.demo_out.clear();
                        state.scroll_back = 0; // each tab opens fresh
                        continue;
                    }
                    KeyCode::BackTab => {
                        state.tab = (state.tab + n - 1) % n;
                        state.demo_out.clear();
                        state.scroll_back = 0;
                        continue;
                    }
                    _ => {}
                }
                if state.tab == 1 || state.tab == 2 {
                    // The Docs (1) and Control (2) tabs: scrollable text views
                    // (top-anchored), no text entry.
                    match key.code {
                        KeyCode::PageDown => {
                            state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP);
                        }
                        KeyCode::PageUp => {
                            state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP);
                        }
                        KeyCode::Esc => {
                            state.tab = 0;
                            state.scroll_back = 0;
                        }
                        _ => {}
                    }
                    continue;
                }
                if state.tab > 2 {
                    // A demo page is a browse view: number keys run steps, no text entry.
                    match key.code {
                        KeyCode::Char(c @ '1'..='9') => {
                            run_step(&mut state, engine, c as usize - '1' as usize);
                        }
                        // `0` runs the tenth step, so a ten-step demo (ZeroTrust) is
                        // fully reachable from the number row.
                        KeyCode::Char('0') => run_step(&mut state, engine, 9),
                        KeyCode::Esc => {
                            state.tab = 0;
                            state.demo_out.clear();
                        }
                        _ => {}
                    }
                    continue;
                }
            }
            // The REPL tab (or the demo off entirely): the normal line editor.
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

/// Load the runbook demos into `state` by enumerating `urn:runbook:*` and sourcing
/// each as `application/json`. Called the first time the demo turns on; a parse or
/// resolve failure simply skips that page rather than aborting the TUI.
fn load_demos(state: &mut State, engine: &Engine) {
    let Some(entries) = engine.entries() else {
        return;
    };
    for entry in entries {
        let Some(id) = entry.pattern.strip_prefix("urn:runbook:") else {
            continue;
        };
        let Action::Output(out) =
            engine.eval(&format!("source urn:runbook:{id} as=application/json"))
        else {
            continue;
        };
        let Ok(json) = out.result else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
            continue;
        };
        let steps = value["steps"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|s| StepData {
                        label: s["label"].as_str().unwrap_or_default().to_string(),
                        cmd: s["cmd"].as_str().unwrap_or_default().to_string(),
                        note: s["note"].as_str().unwrap_or_default().to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        state.demos.push(DemoData {
            label: value["label"].as_str().unwrap_or(id).to_string(),
            intro: value["intro"].as_str().unwrap_or_default().to_string(),
            steps,
        });
    }
    // The Docs tab: the kernel's own catalog rendered as text "cards" — every bound
    // endpoint, transrepted to RDF/XML and styled by the same XSLT the browser demo uses
    // for HTML cards (here with `method="text"`). Turtle all the way down, in the terminal.
    state.docs = match engine.eval(
        "source urn:kernel:catalog | urn:rdf:transrept as=application/rdf+xml \
         | urn:xslt:transform stylesheet=urn:style:catalog as=text/plain",
    ) {
        Action::Output(out) => out.result.unwrap_or_else(|e| format!("error: {e}")),
        _ => String::new(),
    };
    // The Control tab: the kernel control plane (scheduler + cache) as one composed
    // resource — `urn:data:control` is a compose shape whose two `$a{}` markers are the
    // sub-requests. The same resource the browser demo's Control page composes.
    state.control = match engine.eval("source urn:fn:compose src=urn:data:control") {
        Action::Output(out) => out.result.unwrap_or_else(|e| format!("error: {e}")),
        _ => String::new(),
    };
}

/// Run step `idx` of the demo on the current tab, capturing its output (or error)
/// into `demo_out` for display on the page.
fn run_step(state: &mut State, engine: &Engine, idx: usize) {
    // Demo tabs start at index 3 (after REPL, Docs, and Control).
    let Some(demo) = state.demos.get(state.tab.wrapping_sub(3)) else {
        return;
    };
    let Some(step) = demo.steps.get(idx) else {
        return;
    };
    let cmd = step.cmd.clone();
    let out = match engine.eval(&cmd) {
        // Append the cache outcome (computed / cached / …) after the output, so the
        // demo tab shows the caching story inline — parity with the web runbook.
        Action::Output(entry) => match entry.result {
            Ok(text) => {
                let tag = entry
                    .cache
                    .label()
                    .map(|l| format!("   [{l}]"))
                    .unwrap_or_default();
                format!("{text}{tag}")
            }
            Err(e) => format!("error: {e}"),
        },
        Action::Help => HELP.to_string(),
        Action::Clear => {
            state.transcript.clear();
            String::new()
        }
        Action::Quit | Action::Noop => String::new(),
    };
    state.demo_out = format!("$ {cmd}\n{out}");
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
        // Persist across sessions when history is on (a no-op otherwise).
        ikigai_embedded::append_history(&line);
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

/// The current `HH:MM` from the cacheable `urn:time:now` (plain variant), or empty on
/// error. Sourced through the engine so the tab-bar clock is a real resolved resource
/// (cached within the minute), not a direct clock read.
fn clock_text(engine: &Engine) -> String {
    match engine.eval("source urn:time:now") {
        Action::Output(out) => out.result.unwrap_or_default().trim().to_string(),
        _ => String::new(),
    }
}

/// The clock as styled spans `HH : MM` with the colon blinked per second (shown in the
/// first half of each second, dimmed in the second half — computed from the wall clock,
/// so it's aligned to real seconds regardless of the 250ms redraw tick). Empty input
/// (no fetch yet) renders nothing.
fn clock_spans(clock: &str) -> Vec<Span<'static>> {
    let Some((h, m)) = clock.split_once(':') else {
        return vec![clock.to_string().into()];
    };
    let colon_on = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis() < 500)
        .unwrap_or(true);
    let colon = if colon_on { ":" } else { " " };
    vec![
        h.to_string().cyan().bold(),
        colon.cyan().bold(),
        m.to_string().cyan().bold(),
    ]
}

fn draw(frame: &mut Frame, state: &State) {
    // The tab strip is two rows when the demo tabs are shown (core tabs + clock on top,
    // the ~dozen demo tabs wrapped below) — one row otherwise (title + clock).
    let tab_rows = if state.demos.is_empty() { 1 } else { 2 };
    let chunks = Layout::vertical([
        Constraint::Length(tab_rows), // title/tab strip (+ demo-tab row) with the clock
        Constraint::Min(1),           // transcript, or a demo page
        Constraint::Length(3),        // input box, or a demo-page hint
    ])
    .split(frame.area());

    // Reserve a fixed-width cell on the FAR RIGHT of the first row for the clock; the
    // tabs/title take the rest. (The clock lives on row 1 only; demo tabs wrap to row 2.)
    let first_row = Rect {
        height: 1,
        ..chunks[0]
    };
    let top = Layout::horizontal([Constraint::Min(1), Constraint::Length(7)]).split(first_row);
    frame.render_widget(
        Paragraph::new(Line::from(clock_spans(&state.clock))).alignment(Alignment::Right),
        top[1],
    );

    if state.demos.is_empty() {
        // No demo tabs: the usual title/help line (left of the clock).
        let title = Line::from(vec![
            format!("ikigai {} ", env!("CARGO_PKG_VERSION")).bold(),
            "— REPL".into(),
            format!(
                "  (help · demo on → tabs · ↑↓ history · {} · PgUp/PgDn · Ctrl-C)",
                mode_label(state)
            )
            .dim(),
        ]);
        frame.render_widget(Paragraph::new(title), top[0]);
    } else {
        // Row 1: the core tabs (REPL/Docs/Control), left of the clock.
        let core = Tabs::new(vec![
            Line::from("REPL"),
            Line::from("Docs"),
            Line::from("Control"),
        ])
        .select(if state.tab < 3 { state.tab } else { 3 }) // 3 = out of range ⇒ no highlight
        .highlight_style(Style::new().reversed())
        .divider("  ");
        frame.render_widget(core, top[0]);

        // Row 2: the demo tabs, wrapped onto their own full-width line — only when the
        // top strip actually has a second row (a degenerately short terminal may not).
        if chunks[0].height >= 2 {
            let demo_row = Rect {
                y: chunks[0].y + 1,
                height: 1,
                ..chunks[0]
            };
            let demo_titles: Vec<Line> = state
                .demos
                .iter()
                .map(|d| Line::from(d.label.clone()))
                .collect();
            let demo_tabs = Tabs::new(demo_titles)
                .select(if state.tab >= 3 {
                    state.tab - 3
                } else {
                    state.demos.len() // out of range ⇒ no highlight
                })
                .highlight_style(Style::new().reversed())
                .divider(" ");
            frame.render_widget(demo_tabs, demo_row);
        }
    }

    // Main area: REPL transcript on tab 0, the Docs page on tab 1, a demo page beyond.
    if state.tab == 0 {
        let lines = transcript_lines(&state.transcript);
        let bottom = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = bottom.saturating_sub(state.scroll_back);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if state.tab == 1 {
        // Docs: top-anchored, `scroll_back` is the offset down from the top.
        let lines = docs_lines(&state.docs);
        let max = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = state.scroll_back.min(max);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if state.tab == 2 {
        // Control: the composed scheduler + cache readout, top-anchored like Docs.
        let lines = control_lines(&state.control);
        let max = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = state.scroll_back.min(max);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if let Some(demo) = state.demos.get(state.tab - 3) {
        let page = Paragraph::new(demo_lines(demo, &state.demo_out)).wrap(Wrap { trim: false });
        frame.render_widget(page, chunks[1]);
    }

    // Bottom row: the editable request line on the REPL tab; a static hint on the
    // Docs page (scroll-only) and on a demo page (browse-only — keys run steps).
    if state.tab == 0 {
        let input = Paragraph::new(state.input.as_str())
            .block(Block::default().borders(Borders::ALL).title(" request "));
        frame.render_widget(input, chunks[2]);
        // Place the cursor at its column — the display width before it — inside the
        // 1-cell border, clamped so a long line can't draw past the box.
        let col = state.input[..state.cursor].chars().count() as u16;
        let cursor_x = (chunks[2].x + 1 + col).min(chunks[2].x + chunks[2].width.saturating_sub(1));
        frame.set_cursor_position(Position::new(cursor_x, chunks[2].y + 1));
    } else if state.tab == 1 || state.tab == 2 {
        let title = if state.tab == 1 {
            " docs "
        } else {
            " control "
        };
        let hint = Paragraph::new(
            "PgUp/PgDn scroll · Tab/⇧Tab switch · Esc back to REPL · Ctrl-C exit".dim(),
        )
        .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(hint, chunks[2]);
    } else {
        let hint = Paragraph::new(
            "1–9 run a step · Tab/⇧Tab switch · Esc back to REPL · Ctrl-C exit".dim(),
        )
        .block(Block::default().borders(Borders::ALL).title(" runbook "));
        frame.render_widget(hint, chunks[2]);
    }
}

/// Render the Docs page: a header naming the resource, then the catalog text (Turtle).
fn docs_lines(docs: &str) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("the catalog · every bound endpoint, as cards".bold()),
        Line::from("urn:kernel:catalog | urn:rdf:transrept as=rdf/xml | urn:xslt:transform".cyan()),
        Line::from(""),
    ];
    if docs.trim().is_empty() {
        lines.push(Line::from("(catalog unavailable)".dim()));
    } else {
        // Each card line is bordered with `│`. A title line is `│ <title>` (one space);
        // detail lines are `│   <…>` (three) and the separator is a bare `│`. Highlight
        // the titles, dim the rest, for hierarchy.
        for l in docs.lines() {
            let is_title = l.starts_with("│ ") && !l.starts_with("│  ");
            if is_title {
                lines.push(Line::from(l.to_string().cyan().bold()));
            } else {
                lines.push(Line::from(l.to_string().dim()));
            }
        }
    }
    lines
}

/// Render the Control page: a header, then the composed scheduler + cache readout.
/// Section headers (`scheduler`, `cache` — flush-left, no leading space) are
/// highlighted; the indented detail rows are dimmed.
fn control_lines(control: &str) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(
            "the control plane · scheduler + cache + time jobs, one composed resource".bold(),
        ),
        Line::from("source urn:fn:compose src=urn:data:control".cyan()),
        Line::from(""),
    ];
    if control.trim().is_empty() {
        lines.push(Line::from("(control plane unavailable)".dim()));
    } else {
        for l in control.lines() {
            // A readout section header is flush-left and non-empty; detail rows are
            // indented (the kernel renders `  label  value`).
            let is_header = !l.is_empty() && !l.starts_with(' ') && !l.starts_with("urn:");
            if is_header {
                lines.push(Line::from(l.to_string().cyan().bold()));
            } else {
                lines.push(Line::from(l.to_string().dim()));
            }
        }
    }
    lines
}

/// Render a demo page as styled lines: the intro, the numbered runnable steps (each
/// with its command and note), and the most recent step's output beneath them.
fn demo_lines(demo: &DemoData, out: &str) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(demo.intro.clone()),
        Line::from(""),
        Line::from("steps:".bold()),
    ];
    for (i, step) in demo.steps.iter().enumerate() {
        // The leading digit IS the key that runs the step: 1–9, then 0 for a tenth.
        let key = if i < 9 { (b'1' + i as u8) as char } else { '0' };
        lines.push(Line::from(vec![
            format!("  {key}. ").bold(),
            step.label.clone().bold(),
        ]));
        lines.push(Line::from(format!("     {}", step.cmd).cyan()));
        lines.push(Line::from(format!("     — {}", step.note).dim()));
    }
    if !out.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("─ output ─".dim()));
        for l in out.lines() {
            lines.push(Line::from(l.to_string().green()));
        }
    }
    lines
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

    // With demos loaded, `draw` renders the tab strip plus either the transcript
    // (REPL tab) or a demo page (a demo tab, with and without step output).
    #[test]
    fn draws_demo_tabs_without_panicking() {
        let mut state = State::default();
        state.demos.push(DemoData {
            label: "Basics".into(),
            intro: "A resource is resolved by name; functions are resources too.".into(),
            steps: vec![
                StepData {
                    label: "uppercase".into(),
                    cmd: "source urn:fn:toUpper hello".into(),
                    note: "a function resource".into(),
                },
                StepData {
                    label: "pipe".into(),
                    cmd: "source urn:fn:toUpper hi | urn:demo:wrap".into(),
                    note: "pipe output into the next stage".into(),
                },
            ],
        });

        state.docs = "│ urn:fn:toUpper\n│   a function resource".into();
        state.control =
            "scheduler\n  backend    single\n  threads    1\ncache\n  entries  3".into();

        state.tab = 0; // tab strip shown, REPL transcript beneath
        render(80, 24, &state);
        render(1, 1, &state); // degenerate size with tabs present

        state.tab = 1; // Docs page
        render(80, 24, &state);

        state.tab = 2; // Control page (scheduler + cache readout)
        render(80, 24, &state);

        state.tab = 3; // the demo page (demos now start at index 3), no step run yet
        render(80, 24, &state);

        state.demo_out = "$ source urn:fn:toUpper hello\nHELLO".into();
        render(80, 24, &state); // demo page with output
        render(20, 6, &state); // narrow → intro wraps, output scrolls
    }

    // The tab bar is two rows when demos are shown: core tabs + clock (far right) on
    // row 0, the demo tabs wrapped onto row 1.
    #[test]
    fn clock_top_right_and_demo_tabs_wrap_to_row_two() {
        let mut state = State {
            clock: "12:34".into(),
            ..State::default()
        };
        for label in ["Basics", "Piping", "HTTP"] {
            state.demos.push(DemoData {
                label: label.into(),
                intro: String::new(),
                steps: vec![],
            });
        }
        let mut terminal = Terminal::new(TestBackend::new(60, 10)).unwrap();
        terminal.draw(|f| draw(f, &state)).unwrap();
        let buf = terminal.backend().buffer();
        let row = |y: u16| -> String { (0..60).map(|x| buf[(x, y)].symbol()).collect() };
        let (row0, row1) = (row(0), row(1));
        // Core tabs + the clock digits on the top row (the colon may be blinked to a space).
        assert!(
            row0.contains("REPL") && row0.contains("Control"),
            "core tabs: {row0:?}"
        );
        assert!(
            row0.contains("12") && row0.trim_end().ends_with("34"),
            "clock far right: {row0:?}"
        );
        // Demo tabs wrapped onto the second row (not on row 0 with the core tabs).
        assert!(
            row1.contains("Basics") && row1.contains("Piping"),
            "demo tabs row1: {row1:?}"
        );
        assert!(!row0.contains("Basics"), "demo tabs NOT on row0: {row0:?}");
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
