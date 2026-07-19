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
//!
//! A "Scratch (Lisp)" tab (reached with Tab/BackTab) hosts a multi-line buffer that
//! evaluates arbitrary Lisp through the engine's `urn:lisp:eval` path. There, **F5** is
//! the reliable eval key (`Ctrl-Enter`/`Alt-Enter` also work where the terminal reports
//! the modifier; under emacs `C-c C-c` is a chord), and Enter inserts a newline. The
//! same shared editor core ([`edit_text`]) drives both the input line and this buffer.

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

// Tab indices in the always-present tab strip. REPL and Scratch are always shown;
// Docs, Control, and the per-runbook demo pages join only while the demo is on.
const TAB_REPL: usize = 0;
const TAB_SCRATCH: usize = 1;
const TAB_DOCS: usize = 2;
const TAB_CONTROL: usize = 3;
const TAB_DEMO_BASE: usize = 4;

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
    /// The persistent multi-line Lisp scratch buffer (the "Scratch (Lisp)" tab). A
    /// single `String` with `\n`s — the same representation as `input`, so the shared
    /// [`edit_text`] core drives it unchanged; only vertical line motion, line-relative
    /// Home/End, and Enter-inserts-a-newline differ (handled in [`scratch_edit`]).
    scratch: String,
    /// Byte offset of the cursor within `scratch`, always on a `char` boundary.
    scratch_cursor: usize,
    /// The scratch buffer's mark (a byte offset); with the cursor it bounds the region
    /// an eval submits (the whole buffer when unset).
    scratch_mark: Option<usize>,
    /// The most recent scratch evaluation's result, shown beneath the buffer (also
    /// pushed to the transcript). `None` until the first eval.
    scratch_result: Option<Result<String, String>>,
    /// Whether a first emacs `C-c` is armed, awaiting the second to evaluate the buffer
    /// (`C-c C-c`). Set only in the Scratch tab under the emacs scheme.
    scratch_cc: bool,
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
    /// The number of tabs in the strip: REPL and Scratch always, plus Docs, Control,
    /// and one page per runbook demo while the demo is on.
    fn tab_count(&self) -> usize {
        if self.demos.is_empty() {
            2
        } else {
            TAB_DEMO_BASE + self.demos.len()
        }
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
    // The eval-driven readouts (clock + Control tab) refresh at ~1s, not every 250ms
    // draw — the colon blink is computed at draw time, so drawing stays at the full
    // frame rate while these (and their scheduler fan-out) tick just once a second.
    let mut last_refresh: Option<std::time::Instant> = None;
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
            // Docs/Control/demo pages just went away; fall back to REPL if one was up.
            if state.tab >= state.tab_count() {
                state.tab = TAB_REPL;
            }
            state.demo_out.clear();
        }

        // Once a second (not every 250ms draw): refresh the tab-bar clock from the
        // cacheable urn:time:now, and — the CLI analog of the browser's htmx self-refresh
        // — re-compose the Control tab so its scheduler/cache/time-jobs readouts (the
        // clock timer and any greeter timer) tick instead of freezing. Throttling this to
        // 1s (vs every frame) keeps the compose fan-out from spinning the scheduler ~4×/s
        // just to display itself; the colon blink is unaffected (it's computed at draw).
        if last_refresh.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(1)) {
            state.clock = clock_text(engine);
            if state.tab == TAB_CONTROL {
                if let Action::Output(out) =
                    engine.eval("source urn:fn:compose src=urn:data:control")
                {
                    state.control = out.result.unwrap_or_else(|e| format!("error: {e}"));
                }
            }
            last_refresh = Some(std::time::Instant::now());
        }

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
            // Tab/BackTab cycle the always-present tab strip (REPL · Scratch, plus
            // Docs · Control · the demo pages while the demo is on).
            match key.code {
                KeyCode::Tab => {
                    state.tab = (state.tab + 1) % state.tab_count();
                    state.demo_out.clear();
                    state.scroll_back = 0; // each tab opens fresh
                    continue;
                }
                KeyCode::BackTab => {
                    let n = state.tab_count();
                    state.tab = (state.tab + n - 1) % n;
                    state.demo_out.clear();
                    state.scroll_back = 0;
                    continue;
                }
                _ => {}
            }
            // Ctrl-C exits on every tab EXCEPT Scratch, where the editor owns it (the
            // emacs `C-c C-c` eval chord; a lone Ctrl-C under vi still quits, handled
            // inside `scratch_key`).
            if key.code == KeyCode::Char('c')
                && key.modifiers.contains(KeyModifiers::CONTROL)
                && state.tab != TAB_SCRATCH
            {
                return Ok(());
            }
            match state.tab {
                TAB_SCRATCH => {
                    if scratch_key(&mut state, engine, key) {
                        return Ok(());
                    }
                }
                TAB_DOCS | TAB_CONTROL => {
                    // Scrollable text views (top-anchored), no text entry.
                    match key.code {
                        KeyCode::PageDown => {
                            state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP);
                        }
                        KeyCode::PageUp => {
                            state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP);
                        }
                        KeyCode::Esc => {
                            state.tab = TAB_REPL;
                            state.scroll_back = 0;
                        }
                        _ => {}
                    }
                }
                t if t >= TAB_DEMO_BASE => {
                    // A demo page is a browse view: number keys run steps, no text entry.
                    match key.code {
                        KeyCode::Char(c @ '1'..='9') => {
                            run_step(&mut state, engine, c as usize - '1' as usize);
                        }
                        // `0` runs the tenth step, so a ten-step demo (ZeroTrust) is
                        // fully reachable from the number row.
                        KeyCode::Char('0') => run_step(&mut state, engine, 9),
                        KeyCode::Esc => {
                            state.tab = TAB_REPL;
                            state.demo_out.clear();
                        }
                        _ => {}
                    }
                }
                _ => {
                    // The REPL tab: the normal line editor.
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
    decode_line(key, state.keys, state.vi_mode, state.input.is_empty())
}

/// Decode a key under an explicit scheme/mode/emptiness — the scheme-dispatch core
/// shared by the REPL line ([`decode`]) and the Scratch buffer ([`scratch_key`]).
fn decode_line(key: KeyEvent, keys: Keybindings, vi_mode: ViMode, input_empty: bool) -> Edit {
    match keys {
        // `Native` is the platform's terminal default, which is Emacs everywhere.
        Keybindings::Emacs | Keybindings::Native => emacs(key, input_empty),
        Keybindings::Vi => vi(key, vi_mode),
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

/// Apply a line-editing action to the REPL input line. History recall, scrollback,
/// and clearing the line are REPL-specific; every text edit is delegated to the
/// shared [`edit_text`] core (so the REPL line and the Scratch buffer edit
/// identically). Pure (no I/O) so it is fully testable; clipboard sync lives in
/// [`apply`].
fn edit(state: &mut State, action: Edit) {
    match action {
        Edit::HistoryPrev => recall(state, -1),
        Edit::HistoryNext => recall(state, 1),
        Edit::ScrollUp => state.scroll_back = state.scroll_back.saturating_add(SCROLL_STEP),
        Edit::ScrollDown => state.scroll_back = state.scroll_back.saturating_sub(SCROLL_STEP),
        Edit::Clear => {
            state.input.clear();
            state.cursor = 0;
            state.mark = None;
        }
        other => edit_text(
            &mut state.input,
            &mut state.cursor,
            &mut state.mark,
            &mut state.kill,
            &mut state.vi_mode,
            other,
        ),
    }
}

/// The one editor core: apply a text-editing action to a `(text, cursor, mark)`
/// buffer, using `kill` as the shared kill-ring and `vi_mode` for the modal ops. Both
/// the single-line REPL input and the multi-line Scratch buffer call it, so
/// char/word/kill/yank/mark and the vi operators behave identically in each. `Home`/
/// `End` are line-relative (start/end of the cursor's line) — for the single-line REPL
/// that is simply the whole line. The callers handle the non-text actions (history,
/// scroll, vertical line motion, submit).
fn edit_text(
    text: &mut String,
    cursor: &mut usize,
    mark: &mut Option<usize>,
    kill: &mut String,
    vi_mode: &mut ViMode,
    action: Edit,
) {
    // Any edit to the text invalidates the mark (its byte offset would shift);
    // movement and the mark/copy/cut commands manage it themselves.
    match action {
        Edit::Insert(c) => {
            text.insert(*cursor, c);
            *cursor += c.len_utf8();
            *mark = None;
        }
        Edit::DeleteLeft => {
            if *cursor > 0 {
                let from = prev_boundary(text, *cursor);
                text.replace_range(from..*cursor, "");
                *cursor = from;
            }
            *mark = None;
        }
        Edit::DeleteRight => {
            let to = next_boundary(text, *cursor);
            text.replace_range(*cursor..to, "");
            *mark = None;
        }
        Edit::Left => *cursor = prev_boundary(text, *cursor),
        Edit::Right => *cursor = next_boundary(text, *cursor),
        Edit::WordLeft => *cursor = word_left(text, *cursor),
        Edit::WordRight => *cursor = word_right(text, *cursor),
        Edit::Home => *cursor = line_start(text, *cursor),
        Edit::End => *cursor = line_end(text, *cursor),
        Edit::KillToEnd => {
            let hi = line_end(text, *cursor);
            kill_range(text, cursor, mark, kill, *cursor, hi);
        }
        Edit::KillToStart => {
            let lo = line_start(text, *cursor);
            kill_range(text, cursor, mark, kill, lo, *cursor);
        }
        Edit::SetMark => *mark = Some(*cursor),
        Edit::Copy => {
            if let Some((lo, hi)) = region(text, *cursor, *mark) {
                *kill = text[lo..hi].to_string();
            }
            *mark = None;
        }
        Edit::Cut => match region(text, *cursor, *mark) {
            Some((lo, hi)) => kill_range(text, cursor, mark, kill, lo, hi),
            // No region: cut the previous word (readline `Ctrl-W`).
            None => {
                let lo = word_left(text, *cursor);
                kill_range(text, cursor, mark, kill, lo, *cursor);
            }
        },
        Edit::Yank => {
            let yanked = kill.clone();
            text.insert_str(*cursor, &yanked);
            *cursor += yanked.len();
            *mark = None;
        }
        Edit::ViInsert => *vi_mode = ViMode::Insert,
        Edit::ViNormal => *vi_mode = ViMode::Normal,
        Edit::ViAppend => {
            *cursor = next_boundary(text, *cursor);
            *vi_mode = ViMode::Insert;
        }
        Edit::ViInsertHome => {
            *cursor = line_start(text, *cursor);
            *vi_mode = ViMode::Insert;
        }
        Edit::ViAppendEnd => {
            *cursor = line_end(text, *cursor);
            *vi_mode = ViMode::Insert;
        }
        Edit::ViChangeToEnd => {
            let hi = line_end(text, *cursor);
            kill_range(text, cursor, mark, kill, *cursor, hi);
            *vi_mode = ViMode::Insert;
        }
        Edit::ViWordFwd => *cursor = vi_word_forward(text, *cursor),
        Edit::ViWordEnd => *cursor = vi_word_end(text, *cursor),
        Edit::ViOperator(op) => *vi_mode = ViMode::Operator(op),
        Edit::ViMotionApply(motion) => {
            if let ViMode::Operator(op) = *vi_mode {
                let (lo, hi) = vi_range(text, *cursor, op, motion);
                match op {
                    ViOp::Delete => {
                        kill_range(text, cursor, mark, kill, lo, hi);
                        *vi_mode = ViMode::Normal;
                    }
                    ViOp::Change => {
                        kill_range(text, cursor, mark, kill, lo, hi);
                        *vi_mode = ViMode::Insert;
                    }
                    ViOp::Yank => {
                        *kill = text[lo..hi].to_string();
                        *cursor = lo;
                        *mark = None;
                        *vi_mode = ViMode::Normal;
                    }
                }
            }
        }
        // Non-text actions are handled by the callers (`edit` / `scratch_edit`).
        Edit::HistoryPrev
        | Edit::HistoryNext
        | Edit::ScrollUp
        | Edit::ScrollDown
        | Edit::Clear
        | Edit::Submit
        | Edit::Quit
        | Edit::Ignore => {}
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

/// Move the byte range `lo..hi` of `text` into `kill`, leaving the cursor at `lo` and
/// clearing the mark. The range must be on `char` boundaries.
fn kill_range(
    text: &mut String,
    cursor: &mut usize,
    mark: &mut Option<usize>,
    kill: &mut String,
    lo: usize,
    hi: usize,
) {
    *kill = text[lo..hi].to_string();
    text.replace_range(lo..hi, "");
    *cursor = lo;
    *mark = None;
}

/// The active region of a `(text, cursor, mark)` buffer as sorted byte offsets, or
/// `None` when no mark is set. The mark is clamped to the current length, defending
/// against a stale offset even though edits clear it.
fn region(text: &str, cursor: usize, mark: Option<usize>) -> Option<(usize, usize)> {
    let mark = mark?.min(text.len());
    Some((mark.min(cursor), mark.max(cursor)))
}

/// Byte offset of the start of the line containing `cursor` (just after the previous
/// `\n`, or `0` on the first line).
fn line_start(s: &str, cursor: usize) -> usize {
    s[..cursor].rfind('\n').map_or(0, |i| i + 1)
}

/// Byte offset of the end of the line containing `cursor` (the next `\n`, or the end
/// of the text on the last line).
fn line_end(s: &str, cursor: usize) -> usize {
    s[cursor..].find('\n').map_or(s.len(), |i| cursor + i)
}

/// Move the cursor up one line, keeping the same visual column (clamped to the shorter
/// line). Stays put on the first line.
fn line_up(s: &str, cursor: usize) -> usize {
    let start = line_start(s, cursor);
    if start == 0 {
        return cursor;
    }
    let col = s[start..cursor].chars().count();
    let prev_start = line_start(s, start - 1);
    byte_at_col(s, prev_start, start - 1, col)
}

/// Move the cursor down one line, keeping the same visual column. Stays put on the
/// last line.
fn line_down(s: &str, cursor: usize) -> usize {
    let end = line_end(s, cursor);
    if end == s.len() {
        return cursor;
    }
    let col = s[line_start(s, cursor)..cursor].chars().count();
    let next_start = end + 1;
    byte_at_col(s, next_start, line_end(s, next_start), col)
}

/// The byte offset `col` characters into the line `start..end`, clamped to `end`.
fn byte_at_col(s: &str, start: usize, end: usize, col: usize) -> usize {
    let mut i = start;
    for _ in 0..col {
        if i >= end {
            break;
        }
        i = next_boundary(s, i);
    }
    i.min(end)
}

/// The cursor's zero-based `(row, column)` in the buffer — row is the count of
/// newlines before it, column the characters since the line start. Used to place the
/// terminal cursor in the multi-line Scratch view.
fn cursor_row_col(s: &str, cursor: usize) -> (u16, u16) {
    let row = s[..cursor].matches('\n').count() as u16;
    let col = s[line_start(s, cursor)..cursor].chars().count() as u16;
    (row, col)
}

/// The text a Scratch evaluation submits: the marked region if a (non-empty) mark is
/// set, else the whole buffer. Pure, so the region logic is testable without an engine.
fn scratch_eval_src(text: &str, cursor: usize, mark: Option<usize>) -> String {
    match region(text, cursor, mark) {
        Some((lo, hi)) if hi > lo => text[lo..hi].to_string(),
        _ => text.to_string(),
    }
}

/// Handle a key press while the Scratch (Lisp) tab is active; returns `true` if the
/// editor should quit. Eval bindings are checked first — `Ctrl-Enter` / `Alt-Enter`
/// (either scheme) and the emacs `C-c C-c` chord — then the key is decoded by the
/// active scheme and applied to the buffer, with `Enter` alone inserting a newline
/// (this is an editor, not the REPL input line).
fn scratch_key(state: &mut State, engine: &Engine, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let emacs = matches!(state.keys, Keybindings::Emacs | Keybindings::Native);

    // F5 is the reliable, scheme-independent eval key: unlike Ctrl-Enter/Alt-Enter it
    // carries no modifier a terminal might drop, so it works everywhere on both schemes.
    if key.code == KeyCode::F(5) {
        state.scratch_cc = false;
        eval_scratch(state, engine);
        return false;
    }
    // Ctrl-Enter / Alt-Enter also evaluate on either scheme, where the terminal reports
    // the modifier on Enter; otherwise fall back to F5 (or the emacs `C-c C-c` chord).
    if key.code == KeyCode::Enter && (ctrl || alt) {
        state.scratch_cc = false;
        eval_scratch(state, engine);
        return false;
    }
    // Emacs `C-c C-c`: the first Ctrl-C arms, the second evaluates. In the Scratch tab
    // Ctrl-C is this chord (not quit) under the emacs scheme.
    if emacs && ctrl && key.code == KeyCode::Char('c') {
        if state.scratch_cc {
            state.scratch_cc = false;
            eval_scratch(state, engine);
        } else {
            state.scratch_cc = true;
        }
        return false;
    }
    // Any other key disarms a half-entered chord.
    state.scratch_cc = false;

    // Under a non-emacs scheme, a lone Ctrl-C still quits (parity with the REPL).
    if ctrl && key.code == KeyCode::Char('c') {
        return true;
    }

    match decode_line(key, state.keys, state.vi_mode, state.scratch.is_empty()) {
        // Enter alone inserts a newline rather than submitting.
        Edit::Submit => apply_scratch(state, Edit::Insert('\n')),
        // A quit action (e.g. emacs Ctrl-D on an empty buffer) leaves the editor.
        Edit::Quit => return true,
        action => apply_scratch(state, action),
    }
    false
}

/// Apply a Scratch edit, syncing the shared kill-ring with the system clipboard around
/// the pure [`scratch_edit`] — the same best-effort flow as [`apply`].
fn apply_scratch(state: &mut State, action: Edit) {
    if action == Edit::Yank {
        if let Some(text) = clipboard::paste() {
            state.kill = text;
        }
    }
    let before = state.kill.clone();
    scratch_edit(state, action);
    if state.kill != before {
        clipboard::copy(&state.kill);
    }
}

/// Apply an editing action to the multi-line Scratch buffer. Vertical line motion
/// (Up/Down — decoded as `HistoryPrev`/`HistoryNext`, which are exactly the keys emacs
/// `C-p`/`C-n` and vi `k`/`j` produce) is handled here; every text edit is delegated to
/// the shared [`edit_text`] core, so the buffer gets the same char/word/kill/yank/mark/
/// vi editing as the REPL line. Pure (no I/O); clipboard sync lives in [`apply_scratch`].
fn scratch_edit(state: &mut State, action: Edit) {
    match action {
        Edit::HistoryPrev => state.scratch_cursor = line_up(&state.scratch, state.scratch_cursor),
        Edit::HistoryNext => state.scratch_cursor = line_down(&state.scratch, state.scratch_cursor),
        // PgUp/PgDn and emacs `Esc` (Clear) are inert here — the view auto-scrolls to
        // the cursor, and Esc must not wipe the buffer.
        Edit::ScrollUp | Edit::ScrollDown | Edit::Clear => {}
        other => edit_text(
            &mut state.scratch,
            &mut state.scratch_cursor,
            &mut state.scratch_mark,
            &mut state.kill,
            &mut state.vi_mode,
            other,
        ),
    }
}

/// Evaluate the Scratch buffer (or its marked region) through the engine's Lisp path
/// (`urn:lisp:eval`), pushing the result to the transcript and keeping it for the
/// in-place readout beneath the buffer.
fn eval_scratch(state: &mut State, engine: &Engine) {
    let src = scratch_eval_src(&state.scratch, state.scratch_cursor, state.scratch_mark);
    if src.trim().is_empty() {
        return;
    }
    if let Action::Output(entry) = engine.eval_lisp(&src) {
        state.scratch_result = Some(entry.result.clone());
        state.transcript.push(entry);
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

    // Row 1: the core tabs, left of the clock. REPL and Scratch are always present;
    // Docs and Control join while the demo is on (its per-runbook pages wrap to row 2).
    let mut core_titles = vec![Line::from("REPL"), Line::from("Scratch")];
    if !state.demos.is_empty() {
        core_titles.push(Line::from("Docs"));
        core_titles.push(Line::from("Control"));
    }
    let core_len = core_titles.len();
    let core = Tabs::new(core_titles)
        .select(if state.tab < core_len {
            state.tab
        } else {
            core_len
        }) // demo tab ⇒ no highlight
        .highlight_style(Style::new().reversed())
        .divider("  ");
    frame.render_widget(core, top[0]);

    // Row 2: the demo tabs, wrapped onto their own full-width line — only while the demo
    // is on and the top strip actually has a second row (a degenerate terminal may not).
    if !state.demos.is_empty() && chunks[0].height >= 2 {
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
            .select(if state.tab >= TAB_DEMO_BASE {
                state.tab - TAB_DEMO_BASE
            } else {
                state.demos.len() // out of range ⇒ no highlight
            })
            .highlight_style(Style::new().reversed())
            .divider(" ");
        frame.render_widget(demo_tabs, demo_row);
    }

    // Main area: REPL transcript, the Scratch editor, the Docs/Control text views, or a
    // demo page — by the active tab.
    if state.tab == TAB_REPL {
        let lines = transcript_lines(&state.transcript);
        let bottom = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = bottom.saturating_sub(state.scroll_back);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if state.tab == TAB_SCRATCH {
        draw_scratch(frame, state, chunks[1]);
    } else if state.tab == TAB_DOCS {
        // Docs: top-anchored, `scroll_back` is the offset down from the top.
        let lines = docs_lines(&state.docs);
        let max = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = state.scroll_back.min(max);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if state.tab == TAB_CONTROL {
        // Control: the composed scheduler + cache readout, top-anchored like Docs.
        let lines = control_lines(&state.control);
        let max = (lines.len() as u16).saturating_sub(chunks[1].height);
        let scroll_y = state.scroll_back.min(max);
        frame.render_widget(Paragraph::new(lines).scroll((scroll_y, 0)), chunks[1]);
    } else if let Some(demo) = state.demos.get(state.tab - TAB_DEMO_BASE) {
        let page = Paragraph::new(demo_lines(demo, &state.demo_out)).wrap(Wrap { trim: false });
        frame.render_widget(page, chunks[1]);
    }

    // Bottom row: the editable request line on the REPL tab; a keybinding hint on the
    // Scratch, Docs/Control, and demo tabs (the Scratch cursor lives in its own box
    // above, so nothing is placed here for it).
    if state.tab == TAB_REPL {
        let input = Paragraph::new(state.input.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(format!(" request · {} ", mode_label(state)))),
        );
        frame.render_widget(input, chunks[2]);
        // Place the cursor at its column — the display width before it — inside the
        // 1-cell border, clamped so a long line can't draw past the box.
        let col = state.input[..state.cursor].chars().count() as u16;
        let cursor_x = (chunks[2].x + 1 + col).min(chunks[2].x + chunks[2].width.saturating_sub(1));
        frame.set_cursor_position(Position::new(cursor_x, chunks[2].y + 1));
    } else if state.tab == TAB_SCRATCH {
        let hint = if matches!(state.keys, Keybindings::Vi) {
            "F5 evaluate (or Ctrl/Alt-Enter) · Enter newline · Tab switch · Ctrl-C exit"
        } else {
            "F5 evaluate (or Ctrl/Alt-Enter · C-c C-c) · Enter newline · Tab switch"
        };
        let hint = Paragraph::new(hint.dim())
            .block(Block::default().borders(Borders::ALL).title(" lisp "));
        frame.render_widget(hint, chunks[2]);
    } else if state.tab == TAB_DOCS || state.tab == TAB_CONTROL {
        let title = if state.tab == TAB_DOCS {
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

/// Draw the Scratch (Lisp) tab into `area`: the editable buffer (bordered, cursor
/// placed, auto-scrolled to keep the cursor visible) above the most recent eval result.
fn draw_scratch(frame: &mut Frame, state: &State, area: Rect) {
    let result_h = match &state.scratch_result {
        Some(Ok(out)) => (out.lines().count() as u16 + 1).clamp(1, 8),
        Some(Err(_)) => 2,
        None => 0,
    };
    let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(result_h)]).split(area);

    let (crow, ccol) = cursor_row_col(&state.scratch, state.scratch_cursor);
    // Auto-scroll so the cursor row stays within the bordered inner height.
    let inner_h = parts[0].height.saturating_sub(2);
    let scroll_y = crow.saturating_sub(inner_h.saturating_sub(1));
    let buf = Paragraph::new(scratch_lines(&state.scratch))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(format!(
                    " scratch (lisp) · {} ",
                    mode_label(state)
                ))),
        )
        .scroll((scroll_y, 0));
    frame.render_widget(buf, parts[0]);

    // Place the terminal cursor inside the border, clamped to the box.
    let cx = (parts[0].x + 1 + ccol).min(parts[0].x + parts[0].width.saturating_sub(1));
    let cy = (parts[0].y + 1 + crow.saturating_sub(scroll_y))
        .min(parts[0].y + parts[0].height.saturating_sub(1));
    frame.set_cursor_position(Position::new(cx, cy));

    if result_h > 0 {
        if let Some(result) = &state.scratch_result {
            frame.render_widget(Paragraph::new(scratch_result_lines(result)), parts[1]);
        }
    }
}

/// The scratch buffer as plain lines (one per `\n`-separated line; a trailing newline
/// yields a final empty line so the cursor there is visible). An empty buffer shows a
/// dim placeholder.
fn scratch_lines(buf: &str) -> Vec<Line<'static>> {
    if buf.is_empty() {
        return vec![Line::from("(empty — type Lisp, then F5 to evaluate)".dim())];
    }
    buf.split('\n').map(|l| Line::from(l.to_string())).collect()
}

/// The last scratch eval result shown beneath the buffer: a dim header, then the output
/// (green) or the error (red).
fn scratch_result_lines(result: &Result<String, String>) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("─ result ─".dim())];
    match result {
        Ok(out) => lines.extend(out.lines().map(|l| Line::from(l.to_string().green()))),
        Err(err) => lines.push(Line::from(format!("error: {err}").red())),
    }
    lines
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

        state.tab = TAB_REPL; // tab strip shown, REPL transcript beneath
        render(80, 24, &state);
        render(1, 1, &state); // degenerate size with tabs present

        state.tab = TAB_SCRATCH; // the Scratch (Lisp) editor
        render(80, 24, &state);

        state.tab = TAB_DOCS; // Docs page
        render(80, 24, &state);

        state.tab = TAB_CONTROL; // Control page (scheduler + cache readout)
        render(80, 24, &state);

        state.tab = TAB_DEMO_BASE; // the demo page (demos start at index 4), no step run yet
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
        assert!(region(&s.input, s.cursor, s.mark).is_none());
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

    // --- Scratch (Lisp) buffer: multi-line editing logic ---------------------

    fn scratch_state(buf: &str, cursor: usize) -> State {
        State {
            scratch: buf.to_string(),
            scratch_cursor: cursor,
            ..State::default()
        }
    }

    #[test]
    fn scratch_enter_inserts_a_newline_not_submits() {
        // In the Scratch tab a decoded Submit becomes an inserted newline.
        let mut s = scratch_state("(+ 1", 4);
        apply_scratch(&mut s, Edit::Insert('\n'));
        apply_scratch(&mut s, Edit::Insert('2'));
        assert_eq!(s.scratch, "(+ 1\n2");
        assert_eq!(s.scratch_cursor, 6);
    }

    #[test]
    fn scratch_up_down_move_across_lines_keeping_column() {
        // Cursor at column 3 of line 2 ("ghi|jkl").
        let mut s = scratch_state("abcdef\nghijkl\nmno", 10);
        apply_scratch(&mut s, Edit::HistoryPrev); // up → column 3 of line 1
        assert_eq!(s.scratch_cursor, 3); // "abc|def"
        apply_scratch(&mut s, Edit::HistoryNext); // back down to line 2
        assert_eq!(s.scratch_cursor, 10);
        apply_scratch(&mut s, Edit::HistoryNext); // down to the short last line, column clamped
        assert_eq!(s.scratch_cursor, 17); // end of "mno"
        apply_scratch(&mut s, Edit::HistoryNext); // already on the last line → stays put
        assert_eq!(s.scratch_cursor, 17);
    }

    #[test]
    fn scratch_home_end_are_line_relative() {
        let mut s = scratch_state("foo\nbarbaz", 8); // within line 2
        apply_scratch(&mut s, Edit::Home);
        assert_eq!(s.scratch_cursor, 4); // start of line 2
        apply_scratch(&mut s, Edit::End);
        assert_eq!(s.scratch_cursor, 10); // end of line 2 (end of buffer)
    }

    #[test]
    fn scratch_reuses_the_shared_kill_op_line_relative() {
        // Kill-to-end operates on the CURRENT line only (line-relative End), proving the
        // scratch buffer drives the SAME `edit_text` core the REPL line uses.
        let mut s = scratch_state("foo bar\nbaz", 4); // before "bar" on line 1
        apply_scratch(&mut s, Edit::KillToEnd);
        assert_eq!(s.scratch, "foo \nbaz");
        assert_eq!(s.kill, "bar");
    }

    #[test]
    fn scratch_eval_src_picks_the_region_or_whole_buffer() {
        // No mark → the whole buffer is evaluated.
        assert_eq!(scratch_eval_src("(+ 1 2)", 7, None), "(+ 1 2)");
        // A mark → only the region between mark and cursor.
        assert_eq!(scratch_eval_src("(+ 1 2)(+ 3 4)", 14, Some(7)), "(+ 3 4)");
        // A collapsed mark (mark == cursor) falls back to the whole buffer.
        assert_eq!(scratch_eval_src("(+ 1 2)", 3, Some(3)), "(+ 1 2)");
    }

    #[test]
    fn cursor_row_col_tracks_line_and_column() {
        assert_eq!(cursor_row_col("abc", 2), (0, 2));
        assert_eq!(cursor_row_col("abc\nde", 5), (1, 1));
        assert_eq!(cursor_row_col("abc\n", 4), (1, 0)); // trailing newline → next line, col 0
    }

    #[test]
    fn scratch_setmark_then_move_bounds_the_eval_region() {
        // Set the mark, move to the end of the first form, and the region is that form.
        let mut s = scratch_state("(a)\n(b)", 0);
        apply_scratch(&mut s, Edit::SetMark);
        apply_scratch(&mut s, Edit::End); // to end of line 1 (offset 3)
        let src = scratch_eval_src(&s.scratch, s.scratch_cursor, s.scratch_mark);
        assert_eq!(src, "(a)");
    }

    /// A minimal engine whose `urn:lisp:eval` echoes its `in` argument — enough to
    /// observe that a key routed through `scratch_key` reaches the eval path.
    fn echo_lisp_engine() -> Engine {
        use ikigai_core::{
            EndpointSpace, Exact, FnEndpoint, Invocation, Kernel, ReprType, Representation,
        };
        let eval = FnEndpoint::new("lisp", |inv: &Invocation<'_>| {
            let src = inv.inline_str("in")?;
            Ok(Representation::new(
                ReprType::new("text/plain"),
                format!("ok: {src}").into_bytes(),
            ))
        });
        let space = EndpointSpace::new().bind(Exact::new("urn:lisp:eval"), eval);
        Engine::new(Kernel::new(std::sync::Arc::new(space)))
    }

    #[test]
    fn scratch_f5_triggers_an_eval() {
        // F5 in the Scratch tab evaluates the buffer via `urn:lisp:eval` on either
        // scheme — the reliable, terminal-independent eval key.
        let engine = echo_lisp_engine();
        for keys in [Keybindings::Emacs, Keybindings::Vi] {
            let mut s = State {
                scratch: "(+ 1 2)".into(),
                scratch_cursor: 7,
                keys,
                ..State::default()
            };
            let quit = scratch_key(&mut s, &engine, key(KeyCode::F(5), KeyModifiers::NONE));
            assert!(!quit, "F5 must not quit");
            assert_eq!(s.scratch_result, Some(Ok("ok: (+ 1 2)".to_string())));
            assert_eq!(
                s.transcript.len(),
                1,
                "result also appended to the transcript"
            );
        }
    }

    #[test]
    fn draws_the_scratch_tab_without_panicking() {
        let mut state = State {
            scratch: "(+ 1 2)\n(list 1 2 3)".into(),
            scratch_cursor: 5,
            tab: TAB_SCRATCH,
            ..State::default()
        };
        render(80, 24, &state);
        render(1, 1, &state); // degenerate

        state.scratch_result = Some(Ok("3".into()));
        render(80, 24, &state);

        state.scratch_result = Some(Err("unbound symbol: foo".into()));
        render(20, 6, &state); // narrow, with an error readout

        // An empty buffer renders the placeholder without panicking.
        state.scratch.clear();
        state.scratch_cursor = 0;
        state.scratch_result = None;
        render(80, 24, &state);
    }
}
