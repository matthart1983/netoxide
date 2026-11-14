//! netoxide-tui: a terminal UI prototype for the Netoxide firewall.
//!
//! Run it:            cargo run --release
//! Print a screen:    cargo run -- --snapshot policy [--size 160x48]
//!                    cargo run -- --snapshot all
//! Replay keys first: cargo run -- --snapshot changes --keys c
//! Coloured web page: cargo run -- --html netoxide-tui.html
//!
//! All data is mock data from `data.rs`. Nothing talks to a firewall.

#![forbid(unsafe_code)]

mod app;
mod data;
mod html;
mod ui;

use std::{
    io::{self, Write},
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use app::{App, Screen};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = args.iter().position(|a| a == "--html") {
        let path = args
            .get(i + 1)
            .map(String::as_str)
            .unwrap_or("netoxide-tui.html");
        std::fs::write(path, html::page(148, 40))?;
        eprintln!("wrote {path}");
        return Ok(());
    }
    if let Some(i) = args.iter().position(|a| a == "--snapshot") {
        let which = args.get(i + 1).map(String::as_str).unwrap_or("all");
        let (w, h) = args
            .iter()
            .position(|a| a == "--size")
            .and_then(|j| args.get(j + 1))
            .and_then(|s| s.split_once('x'))
            .and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)))
            .unwrap_or((160, 46));
        let keys = args
            .iter()
            .position(|a| a == "--keys")
            .and_then(|j| args.get(j + 1))
            .cloned();
        return snapshot(which, w, h, keys.as_deref());
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("netoxide-tui [--snapshot <screen|all> [--size WxH]]");
        println!(
            "screens: {}",
            Screen::ALL.map(|s| s.title().to_lowercase()).join(", ")
        );
        return Ok(());
    }

    let mut terminal = ratatui::init();
    let res = run(&mut terminal);
    ratatui::restore();
    res
}

fn run(terminal: &mut ratatui::DefaultTerminal) -> io::Result<()> {
    let mut app = App::new();
    while app.running {
        terminal.draw(|f| ui::draw(f, &mut app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key);
        }
        app.tick();
    }
    Ok(())
}

/// Render screens into an in-memory buffer and print them as plain text.
fn snapshot(which: &str, w: u16, h: u16, keys: Option<&str>) -> io::Result<()> {
    let screens: Vec<Screen> = if which == "all" {
        Screen::ALL.to_vec()
    } else {
        match Screen::from_name(which) {
            Some(s) => vec![s],
            None => {
                eprintln!("unknown screen '{which}'");
                std::process::exit(2);
            }
        }
    };
    for s in screens {
        let mut app = App::new();
        app.screen = s;
        // Replay key presses first, e.g. --keys c on the changes screen.
        for c in keys.unwrap_or("").chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        // Stop quietly if the reader goes away (e.g. piped into `head`).
        if io::stdout()
            .lock()
            .write_all(render_text(&mut app, w, h)?.as_bytes())
            .is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}

/// One screen as plain text: a title line, then one line per terminal row.
fn render_text(app: &mut App, w: u16, h: u16) -> io::Result<String> {
    let mut term = Terminal::new(TestBackend::new(w, h))?;
    term.draw(|f| ui::draw(f, app))?;
    let buf = term.backend().buffer();
    let mut out = format!("── {} ──\n", app.screen.title());
    for y in 0..h {
        let mut line = String::new();
        for x in 0..w {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(app: &mut App, c: char) {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }

    fn screen(app: &mut App, s: Screen, w: u16, h: u16) -> String {
        app.screen = s;
        render_text(app, w, h).unwrap()
    }

    /// `snapshots.txt` is `--snapshot all --size 160x46`. Regenerate it with
    /// that command when a layout change is intended.
    #[test]
    fn snapshots_match() {
        let mut got = String::new();
        for s in Screen::ALL {
            got.push_str(&screen(&mut App::new(), s, 160, 46));
        }
        let want = include_str!("../snapshots.txt");
        assert!(
            got == want,
            "screens differ from snapshots.txt; regenerate it if intended"
        );
    }

    #[test]
    fn every_screen_draws_at_the_minimum_size() {
        for s in Screen::ALL {
            let text = screen(&mut App::new(), s, ui::MIN_W, ui::MIN_H);
            assert!(
                !text.contains("needs at least"),
                "{s:?} refused the minimum size"
            );
        }
    }

    #[test]
    fn confirm_makes_the_candidate_the_running_config() {
        let mut app = App::new();
        app.screen = Screen::Changes;
        assert_eq!(app.running_commit(), data::BASE_COMMIT);
        key(&mut app, 'c');
        assert!(app.applied() && app.has_candidate());
        assert_eq!(app.running_commit(), data::NEXT_COMMIT);
        key(&mut app, 'y');
        assert!(app.applied() && !app.has_candidate());

        let policy = screen(&mut app, Screen::Policy, 160, 46);
        assert!(policy.contains("running #2480") && policy.contains("no candidate"));
        assert!(
            !policy.contains('◆'),
            "confirmed rule is still marked as candidate"
        );
        let explain = screen(&mut app, Screen::Explain, 160, 46);
        assert!(explain.contains("DROP") && !explain.contains("ACCEPT"));
    }

    #[test]
    fn a_confirmed_commit_cannot_be_committed_again() {
        let mut app = App::new();
        app.screen = Screen::Changes;
        for c in ['c', 'y', 'c'] {
            key(&mut app, c);
        }
        assert!(matches!(app.commit, app::CommitPhase::Confirmed));
    }

    #[test]
    fn revert_keeps_the_candidate_and_the_old_commit() {
        let mut app = App::new();
        app.screen = Screen::Changes;
        key(&mut app, 'c');
        key(&mut app, 'r');
        assert!(!app.applied() && app.has_candidate());
        assert_eq!(app.running_commit(), data::BASE_COMMIT);
        let explain = screen(&mut app, Screen::Explain, 160, 46);
        assert!(explain.contains("ACCEPT"));
    }
}
