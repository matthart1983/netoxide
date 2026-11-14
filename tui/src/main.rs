//! netoxide-tui: a terminal UI prototype for the Netoxide firewall.
//!
//! Run it:            cargo run --release
//! Print a screen:    cargo run -- --snapshot policy [--size 160x48]
//!                    cargo run -- --snapshot all
//! Replay keys first: cargo run -- --snapshot changes --keys c
//! Coloured web page: cargo run -- --html netoxide-tui.html
//!
//! Live against oxd: cargo run -- --socket /run/netoxide/oxd.sock
//!                    (or --live, which uses $OX_SOCKET or the default path)
//!
//! A box on the network: cargo run -- --remote <name>
//!                    (a name saved with `ox remote add`, or $OX_REMOTE with --live)
//!
//! Without --socket, --remote or --live, all data is mock data from `data.rs` and
//! nothing talks to a firewall.

#![forbid(unsafe_code)]

mod app;
mod data;
mod html;
mod live;
mod live_ui;
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
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let socket = value("--socket").or_else(|| {
        args.iter()
            .any(|a| a == "--live")
            .then(|| std::env::var("OX_SOCKET").unwrap_or_else(|_| "/run/netoxide/oxd.sock".into()))
    });
    let live = args.iter().any(|a| a == "--live");
    let remote = value("--remote").or_else(|| {
        std::env::var("OX_REMOTE")
            .ok()
            .filter(|r| live && !r.is_empty() && value("--socket").is_none())
    });
    let backend = match (remote, socket) {
        (Some(name), _) => Some(live::SocketBackend::remote(&name).map_err(io::Error::other)?),
        (None, Some(socket)) => Some(live::SocketBackend::new(std::path::Path::new(&socket))),
        (None, None) => None,
    };
    if let Some(backend) = backend {
        if let Some(which) = value("--snapshot") {
            let (w, h) = value("--size")
                .and_then(|s| {
                    let (w, h) = s.split_once('x')?;
                    Some((w.parse().ok()?, h.parse().ok()?))
                })
                .unwrap_or((160, 46));
            return live_snapshot(&backend, &which, w, h, value("--keys").as_deref());
        }
        let mut terminal = ratatui::init();
        let res = run_live(&mut terminal, &backend);
        ratatui::restore();
        return res;
    }
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

fn run_live(
    terminal: &mut ratatui::DefaultTerminal,
    backend: &dyn live::Backend,
) -> io::Result<()> {
    let mut app = live::LiveApp::new(backend);
    let mut last = std::time::Instant::now();
    while app.running {
        terminal.draw(|f| live_ui::draw(f, &mut app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            app.on_key(key, backend);
        }
        // Once a second, so the countdown and the packet counters move.
        if last.elapsed() >= Duration::from_secs(1) {
            app.refresh(backend);
            last = std::time::Instant::now();
        }
    }
    Ok(())
}

/// One live screen as plain text.
fn live_text(app: &mut live::LiveApp, w: u16, h: u16) -> io::Result<String> {
    let mut term = Terminal::new(TestBackend::new(w, h))?;
    term.draw(|f| live_ui::draw(f, app))?;
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

/// Prints live screens as text, optionally after replaying keys. A key
/// written as `\n` in `--keys` is Enter.
fn live_snapshot(
    backend: &dyn live::Backend,
    which: &str,
    w: u16,
    h: u16,
    keys: Option<&str>,
) -> io::Result<()> {
    let screens: Vec<live::Screen> = if which == "all" {
        live::Screen::ALL.to_vec()
    } else {
        match live::Screen::from_name(which) {
            Some(s) => vec![s],
            None => {
                eprintln!("unknown live screen '{which}'");
                std::process::exit(2);
            }
        }
    };
    for s in screens {
        let mut app = live::LiveApp::new(backend);
        app.screen = s;
        for c in keys.unwrap_or("").chars() {
            let code = if c == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(c)
            };
            app.on_key(KeyEvent::new(code, KeyModifiers::NONE), backend);
        }
        if io::stdout()
            .lock()
            .write_all(live_text(&mut app, w, h)?.as_bytes())
            .is_err()
        {
            return Ok(());
        }
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

    // ── live mode ───────────────────────────────────────────────────────

    use live::{LiveApp, fixture::Fixture};

    fn live_keys(app: &mut LiveApp, backend: &Fixture, keys: &str) {
        for c in keys.chars() {
            let code = if c == '\n' {
                KeyCode::Enter
            } else {
                KeyCode::Char(c)
            };
            app.on_key(KeyEvent::new(code, KeyModifiers::NONE), backend);
        }
    }

    /// `snapshots-live.txt` is every live screen at 160x46 against the test
    /// fixture. Run the tests with UPDATE_SNAPSHOTS=1 to rewrite it.
    #[test]
    fn live_snapshots_match() {
        let backend = Fixture::default();
        let mut got = String::new();
        for s in live::Screen::ALL {
            let mut app = LiveApp::new(&backend);
            app.screen = s;
            got.push_str(&live_text(&mut app, 160, 46).unwrap());
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/snapshots-live.txt");
        if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
            std::fs::write(path, &got).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            got == want,
            "live screens differ from snapshots-live.txt; rerun with UPDATE_SNAPSHOTS=1 if intended"
        );
    }

    #[test]
    fn every_live_screen_draws_at_the_minimum_size() {
        let backend = Fixture::default();
        for s in live::Screen::ALL {
            let mut app = LiveApp::new(&backend);
            app.screen = s;
            let text = live_text(&mut app, ui::MIN_W, ui::MIN_H).unwrap();
            assert!(
                !text.contains("needs at least"),
                "{s:?} refused the minimum size"
            );
        }
    }

    #[test]
    fn live_policy_shows_the_running_config_and_kernel_counters() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(text.contains("syd-br-014-a") && text.contains("running #1"));
        assert!(text.contains("r-0388 Finance to file servers") && text.contains("1204"));
        assert!(
            text.contains("2114"),
            "the default drop shows its own counter"
        );
        assert!(
            !text.contains("r-0412"),
            "a candidate rule is not in the running config"
        );
    }

    #[test]
    fn live_commit_asks_for_a_reason_then_commits_with_the_window() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        // Changes screen, shorten the window twice (5m → 10m → 30s), commit.
        live_keys(&mut app, &backend, "4wwc");
        assert_eq!(app.reason.as_deref(), Some(""));
        // While the prompt is open, q is a letter, not quit.
        live_keys(&mut app, &backend, "q-CHG-2207\n");
        assert!(app.running);
        assert_eq!(
            backend.0.borrow().commits,
            [("block-legacy-smb".to_string(), 30, "q-CHG-2207".to_string())]
        );
        assert_eq!(app.status.reverts_in, Some(287));
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(
            text.contains("reverts in 04:47 unless you press y"),
            "{text}"
        );

        // A second commit is not offered while one is pending.
        live_keys(&mut app, &backend, "c");
        assert!(app.reason.is_none());

        // y works from any screen and the new rule is now the running config.
        live_keys(&mut app, &backend, "1y");
        assert!(!backend.0.borrow().pending);
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(text.contains("kept #2") && text.contains("r-0412 Drop SMB and NetBIOS"));
    }

    #[test]
    fn live_revert_goes_back_to_the_old_config() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "4c\nr");
        assert!(!backend.0.borrow().applied);
        assert_eq!(app.status.running.as_ref().unwrap().id, 1);
        assert_eq!(app.selected_candidate(), Some("block-legacy-smb"));
    }

    #[test]
    fn live_x_explains_a_packet_the_rule_is_about() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "x");
        assert_eq!(app.screen, live::Screen::Explain);
        let (q, candidate) = backend.0.borrow().explained[0].clone();
        assert_eq!(
            (
                q.src.as_str(),
                q.dst.as_str(),
                q.proto.as_str(),
                q.dport.as_str(),
                q.iif.as_str()
            ),
            ("10.20.4.17", "10.30.0.8", "tcp", "445", "lan0.20")
        );
        assert_eq!(candidate.as_deref(), Some("block-legacy-smb"));
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(text.contains("ACCEPT") && text.contains("DROP"));

        // m drops the comparison and asks again.
        live_keys(&mut app, &backend, "m");
        assert_eq!(backend.0.borrow().explained[1].1, None);
    }

    #[test]
    fn live_explain_form_takes_typing_and_reports_bad_input() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "5e");
        assert_eq!(app.editing, Some(0));
        live_keys(&mut app, &backend, "nonsense\n");
        assert!(app.running && app.editing.is_none());
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(
            text.contains("cannot explain: src 'nonsense' is not an address"),
            "{text}"
        );
    }

    #[test]
    fn daemon_answers_are_parsed() {
        let status = live::parse_status(&serde_json::json!({
            "running": { "id": 7, "author": "ana", "source": "candidate x", "reason": "r", "state": "pending", "deadline": 99 },
            "reverts_in": 42, "candidates": ["a", "b"], "applier": "kernel"
        }));
        assert_eq!(
            status.running.as_ref().map(|c| (c.id, c.pending)),
            Some((7, true))
        );
        assert_eq!((status.reverts_in, status.candidates.len()), (Some(42), 2));
        assert_eq!(
            live::parse_status(&serde_json::json!({ "running": null })).running,
            None
        );

        // One config rule is two kernel rules here, one per address family.
        let hits = live::parse_hits(&serde_json::json!({ "nftables": [
            { "rule": { "comment": "r-1", "expr": [{ "counter": { "packets": 5, "bytes": 300 } }, { "accept": null }] } },
            { "rule": { "comment": "r-1", "expr": [{ "counter": { "packets": 2, "bytes": 120 } }, { "accept": null }] } },
            { "rule": { "expr": [{ "accept": null }] } },
            { "set": { "name": "x" } }
        ] }));
        assert_eq!(hits.get("r-1"), Some(&7));
        assert_eq!(hits.len(), 1);
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
