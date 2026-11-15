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
//! A live screen as HTML: cargo run -- --socket <path> --snapshot policy --html-out policy.html
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
mod live_view;
mod spark;
mod tasks;
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
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("netoxide-tui {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
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
            // With --html-out, one live screen is written as a coloured page.
            if let Some(path) = value("--html-out") {
                let Some(screen) = live::Screen::from_name(&which) else {
                    eprintln!("unknown live screen '{which}'");
                    std::process::exit(2);
                };
                let mut app = live::LiveApp::new(&backend);
                app.screen = screen;
                app.refresh(&backend);
                for c in value("--keys").unwrap_or_default().chars() {
                    app.on_key(KeyEvent::new(key_for(c), KeyModifiers::NONE), &backend);
                }
                let mut term = Terminal::new(TestBackend::new(w, h))?;
                term.draw(|f| live_ui::draw(f, &mut app))?;
                std::fs::write(&path, html::single(term.backend().buffer()))?;
                eprintln!("wrote {path}");
                return Ok(());
            }
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
    // The detailed screens switched on last time, kept beside the saved remotes.
    if let Ok(remotes) = ox_client::remotes::path() {
        app.load_prefs(remotes.with_file_name("tui-screens"));
    }
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

/// The key a character of `--keys` stands for: a newline is Enter, a tab is
/// Tab and an escape character is Esc.
fn key_for(c: char) -> KeyCode {
    match c {
        '\n' => KeyCode::Enter,
        '\t' => KeyCode::Tab,
        '\u{1b}' => KeyCode::Esc,
        c => KeyCode::Char(c),
    }
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
        app.refresh(backend);
        for c in keys.unwrap_or("").chars() {
            app.on_key(KeyEvent::new(key_for(c), KeyModifiers::NONE), backend);
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
            app.on_key(KeyEvent::new(key_for(c), KeyModifiers::NONE), backend);
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
            app.refresh(&backend);
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
            app.refresh(&backend);
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
        live_keys(&mut app, &backend, "A6");
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

    /// Keys by name, for the ones a character cannot stand for.
    fn press(app: &mut LiveApp, backend: &Fixture, codes: &[KeyCode]) {
        for code in codes {
            app.on_key(KeyEvent::new(*code, KeyModifiers::NONE), backend);
        }
    }

    #[test]
    fn live_opens_on_plain_screens_and_keeps_the_detailed_ones_behind_switches() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        assert_eq!(app.screen, live::Screen::Home);
        assert_eq!(app.tabs(), live::SIMPLE);
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(text.contains("The firewall is running"), "{text}");
        assert!(
            text.contains("Staff network") && text.contains("14 devices"),
            "{text}"
        );
        assert!(text.contains("1 change is waiting"), "{text}");
        // Plain words only: no commit numbers, candidates or detailed tabs.
        for word in ["Policy", "Audit", "candidate", "commit", "#1", "kernel"] {
            assert!(!text.contains(word), "'{word}' on the plain home: {text}");
        }

        // The grid is on Access, with hand-written rules read as what they do.
        live_keys(&mut app, &backend, "3");
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(
            text.contains("who can reach what") && text.contains("Internet"),
            "{text}"
        );
        assert!(
            text.contains("3 rules") && text.contains("1 service let in"),
            "{text}"
        );

        // One switch on Settings adds one tab and nothing else.
        live_keys(&mut app, &backend, "5\n");
        assert_eq!(app.tabs().len(), 6);
        assert_eq!(app.tabs()[5], live::Screen::Policy);
        live_keys(&mut app, &backend, "\n");
        assert_eq!(app.tabs(), live::SIMPLE);

        // A shows all the detailed screens, and hides them again without
        // leaving the user on a hidden one.
        live_keys(&mut app, &backend, "A");
        assert_eq!(app.tabs().len(), 11);
        // 0 is the tenth tab. The eleventh has no digit and is reached with tab.
        live_keys(&mut app, &backend, "0");
        assert_eq!(app.screen, live::Screen::Explain);
        press(&mut app, &backend, &[KeyCode::Tab]);
        assert_eq!(app.screen, live::Screen::Audit);
        live_keys(&mut app, &backend, "A");
        assert_eq!(app.screen, live::Screen::Home);
        // A digit past the last tab does nothing.
        live_keys(&mut app, &backend, "9");
        assert_eq!(app.screen, live::Screen::Home);
    }

    #[test]
    fn the_switches_are_remembered_between_runs() {
        let backend = Fixture::default();
        let file = std::env::temp_dir().join(format!("ox-tui-screens-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let mut app = LiveApp::new(&backend);
        app.load_prefs(file.clone());
        assert!(app.detailed.is_empty());
        // Settings, down to the packet tracer, switch it on.
        live_keys(&mut app, &backend, "5jjjj\n");
        assert_eq!(app.detailed, [live::Screen::Explain]);

        let mut again = LiveApp::new(&backend);
        again.load_prefs(file.clone());
        assert_eq!(again.detailed, [live::Screen::Explain]);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_task_is_a_short_form_that_ends_in_a_review() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        // Home menu: second line is "Add a network".
        live_keys(&mut app, &backend, "j\n");
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(
            text.contains("add a network") && text.contains("VLAN number"),
            "{text}"
        );
        // Sent empty, it says what is missing and asks the box nothing.
        live_keys(&mut app, &backend, "\n");
        assert!(backend.0.borrow().actions.is_empty());
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(
            text.contains("Fill in \"What is it for?\" first."),
            "{text}"
        );

        // q is a letter while typing. Tab moves on. The arrows change an answer.
        live_keys(&mut app, &backend, "quests");
        press(&mut app, &backend, &[KeyCode::Tab, KeyCode::Tab]);
        live_keys(&mut app, &backend, "20");
        press(
            &mut app,
            &backend,
            &[KeyCode::Tab, KeyCode::Tab, KeyCode::Right, KeyCode::Enter],
        );
        assert!(app.running);
        let (path, body) = backend.0.borrow().actions[0].clone();
        assert_eq!(path, "/v1/actions/network");
        assert_eq!(
            body,
            serde_json::json!({ "name": "quests", "port": "lan0.20", "vlan": 20, "internet": false })
        );

        // It lands on Review with the new change selected, and nothing applied.
        assert_eq!(app.screen, live::Screen::Review);
        assert_eq!(app.selected_candidate(), Some("task-1"));
        assert!(backend.0.borrow().commits.is_empty());
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("Nothing is applied yet."), "{text}");

        // Enter applies it with the two-minute timer and no reason to type.
        live_keys(&mut app, &backend, "\n");
        assert_eq!(
            backend.0.borrow().commits,
            [("task-1".to_string(), 120, String::new())]
        );
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("undoes itself in 04:47"), "{text}");
        // Applied is past review: the screen offers keep or undo, and the
        // change no longer counts as waiting.
        assert!(
            text.contains("keep it or undo it") && text.contains("no changes waiting"),
            "{text}"
        );
        live_keys(&mut app, &backend, "y");
        assert!(!backend.0.borrow().pending);
    }

    #[test]
    fn a_refused_task_stays_open_with_the_reason() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        // "Let something in from the internet".
        live_keys(&mut app, &backend, "jj\nrefuse me");
        press(&mut app, &backend, &[KeyCode::Tab]);
        live_keys(&mut app, &backend, "tcp/443");
        press(&mut app, &backend, &[KeyCode::Tab]);
        live_keys(&mut app, &backend, "10.30.0.10\n");
        assert!(app.form.is_some());
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("the daemon said no"), "{text}");
        // Esc leaves without a trace.
        press(&mut app, &backend, &[KeyCode::Esc]);
        assert!(app.form.is_none());
        assert_eq!(app.screen, live::Screen::Home);
        assert!(backend.0.borrow().saved.is_empty());
    }

    #[test]
    fn blocking_tells_a_device_from_a_website() {
        let backend = Fixture::default();
        for (typed, path, body) in [
            (
                "10.50.0.66",
                "/v1/actions/block",
                serde_json::json!({ "address": "10.50.0.66" }),
            ),
            (
                "2001:db8::66",
                "/v1/actions/block",
                serde_json::json!({ "address": "2001:db8::66" }),
            ),
            (
                "example.com",
                "/v1/actions/block-site",
                serde_json::json!({ "name": "example.com", "block": true }),
            ),
        ] {
            let mut app = LiveApp::new(&backend);
            let line = app
                .menu_items()
                .iter()
                .position(|m| m.0 == tasks::Choice::Task(tasks::Task::Block))
                .unwrap();
            app.menu = line;
            live_keys(&mut app, &backend, "\n");
            live_keys(&mut app, &backend, typed);
            live_keys(&mut app, &backend, "\n");
            let last = backend.0.borrow().actions.last().cloned().unwrap();
            assert_eq!(last, (path.to_string(), body), "{typed}");
        }
    }

    #[test]
    fn access_flips_one_pair_and_leaves_the_rest_alone() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        // Access opens on the first pair that is not a network to itself:
        // Servers to Guest Wi-Fi, which is Blocked.
        live_keys(&mut app, &backend, "3\n");
        let (path, body) = backend.0.borrow().actions[0].clone();
        assert_eq!(path, "/v1/actions/access");
        assert_eq!(
            body,
            serde_json::json!({ "from": "dmz", "to": "guest", "allow": true })
        );
        assert_eq!(app.screen, live::Screen::Review);

        // A pair with rules of its own is read-only here: Staff to Servers.
        let mut app = LiveApp::new(&backend);
        app.screen = live::Screen::Access;
        app.cell = (2, 0);
        let before = backend.0.borrow().actions.len();
        live_keys(&mut app, &backend, "\n");
        assert_eq!(backend.0.borrow().actions.len(), before);
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("rules of its own"), "{text}");
        // So is anything from the internet, which is let in one service at a time.
        app.cell = (3, 1);
        live_keys(&mut app, &backend, "\n");
        assert_eq!(backend.0.borrow().actions.len(), before);
    }

    #[test]
    fn a_check_asks_the_box_and_changes_nothing() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        let line = app.menu_items().len() - 1;
        app.menu = line;
        live_keys(&mut app, &backend, "\n10.20.4.17");
        press(&mut app, &backend, &[KeyCode::Tab]);
        live_keys(&mut app, &backend, "10.30.0.8\n");
        let (q, candidate) = backend.0.borrow().explained[0].clone();
        assert_eq!(
            (
                q.src.as_str(),
                q.dst.as_str(),
                q.proto.as_str(),
                q.dport.as_str()
            ),
            ("10.20.4.17", "10.30.0.8", "tcp", "443")
        );
        assert_eq!(candidate, None);
        assert!(backend.0.borrow().actions.is_empty());
        assert_eq!(app.screen, live::Screen::Home);
        let text = live_text(&mut app, 80, 24).unwrap();
        // The answer names the rule as someone called it, not by its ID alone.
        assert!(
            text.contains("Allowed") && text.contains("\"Finance to file servers\""),
            "{text}"
        );
    }

    #[test]
    fn a_vpn_device_is_shown_until_it_is_closed_on_purpose() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "jjj\nlaptop");
        press(&mut app, &backend, &[KeyCode::Tab]);
        live_keys(&mut app, &backend, "home.example.net\n");
        assert_eq!(backend.0.borrow().actions[0].0, "/v1/actions/vpn-peer");
        assert!(app.device.is_some());
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(
            text.contains("PrivateKey = not-a-real-key") && text.contains("shown once"),
            "{text}"
        );
        // Too small for a code, and it says how big the window must be.
        assert!(text.contains("A code to scan needs a window"), "{text}");
        // In a big window the code and the text are both there.
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(
            text.contains('▀') && text.contains("PrivateKey = not-a-real-key"),
            "{text}"
        );
        // Stray keys do not close it, quit included.
        live_keys(&mut app, &backend, "q\ny ");
        assert!(app.device.is_some() && app.running);
        press(&mut app, &backend, &[KeyCode::Esc]);
        assert!(app.device.is_none());
        assert_eq!(app.screen, live::Screen::Review);
    }

    #[test]
    fn live_shows_what_the_daemon_measured_and_can_be_paused() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        assert!(app.live.is_none(), "nothing is fetched until Live is open");
        live_keys(&mut app, &backend, "2");
        assert_eq!(app.screen, live::Screen::Live);
        assert!(app.live.is_some(), "Live has its readings as it opens");
        let text = live_text(&mut app, 80, 24).unwrap();
        for part in [
            "download",
            "upload",
            "connections",
            "blocked",
            "internet traffic",
            "Staff network",
            "just blocked",
            "Internet tried to reach the box itself",
            "p to pause",
        ] {
            assert!(text.contains(part), "'{part}' is missing: {text}");
        }
        // The plots are drawn in braille.
        assert!(
            text.chars().any(|c| ('\u{2801}'..='\u{28ff}').contains(&c)),
            "{text}"
        );

        // Paused, it keeps what it has and says so.
        live_keys(&mut app, &backend, "p");
        assert!(app.paused);
        let frozen = app.live.clone();
        app.refresh(&backend);
        assert_eq!(app.live, frozen);
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("paused") && text.contains("resume"), "{text}");
        live_keys(&mut app, &backend, "p");
        assert!(!app.paused);
    }

    #[test]
    fn live_leaves_out_what_the_box_cannot_measure() {
        // A dry run has no rules in a kernel and may have no connection count.
        let data = live_view::LiveData {
            window: 120,
            download: Some([1_000_000, 2_000_000].into()),
            upload: Some([100_000, 200_000].into()),
            connections: None,
            blocked: None,
            networks: vec![],
            feed: vec![],
        };
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| live_view::draw(f, Some(&data), false, f.area()))
            .unwrap();
        let buf = term.backend().buffer();
        let text: String = (0..24)
            .flat_map(|y| (0..80).map(move |x| (x, y)))
            .map(|(x, y)| buf[(x, y)].symbol().to_string())
            .collect();
        assert!(
            text.contains("download") && text.contains("2.0 Mb/s"),
            "{text}"
        );
        assert!(
            !text.contains("connections") && !text.contains("blocked"),
            "{text}"
        );
    }

    #[test]
    fn rates_read_in_the_unit_that_fits() {
        assert_eq!(live_view::rate(0), ("0".to_string(), "b/s"));
        assert_eq!(live_view::rate(950), ("950".to_string(), "b/s"));
        assert_eq!(live_view::rate(48_400), ("48".to_string(), "kb/s"));
        assert_eq!(live_view::rate(12_340_000), ("12.3".to_string(), "Mb/s"));
        assert_eq!(live_view::rate(2_500_000_000), ("2.5".to_string(), "Gb/s"));
    }

    #[test]
    fn discarding_takes_two_presses() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "4d");
        assert!(!backend.0.borrow().discarded);
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("Press d again"), "{text}");
        // Another key in between calls it off.
        live_keys(&mut app, &backend, "jd");
        assert!(!backend.0.borrow().discarded);
        live_keys(&mut app, &backend, "d");
        assert!(backend.0.borrow().discarded);
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(
            text.contains("Discarded. Nothing was changed.") && text.contains("Nothing is waiting"),
            "{text}"
        );
    }

    /// Every plain screen, form and panel at the smallest size it promises.
    #[test]
    fn plain_screens_fit_a_terminal_as_it_opens() {
        let backend = Fixture::default();
        let fits = |app: &mut LiveApp, what: &str| {
            let text = live_text(app, live_ui::SIMPLE_W, live_ui::SIMPLE_H).unwrap();
            assert!(!text.contains("needs at least"), "{what}: {text}");
            // The last line is the keys, and they must all fit.
            let keys = text.lines().last().unwrap_or("");
            assert!(
                keys.contains("quit") || keys.contains("cancel") || keys.contains("close"),
                "{what}: the keys are cut off: {keys}"
            );
        };
        for s in live::SIMPLE {
            let mut app = LiveApp::new(&backend);
            app.screen = s;
            app.refresh(&backend);
            fits(&mut app, s.title());
        }
        for (i, (choice, label)) in tasks::MENU.iter().enumerate() {
            if let tasks::Choice::Task(_) = choice {
                let mut app = LiveApp::new(&backend);
                app.menu = i;
                live_keys(&mut app, &backend, "\n");
                assert!(app.form.is_some(), "{label}");
                // On every line of the form, since the keys depend on the line.
                for _ in 0..app.form.as_ref().unwrap().fields.len() {
                    fits(&mut app, label);
                    press(&mut app, &backend, &[KeyCode::Tab]);
                }
                let text = live_text(&mut app, 80, 24).unwrap();
                // Every line of the form is on screen, the last one included.
                let last = app.form.as_ref().unwrap().fields.last().unwrap().label;
                assert!(text.contains(last), "{label}: {text}");
            }
        }
        // With a change applied and waiting to be kept.
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "4\n");
        for s in live::SIMPLE {
            app.screen = s;
            app.refresh(&backend);
            fits(&mut app, s.title());
        }
    }

    #[test]
    fn a_detailed_screen_in_a_small_window_says_what_it_needs() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "A6");
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(
            text.contains("This detailed screen needs at least 132×34"),
            "{text}"
        );
        // Tab still leaves it.
        press(&mut app, &backend, &[KeyCode::BackTab]);
        let text = live_text(&mut app, 80, 24).unwrap();
        assert!(text.contains("basics"), "{text}");
    }

    #[test]
    fn live_commit_asks_for_a_reason_then_commits_with_the_window() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        // Changes screen, shorten the window twice (5m → 10m → 30s), commit.
        live_keys(&mut app, &backend, "A9wwc");
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
            text.contains("undoes itself in 04:47 unless you keep it"),
            "{text}"
        );

        // A second commit is not offered while one is pending.
        live_keys(&mut app, &backend, "c");
        assert!(app.reason.is_none());

        // y works from any screen and the new rule is now the running config.
        live_keys(&mut app, &backend, "y6");
        assert!(!backend.0.borrow().pending);
        let text = live_text(&mut app, 160, 46).unwrap();
        assert!(
            text.contains("Kept. Change #2 stays.") && text.contains("r-0412 Drop SMB and NetBIOS")
        );
    }

    #[test]
    fn live_revert_goes_back_to_the_old_config() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "A9c\nr");
        assert!(!backend.0.borrow().applied);
        assert_eq!(app.status.running.as_ref().unwrap().id, 1);
        assert_eq!(app.selected_candidate(), Some("block-legacy-smb"));
    }

    #[test]
    fn live_x_explains_a_packet_the_rule_is_about() {
        let backend = Fixture::default();
        let mut app = LiveApp::new(&backend);
        live_keys(&mut app, &backend, "A6x");
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
        live_keys(&mut app, &backend, "A0e");
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
