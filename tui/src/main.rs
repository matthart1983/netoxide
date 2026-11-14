//! netoxide-tui: a terminal UI prototype for the Netoxide firewall.
//!
//! Run it:            cargo run --release
//! Print a screen:    cargo run -- --snapshot policy [--size 160x48]
//!                    cargo run -- --snapshot all
//! Replay keys first: cargo run -- --snapshot changes --keys c
//! Coloured web page: cargo run -- --html netoxide-tui.html
//!
//! All data is mock data from `data.rs`. Nothing talks to a firewall.

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
        let path = args.get(i + 1).map(String::as_str).unwrap_or("netoxide-tui.html");
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
        let mut term = Terminal::new(TestBackend::new(w, h))?;
        term.draw(|f| ui::draw(f, &mut app))?;
        let buf = term.backend().buffer();
        let mut out = io::stdout().lock();
        // Stop quietly if the reader goes away (e.g. piped into `head`).
        if writeln!(out, "── {} ──", s.title()).is_err() {
            return Ok(());
        }
        for y in 0..h {
            let mut line = String::new();
            let mut x = 0;
            while x < w {
                let cell = &buf[(x, y)];
                line.push_str(cell.symbol());
                x += 1;
            }
            if writeln!(out, "{}", line.trim_end()).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}
