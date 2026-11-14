//! `--html <file>`: render a set of screens and states, colours included, into
//! one self-contained HTML page, so the TUI can be viewed without a terminal.

use std::fmt::Write as _;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, style::Color, style::Modifier};

use crate::app::{App, Screen};
use crate::ui;

const FG: &str = "#d4d7dd";
const BG: &str = "#0e1116";

fn hex(c: Color, fallback: &str) -> String {
    match c {
        Color::Reset => fallback.into(),
        Color::Black => "#0e1116".into(),
        Color::Red => "#f87171".into(),
        Color::Green => "#4ade80".into(),
        Color::Yellow => "#facc15".into(),
        Color::Blue => "#60a5fa".into(),
        Color::Magenta => "#e879f9".into(),
        Color::Cyan => "#22d3ee".into(),
        Color::Gray => "#a8adb7".into(),
        Color::DarkGray => "#6b7280".into(),
        Color::LightRed => "#fca5a5".into(),
        Color::LightGreen => "#86efac".into(),
        Color::LightYellow => "#fde68a".into(),
        Color::LightBlue => "#93c5fd".into(),
        Color::LightMagenta => "#f0abfc".into(),
        Color::LightCyan => "#a5f3fc".into(),
        Color::White => "#f3f4f6".into(),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Indexed(_) => fallback.into(),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn buffer_to_html(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in 0..area.height {
        let mut run_style = String::new();
        let mut run_text = String::new();
        for x in 0..area.width {
            let cell = &buf[(x, y)];
            if cell.skip {
                continue;
            }
            let m = cell.modifier;
            let (mut fg, mut bg) = (hex(cell.fg, FG), hex(cell.bg, BG));
            if m.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let mut st = String::new();
            if fg != FG {
                let _ = write!(st, "color:{fg};");
            }
            if bg != BG {
                let _ = write!(st, "background:{bg};");
            }
            if m.contains(Modifier::BOLD) {
                st.push_str("font-weight:700;");
            }
            if m.contains(Modifier::UNDERLINED) {
                st.push_str("text-decoration:underline;");
            }
            if st != run_style {
                flush(&mut out, &run_style, &run_text);
                run_text.clear();
                run_style = st;
            }
            run_text.push_str(cell.symbol());
        }
        flush(&mut out, &run_style, &run_text);
        out.push('\n');
    }
    out
}

fn flush(out: &mut String, style: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    if style.is_empty() {
        out.push_str(&esc(text));
    } else {
        let _ = write!(out, "<span style=\"{style}\">{}</span>", esc(text));
    }
}

fn render(screen: Screen, keys: &str, w: u16, h: u16) -> String {
    let mut app = App::new();
    app.screen = screen;
    for c in keys.chars() {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    }
    let mut term = Terminal::new(TestBackend::new(w, h)).expect("test backend");
    term.draw(|f| ui::draw(f, &mut app)).expect("draw");
    buffer_to_html(term.backend().buffer())
}

pub fn page(w: u16, h: u16) -> String {
    // (group, label, screen, keys replayed, caption)
    let states: &[(&str, &str, Screen, &str, &str)] = &[
        (
            "Firewall",
            "1 Policy",
            Screen::Policy,
            "",
            "Rules for the lan → dmz pair. The ◆ rule exists only in the candidate.",
        ),
        (
            "Firewall",
            "Policy · lan → wan",
            Screen::Policy,
            "lj",
            "After → and ↓: another zone pair, second rule selected, hygiene flag visible.",
        ),
        (
            "Firewall",
            "2 NAT",
            Screen::Nat,
            "",
            "Port forwards. Each one names its filter rule. ←→ switches NAT type.",
        ),
        (
            "Firewall",
            "NAT · outbound",
            Screen::Nat,
            "l",
            "Outbound NAT per zone and egress interface.",
        ),
        (
            "Firewall",
            "3 VPN",
            Screen::Vpn,
            "jjjjj",
            "Site-to-site tunnels with the down tunnel selected; its reason shows on the panel edge.",
        ),
        (
            "Firewall",
            "4 IPS",
            Screen::Ips,
            "",
            "Suricata inline: per-zone mode, fail-open or fail-closed, recent events.",
        ),
        (
            "Firewall",
            "5 Interfaces",
            Screen::Interfaces,
            "",
            "Interfaces, VLANs, LAG, PPPoE, multi-WAN gateway group and policy routing.",
        ),
        (
            "Firewall",
            "6 HA",
            Screen::Ha,
            "",
            "Active/backup pair, authenticated state sync, failover test history.",
        ),
        (
            "Firewall",
            "HA · press f",
            Screen::Ha,
            "f",
            "Failover asks first.",
        ),
        (
            "Firewall",
            "HA · then y",
            Screen::Ha,
            "fy",
            "After failover: node b is active and the top bar follows.",
        ),
        (
            "Operate",
            "7 Changes",
            Screen::Changes,
            "",
            "Candidate diff, plan, change impact, four-eyes approval.",
        ),
        (
            "Operate",
            "Changes · press c",
            Screen::Changes,
            "c",
            "Commit with confirm: applied, countdown in the top bar on every screen.",
        ),
        (
            "Operate",
            "Changes · then y",
            Screen::Changes,
            "cy",
            "Confirmed: committed as #2482.",
        ),
        (
            "Operate",
            "8 Explain",
            Screen::Explain,
            "",
            "Why did this packet do that? Against the running config: ACCEPT.",
        ),
        (
            "Operate",
            "Explain · press m",
            Screen::Explain,
            "m",
            "Same packet against the candidate: DROP, with the rule's origin.",
        ),
        (
            "Operate",
            "9 Admin/Audit",
            Screen::Audit,
            "",
            "Administrators, scoped API tokens, hash-chained audit log.",
        ),
        (
            "Fleet",
            "0 Fleet",
            Screen::Fleet,
            "",
            "Fleet controller: drift, approvals, tunnels, support expiry, rollout rings.",
        ),
        (
            "Fleet",
            "Help · press ?",
            Screen::Fleet,
            "?",
            "Key reference overlay.",
        ),
    ];

    let mut nav = String::new();
    let mut panes = String::new();
    let mut last_group = "";
    for (i, (group, label, screen, keys, caption)) in states.iter().enumerate() {
        if *group != last_group {
            let _ = write!(nav, "<div class=\"grp\">{group}</div>");
            last_group = group;
        }
        let keyinfo = if keys.is_empty() {
            String::new()
        } else {
            format!(" <span class=\"keys\">keys: {}</span>", esc(keys))
        };
        let _ = write!(
            nav,
            "<button type=\"button\" data-i=\"{i}\"{}>{}</button>",
            if i == 0 {
                " aria-pressed=\"true\""
            } else {
                " aria-pressed=\"false\""
            },
            esc(label)
        );
        let _ = write!(
            panes,
            "<section data-i=\"{i}\"{}><p class=\"cap\">{}{keyinfo}</p><pre class=\"term\">{}</pre></section>",
            if i == 0 { "" } else { " hidden" },
            esc(caption),
            render(*screen, keys, w, h)
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netoxide-tui · Netoxide terminal UI</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; background: #07090c; color: {FG}; font-family: Inter, system-ui, sans-serif; }}
  header {{ padding: 20px 24px 8px; display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: baseline; }}
  h1 {{ margin: 0; font-size: 18px; font-weight: 600; }}
  header p {{ margin: 0; color: #9aa1ad; font-size: 13px; }}
  .wrap {{ display: flex; flex-wrap: wrap; gap: 16px; padding: 8px 24px 32px; }}
  nav {{ flex: 1 1 200px; max-width: 220px; display: flex; flex-direction: column; gap: 2px; }}
  .grp {{ font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: #8b93a1; padding: 12px 10px 4px; }}
  nav button {{ text-align: left; background: transparent; color: #c9ced6; border: 0; border-radius: 6px; padding: 9px 10px; min-height: 36px; font: inherit; font-size: 13px; cursor: pointer; }}
  nav button:hover {{ background: #141922; }}
  nav button[aria-pressed="true"] {{ background: #12303a; color: #22d3ee; font-weight: 600; }}
  main {{ flex: 999 1 600px; min-width: 0; }}
  .cap {{ margin: 0 0 10px; font-size: 13px; color: #b6bcc6; }}
  .keys {{ margin-left: 8px; font-family: 'JetBrains Mono', monospace; color: #facc15; }}
  .term {{ margin: 0; background: {BG}; color: {FG}; border: 1px solid #1f2630; border-radius: 10px; padding: 14px 16px; overflow-x: auto;
          font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace; font-size: 12.5px; line-height: 1.18; box-shadow: 0 10px 40px rgba(0,0,0,.45); }}
  footer {{ padding: 0 24px 24px; color: #8b93a1; font-size: 12px; }}
</style>
</head>
<body>
<header><h1>netoxide-tui · Netoxide terminal UI</h1><p>Rendered from the ratatui code at {w}×{h}. Mock data. Use the list or ←/→ to step through screens and states.</p></header>
<div class="wrap">
<nav aria-label="Screens">{nav}</nav>
<main>{panes}</main>
</div>
<footer>Each frame is the program's own render buffer, converted cell by cell to HTML. Run it yourself with <code>cargo run --release</code>.</footer>
<script>
  const btns = [...document.querySelectorAll('nav button')];
  const panes = [...document.querySelectorAll('main section')];
  function show(i) {{
    btns.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.i == i)));
    panes.forEach(p => p.hidden = p.dataset.i != i);
  }}
  btns.forEach(b => b.addEventListener('click', () => show(b.dataset.i)));
  document.addEventListener('keydown', e => {{
    if (e.target.closest('input,textarea')) return;
    const cur = btns.findIndex(b => b.getAttribute('aria-pressed') === 'true');
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {{ e.preventDefault(); show(Math.min(cur + 1, btns.length - 1)); btns[Math.min(cur + 1, btns.length - 1)].focus(); }}
    if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {{ e.preventDefault(); show(Math.max(cur - 1, 0)); btns[Math.max(cur - 1, 0)].focus(); }}
  }});
</script>
</body>
</html>
"#
    )
}
