//! Drawing for live mode. Each screen shows only what the daemon reported.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Tabs, Wrap,
    },
};

use ox_schema::Action;

use crate::live::{DETAILED, LiveApp, Query, SAFE_SECS, SIMPLE, Screen, WINDOWS, addrs, services};
use crate::tasks::{Choice, Form, Kind, Task};
use crate::ui::{
    ACCENT, BAD, DIM, MIN_H, MIN_W, OK, WARN, centered, header, kv, mmss, panel, sel_style,
};

/// `2026-11-14 10:52:03` in UTC from Unix seconds.
fn when(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    // Civil-from-days, after Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

fn action_span(a: Action) -> Span<'static> {
    let color = if a == Action::Accept { OK } else { BAD };
    Span::styled(a.as_str(), Style::new().fg(color).bold())
}

fn boxed(text: String, color: Color) -> Paragraph<'static> {
    Paragraph::new(Span::styled(text, Style::new().fg(color).bold()))
        .wrap(Wrap { trim: true })
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(color)),
        )
}

fn empty(f: &mut Frame, area: Rect, title: &str, text: &str) {
    f.render_widget(
        Paragraph::new(Span::styled(text.to_string(), Style::new().fg(DIM)))
            .wrap(Wrap { trim: true })
            .block(panel(title)),
        area,
    );
}

const NO_COMMIT: &str = "There is no commit yet, so nothing is loaded. Save a candidate with `ox candidate save <name> <file>`, then commit it on the Changes screen.";

const NOT_SET_UP: &str = "This box is not set up yet. Run `ox init --save starter` then `ox apply starter` on the box, or open its web page and enter the setup code.";

/// The plain screens fit a terminal as it opens. The detailed ones need more.
pub const SIMPLE_W: u16 = 80;
pub const SIMPLE_H: u16 = 24;

/// Text cut to fit, with a mark where it was cut.
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn dim(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(text.into(), Style::new().fg(DIM)))
}

pub fn draw(f: &mut Frame, app: &mut LiveApp) {
    let a = f.area();
    let plain = SIMPLE.contains(&app.screen);
    let (need_w, need_h) = if plain {
        (SIMPLE_W, SIMPLE_H)
    } else {
        (MIN_W, MIN_H)
    };
    if a.width < need_w || a.height < need_h {
        let msg = if plain {
            format!(
                "Netoxide needs at least {need_w}×{need_h}; this terminal is {}×{}. Enlarge it or press q.",
                a.width, a.height
            )
        } else {
            format!(
                "This detailed screen needs at least {need_w}×{need_h}; this terminal is {}×{}. Enlarge it, or press tab for the next screen.",
                a.width, a.height
            )
        };
        f.render_widget(
            Paragraph::new(msg)
                .wrap(Wrap { trim: true })
                .alignment(Alignment::Center),
            centered(a, a.width.saturating_sub(4).max(1), 3),
        );
        return;
    }
    // One banner at most: a daemon error, then the countdown, then the last result.
    let banner: Option<(String, Color)> = if let Some(e) = &app.error {
        Some((format!("oxd: {e}"), BAD))
    } else if let Some(left) = app.status.reverts_in {
        Some((
            format!(
                "Your change is applied. It undoes itself in {} unless you keep it: y keeps it, r undoes it now.",
                mmss(left)
            ),
            WARN,
        ))
    } else {
        app.message.clone().map(|m| {
            let color = if m.starts_with("refused") { BAD } else { OK };
            (m, color)
        })
    };
    // Tall enough for the text to wrap in full, up to three lines.
    let banner_h = banner.as_ref().map_or(0, |(text, _)| {
        let inner = usize::from(a.width.saturating_sub(2)).max(1);
        (text.chars().count().div_ceil(inner) as u16).clamp(1, 3) + 2
    });
    let [top, tabs, note, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(banner_h),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(a);

    draw_top(f, app, top);
    let shown = app.tabs();
    let titles: Vec<Line> = shown
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Line::from(vec![
                Span::styled(format!("{} ", (i + 1) % 10), Style::new().fg(DIM)),
                Span::raw(s.title()),
            ])
        })
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(shown.iter().position(|s| *s == app.screen))
            .highlight_style(Style::new().fg(ACCENT).bold().underlined())
            .divider("")
            .padding(" ", " "),
        tabs,
    );
    if let Some((text, color)) = banner {
        f.render_widget(boxed(text, color), note);
    }
    // Nothing has ever been read, so there is nothing true to show.
    if app.error.is_some() && app.status.applier.is_empty() {
        empty(
            f,
            body,
            "no data",
            "The daemon has not answered yet. Start oxd, or pass its socket with --socket, then press R.",
        );
        draw_footer(f, app, foot);
        return;
    }
    if let Some(form) = &app.form {
        draw_form(f, form, body);
    } else {
        match app.screen {
            Screen::Home => draw_home(f, app, body),
            Screen::Live => {
                if app.config.is_some() {
                    crate::live_view::draw(f, app.live.as_ref(), app.paused, body);
                } else {
                    empty(f, body, "live", NOT_SET_UP);
                }
            }
            Screen::Access => draw_access(f, app, body),
            Screen::Review => draw_review(f, app, body),
            Screen::Settings => draw_settings(f, app, body),
            Screen::Policy => draw_policy(f, app, body),
            Screen::Nat => draw_nat(f, app, body),
            Screen::Interfaces => draw_interfaces(f, app, body),
            Screen::Changes => draw_changes(f, app, body),
            Screen::Explain => draw_explain(f, app, body),
            Screen::Audit => draw_audit(f, app, body),
        }
    }
    draw_footer(f, app, foot);
    if app.device.is_some() {
        draw_device(f, app);
    }
    if app.show_help {
        draw_help(f);
    }
}

fn draw_top(f: &mut Frame, app: &LiveApp, area: Rect) {
    let sep = || Span::styled("  │  ", Style::new().fg(DIM));
    let host = app
        .config
        .as_ref()
        .map_or("not set up", |c| c.hostname.as_str());
    let mut spans = vec![
        Span::styled(
            " Netoxide ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::raw(" "),
        Span::styled(host.to_string(), Style::new().bold()),
        sep(),
    ];
    let n = app.status.candidates.len();
    let dry = !app.status.applier.is_empty() && app.status.applier != "kernel";
    // With no detailed screen switched on, the top line uses plain words too.
    if app.detailed.is_empty() {
        let n = app.waiting();
        let (text, color) = match (&app.status.running, dry) {
            (None, _) => ("nothing is running yet", WARN),
            (Some(_), true) => ("dry run: nothing is loaded", WARN),
            (Some(c), false) if c.pending => ("applied, not kept yet", WARN),
            (Some(_), false) => ("the firewall is running", OK),
        };
        spans.push(Span::styled(text, Style::new().fg(color)));
        spans.push(sep());
        spans.push(Span::raw(match n {
            0 => "no changes waiting".to_string(),
            1 => "1 change waiting".to_string(),
            _ => format!("{n} changes waiting"),
        }));
        f.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    match &app.status.running {
        Some(c) => {
            spans.push(Span::raw("running "));
            spans.push(Span::styled(format!("#{}", c.id), Style::new().bold()));
            if c.pending {
                spans.push(Span::styled(" unconfirmed", Style::new().fg(WARN)));
            }
        }
        None => spans.push(Span::styled("no commit yet", Style::new().fg(WARN))),
    }
    spans.push(sep());
    spans.push(Span::raw(match n {
        0 => "no candidates".to_string(),
        1 => format!("candidate {}", app.status.candidates[0]),
        _ => format!("{n} candidates"),
    }));
    if !app.status.applier.is_empty() {
        spans.push(sep());
        let (text, color) = if dry {
            ("dry run: nothing is loaded", WARN)
        } else {
            ("applying to the kernel", DIM)
        };
        spans.push(Span::styled(text, Style::new().fg(color)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(f: &mut Frame, app: &LiveApp, area: Rect) {
    let pending = app.status.reverts_in.is_some();
    let waiting = !app.status.candidates.is_empty();
    let typing = app.reason.is_some() || app.editing.is_some() || app.form.is_some();
    let mut keys: Vec<(&str, &str)> = if app.device.is_some() {
        vec![("tab", "code or text"), ("esc", "close for good")]
    } else if app.reason.is_some() {
        vec![("enter", "commit"), ("esc", "cancel")]
    } else if app.editing.is_some() {
        vec![
            ("tab", "next field"),
            ("enter", "explain"),
            ("esc", "stop editing"),
        ]
    } else if let Some(form) = &app.form {
        let mut keys = vec![("tab", "next")];
        if matches!(form.fields[form.at].kind, Kind::Pick(_)) {
            keys.push(("←→", "change"));
        }
        keys.push((
            "enter",
            if form.task == Task::Check {
                "check"
            } else {
                "see the change first"
            },
        ));
        keys.push(("esc", "cancel"));
        keys
    } else {
        match app.screen {
            Screen::Home => vec![("↑↓", "choose"), ("enter", "open")],
            Screen::Live => vec![("p", if app.paused { "resume" } else { "pause" })],
            Screen::Access => vec![("↑↓←→", "move"), ("enter", "allow or block")],
            Screen::Review if pending => vec![("y", "keep"), ("r", "undo")],
            Screen::Review if waiting => vec![("enter", "apply safely"), ("d", "discard")],
            Screen::Review => vec![],
            Screen::Settings => vec![("↑↓", "choose"), ("enter", "switch on or off")],
            Screen::Policy => vec![("←→", "zone pair"), ("↑↓", "rule"), ("x", "explain")],
            Screen::Changes if pending => vec![("↑↓", "candidate")],
            Screen::Changes => vec![
                ("↑↓", "candidate"),
                ("c", "commit"),
                ("w", "confirm window"),
            ],
            Screen::Explain => vec![
                ("e", "edit packet"),
                ("enter", "explain"),
                ("m", "compare candidate"),
            ],
            Screen::Audit => vec![("↑↓", "entry")],
            Screen::Nat | Screen::Interfaces => vec![],
        }
    };
    if !typing && app.device.is_none() {
        // The plain screens name the few keys they need. The rest are in the help.
        if !SIMPLE.contains(&app.screen) {
            if pending {
                keys.extend([("y", "keep commit"), ("r", "undo commit")]);
            }
            keys.push(("R", "reload"));
        }
        keys.extend([("tab", "next screen"), ("?", "help"), ("q", "quit")]);
    }
    let mut spans = vec![Span::raw(" ")];
    for (k, v) in keys {
        spans.push(Span::styled(
            format!(" {k} "),
            Style::new().fg(Color::Black).bg(DIM),
        ));
        spans.push(Span::styled(format!(" {v}  "), Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(f: &mut Frame) {
    let area = centered(f.area(), 72, 20);
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from("Getting around".bold()),
        kv("tab, 1 … 9", "the next screen, or a screen by its number"),
        kv("↑↓ ←→", "move the selection"),
        kv("enter", "open, switch, or send what is selected"),
        kv("esc", "leave a form without changing anything"),
        Line::from(""),
        Line::from("Changes".bold()),
        kv("a", "home: go to the waiting change"),
        kv("y, r", "keep or undo an applied change, on any screen"),
        kv("d", "review: discard the waiting change"),
        Line::from(""),
        Line::from("More".bold()),
        kv("A", "show or hide all the detailed screens"),
        kv("R", "read everything from the box again"),
        kv("q", "quit; the box carries on as it is"),
        Line::from(""),
        dim("Nothing is applied until you review it. Any key closes this."),
    ];
    f.render_widget(
        Paragraph::new(lines).block(panel("help").border_style(Style::new().fg(ACCENT))),
        area,
    );
}

/// Home: is the box all right, the networks, and the things you can do.
fn draw_home(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let Some(config) = &app.config else {
        empty(f, area, "home", NOT_SET_UP);
        return;
    };
    let grid = ox_setup::grid(config);
    let waiting = app.waiting();
    let pending = app.status.reverts_in.is_some();
    let dry = !app.status.applier.is_empty() && app.status.applier != "kernel";
    let (mark, color, headline) = if dry {
        (
            "!",
            WARN,
            "Dry run: the box keeps its config and loads nothing into the kernel",
        )
    } else if pending {
        ("!", WARN, "A change is waiting for you to keep it")
    } else {
        ("✓", OK, "The firewall is running")
    };
    let let_in = match grid.let_in.len() {
        0 => "Everything from the internet is blocked. Nothing is let in.".to_string(),
        1 => "1 thing is let in from the internet. Everything else is blocked.".to_string(),
        n => format!("{n} things are let in from the internet. Everything else is blocked."),
    };
    let status = vec![
        Line::from(vec![
            Span::styled(format!(" {mark} "), Style::new().fg(color).bold()),
            Span::styled(headline, Style::new().bold()),
        ]),
        dim(format!("   {let_in}")),
        Line::from(Span::styled(
            match waiting {
                0 => format!(
                    "   A change undoes itself after {} minutes unless you keep it.",
                    SAFE_SECS / 60
                ),
                1 => "   1 change is waiting. Nothing is applied until you review it.".to_string(),
                n => {
                    format!("   {n} changes are waiting. Nothing is applied until you review them.")
                }
            },
            Style::new().fg(if waiting == 0 { DIM } else { WARN }),
        )),
    ];

    let inside: Vec<(usize, &ox_setup::Network)> = grid
        .networks
        .iter()
        .enumerate()
        .filter(|(_, n)| !n.internet)
        .collect();
    let name_w = inside
        .iter()
        .map(|(_, n)| n.name.chars().count())
        .max()
        .unwrap_or(8)
        .clamp(8, 20)
        + 2;
    let reach_w = if area.width >= 100 { 32 } else { 26 };
    let rest_w = usize::from(
        area.width
            .saturating_sub(if area.width >= 124 { 52 } else { 2 }),
    )
    .saturating_sub(name_w + 12 + reach_w);
    let mut nets = vec![dim(format!(
        "{:<name_w$}{:<12}{:<reach_w$}{}",
        "network", "devices", "can reach", "port and address"
    ))];
    for (i, n) in &inside {
        let devices = match app.devices.get(*i).copied().unwrap_or(0) {
            1 => "1 device".to_string(),
            d => format!("{d} devices"),
        };
        nets.push(Line::from(vec![
            Span::styled(
                format!("{:<name_w$}", clip(&n.name, name_w - 1)),
                Style::new().bold(),
            ),
            Span::raw(format!("{devices:<12}")),
            Span::raw(format!("{:<reach_w$}", clip(&n.reaches, reach_w - 1))),
            Span::styled(
                clip(
                    &format!("{}  {}", n.interfaces.join(", "), n.addresses.join(", ")),
                    rest_w,
                ),
                Style::new().fg(DIM),
            ),
        ]));
    }

    let items = app.menu_items();
    let menu: Vec<ListItem> = items
        .iter()
        .map(|(choice, label)| {
            let style = if *choice == Choice::Review {
                Style::new().fg(WARN)
            } else {
                Style::new()
            };
            ListItem::new(Span::styled(label.to_string(), style))
        })
        .collect();
    let mut selected = ListState::default();
    selected.select(Some(app.menu));
    let menu = List::new(menu)
        .block(panel("what would you like to do?"))
        .highlight_style(Style::new().fg(ACCENT).bold())
        .highlight_symbol("▸ ");

    let answer = app.checked.as_ref().map(|result| match result {
        Err(e) => vec![Line::from(Span::styled(e.clone(), Style::new().fg(BAD)))],
        Ok(c) => vec![
            Line::from(vec![
                Span::styled(
                    if c.allowed { " Allowed " } else { " Blocked " },
                    Style::new()
                        .fg(Color::Black)
                        .bg(if c.allowed { OK } else { BAD })
                        .bold(),
                ),
                Span::raw(" "),
                Span::raw(c.why.clone()),
            ]),
            dim(c.packet.clone()),
        ],
    });
    let answer_h = answer.as_ref().map_or(0, |a| a.len() as u16 + 2);
    let menu_h = items.len() as u16 + 2;
    let nets_h = nets.len() as u16 + 2;

    // Side by side when there is room, stacked when there is not.
    let (top, mid, low, right) = if area.width >= 124 {
        let [left, right] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(50)]).areas(area);
        let [top, low, mid] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(answer_h),
            Constraint::Min(0),
        ])
        .areas(left);
        (top, mid, low, right)
    } else {
        // The menu keeps its lines; the networks take what is left.
        let [top, low, mid, menu] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(answer_h),
            Constraint::Max(nets_h),
            Constraint::Min(menu_h),
        ])
        .areas(area);
        (top, mid, low, menu)
    };
    f.render_widget(Paragraph::new(status).block(panel("status")), top);
    f.render_widget(Paragraph::new(nets).block(panel("your networks")), mid);
    if let Some(lines) = answer {
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(panel("is it blocked?")),
            low,
        );
    }
    f.render_stateful_widget(menu, right, &mut selected);
}

/// Access: who can reach what, one cell to move and flip.
fn draw_access(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let Some(config) = &app.config else {
        empty(f, area, "access", NOT_SET_UP);
        return;
    };
    let grid = ox_setup::grid(config);
    let n = grid.networks.len();
    let pending = app.status.reverts_in.is_some();
    let name_w = grid
        .networks
        .iter()
        .map(|n| n.name.chars().count())
        .max()
        .unwrap_or(8)
        .clamp(12, 18)
        + 2;
    let room = usize::from(area.width.saturating_sub(2)).saturating_sub(name_w);
    let cell_w = (room / n.max(1)).clamp(9, 24);
    let (row, col) = app.cell;

    let mut lines = vec![Line::from(
        std::iter::once(Span::styled(
            format!("{:<name_w$}", "from ↓  to →"),
            Style::new().fg(DIM),
        ))
        .chain(grid.networks.iter().map(|n| {
            Span::styled(
                format!("{:<cell_w$}", clip(&n.name, cell_w - 1)),
                Style::new().fg(DIM),
            )
        }))
        .collect::<Vec<_>>(),
    )];
    for (i, from) in grid.networks.iter().enumerate() {
        let mut spans = vec![Span::styled(
            format!("{:<name_w$}", clip(&from.name, name_w - 1)),
            Style::new().bold(),
        )];
        for (j, cell) in grid.cells[i].iter().enumerate() {
            let (text, style) = match cell {
                ox_setup::Cell::Same => ("—".to_string(), Style::new().fg(DIM)),
                ox_setup::Cell::Allowed => ("Allowed".to_string(), Style::new().fg(OK)),
                ox_setup::Cell::Blocked => ("Blocked".to_string(), Style::new().fg(BAD)),
                ox_setup::Cell::Custom { summary } => (summary.clone(), Style::new().fg(WARN)),
            };
            let text = clip(&text, cell_w - 2);
            if (i, j) == (row, col) {
                let pad = cell_w - 1 - text.chars().count();
                spans.push(Span::styled(format!(" {text} "), style.reversed().bold()));
                spans.push(Span::raw(" ".repeat(pad.saturating_sub(1))));
            } else {
                spans.push(Span::styled(format!(" {text:<w$}", w = cell_w - 1), style));
            }
        }
        lines.push(Line::from(spans));
    }

    // The selected cell, in a sentence, and what enter would do.
    let about = match (grid.networks.get(row), grid.networks.get(col)) {
        (Some(from), Some(to)) => {
            let pair = format!("{} to {}", from.name, to.name);
            match &grid.cells[row][col] {
                ox_setup::Cell::Same => vec![dim("A network always reaches itself.")],
                _ if from.internet => vec![
                    Line::from(format!("{pair}.")),
                    dim("The internet is let in one service at a time: see the list below."),
                ],
                ox_setup::Cell::Custom { summary } => vec![
                    Line::from(format!("{pair}: {summary}.")),
                    dim(
                        "This pair has rules of its own, for particular devices or services. It is not changed here, so nothing happens by accident.",
                    ),
                ],
                cell => {
                    let allowed = *cell == ox_setup::Cell::Allowed;
                    vec![
                        Line::from(format!(
                            "{pair}: {}.",
                            if allowed { "Allowed" } else { "Blocked" }
                        )),
                        if pending {
                            dim("A change is waiting to be kept or undone. Deal with that first.")
                        } else {
                            dim(format!(
                                "Press enter to {} it. You see the change before anything is applied.",
                                if allowed { "block" } else { "allow" }
                            ))
                        },
                    ]
                }
            }
        }
        _ => vec![],
    };

    let mut let_in: Vec<Line> = grid
        .let_in
        .iter()
        .map(|l| {
            Line::from(vec![
                Span::styled(format!("{:<26}", clip(&l.name, 25)), Style::new().bold()),
                Span::raw(format!("{:<12}", l.service)),
                Span::styled(format!("goes to {}", l.to), Style::new().fg(DIM)),
            ])
        })
        .collect();
    if let_in.is_empty() {
        let_in.push(dim(
            "Nothing. Everything arriving from the internet is blocked.",
        ));
    }

    let [table, selected, rest] = Layout::vertical([
        Constraint::Length(n as u16 + 3),
        Constraint::Length(5),
        Constraint::Min(0),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(lines).block(panel(
            "who can reach what · anything not allowed is blocked",
        )),
        table,
    );
    f.render_widget(
        Paragraph::new(about)
            .wrap(Wrap { trim: true })
            .block(panel("selected")),
        selected,
    );
    f.render_widget(
        Paragraph::new(let_in).block(panel("let in from the internet")),
        rest,
    );
}

/// Review: one waiting change in sentences, and one safe way to apply it.
fn draw_review(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let names = &app.status.candidates;
    let pending = app.status.reverts_in.is_some();
    // An applied change is past review. What is left is to keep it or undo it.
    if pending {
        let key = |k: &'static str| Span::styled(k, Style::new().fg(ACCENT).bold());
        let lines = vec![
            Line::from("Your change is applied. Check things still work.".bold()),
            Line::from(""),
            Line::from(vec![
                key("y"),
                Span::raw(" keeps it. It stays until you change it again."),
            ]),
            Line::from(vec![
                key("r"),
                Span::raw(" undoes it now. The box goes back to how it was."),
            ]),
            Line::from(""),
            dim(
                "Do nothing and it undoes itself when the time at the top runs out, so a mistake cannot lock you out.",
            ),
        ];
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(panel("keep it or undo it")),
            area,
        );
        return;
    }
    if names.is_empty() {
        empty(
            f,
            area,
            "review",
            "Nothing is waiting. A change you make on Home or Access shows up here first, and nothing is applied until you say so.",
        );
        return;
    }
    let several = names.len() > 1;
    let [list, what, how] = Layout::vertical([
        Constraint::Length(if several {
            (names.len() as u16).min(5) + 2
        } else {
            0
        }),
        Constraint::Min(4),
        Constraint::Length(6),
    ])
    .areas(area);
    if several {
        let items: Vec<ListItem> = names.iter().map(|c| ListItem::new(c.clone())).collect();
        let mut ls = ListState::default();
        ls.select(Some(app.candidate));
        f.render_stateful_widget(
            List::new(items)
                .block(panel("waiting changes · ↑↓ to choose"))
                .highlight_style(Style::new().fg(ACCENT).bold())
                .highlight_symbol("▸ "),
            list,
            &mut ls,
        );
    }

    let mut broken = false;
    let lines: Vec<Line> = match &app.plan {
        None => vec![dim("Reading the change…")],
        Some(Err(e)) => {
            broken = true;
            vec![
                Line::from(Span::styled(
                    "This change cannot be applied as it is:",
                    Style::new().fg(BAD).bold(),
                )),
                Line::from(Span::styled(e.clone(), Style::new().fg(BAD))),
            ]
        }
        Some(Ok(p)) => {
            let mut v = vec![];
            if p.first_commit {
                v.push(Line::from("This is the first config for the box."));
            }
            for line in &p.headline {
                v.push(Line::from(vec![
                    Span::styled("• ", Style::new().fg(ACCENT)),
                    Span::styled(line.clone(), Style::new().bold()),
                ]));
            }
            if !p.starts.is_empty() || !p.stops.is_empty() {
                if !p.headline.is_empty() {
                    v.push(Line::from(""));
                    v.push(dim("In detail"));
                }
                if !p.starts.is_empty() {
                    v.push(Line::from("The box will start doing this:"));
                    v.extend(p.starts.iter().map(|l| {
                        Line::from(Span::styled(format!("  + {l}"), Style::new().fg(OK)))
                    }));
                }
                if !p.stops.is_empty() {
                    v.push(Line::from("The box will stop doing this:"));
                    v.extend(p.stops.iter().map(|l| {
                        Line::from(Span::styled(format!("  - {l}"), Style::new().fg(BAD)))
                    }));
                }
            } else if !p.first_commit && p.headline.is_empty() {
                v.push(if p.changes.is_empty() {
                    dim("Nothing. This is the same as what the box does now.")
                } else {
                    dim(format!(
                        "This changes details that have no plain sentence: {}",
                        p.changes.join("; ")
                    ))
                });
            }
            v
        }
    };
    let title = match app.selected_candidate() {
        Some(name) if several => format!("what will change · {name}"),
        _ => "what will change".to_string(),
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(title)),
        what,
    );

    let last = if app.discarding {
        Line::from(Span::styled(
            "Press d again to throw this change away. Any other key keeps it.",
            Style::new().fg(WARN).bold(),
        ))
    } else if broken {
        dim("Press d to discard it.")
    } else {
        Line::from(vec![
            Span::styled("enter", Style::new().fg(ACCENT).bold()),
            Span::raw(" applies it safely.  "),
            Span::styled("d", Style::new().fg(ACCENT).bold()),
            Span::raw(" discards it. Nothing changes until you choose."),
        ])
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "You get {} minutes to check things still work. If you do not keep the change, it undoes itself, so a mistake cannot lock you out.",
                SAFE_SECS / 60
            )),
            Line::from(""),
            last,
        ])
        .wrap(Wrap { trim: true })
        .block(panel("apply safely")),
        how,
    );
}

/// Settings: the basics, and a switch for each detailed screen.
fn draw_settings(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let dry = !app.status.applier.is_empty() && app.status.applier != "kernel";
    let basics = vec![
        kv(
            "box name",
            app.config
                .as_ref()
                .map_or("not set up".to_string(), |c| c.hostname.clone()),
        ),
        kv(
            "changes",
            format!(
                "applied safely: each undoes itself after {} minutes unless kept",
                SAFE_SECS / 60
            ),
        ),
        kv(
            "rules",
            if dry {
                "dry run: nothing is loaded into the kernel"
            } else {
                "loaded into the kernel of this box"
            },
        ),
    ];
    let label_w = DETAILED.iter().map(|d| d.1.len()).max().unwrap_or(0) + 2;
    let items: Vec<ListItem> = DETAILED
        .iter()
        .map(|(screen, title, about)| {
            let on = app.detailed.contains(screen);
            ListItem::new(Line::from(vec![
                Span::styled(
                    if on { "[x] " } else { "[ ] " },
                    Style::new().fg(if on { OK } else { DIM }),
                ),
                Span::raw(format!("{title:<label_w$}")),
                Span::styled(about.to_string(), Style::new().fg(DIM)),
            ]))
        })
        .collect();
    let [top, switches] = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).areas(area);
    f.render_widget(Paragraph::new(basics).block(panel("basics")), top);
    let mut ls = ListState::default();
    ls.select(Some(app.switch));
    f.render_stateful_widget(
        List::new(items)
            .block(
                panel("detailed screens · each adds a tab").title_bottom(Span::styled(
                    " a switch shows or hides a screen and never changes what the box does ",
                    Style::new().fg(DIM),
                )),
            )
            .highlight_style(Style::new().bold())
            .highlight_symbol("▸ "),
        switches,
        &mut ls,
    );
}

/// A task: a few lines to fill in, then one key to see the change.
fn draw_form(f: &mut Frame, form: &Form, area: Rect) {
    let inner = usize::from(area.width.saturating_sub(4));
    let label_w = form
        .fields
        .iter()
        .map(|f| f.label.chars().count())
        .max()
        .unwrap_or(0)
        + 2;
    let value_w = inner.saturating_sub(label_w + 4).max(8);
    let mut lines = vec![dim(form.about), Line::from("")];
    for (i, field) in form.fields.iter().enumerate() {
        let here = i == form.at;
        let mut spans = vec![
            Span::styled(
                if here { "▸ " } else { "  " },
                Style::new().fg(ACCENT).bold(),
            ),
            Span::styled(
                format!("{:<label_w$}", field.label),
                if here {
                    Style::new().bold()
                } else {
                    Style::new()
                },
            ),
        ];
        match &field.kind {
            Kind::Pick(_) => {
                let style = if here {
                    Style::new().fg(Color::Black).bg(ACCENT)
                } else {
                    Style::new()
                };
                spans.push(Span::styled(
                    if here { "‹ " } else { "  " },
                    Style::new().fg(DIM),
                ));
                spans.push(Span::styled(
                    if field.value.is_empty() {
                        "none".to_string()
                    } else {
                        field.value.clone()
                    },
                    style,
                ));
                spans.push(Span::styled(
                    if here { " ›" } else { "" },
                    Style::new().fg(DIM),
                ));
            }
            Kind::Text if field.value.is_empty() && !here => {
                spans.push(Span::styled(
                    format!(
                        "  {}",
                        if field.required {
                            format!("such as {}", field.hint)
                        } else {
                            field.hint.to_string()
                        }
                    ),
                    Style::new().fg(DIM),
                ));
            }
            Kind::Text => {
                // A long value shows its end, where the typing is.
                let count = field.value.chars().count();
                let shown: String = field
                    .value
                    .chars()
                    .skip(count.saturating_sub(value_w))
                    .collect();
                spans.push(Span::raw("  "));
                if here {
                    spans.push(Span::styled(
                        format!("{shown}█"),
                        Style::new().fg(Color::Black).bg(ACCENT),
                    ));
                    if field.value.is_empty() {
                        spans.push(Span::styled(
                            format!(
                                "  {}",
                                if field.required {
                                    format!("such as {}", field.hint)
                                } else {
                                    format!("leave empty: {}", field.hint)
                                }
                            ),
                            Style::new().fg(DIM),
                        ));
                    }
                } else {
                    spans.push(Span::raw(shown));
                }
            }
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    if let Some(error) = &form.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::new().fg(BAD).bold(),
        )));
    } else if !form.note.is_empty() {
        lines.push(dim(form.note));
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(form.title.to_lowercase()).border_style(Style::new().fg(ACCENT))),
        area,
    );
}

/// A VPN device's settings: a code to scan if it fits, and the text.
fn draw_device(f: &mut Frame, app: &LiveApp) {
    let Some(device) = &app.device else {
        return;
    };
    let area = f.area();
    f.render_widget(Clear, area);
    let block = panel("set up the device").border_style(Style::new().fg(ACCENT));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut intro = if device.key_made_here {
        vec![
            Line::from(
                "These settings hold the device's private key. They are shown once and kept nowhere on the box.",
            ),
            Line::from("Scan the code with the WireGuard app, or copy the text into it."),
        ]
    } else {
        vec![Line::from(
            "Put the device's own private key where the settings say, then load them into WireGuard.",
        )]
    };
    intro.push(dim(
        "The device can connect once you apply the waiting change. esc closes this for good.",
    ));
    // Tall enough for each sentence to wrap in full, and a blank line after.
    let wide = usize::from(inner.width).max(1);
    let intro_h = intro
        .iter()
        .map(|l| l.width().div_ceil(wide).max(1) as u16)
        .sum::<u16>()
        + 1;
    let [top, rest] =
        Layout::vertical([Constraint::Length(intro_h), Constraint::Min(0)]).areas(inner);
    f.render_widget(Paragraph::new(intro).wrap(Wrap { trim: true }), top);

    // A code is only any use with the device's key inside it.
    let code = device
        .key_made_here
        .then(|| ox_setup::qr_rows(&device.config))
        .flatten()
        .map(|rows| ox_setup::qr_text(&rows));
    let size = code.as_ref().map(|c| {
        (
            c.lines().next().map_or(0, |l| l.chars().count()) as u16,
            c.lines().count() as u16,
        )
    });
    let text_w = device
        .config
        .lines()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0) as u16;
    let fits = size.is_some_and(|(w, h)| w <= rest.width && h <= rest.height);
    let both = size.is_some_and(|(w, h)| w + 2 + text_w <= rest.width && h <= rest.height);
    let code_style = Style::new().fg(Color::White).bg(Color::Black);
    let text = |extra: Option<String>| {
        let mut lines: Vec<Line> = device
            .config
            .lines()
            .map(|l| Line::from(l.to_string()))
            .collect();
        if let Some(extra) = extra {
            lines.push(Line::from(""));
            lines.push(dim(extra));
        }
        Paragraph::new(lines).wrap(Wrap { trim: false })
    };
    match (&code, size) {
        (Some(code), Some((w, _))) if both => {
            let [left, _, right] = Layout::horizontal([
                Constraint::Length(w),
                Constraint::Length(2),
                Constraint::Min(0),
            ])
            .areas(rest);
            f.render_widget(Paragraph::new(code.clone()).style(code_style), left);
            f.render_widget(text(None), right);
        }
        (Some(code), Some((w, h))) if fits && !app.device_text => {
            let [left, _] =
                Layout::horizontal([Constraint::Length(w), Constraint::Min(0)]).areas(rest);
            let [left, _] =
                Layout::vertical([Constraint::Length(h), Constraint::Min(0)]).areas(left);
            f.render_widget(Paragraph::new(code.clone()).style(code_style), left);
        }
        (_, Some((w, h))) if !fits => f.render_widget(
            text(Some(format!(
                "A code to scan needs a window of at least {}×{}; this one is {}×{}.",
                w + 2,
                h + intro_h + 2,
                area.width,
                area.height
            ))),
            rest,
        ),
        _ => f.render_widget(text(None), rest),
    }
}

fn draw_policy(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let Some(config) = &app.config else {
        empty(f, area, "policy", NO_COMMIT);
        return;
    };
    if config.policies.is_empty() {
        empty(
            f,
            area,
            "policy",
            "The running config has no policies, so every forwarded packet is dropped.",
        );
        return;
    }
    let [left, right] =
        Layout::horizontal([Constraint::Length(28), Constraint::Min(0)]).areas(area);
    let items: Vec<ListItem> = config
        .policies
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:<19}", format!("{} → {}", p.from, p.to))),
                Span::styled(format!("{:>3}", p.rules.len()), Style::new().fg(DIM)),
            ]))
        })
        .collect();
    let total: usize = config.policies.iter().map(|p| p.rules.len()).sum();
    let mut ls = ListState::default();
    ls.select(Some(app.pair));
    f.render_stateful_widget(
        List::new(items)
            .block(panel("zone pairs").title_bottom(Span::styled(
                format!(" {total} rules · {} pairs ", config.policies.len()),
                Style::new().fg(DIM),
            )))
            .highlight_style(Style::new().fg(ACCENT).bold())
            .highlight_symbol("▸ "),
        left,
        &mut ls,
    );

    let policy = &config.policies[app.pair];
    let [tbl, detail] = Layout::vertical([Constraint::Min(6), Constraint::Length(8)]).areas(right);
    let hits =
        |id: &str| -> String { app.hits.get(id).map_or("—".to_string(), |n| n.to_string()) };
    let mut rows: Vec<Row> = policy
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut name = vec![
                Span::styled(format!("{} ", r.id), Style::new().fg(DIM)),
                Span::raw(r.name.clone()),
            ];
            if !r.enabled {
                name.push(Span::styled(" (disabled)", Style::new().fg(WARN)));
            }
            let what = Line::from(Span::styled(
                format!(
                    "  {} → {} · {}",
                    addrs(&r.source),
                    addrs(&r.destination),
                    services(r)
                ),
                Style::new().fg(DIM),
            ));
            Row::new(vec![
                Cell::from(Span::styled(format!("{}", i + 1), Style::new().fg(DIM))),
                Cell::from(Text::from(vec![Line::from(name), what])),
                Cell::from(action_span(r.action)),
                Cell::from(Line::from(hits(&r.id)).alignment(Alignment::Right)),
                Cell::from(if r.log { "logged" } else { "" }),
            ])
            .height(2)
        })
        .collect();
    rows.push(
        Row::new(vec![
            Cell::from("—"),
            Cell::from("default for this pair: any → any · any"),
            Cell::from(action_span(Action::Drop)),
            Cell::from(
                Line::from(hits(&format!("default {}-{}", policy.from, policy.to)))
                    .alignment(Alignment::Right),
            ),
            Cell::from(if policy.log_default { "logged" } else { "" }),
        ])
        .style(Style::new().fg(DIM)),
    );
    let mut state = TableState::default();
    state.select((!policy.rules.is_empty()).then_some(app.rule));
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Fill(1),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(7),
            ],
        )
        .header(header(&["#", "rule", "action", "packets", "log"]))
        .block(panel(format!(
            "{} → {} · {} rules · first match wins",
            policy.from,
            policy.to,
            policy.rules.len()
        )))
        .row_highlight_style(sel_style())
        .highlight_symbol("▸")
        .column_spacing(1),
        tbl,
        &mut state,
    );

    let lines = match policy.rules.get(app.rule) {
        None => vec![Line::from(Span::styled(
            "This pair has no rules, so everything in it is dropped.",
            Style::new().fg(DIM),
        ))],
        Some(r) => vec![
            Line::from(vec![
                Span::styled(r.id.clone(), Style::new().fg(ACCENT).bold()),
                Span::raw("  "),
                Span::raw(r.name.clone()).bold(),
            ]),
            kv("source", addrs(&r.source)),
            kv("destination", addrs(&r.destination)),
            kv("service", services(r)),
            kv(
                "reason",
                r.reason.clone().unwrap_or_else(|| "none given".into()),
            ),
            kv(
                "state",
                if r.enabled {
                    "enabled, in the kernel"
                } else {
                    "disabled, left out of the kernel"
                },
            ),
        ],
    };
    f.render_widget(
        Paragraph::new(lines).block(panel("rule").title_bottom(Span::styled(
            " packets are kernel counters since the last load ",
            Style::new().fg(DIM),
        ))),
        detail,
    );
}

fn draw_nat(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let Some(config) = &app.config else {
        empty(f, area, "nat", NO_COMMIT);
        return;
    };
    let [fwd, out] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let rows: Vec<Row> = config
        .nat
        .forward
        .iter()
        .map(|n| {
            Row::new(vec![
                Cell::from(Span::styled(n.id.clone(), Style::new().fg(DIM))),
                Cell::from(n.name.clone()),
                Cell::from(n.from.clone()),
                Cell::from(format!(
                    "{} {}",
                    n.address
                        .map_or("the box's address".to_string(), |a| a.to_string()),
                    n.service
                )),
                Cell::from(match n.to_port {
                    Some(p) => format!("{} port {p}", n.to),
                    None => n.to.to_string(),
                }),
                Cell::from(n.rule.clone()),
                Cell::from(
                    Line::from(
                        app.hits
                            .get(&n.id)
                            .map_or("—".to_string(), |h| h.to_string()),
                    )
                    .alignment(Alignment::Right),
                ),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Fill(2),
                Constraint::Length(10),
                Constraint::Fill(2),
                Constraint::Fill(2),
                Constraint::Length(14),
                Constraint::Length(10),
            ],
        )
        .header(header(&[
            "id",
            "name",
            "from zone",
            "match",
            "translate to",
            "filter rule",
            "packets",
        ]))
        .block(
            panel(format!("port forwards · {}", config.nat.forward.len())).title_bottom(
                Span::styled(
                    " a forward only rewrites the destination; its filter rule decides ",
                    Style::new().fg(DIM),
                ),
            ),
        ),
        fwd,
    );
    let rows: Vec<Row> = config
        .nat
        .outbound
        .iter()
        .map(|n| {
            Row::new(vec![
                Cell::from(Span::styled(n.id.clone(), Style::new().fg(DIM))),
                Cell::from(n.name.clone()),
                Cell::from(format!("{} → {}", n.from, n.to)),
                Cell::from(addrs(&n.source)),
                Cell::from(n.translate.to_string()),
                Cell::from(
                    Line::from(
                        app.hits
                            .get(&n.id)
                            .map_or("—".to_string(), |h| h.to_string()),
                    )
                    .alignment(Alignment::Right),
                ),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Fill(2),
                Constraint::Length(22),
                Constraint::Fill(2),
                Constraint::Length(16),
                Constraint::Length(10),
            ],
        )
        .header(header(&[
            "id",
            "name",
            "zones",
            "source",
            "translate",
            "packets",
        ]))
        .block(panel(format!("outbound · {}", config.nat.outbound.len()))),
        out,
    );
}

fn draw_interfaces(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let Some(config) = &app.config else {
        empty(f, area, "interfaces", NO_COMMIT);
        return;
    };
    let rows: Vec<Row> = config
        .interfaces
        .iter()
        .map(|(name, i)| {
            Row::new(vec![
                Cell::from(Span::styled(name.clone(), Style::new().bold())),
                Cell::from(i.zone.clone()),
                Cell::from(
                    config
                        .zones
                        .get(&i.zone)
                        .and_then(|z| z.description.clone())
                        .unwrap_or_default(),
                ),
                Cell::from(
                    i.addresses
                        .iter()
                        .map(|a| a.0.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                Cell::from(if i.default_route { "default route" } else { "" }),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(12),
                Constraint::Fill(1),
                Constraint::Fill(2),
                Constraint::Length(14),
            ],
        )
        .header(header(&[
            "interface",
            "zone",
            "zone description",
            "addresses",
            "route",
        ]))
        .block(
            panel(format!("interfaces · {}", config.interfaces.len())).title_bottom(Span::styled(
                " from the running config; link state is not read yet ",
                Style::new().fg(DIM),
            )),
        ),
        area,
    );
}

fn draw_changes(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area);
    let n = app.status.candidates.len() as u16;
    let [list, plan] =
        Layout::vertical([Constraint::Length(n.clamp(1, 8) + 2), Constraint::Min(6)]).areas(left);

    if app.status.candidates.is_empty() {
        empty(
            f,
            list,
            "candidates",
            "none; save one with `ox candidate save <name> <file>`",
        );
    } else {
        let items: Vec<ListItem> = app
            .status
            .candidates
            .iter()
            .map(|c| ListItem::new(c.clone()))
            .collect();
        let mut ls = ListState::default();
        ls.select(Some(app.candidate));
        f.render_stateful_widget(
            List::new(items)
                .block(panel("candidates"))
                .highlight_style(Style::new().fg(ACCENT).bold())
                .highlight_symbol("▸ "),
            list,
            &mut ls,
        );
    }

    let title = app
        .selected_candidate()
        .map_or("plan".to_string(), |c| format!("plan · {c}"));
    let lines: Vec<Line> = match &app.plan {
        None => vec![Line::from(Span::styled(
            "Select a candidate to see its plan.",
            Style::new().fg(DIM),
        ))],
        Some(Err(e)) => vec![Line::from(Span::styled(
            format!("cannot plan: {e}"),
            Style::new().fg(BAD),
        ))],
        Some(Ok(p)) => {
            let ok =
                |t: String| Line::from(vec![Span::styled("✓ ", Style::new().fg(OK)), Span::raw(t)]);
            let mut v = vec![
                ok("schema validation passed".into()),
                ok(format!("compiled {}", p.summary)),
                ok("one nftables transaction, atomic swap".into()),
                Line::from(""),
            ];
            if p.first_commit {
                v.push(Line::from(
                    "first commit: there is no running config to compare with",
                ));
            } else if p.changes.is_empty() {
                v.push(Line::from(Span::styled(
                    "no changes against the running config",
                    Style::new().fg(DIM),
                )));
            } else {
                v.push(Line::from(format!("{} change(s)", p.changes.len()).bold()));
                for c in &p.changes {
                    let color = match c.chars().next() {
                        Some('+') => OK,
                        Some('-') => BAD,
                        _ => WARN,
                    };
                    v.push(Line::from(Span::styled(c.clone(), Style::new().fg(color))));
                }
            }
            v
        }
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(title)),
        plan,
    );

    let [now, how] = Layout::vertical([Constraint::Length(8), Constraint::Min(6)]).areas(right);
    let lines = match &app.status.running {
        None => vec![Line::from(Span::styled(
            "no commit yet; nothing is loaded",
            Style::new().fg(WARN),
        ))],
        Some(c) => vec![
            Line::from(vec![
                Span::styled(format!("#{}", c.id), Style::new().fg(ACCENT).bold()),
                Span::raw(if c.pending {
                    "  unconfirmed"
                } else {
                    "  confirmed"
                }),
            ]),
            kv("by", c.author.clone()),
            kv("from", c.source.clone()),
            kv(
                "reason",
                if c.reason.is_empty() {
                    "none given".into()
                } else {
                    c.reason.clone()
                },
            ),
        ],
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("running")),
        now,
    );

    let window = WINDOWS[app.window];
    let name = app.selected_candidate().unwrap_or("<candidate>");
    let lines = vec![
        kv("confirm window", mmss(window)),
        Line::from(Span::styled(
            "The commit reverts by itself unless you press y inside the window.",
            Style::new().fg(DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("$ ox commit {name} --confirm {window}s"),
            Style::new().fg(ACCENT),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("commit")),
        how,
    );

    if let Some(reason) = &app.reason {
        let r = centered(f.area(), 70, 7);
        f.render_widget(Clear, r);
        let lines = vec![
            Line::from(format!("Commit {name} with a {} window", mmss(window)).bold()),
            Line::from(""),
            Line::from(vec![
                Span::styled("reason  ", Style::new().fg(DIM)),
                Span::raw(reason.clone()),
                Span::styled("█", Style::new().fg(ACCENT)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "enter commits · esc cancels",
                Style::new().fg(DIM),
            )),
        ];
        f.render_widget(
            Paragraph::new(lines).block(panel("commit").border_style(Style::new().fg(WARN))),
            r,
        );
    }
}

fn draw_explain(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    let [form, results] = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).areas(area);
    let mut spans = vec![];
    for (i, label) in Query::FIELDS.iter().enumerate() {
        let value = app.query.field(i);
        let editing = app.editing == Some(i);
        spans.push(Span::styled(format!("{label} "), Style::new().fg(DIM)));
        let shown = if value.is_empty() && !editing {
            "—".to_string()
        } else {
            value.to_string()
        };
        spans.push(if editing {
            Span::styled(
                format!("{shown}█"),
                Style::new().fg(Color::Black).bg(ACCENT),
            )
        } else {
            Span::raw(shown)
        });
        spans.push(Span::raw("   "));
    }
    let compare = match (app.compare, app.selected_candidate()) {
        (true, Some(c)) => format!("also against candidate {c}"),
        (true, None) => "no candidate to compare with".to_string(),
        (false, _) => "running config only".to_string(),
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(spans),
            Line::from(""),
            Line::from(Span::styled(compare, Style::new().fg(DIM))),
        ])
        .block(panel("why did this packet do that?")),
        form,
    );

    let result = match &app.explained {
        None => {
            empty(
                f,
                results,
                "result",
                "Press e to type a packet, or press x on a rule in Policy.",
            );
            return;
        }
        Some(Err(e)) => {
            f.render_widget(boxed(format!("cannot explain: {e}"), BAD), results);
            return;
        }
        Some(Ok(r)) => r,
    };
    let sides: Vec<(String, &crate::live::ExplainSide)> = [
        result.running.as_ref().map(|s| ("running".to_string(), s)),
        result.candidate.as_ref().map(|s| {
            (
                format!("candidate {}", app.selected_candidate().unwrap_or("")),
                s,
            )
        }),
    ]
    .into_iter()
    .flatten()
    .collect();
    if sides.is_empty() {
        empty(
            f,
            results,
            "result",
            "There is no commit yet, so nothing decides this packet.",
        );
        return;
    }
    let cols = Layout::horizontal(vec![Constraint::Ratio(1, sides.len() as u32); sides.len()])
        .split(results);
    for (i, (title, side)) in sides.iter().enumerate() {
        let color = if side.verdict == "ACCEPT" { OK } else { BAD };
        let mut lines = vec![
            Line::from(vec![
                Span::raw("verdict  "),
                Span::styled(
                    format!(" {} ", side.verdict),
                    Style::new().fg(Color::Black).bg(color).bold(),
                ),
            ]),
            Line::from(""),
        ];
        lines.extend(side.lines.iter().map(|l| Line::from(l.clone())));
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(panel(title)),
            cols[i],
        );
    }
}

fn draw_audit(f: &mut Frame, app: &mut LiveApp, area: Rect) {
    if app.audit.is_empty() {
        empty(f, area, "audit log", "The audit log is empty.");
        return;
    }
    let [tbl, detail] = Layout::vertical([Constraint::Min(6), Constraint::Length(5)]).areas(area);
    // Newest first.
    let rows: Vec<Row> = app
        .audit
        .iter()
        .rev()
        .map(|e| {
            Row::new(vec![
                Cell::from(Line::from(e.seq.to_string()).alignment(Alignment::Right)),
                Cell::from(when(e.time)),
                Cell::from(e.who.clone()),
                Cell::from(e.event.clone()),
                Cell::from(e.detail.clone()),
                Cell::from(Span::styled(
                    format!("{}…", &e.hash[..e.hash.len().min(10)]),
                    Style::new().fg(DIM),
                )),
            ])
        })
        .collect();
    let mut state = TableState::default();
    state.select(Some(app.audit_row));
    f.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(4),
                Constraint::Length(19),
                Constraint::Length(12),
                Constraint::Length(17),
                Constraint::Fill(1),
                Constraint::Length(11),
            ],
        )
        .header(header(&[
            "#",
            "time (UTC)",
            "who",
            "event",
            "detail",
            "hash",
        ]))
        .block(panel(format!(
            "audit log · {} entries · hash chain verified by oxd",
            app.audit.len()
        )))
        .row_highlight_style(sel_style())
        .highlight_symbol("▸"),
        tbl,
        &mut state,
    );
    let selected = app.audit.iter().rev().nth(app.audit_row);
    let lines = selected.map_or(vec![], |e| {
        vec![
            Line::from(e.detail.clone()),
            Line::from(Span::styled(
                format!("hash {}", e.hash),
                Style::new().fg(DIM),
            )),
        ]
    });
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("entry")),
        detail,
    );
}
