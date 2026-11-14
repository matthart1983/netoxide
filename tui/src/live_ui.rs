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

use crate::live::{LiveApp, Query, Screen, WINDOWS, addrs, services};
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

pub fn draw(f: &mut Frame, app: &mut LiveApp) {
    let a = f.area();
    if a.width < MIN_W || a.height < MIN_H {
        let msg = format!(
            "Netoxide needs at least {MIN_W}×{MIN_H}; this terminal is {}×{}. Enlarge it or press q.",
            a.width, a.height
        );
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
        let id = app.status.running.as_ref().map_or(0, |c| c.id);
        Some((
            format!(
                "Commit #{id} is applied and reverts in {} unless you press y. Press r to undo it now.",
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
    let titles: Vec<Line> = Screen::ALL
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Line::from(vec![
                Span::styled(format!("{} ", i + 1), Style::new().fg(DIM)),
                Span::raw(s.title()),
            ])
        })
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.screen.index())
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
    match app.screen {
        Screen::Policy => draw_policy(f, app, body),
        Screen::Nat => draw_nat(f, app, body),
        Screen::Interfaces => draw_interfaces(f, app, body),
        Screen::Changes => draw_changes(f, app, body),
        Screen::Explain => draw_explain(f, app, body),
        Screen::Audit => draw_audit(f, app, body),
    }
    draw_footer(f, app, foot);
    if app.show_help {
        draw_help(f);
    }
}

fn draw_top(f: &mut Frame, app: &LiveApp, area: Rect) {
    let sep = || Span::styled("  │  ", Style::new().fg(DIM));
    let host = app
        .config
        .as_ref()
        .map_or("no config", |c| c.hostname.as_str());
    let mut spans = vec![
        Span::styled(
            " Netoxide ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::raw(" "),
        Span::styled(host.to_string(), Style::new().bold()),
        sep(),
    ];
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
    let n = app.status.candidates.len();
    spans.push(Span::raw(match n {
        0 => "no candidates".to_string(),
        1 => format!("candidate {}", app.status.candidates[0]),
        _ => format!("{n} candidates"),
    }));
    if !app.status.applier.is_empty() {
        spans.push(sep());
        let (text, color) = if app.status.applier == "kernel" {
            ("applying to the kernel", DIM)
        } else {
            ("dry run: nothing is loaded", WARN)
        };
        spans.push(Span::styled(text, Style::new().fg(color)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(f: &mut Frame, app: &LiveApp, area: Rect) {
    let pending = app.status.reverts_in.is_some();
    let mut keys: Vec<(&str, &str)> = if app.reason.is_some() {
        vec![("enter", "commit"), ("esc", "cancel")]
    } else if app.editing.is_some() {
        vec![
            ("tab", "next field"),
            ("enter", "explain"),
            ("esc", "stop editing"),
        ]
    } else {
        match app.screen {
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
    if app.reason.is_none() && app.editing.is_none() {
        if pending {
            keys.extend([("y", "keep commit"), ("r", "undo commit")]);
        }
        keys.extend([
            ("1-6", "screens"),
            ("R", "reload"),
            ("?", "help"),
            ("q", "quit"),
        ]);
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
    let area = centered(f.area(), 66, 17);
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from("Navigation".bold()),
        kv("1 … 6, tab", "screens"),
        kv("↑↓ or j k", "move the selection"),
        kv("←→ or h l", "zone pair on Policy"),
        kv("R", "read everything from the daemon again"),
        Line::from(""),
        Line::from("Actions".bold()),
        kv("x", "policy: explain a packet the rule is about"),
        kv("c, w", "changes: commit the candidate; cycle the window"),
        kv("y, r", "keep or undo an unconfirmed commit, anywhere"),
        kv("e, enter, m", "explain: edit, run, compare with candidate"),
        Line::from(""),
        Line::from(Span::styled(
            "Everything shown comes from oxd. Any key closes this.",
            Style::new().fg(DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).block(panel("help").border_style(Style::new().fg(ACCENT))),
        area,
    );
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
                Cell::from(format!("{} {}", n.address, n.service)),
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
