use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table,
        Tabs, Wrap,
    },
};

use crate::app::{App, CommitPhase, Screen};
use crate::data::{self, Action};

pub(crate) const ACCENT: Color = Color::Cyan;
pub(crate) const DIM: Color = Color::DarkGray;
pub(crate) const OK: Color = Color::Green;
pub(crate) const WARN: Color = Color::Yellow;
pub(crate) const BAD: Color = Color::Red;

pub(crate) fn panel(title: impl AsRef<str>) -> Block<'static> {
    let title = title.as_ref();
    let b = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(DIM));
    if title.is_empty() {
        b
    } else {
        b.title(Span::styled(format!(" {title} "), Style::new().bold()))
    }
}

pub(crate) fn header(cells: &[&'static str]) -> Row<'static> {
    Row::new(cells.iter().map(|c| Cell::from(*c)))
        .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD))
        .bottom_margin(0)
}

pub(crate) fn sel_style() -> Style {
    Style::new()
        .bg(Color::Rgb(30, 41, 59))
        .add_modifier(Modifier::BOLD)
}

fn action_cell(a: Action) -> Cell<'static> {
    let color = match a {
        Action::Accept => OK,
        Action::Drop | Action::Reject => BAD,
    };
    Cell::from(Span::styled(a.label(), Style::new().fg(color).bold()))
}

pub(crate) fn kv(k: &str, v: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{k:<16}"), Style::new().fg(DIM)),
        Span::raw(v.into()),
    ])
}

pub(crate) fn mmss(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

// The smallest terminal where no screen clips a value. Policy and Changes
// also reflow below this, but the wide tables (VPN, IPS, Interfaces) do not.
pub const MIN_W: u16 = 132;
pub const MIN_H: u16 = 34;

pub fn draw(f: &mut Frame, app: &mut App) {
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
    let [top, tabs, body, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(f.area());

    draw_top(f, app, top);
    draw_tabs(f, app, tabs);
    match app.screen {
        Screen::Policy => draw_policy(f, app, body),
        Screen::Nat => draw_nat(f, app, body),
        Screen::Vpn => draw_vpn(f, app, body),
        Screen::Ips => draw_ips(f, app, body),
        Screen::Interfaces => draw_interfaces(f, app, body),
        Screen::Ha => draw_ha(f, app, body),
        Screen::Changes => draw_changes(f, app, body),
        Screen::Explain => draw_explain(f, app, body),
        Screen::Audit => draw_audit(f, app, body),
        Screen::Fleet => draw_fleet(f, app, body),
        Screen::Import => draw_import(f, body),
    }
    draw_footer(f, app, foot);

    if app.show_help {
        draw_help(f);
    }
}

fn draw_top(f: &mut Frame, app: &App, area: Rect) {
    let active = if app.ha_active_a {
        "syd-br-014-a"
    } else {
        "syd-br-014-b"
    };
    let mut spans = vec![
        Span::styled(
            " Netoxide ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::raw(" "),
        Span::styled(active, Style::new().bold()),
        Span::styled(" ● active", Style::new().fg(OK)),
        Span::styled("  │  ", Style::new().fg(DIM)),
        Span::raw("running "),
        Span::styled(app.running_commit(), Style::new().bold()),
    ];
    if matches!(app.commit, CommitPhase::Pending { .. }) {
        spans.push(Span::styled(" unconfirmed", Style::new().fg(WARN)));
    }
    spans.push(Span::styled("  │  ", Style::new().fg(DIM)));
    match app.commit {
        CommitPhase::Pending { .. } => {
            let left = app.commit_remaining().unwrap_or(0);
            spans.push(Span::styled(
                format!(" reverts in {} · y confirm · r revert ", mmss(left)),
                Style::new().fg(Color::Black).bg(WARN).bold(),
            ));
        }
        CommitPhase::Confirmed => spans.push(Span::styled("no candidate", Style::new().fg(DIM))),
        _ => {
            spans.push(Span::raw("candidate "));
            spans.push(Span::styled("block-legacy-smb", Style::new().fg(WARN)));
        }
    }
    // The support date is the least urgent item, so it goes first when the bar is full.
    let support = "  │  support to 30 Nov 2026";
    let approved = " (approved)";
    let reviewing = matches!(
        app.commit,
        CommitPhase::Review | CommitPhase::Reverted { .. }
    );
    let mut used: usize = spans.iter().map(Span::width).sum();
    let width = area.width as usize;
    if reviewing && used + approved.len() + support.chars().count() <= width {
        spans.push(Span::styled(approved, Style::new().fg(DIM)));
        used += approved.len();
    }
    if used + support.chars().count() <= width {
        spans.push(Span::styled("  │  ", Style::new().fg(DIM)));
        spans.push(Span::styled("support to 30 Nov 2026", Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Screen::ALL
        .iter()
        .map(|s| {
            Line::from(vec![
                Span::styled(format!("{} ", s.key()), Style::new().fg(DIM)),
                Span::raw(s.title()),
            ])
        })
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.screen.index())
        .highlight_style(Style::new().fg(ACCENT).bold().underlined())
        // No divider: eleven tabs with dividers don't fit in 110 columns.
        .divider("")
        .padding(" ", " ");
    f.render_widget(tabs, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let screen_keys: &[(&str, &str)] = match app.screen {
        Screen::Policy => &[("←→", "zone pair"), ("↑↓", "rule"), ("x", "explain")],
        Screen::Nat => &[("←→", "NAT type"), ("↑↓", "rule")],
        Screen::Vpn | Screen::Ips | Screen::Interfaces | Screen::Audit | Screen::Fleet => {
            &[("↑↓", "select")]
        }
        Screen::Ha => &[("f", "fail over")],
        Screen::Changes => match app.commit {
            CommitPhase::Pending { .. } => &[("y", "confirm commit"), ("r", "revert now")],
            CommitPhase::Confirmed => &[],
            _ => &[("c", "commit with confirm"), ("w", "confirm window")],
        },
        Screen::Explain if app.applied() => &[],
        Screen::Explain => &[("m", "running ↔ candidate")],
        Screen::Import => &[],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, v) in screen_keys.iter().chain(
        [
            ("1-0 i", "screens"),
            ("tab", "next"),
            ("?", "help"),
            ("q", "quit"),
        ]
        .iter(),
    ) {
        spans.push(Span::styled(
            format!(" {k} "),
            Style::new().fg(Color::Black).bg(DIM),
        ));
        spans.push(Span::styled(format!(" {v}  "), Style::new().fg(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(f: &mut Frame) {
    let area = centered(f.area(), 60, 18);
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from("Navigation".bold()),
        kv("1 … 9, 0, i", "jump to a screen (0 fleet, i import)"),
        kv("tab / shift-tab", "next / previous screen"),
        kv("↑↓ or j k", "move the selection"),
        kv("←→ or h l", "zone pair (policy), NAT type (nat)"),
        Line::from(""),
        Line::from("Actions".bold()),
        kv("x", "policy: explain a packet"),
        kv("c / y / r", "changes: commit with confirm, confirm, revert"),
        kv("w", "changes: cycle confirm window 2/5/10 min"),
        kv("m", "explain: running config ↔ candidate"),
        kv("f", "ha: fail over to the other node"),
        Line::from(""),
        Line::from(Span::styled(
            "All data is mock data. Nothing talks to a box.",
            Style::new().fg(DIM),
        )),
        Line::from(Span::styled("Any key closes this.", Style::new().fg(DIM))),
    ];
    f.render_widget(
        Paragraph::new(lines).block(panel("help").border_style(Style::new().fg(ACCENT))),
        area,
    );
}

pub(crate) fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

// ───────────────────────────── Policy ─────────────────────────────

fn draw_policy(f: &mut Frame, app: &mut App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Length(24), Constraint::Min(0)]).areas(area);

    let items: Vec<ListItem> = app
        .pairs
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:<14}", p.label)),
                Span::styled(format!("{:>4}", p.total), Style::new().fg(DIM)),
            ]))
        })
        .collect();
    let mut ls = ListState::default();
    ls.select(Some(app.pair_idx));
    let list = List::new(items)
        .block(panel("zone pairs").title_bottom(Span::styled(
            format!(
                " {} rules · {} pairs ",
                app.pairs.iter().map(|p| p.total).sum::<u32>(),
                app.pairs.len()
            ),
            Style::new().fg(DIM),
        )))
        .highlight_style(Style::new().fg(ACCENT).bold())
        .highlight_symbol("▸ ");
    f.render_stateful_widget(list, left, &mut ls);

    let pair = &app.pairs[app.pair_idx];
    // The rule list takes the spare height; the detail panel stays at the bottom.
    let [tbl, detail] = Layout::vertical([Constraint::Min(6), Constraint::Length(7)]).areas(right);
    // A candidate rule is marked until its commit is confirmed.
    let (has_candidate, applied) = (app.has_candidate(), app.applied());
    let marked = |r: &data::Rule| r.pending && has_candidate;
    let (legend, legend_color) = match app.commit {
        CommitPhase::Pending { .. } => (" ◆ applied, waiting for confirm ", WARN),
        CommitPhase::Confirmed => ("", DIM),
        _ => (" ◆ in candidate, not applied ", WARN),
    };
    let shown = if pair.rules.len() as u32 == pair.total {
        format!("{} rules", pair.total)
    } else {
        format!("showing {} of {} rules", pair.rules.len(), pair.total)
    };

    // Under 110 columns the source, destination and service columns would be
    // cut to a few characters, so each rule takes two lines instead.
    let narrow = right.width < 112;
    if narrow {
        let mut rows: Vec<Row> = pair
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let mut name = vec![Span::styled(format!("{} ", r.id), Style::new().fg(DIM))];
                if marked(r) {
                    name.push(Span::styled("◆ ", Style::new().fg(WARN).bold()));
                }
                name.push(Span::raw(r.name));
                let what = Line::from(Span::styled(
                    format!("  {} → {} · {}", r.src, r.dst, r.svc),
                    Style::new().fg(DIM),
                ));
                Row::new(vec![
                    Cell::from(Span::styled(format!("{}", i + 1), Style::new().fg(DIM))),
                    Cell::from(Text::from(vec![Line::from(name), what])),
                    action_cell(r.action),
                    Cell::from(Line::from(r.hits).alignment(Alignment::Right)),
                    Cell::from(Span::styled(r.hygiene, Style::new().fg(WARN))),
                ])
                .height(2)
            })
            .collect();
        rows.push(
            Row::new(vec![
                Cell::from("—"),
                Cell::from("default for this pair: any → any · any"),
                action_cell(Action::Drop),
                Cell::from(Line::from(pair.default_hits).alignment(Alignment::Right)),
                Cell::from("logged"),
            ])
            .style(Style::new().fg(DIM)),
        );
        let table = Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Fill(1),
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Length(19),
            ],
        )
        .header(header(&["#", "rule", "action", "hits 30d", "hygiene"]))
        .block(
            panel(format!("{} · {shown} · first match wins", pair.label))
                .title_bottom(Span::styled(legend, Style::new().fg(legend_color))),
        )
        .row_highlight_style(sel_style())
        .highlight_symbol("▸")
        .column_spacing(1);
        if let Some(i) = app.rule_state.selected()
            && i >= pair.rules.len()
        {
            app.rule_state.select(Some(0));
        }
        f.render_stateful_widget(table, tbl, &mut app.rule_state);
    } else {
        let mut rows: Vec<Row> = pair
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let mut name = vec![];
                if marked(r) {
                    name.push(Span::styled("◆ ", Style::new().fg(WARN).bold()));
                }
                name.push(Span::raw(r.name));
                let hy = if r.hygiene.is_empty() {
                    Cell::from("")
                } else {
                    Cell::from(Span::styled(r.hygiene, Style::new().fg(WARN)))
                };
                Row::new(vec![
                    Cell::from(Span::styled(format!("{}", i + 1), Style::new().fg(DIM))),
                    Cell::from(Span::styled(r.id, Style::new().fg(DIM))),
                    Cell::from(Line::from(name)),
                    Cell::from(r.src),
                    Cell::from(r.dst),
                    Cell::from(r.svc),
                    action_cell(r.action),
                    Cell::from(Line::from(r.hits).alignment(Alignment::Right)),
                    hy,
                ])
            })
            .collect();
        rows.push(
            Row::new(vec![
                Cell::from("—"),
                Cell::from(""),
                Cell::from("default for this pair"),
                Cell::from("any"),
                Cell::from("any"),
                Cell::from("any"),
                action_cell(Action::Drop),
                Cell::from(Line::from(pair.default_hits).alignment(Alignment::Right)),
                Cell::from("logged"),
            ])
            .style(Style::new().fg(DIM)),
        );

        let widths = [
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(19),
        ];
        let table = Table::new(rows, widths)
            .header(header(&[
                "#",
                "id",
                "rule",
                "source",
                "destination",
                "service",
                "action",
                "hits 30d",
                "hygiene",
            ]))
            .block(
                panel(format!("{} · {shown} · first match wins", pair.label))
                    .title_bottom(Span::styled(legend, Style::new().fg(legend_color))),
            )
            .row_highlight_style(sel_style())
            .highlight_symbol("▸")
            .column_spacing(1);
        // The default row is display-only; keep the selection on real rules.
        if let Some(i) = app.rule_state.selected()
            && i >= pair.rules.len()
        {
            app.rule_state.select(Some(0));
        }
        f.render_stateful_widget(table, tbl, &mut app.rule_state);
    }

    let r = &pair.rules[app.rule_state.selected().unwrap_or(0)];
    let mut lines = vec![
        Line::from(vec![
            Span::styled(r.id, Style::new().fg(ACCENT).bold()),
            Span::raw("  "),
            Span::raw(r.name).bold(),
        ]),
        kv("match", format!("{} → {}  {}", r.src, r.dst, r.svc)),
        kv("schedule", r.schedule),
        kv(
            "logging",
            if r.log {
                "yes, rule ID in flow log and syslog"
            } else {
                "counters only"
            },
        ),
    ];
    if marked(r) {
        lines.push(kv(
            "state",
            if applied {
                "applied from candidate block-legacy-smb, waiting for confirm"
            } else {
                "in candidate block-legacy-smb, not applied"
            },
        ));
    } else if !r.hygiene.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<16}", "hygiene"), Style::new().fg(DIM)),
            Span::styled(r.hygiene, Style::new().fg(WARN)),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(panel("rule").title_bottom(Span::styled(
            " edits go to a candidate and apply only through a commit ",
            Style::new().fg(DIM),
        ))),
        detail,
    );
}

// ───────────────────────────── NAT ─────────────────────────────

fn draw_nat(f: &mut Frame, app: &mut App, area: Rect) {
    let [tabs, blurb, tbl] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(0),
    ])
    .areas(area);
    let titles: Vec<String> = app
        .nat
        .iter()
        .map(|t| format!("{} ({})", t.label, t.rows.len()))
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.nat_idx)
            .highlight_style(Style::new().fg(ACCENT).bold())
            .divider(Span::styled("·", Style::new().fg(DIM))),
        tabs,
    );
    let tab = &app.nat[app.nat_idx];
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {}", tab.blurb),
            Style::new().fg(DIM),
        ))
        .wrap(Wrap { trim: true }),
        blurb,
    );
    let rows: Vec<Row> = tab
        .rows
        .iter()
        .map(|n| {
            Row::new(vec![
                Cell::from(Span::styled(n.id, Style::new().fg(DIM))),
                Cell::from(n.name),
                Cell::from(n.matches),
                Cell::from(n.to),
                Cell::from(Span::styled(n.rule, Style::new().fg(ACCENT))),
                Cell::from(n.hairpin),
                Cell::from(Line::from(n.hits).alignment(Alignment::Right)),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(6),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Length(11),
        Constraint::Length(7),
        Constraint::Length(9),
    ];
    let t = Table::new(rows, widths)
        .header(header(&[
            "id",
            "name",
            "match",
            "translate to",
            "filter rule",
            "hairpin",
            "hits 30d",
        ]))
        .block(panel(format!("NAT · {}", tab.label)))
        .row_highlight_style(sel_style())
        .highlight_symbol("▸");
    f.render_stateful_widget(t, tbl, &mut app.nat_state);
}

// ───────────────────────────── VPN ─────────────────────────────

fn draw_vpn(f: &mut Frame, app: &mut App, area: Rect) {
    let [sum, tbl, bottom] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(9),
        Constraint::Length(9),
    ])
    .areas(area);

    let s = Line::from(vec![
        Span::styled("site-to-site ", Style::new().fg(DIM)),
        Span::styled("5/6 up", Style::new().bold()),
        Span::styled("   remote users ", Style::new().fg(DIM)),
        Span::styled("42", Style::new().bold()),
        Span::styled("   sign-in ", Style::new().fg(DIM)),
        Span::raw("OIDC (Entra ID)"),
        Span::styled("   FIPS mode ", Style::new().fg(DIM)),
        Span::raw("off — when on, IPsec only"),
    ]);
    f.render_widget(Paragraph::new(s).block(panel("vpn")), sum);

    let tunnels = data::tunnels();
    let rows: Vec<Row> = tunnels
        .iter()
        .map(|t| {
            let st = if t.up {
                Span::styled("● up", Style::new().fg(OK))
            } else {
                Span::styled("✕ down", Style::new().fg(BAD).bold())
            };
            Row::new(vec![
                Cell::from(t.name),
                Cell::from(t.kind),
                Cell::from(t.peer),
                Cell::from(t.nets),
                Cell::from(st),
                Cell::from(t.last),
                Cell::from(Line::from(t.bytes).alignment(Alignment::Right)),
            ])
        })
        .collect();
    let sel = &tunnels[app.tunnel_state.selected().unwrap_or(0)];
    let bottom_title = if sel.up {
        Span::styled(format!(" {} healthy ", sel.name), Style::new().fg(DIM))
    } else {
        Span::styled(format!(" {}: {} ", sel.name, sel.why), Style::new().fg(BAD))
    };
    let widths = [
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Fill(1),
        Constraint::Fill(1),
        Constraint::Length(7),
        Constraint::Length(18),
        Constraint::Length(15),
    ];
    let t = Table::new(rows, widths)
        .header(header(&[
            "tunnel",
            "type",
            "peer",
            "local ↔ remote",
            "status",
            "handshake/rekey",
            "in / out 24h",
        ]))
        .block(panel("site-to-site").title_bottom(bottom_title))
        .row_highlight_style(sel_style())
        .highlight_symbol("▸");
    f.render_stateful_widget(t, tbl, &mut app.tunnel_state);

    let [users, groups] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);
    let urows: Vec<Row> = data::VPN_USERS
        .iter()
        .map(|(n, g, a, s)| Row::new(vec![*n, *g, *a, *s]))
        .collect();
    f.render_widget(
        Table::new(
            urows,
            [
                Constraint::Fill(1),
                Constraint::Length(12),
                Constraint::Length(11),
                Constraint::Length(6),
            ],
        )
        .header(header(&["user", "group", "address", "since"]))
        .block(panel("remote access · WireGuard portal")),
        users,
    );
    let mut gl: Vec<Line> = data::VPN_GROUPS
        .iter()
        .map(|(g, r)| {
            Line::from(vec![
                Span::raw(format!("{g:<13}")),
                Span::styled(*r, Style::new().fg(ACCENT)),
            ])
        })
        .collect();
    gl.push(Line::from(""));
    gl.push(Line::from(Span::styled(
        "keys expire after 12 h; removing a user from the IdP group disconnects them within 5 min",
        Style::new().fg(DIM),
    )));
    f.render_widget(
        Paragraph::new(gl)
            .wrap(Wrap { trim: true })
            .block(panel("IdP group → policy")),
        groups,
    );
}

// ───────────────────────────── IPS ─────────────────────────────

fn draw_ips(f: &mut Frame, app: &mut App, area: Rect) {
    let [sum, zones, events] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(8),
        Constraint::Min(6),
    ])
    .areas(area);
    let [a, b] =
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(sum);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Suricata 8 inline · ruleset ", Style::new().fg(DIM)),
                Span::raw("ET Open"),
                Span::styled(" updated 03:10, signature ok", Style::new().fg(DIM)),
            ]),
            Line::from(vec![
                Span::styled("blocked 24h ", Style::new().fg(DIM)),
                Span::styled("1,286", Style::new().bold()),
                Span::styled("   alerted only ", Style::new().fg(DIM)),
                Span::styled("214", Style::new().bold()),
            ]),
        ])
        .block(panel("intrusion prevention")),
        a,
    );
    f.render_widget(
        Gauge::default()
            .block(panel("inspection load"))
            .gauge_style(Style::new().fg(ACCENT).bg(Color::Rgb(30, 41, 59)))
            .ratio(0.62)
            .label("310 of 500 Mb/s branch target"),
        b,
    );

    let zrows: Vec<Row> = data::IPS_ZONES
        .iter()
        .map(|(z, m, p, s, fl)| {
            let c = match *m {
                "block" => Style::new().fg(ACCENT).bold(),
                "alert" => Style::new().fg(WARN).bold(),
                _ => Style::new().fg(DIM),
            };
            Row::new(vec![
                Cell::from(*z),
                Cell::from(Span::styled(*m, c)),
                Cell::from(*p),
                Cell::from(*s),
                Cell::from(*fl),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            zrows,
            [
                Constraint::Length(13),
                Constraint::Length(7),
                Constraint::Fill(1),
                Constraint::Length(12),
                Constraint::Fill(1),
            ],
        )
        .header(header(&[
            "zone pair",
            "mode",
            "profile",
            "suppressed",
            "on engine failure",
        ]))
        .block(panel("per-zone mode")),
        zones,
    );

    let erows: Vec<Row> = data::IPS_EVENTS
        .iter()
        .map(|(t, sev, sig, flow, pair, act)| {
            let sc = match *sev {
                "high" => Style::new().fg(BAD).bold(),
                "medium" => Style::new().fg(WARN),
                _ => Style::new().fg(DIM),
            };
            Row::new(vec![
                Cell::from(*t),
                Cell::from(Span::styled(*sev, sc)),
                Cell::from(*sig),
                Cell::from(*flow),
                Cell::from(*pair),
                Cell::from(*act),
            ])
        })
        .collect();
    let t = Table::new(
        erows,
        [
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Length(11),
            Constraint::Length(7),
        ],
    )
    .header(header(&[
        "time",
        "sev",
        "signature",
        "flow",
        "zone pair",
        "action",
    ]))
    .block(panel("recent events").title_bottom(Span::styled(
        " ET Open only; no paid feed. Bring your own commercial ruleset key if you have one ",
        Style::new().fg(DIM),
    )))
    .row_highlight_style(sel_style())
    .highlight_symbol("▸");
    f.render_stateful_widget(t, events, &mut app.ips_state);
}

// ───────────────────────────── Interfaces ─────────────────────────────

fn draw_interfaces(f: &mut Frame, app: &mut App, area: Rect) {
    let [tbl, bottom] = Layout::vertical([Constraint::Min(10), Constraint::Length(10)]).areas(area);
    let rows: Vec<Row> = data::IFACES
        .iter()
        .map(|(n, t, z, v4, v6, l, r)| {
            Row::new(vec![
                Cell::from(Span::styled(*n, Style::new().bold())),
                Cell::from(*t),
                Cell::from(Span::styled(*z, Style::new().fg(ACCENT))),
                Cell::from(*v4),
                Cell::from(*v6),
                Cell::from(*l),
                Cell::from(Line::from(*r).alignment(Alignment::Right)),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(19),
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(9),
            Constraint::Length(14),
        ],
    )
    .header(header(&[
        "iface",
        "type",
        "zone",
        "ipv4",
        "ipv6",
        "link",
        "in / out now",
    ]))
    .block(panel("interfaces · Intel N100, 4 × 2.5GbE igc"))
    .row_highlight_style(sel_style())
    .highlight_symbol("▸");
    f.render_stateful_widget(t, tbl, &mut app.iface_state);

    let [gw, pr] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(bottom);
    let grows: Vec<Row> = data::GATEWAYS
        .iter()
        .map(|(n, s, tier, lat, loss, probe)| {
            let sc = if s.starts_with("active") {
                Style::new().fg(OK).bold()
            } else {
                Style::new()
            };
            Row::new(vec![
                Cell::from(*n),
                Cell::from(Span::styled(*s, sc)),
                Cell::from(*tier),
                Cell::from(*lat),
                Cell::from(*loss),
                Cell::from(*probe),
            ])
        })
        .collect();
    let gw_block =
        panel("gateway group: internet · failover, probe 1 s").title_bottom(Span::styled(
            " fail over at >10% loss or >250 ms for 5 s · fail back after 60 s ",
            Style::new().fg(DIM),
        ));
    f.render_widget(
        Table::new(
            grows,
            [
                Constraint::Fill(1),
                Constraint::Length(16),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Length(6),
                Constraint::Length(17),
            ],
        )
        .header(header(&[
            "gateway", "state", "tier", "latency", "loss", "probe",
        ]))
        .block(gw_block),
        gw,
    );
    let mut lines: Vec<Line> = data::POLICY_ROUTES
        .iter()
        .map(|(m, v)| {
            Line::from(vec![
                Span::raw(format!("{m:<30}")),
                Span::styled(*v, Style::new().fg(ACCENT)),
            ])
        })
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "IPv6: wan0 gets 2001:db8:4a00::/56 by DHCPv6-PD; VLANs 20/30/40 track /64s 1/2/3 and follow prefix changes",
        Style::new().fg(DIM),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("policy routing")),
        pr,
    );
}

// ───────────────────────────── HA ─────────────────────────────

fn draw_ha(f: &mut Frame, app: &mut App, area: Rect) {
    let msg_h = if app.ha_message.is_some() { 3 } else { 0 };
    let [msg, nodes, sync, tests] = Layout::vertical([
        Constraint::Length(msg_h),
        Constraint::Length(8),
        Constraint::Length(4),
        Constraint::Min(6),
    ])
    .areas(area);

    if let Some(m) = &app.ha_message {
        f.render_widget(
            Paragraph::new(Span::styled(m.clone(), Style::new().fg(OK).bold())).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(OK)),
            ),
            msg,
        );
    }

    let [a, b] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(nodes);
    for (i, (rect, name, prio, ct)) in [
        (a, "syd-br-014-a", "200", "412,903"),
        (b, "syd-br-014-b", "100", "412,880"),
    ]
    .into_iter()
    .enumerate()
    {
        let is_active = (i == 0) == app.ha_active_a;
        let badge = if is_active {
            Span::styled(" ACTIVE ", Style::new().fg(Color::Black).bg(OK).bold())
        } else {
            Span::styled(" STANDBY ", Style::new().fg(Color::Black).bg(DIM).bold())
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(name, Style::new().bold()),
                Span::raw("  "),
                badge,
            ]),
            kv("VRRP priority", prio),
            kv("running config", app.running_commit()),
            kv("version", "1.0.4, slot B"),
            kv("conntrack", ct),
            kv("uptime", "41 days"),
        ];
        let border = if is_active { OK } else { DIM };
        f.render_widget(
            Paragraph::new(lines).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(border)),
            ),
            rect,
        );
    }

    let sync_lines = vec![
        Line::from(vec![
            Span::styled("state sync   ", Style::new().fg(DIM)),
            Span::raw("conntrackd over igc3, encrypted link · lag 120 ms, 23 entries behind  "),
            Span::styled("authenticated", Style::new().fg(OK)),
        ]),
        Line::from(vec![
            Span::styled("config sync  ", Style::new().fg(DIM)),
            Span::raw("one transaction to both nodes; backup failure rolls back primary  "),
            Span::styled(
                format!("both on {}", app.running_commit()),
                Style::new().fg(OK),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(sync_lines).block(panel("sync")), sync);

    let rows: Vec<Row> = data::HA_TESTS
        .iter()
        .map(|(d, t, l, loss, kept, pass)| {
            let res = if *pass {
                Span::styled("pass", Style::new().fg(OK).bold())
            } else {
                Span::styled("miss: sync lag in IPS reload", Style::new().fg(BAD).bold())
            };
            Row::new(vec![
                Cell::from(*d),
                Cell::from(*t),
                Cell::from(*l),
                Cell::from(Line::from(*loss).alignment(Alignment::Right)),
                Cell::from(Line::from(*kept).alignment(Alignment::Right)),
                Cell::from(res),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(11),
                Constraint::Fill(1),
                Constraint::Length(13),
                Constraint::Length(7),
                Constraint::Length(10),
                Constraint::Length(28),
            ],
        )
        .header(header(&[
            "date",
            "trigger",
            "load",
            "loss",
            "flows kept",
            "result",
        ]))
        .block(
            panel("failover tests · target < 1 s loss, ≥ 99% of TCP flows kept").title_bottom(
                Span::styled(
                    " active/backup only; active/active is not supported ",
                    Style::new().fg(DIM),
                ),
            ),
        ),
        tests,
    );

    if app.ha_confirming {
        let other = if app.ha_active_a {
            "syd-br-014-b"
        } else {
            "syd-br-014-a"
        };
        let r = centered(f.area(), 64, 8);
        f.render_widget(Clear, r);
        let lines = vec![
            Line::from(format!("Move traffic to {other}?").bold()),
            Line::from(""),
            Line::from("State sync is current (lag 120 ms). Expect under 1 s of"),
            Line::from("forwarding loss. This is written to the audit log."),
            Line::from(""),
            Line::from(vec![
                Span::styled(" y ", Style::new().fg(Color::Black).bg(WARN).bold()),
                Span::raw(" fail over now    "),
                Span::styled(" any other key ", Style::new().fg(Color::Black).bg(DIM)),
                Span::raw(" cancel"),
            ]),
        ];
        f.render_widget(
            Paragraph::new(lines).block(panel("fail over").border_style(Style::new().fg(WARN))),
            r,
        );
    }
}

// ───────────────────────────── Changes ─────────────────────────────

fn draw_changes(f: &mut Frame, app: &mut App, area: Rect) {
    let banner_h = if matches!(app.commit, CommitPhase::Review) {
        0
    } else {
        3
    };
    let [banner, main] =
        Layout::vertical([Constraint::Length(banner_h), Constraint::Min(0)]).areas(area);

    let (text, color) = match app.commit {
        CommitPhase::Review => (String::new(), DIM),
        CommitPhase::Pending { .. } => (
            format!(
                "Applied as {}. Reverts in {} unless you confirm (y). Revert replays {} through the reconciler, no reboot.",
                data::NEXT_COMMIT,
                mmss(app.commit_remaining().unwrap_or(0)),
                data::BASE_COMMIT
            ),
            WARN,
        ),
        CommitPhase::Confirmed => (
            format!(
                "Committed as {}. Both HA nodes run it and the candidate is closed.",
                data::NEXT_COMMIT
            ),
            OK,
        ),
        CommitPhase::Reverted { auto: true } => (
            format!(
                "Not confirmed in time. Reverted to {} in 0.4 s. The candidate is kept.",
                data::BASE_COMMIT
            ),
            BAD,
        ),
        CommitPhase::Reverted { auto: false } => (
            format!(
                "Reverted to {} in 0.4 s. The candidate is kept.",
                data::BASE_COMMIT
            ),
            Color::White,
        ),
    };
    if banner_h > 0 {
        f.render_widget(
            Paragraph::new(Span::styled(text, Style::new().fg(color).bold())).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(color)),
            ),
            banner,
        );
    }

    let [diff, right] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(main);
    let lines: Vec<Line> = data::DIFF
        .iter()
        .map(|(k, t)| match k {
            '+' => Line::from(Span::styled(format!("+ {t}"), Style::new().fg(OK))),
            '-' => Line::from(Span::styled(format!("- {t}"), Style::new().fg(BAD))),
            _ => Line::from(Span::styled(format!("  {t}"), Style::new().fg(Color::Gray))),
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(
            panel(if app.has_candidate() {
                "candidate block-legacy-smb · gateway.toml · +9 −1".to_string()
            } else {
                format!("commit {} · gateway.toml · +9 −1", data::NEXT_COMMIT)
            })
            .title_bottom(Span::styled(
                " by j.nguyen · reason: Retire SMBv1 shares, CHG-2207 ",
                Style::new().fg(DIM),
            )),
        ),
        diff,
    );

    // Below 64 columns a flow and its note don't fit on one line, so the note
    // moves to its own line and the panel grows to hold it.
    let impact_inner = right.width.saturating_sub(2) as usize;
    let stacked = impact_inner < 64;
    let impact_h = if stacked {
        4 + 2 * data::IMPACT.len() as u16
    } else {
        3 + data::IMPACT.len() as u16
    };
    let [plan, impact, approve] = Layout::vertical([
        Constraint::Length(6),
        Constraint::Length(impact_h),
        Constraint::Min(6),
    ])
    .areas(right);
    let pl: Vec<Line> = data::PLAN
        .iter()
        .map(|p| Line::from(vec![Span::styled("✓ ", Style::new().fg(OK)), Span::raw(*p)]))
        .collect();
    f.render_widget(
        Paragraph::new(pl)
            .wrap(Wrap { trim: true })
            .block(panel("plan")),
        plan,
    );

    let impact_verb = if app.has_candidate() && !app.applied() {
        "would have blocked"
    } else {
        "blocks"
    };
    let mut il = vec![Line::from(Span::styled(
        format!("{impact_verb} {} active services", data::IMPACT.len()),
        Style::new().fg(WARN).bold(),
    ))];
    if stacked {
        il.push(Line::from(Span::styled(
            "from flow logs, last 24 h",
            Style::new().fg(DIM),
        )));
    } else {
        il[0].push_span(Span::styled(
            " (flow logs, last 24 h)",
            Style::new().fg(WARN).bold(),
        ));
    }
    for (flow, seen) in data::IMPACT {
        if stacked {
            il.push(Line::from(*flow));
            il.push(Line::from(Span::styled(
                format!("  {seen}"),
                Style::new().fg(DIM),
            )));
        } else {
            il.push(Line::from(vec![
                Span::raw(format!("{flow:<32}")),
                Span::styled(*seen, Style::new().fg(DIM)),
            ]));
        }
    }
    f.render_widget(Paragraph::new(il).block(panel("change impact")), impact);

    let window = format!("{} min", app.commit_window / 60);
    let al = vec![
        Line::from(vec![
            Span::styled("✓ ", Style::new().fg(OK)),
            Span::raw("approved by a.okafor (security admin)"),
        ]),
        Line::from(Span::styled("  four-eyes policy met", Style::new().fg(DIM))),
        Line::from(""),
        kv("confirm window", window.clone()),
        Line::from(Span::styled(
            match app.commit {
                CommitPhase::Pending { .. } => "$ ox commit --confirmed".to_string(),
                CommitPhase::Confirmed => {
                    format!("$ ox rollback 1    # back to {}", data::BASE_COMMIT)
                }
                _ => format!(
                    "$ ox commit block-legacy-smb --confirm {}m",
                    app.commit_window / 60
                ),
            },
            Style::new().fg(ACCENT),
        )),
    ];
    f.render_widget(
        Paragraph::new(al).block(panel("approval and commit")),
        approve,
    );
}

// ───────────────────────────── Explain ─────────────────────────────

fn draw_explain(f: &mut Frame, app: &mut App, area: Rect) {
    // Once the candidate is applied, its rules are the running config.
    let applied = app.applied();
    let toggled = app.explain_candidate && !applied;
    let cand = toggled || applied;
    let running_label = format!("running {}", app.running_commit());
    let [q, main] = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).areas(area);

    let mode = |on: bool, s: &str| {
        if on {
            Span::styled(
                format!(" {s} "),
                Style::new().fg(Color::Black).bg(ACCENT).bold(),
            )
        } else {
            Span::styled(format!(" {s} "), Style::new().fg(DIM))
        }
    };
    let ql = vec![
        Line::from(vec![
            Span::styled("src ", Style::new().fg(DIM)),
            Span::raw("10.20.4.17   "),
            Span::styled("dst ", Style::new().fg(DIM)),
            Span::raw("10.30.0.8   "),
            Span::styled("proto ", Style::new().fg(DIM)),
            Span::raw("tcp   "),
            Span::styled("dport ", Style::new().fg(DIM)),
            Span::raw("445   "),
            Span::styled("in ", Style::new().fg(DIM)),
            Span::raw("lan0.20"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("evaluate against  ", Style::new().fg(DIM)),
            mode(!toggled, &running_label),
            Span::raw(" "),
            if applied {
                Span::styled(
                    match app.commit {
                        CommitPhase::Pending { .. } => " unconfirmed, no separate candidate ",
                        _ => " no candidate ",
                    },
                    Style::new().fg(DIM),
                )
            } else {
                mode(toggled, "candidate block-legacy-smb")
            },
            Span::styled(
                if applied { "" } else { "   (m to switch)" },
                Style::new().fg(DIM),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(ql).block(panel("why did this packet do that?")),
        q,
    );

    let [steps, right] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(main);

    let verdict = if cand {
        Span::styled(" DROP ", Style::new().fg(Color::Black).bg(BAD).bold())
    } else {
        Span::styled(" ACCEPT ", Style::new().fg(Color::Black).bg(OK).bold())
    };
    let s: Vec<(&str, &str, &str)> = vec![
        (
            "ingress",
            "lan0.20 → zone lan",
            "interface group lan, VLAN 20",
        ),
        ("zone pair", "lan → dmz", "route lookup selects egress dmz0"),
        if cand {
            (
                "rule",
                "r-0412 drop smb, netbios",
                "set @svc_smb · position 1 of 7",
            )
        } else {
            (
                "rule",
                "r-0388 accept to finance file servers",
                "set @finance-file-servers · position 1 of 6",
            )
        },
        ("nat", "none", "no source or destination NAT for lan → dmz"),
        ("route", "10.30.0.0/24 via dmz0", "connected · table main"),
        if cand {
            (
                "logged",
                "yes, rule ID r-0412",
                "flow log + syslog over TLS",
            )
        } else {
            (
                "conntrack",
                "new flow, offloaded after handshake",
                "flowtable ft-lan-dmz",
            )
        },
    ];
    let mut lines = vec![
        Line::from(vec![Span::raw("verdict  "), verdict]),
        Line::from(""),
    ];
    for (i, (label, value, detail)) in s.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", i + 1), Style::new().fg(ACCENT).bold()),
            Span::styled(format!("{label:<10}"), Style::new().fg(DIM)),
            Span::styled(*value, Style::new().bold()),
        ]));
        lines.push(Line::from(vec![
            Span::styled(
                if i + 1 < s.len() { " │ " } else { "   " },
                Style::new().fg(DIM),
            ),
            Span::raw("          "),
            Span::styled(*detail, Style::new().fg(DIM)),
        ]));
    }
    f.render_widget(Paragraph::new(lines).block(panel("result")), steps);

    let [origin, cli] = Layout::vertical([Constraint::Length(8), Constraint::Min(5)]).areas(right);
    let ol = if cand {
        vec![
            kv(
                "commit",
                match app.commit {
                    CommitPhase::Pending { .. } => format!("{} (unconfirmed)", data::NEXT_COMMIT),
                    CommitPhase::Confirmed => data::NEXT_COMMIT.to_string(),
                    _ => "candidate block-legacy-smb (not applied)".to_string(),
                },
            ),
            kv("author", "j.nguyen"),
            kv("when", "today 10:52"),
            kv("reason", "Retire SMBv1 shares, CHG-2207"),
        ]
    } else {
        vec![
            kv("commit", "#2213"),
            kv("author", "s.patel"),
            kv("when", "3 Aug 2026 14:08"),
            kv("reason", "Open file share for finance, CHG-1984"),
        ]
    };
    f.render_widget(
        Paragraph::new(ol)
            .wrap(Wrap { trim: true })
            .block(panel("where the rule came from")),
        origin,
    );
    let mut c = vec![
        Line::from(Span::styled(
            "$ ox explain --src 10.20.4.17 --dst 10.30.0.8 \\",
            Style::new().fg(ACCENT),
        )),
        Line::from(Span::styled(
            "    --proto tcp --dport 445 --in lan0.20",
            Style::new().fg(ACCENT),
        )),
    ];
    if toggled {
        c[1] = Line::from(Span::styled(
            "    --proto tcp --dport 445 --in lan0.20 \\",
            Style::new().fg(ACCENT),
        ));
        c.push(Line::from(Span::styled(
            "    --candidate block-legacy-smb",
            Style::new().fg(ACCENT),
        )));
    }
    c.push(Line::from(""));
    c.push(Line::from(Span::styled(
        "ox trace follows a real packet with nftables tracing",
        Style::new().fg(DIM),
    )));
    f.render_widget(
        Paragraph::new(c)
            .wrap(Wrap { trim: false })
            .block(panel("same query from the CLI")),
        cli,
    );
}

// ───────────────────────────── Admin / audit ─────────────────────────────

fn draw_audit(f: &mut Frame, app: &mut App, area: Rect) {
    let [top, log] = Layout::vertical([Constraint::Length(10), Constraint::Min(6)]).areas(area);
    let [admins, right] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(59)]).areas(top);

    let arows: Vec<Row> = data::ADMINS
        .iter()
        .map(|(n, h, r, s, l)| {
            Row::new(vec![
                Cell::from(*n),
                Cell::from(Span::styled(*h, Style::new().fg(DIM))),
                Cell::from(*r),
                Cell::from(*s),
                Cell::from(*l),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            arows,
            [
                Constraint::Fill(1),
                Constraint::Length(11),
                Constraint::Length(14),
                Constraint::Fill(1),
                Constraint::Length(9),
            ],
        )
        .header(header(&[
            "administrator",
            "handle",
            "role",
            "sign-in",
            "last",
        ]))
        .block(panel("administrators · SSO via Entra ID")),
        admins,
    );

    let trows: Vec<Row> = data::TOKENS
        .iter()
        .map(|(t, s, o, e)| {
            Row::new(vec![
                Cell::from(*t),
                Cell::from(Span::styled(*s, Style::new().fg(ACCENT))),
                Cell::from(*o),
                Cell::from(*e),
            ])
        })
        .collect();
    f.render_widget(
        Table::new(
            trows,
            [
                Constraint::Length(12),
                Constraint::Fill(1),
                Constraint::Length(9),
                Constraint::Length(11),
            ],
        )
        .header(header(&["token", "scopes", "owner", "expires"]))
        .block(panel("API tokens").title_bottom(Span::styled(
            " four-eyes: policy, NAT and VPN need a second approver ",
            Style::new().fg(DIM),
        ))),
        right,
    );

    let rows: Vec<Row> = data::AUDIT
        .iter()
        .map(|(t, w, e, fr, h)| {
            Row::new(vec![
                Cell::from(*t),
                Cell::from(Span::styled(*w, Style::new().bold())),
                Cell::from(*e),
                Cell::from(*fr),
                Cell::from(Span::styled(*h, Style::new().fg(DIM))),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(13),
            Constraint::Fill(1),
            Constraint::Length(16),
            Constraint::Length(11),
        ],
    )
    .header(header(&["time", "who", "event", "from", "entry hash"]))
    .block(
        panel("audit log · write-once, hash-chained")
            .title_bottom(Span::styled(" chain verified 11:50 ", Style::new().fg(OK))),
    )
    .row_highlight_style(sel_style())
    .highlight_symbol("▸");
    f.render_stateful_widget(t, log, &mut app.audit_state);
}

// ───────────────────────────── Fleet ─────────────────────────────

fn draw_fleet(f: &mut Frame, app: &mut App, area: Rect) {
    let [sum, mid, tbl] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(12),
        Constraint::Min(6),
    ])
    .areas(area);

    let s = Line::from(vec![
        Span::styled("firewalls ", Style::new().fg(DIM)),
        Span::styled("184", Style::new().bold()),
        Span::styled(" in 92 pairs  on template ", Style::new().fg(DIM)),
        Span::styled("181", Style::new().bold()),
        Span::styled(" · 3 drift", Style::new().fg(WARN)),
        Span::styled("  approvals ", Style::new().fg(DIM)),
        Span::styled("2", Style::new().bold()),
        Span::styled("  VPN down ", Style::new().fg(DIM)),
        Span::styled("1/214", Style::new().fg(BAD).bold()),
        Span::styled("  support ends ≤30 d ", Style::new().fg(DIM)),
        Span::styled("14", Style::new().bold()),
    ]);
    f.render_widget(
        Paragraph::new(s).block(panel("fleet controller · self-hosted · 12 tenants")),
        sum,
    );

    let [needs, roll] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(mid);
    let nl: Vec<Line> = data::NEEDS_ACTION
        .iter()
        .flat_map(|(t, d)| {
            [
                Line::from(vec![
                    Span::styled("• ", Style::new().fg(WARN)),
                    Span::styled(*t, Style::new().bold()),
                ]),
                Line::from(Span::styled(format!("  {d}"), Style::new().fg(DIM))),
            ]
        })
        .collect();
    f.render_widget(Paragraph::new(nl).block(panel("needs action")), needs);

    let [r0, r1, r2, note] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Min(1),
    ])
    .areas(panel("").inner(roll));
    f.render_widget(panel("rollout 1.0.3 → 1.0.4"), roll);
    for (rect, label, ratio, color) in [
        (r0, "ring 0 canary · 4/4 done", 1.0, OK),
        (r1, "ring 1 internal · 20/20 done", 1.0, OK),
        (r2, "ring 2 tenants · 63/160", 63.0 / 160.0, ACCENT),
    ] {
        let [l, g] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(rect);
        f.render_widget(Paragraph::new(Span::styled(label, Style::new().fg(DIM))), l);
        let filled = (g.width as f64 * ratio).round() as usize;
        let empty = g.width as usize - filled;
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("█".repeat(filled), Style::new().fg(color)),
                Span::styled("░".repeat(empty), Style::new().fg(DIM)),
            ])),
            g,
        );
    }
    f.render_widget(
        Paragraph::new(Span::styled(
            "standby node first, fail over, then the other; halts on a failed boot",
            Style::new().fg(DIM),
        ))
        .wrap(Wrap { trim: true }),
        note,
    );

    let rows: Vec<Row> = data::FLEET
        .iter()
        .map(|(p, t, tpl, pol, drift, ha, v, vpn, sup)| {
            let pc = if *drift {
                Style::new().fg(WARN).bold()
            } else {
                Style::new().fg(OK)
            };
            Row::new(vec![
                Cell::from(Span::styled(*p, Style::new().bold())),
                Cell::from(*t),
                Cell::from(*tpl),
                Cell::from(Span::styled(*pol, pc)),
                Cell::from(*ha),
                Cell::from(*v),
                Cell::from(*vpn),
                Cell::from(*sup),
            ])
        })
        .collect();
    let t = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Fill(1),
            Constraint::Length(14),
            Constraint::Length(21),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(11),
        ],
    )
    .header(header(&[
        "pair",
        "tenant",
        "template",
        "policy",
        "HA",
        "version",
        "site VPN",
        "support to",
    ]))
    .block(panel("firewalls"))
    .row_highlight_style(sel_style())
    .highlight_symbol("▸");
    f.render_stateful_widget(t, tbl, &mut app.fleet_state);
}

// ───────────────────────────── Import report ─────────────────────────────

fn draw_import(f: &mut Frame, area: Rect) {
    let pairs_h = |n: usize| 2 * n as u16 + 2;
    let [sum, changed, unsup, verify] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(pairs_h(data::IMPORT_CHANGED.len())),
        Constraint::Length(pairs_h(data::IMPORT_UNSUPPORTED.len())),
        Constraint::Min(5),
    ])
    .areas(area);

    let mut s = vec![];
    for (i, (n, label)) in data::IMPORT_TOTALS.iter().enumerate() {
        if i > 0 {
            s.push(Span::styled("  ·  ", Style::new().fg(DIM)));
        }
        let color = [OK, WARN, BAD][i.min(2)];
        s.push(Span::styled(*n, Style::new().fg(color).bold()));
        s.push(Span::raw(format!(" {label}")));
    }
    f.render_widget(
        Paragraph::new(Line::from(s)).block(
            panel(format!(
                "import report · {} · {} · 1,284 items",
                data::IMPORT_FILE,
                data::IMPORT_SOURCE
            ))
            .title_bottom(Span::styled(
                " the importer never guesses; anything inexact is listed below ",
                Style::new().fg(DIM),
            )),
        ),
        sum,
    );

    // Each entry takes two lines, so long text stays readable in a narrow terminal.
    let pairs = |rows: &[(&'static str, &'static str)], lead: &'static str, color: Color| {
        rows.iter()
            .flat_map(|(a, b)| {
                [
                    Line::from(Span::styled(*a, Style::new().bold())),
                    Line::from(vec![
                        Span::styled(lead, Style::new().fg(color)),
                        Span::styled(*b, Style::new().fg(DIM)),
                    ]),
                ]
            })
            .collect::<Vec<Line>>()
    };
    f.render_widget(
        Paragraph::new(pairs(data::IMPORT_CHANGED, "  → ", WARN))
            .block(panel("changed · 41 · works, but differs (first 4)")),
        changed,
    );
    f.render_widget(
        Paragraph::new(pairs(data::IMPORT_UNSUPPORTED, "  manual step: ", BAD))
            .block(panel("unsupported · 12 · manual step needed (first 4)")),
        unsup,
    );

    let mut v = vec![];
    for (flow, old, now, why) in data::IMPORT_DIFFS {
        let verdict = |s: &'static str| {
            Span::styled(
                format!("{s:<5}"),
                Style::new().fg(if s == "pass" { OK } else { BAD }).bold(),
            )
        };
        v.push(Line::from(vec![
            Span::raw(format!("{flow:<40}")),
            Span::styled("pfSense ", Style::new().fg(DIM)),
            verdict(old),
            Span::styled(" Netoxide ", Style::new().fg(DIM)),
            verdict(now),
        ]));
        v.push(Line::from(Span::styled(
            format!("  {why}"),
            Style::new().fg(DIM),
        )));
    }
    f.render_widget(
        Paragraph::new(v).block(
            panel("verify · 3 of 12,402 replayed flows get a different verdict").title_bottom(
                Span::styled(
                    format!(
                        " $ ox import {} --verify fw-par-02-week.pcap ",
                        data::IMPORT_FILE
                    ),
                    Style::new().fg(ACCENT),
                ),
            ),
        ),
        verify,
    );
}
