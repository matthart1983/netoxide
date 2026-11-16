//! The Live screen: what the box is doing right now, one reading a second.
//!
//! Every number is one the daemon measured from a kernel counter. A series
//! the box cannot measure is absent from its answer, and its tile is left
//! out here. Nothing is estimated and there is no sample data.

use std::collections::VecDeque;

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use serde_json::Value;

use crate::spark::{self, Ramp};
use crate::ui::{DIM, OK, panel};

const DOWN: (u8, u8, u8) = (42, 120, 214);
const UP: (u8, u8, u8) = (235, 104, 52);
const TEAL: (u8, u8, u8) = (27, 175, 122);
const RED: (u8, u8, u8) = (208, 59, 59);

/// One network's traffic, in bits per second, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetSeries {
    pub name: String,
    pub down: VecDeque<u64>,
    pub up: VecDeque<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Blocked {
    /// Seconds since it last happened.
    pub ago: u64,
    pub packets: u64,
    pub text: String,
}

/// What `/v1/live` answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveData {
    /// How many readings a full series holds.
    pub window: usize,
    pub download: Option<VecDeque<u64>>,
    pub upload: Option<VecDeque<u64>>,
    pub connections: Option<VecDeque<u64>>,
    /// Packets blocked per second.
    pub blocked: Option<VecDeque<u64>>,
    pub networks: Vec<NetSeries>,
    pub feed: Vec<Blocked>,
}

pub fn parse(v: &Value) -> LiveData {
    let series = |v: &Value| -> Option<VecDeque<u64>> {
        Some(v.as_array()?.iter().filter_map(Value::as_u64).collect())
    };
    LiveData {
        window: v["window"].as_u64().unwrap_or(120) as usize,
        download: series(&v["download"]),
        upload: series(&v["upload"]),
        connections: series(&v["connections"]),
        blocked: series(&v["blocked"]),
        networks: v["networks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|n| NetSeries {
                name: n["name"].as_str().unwrap_or("").to_string(),
                down: series(&n["down"]).unwrap_or_default(),
                up: series(&n["up"]).unwrap_or_default(),
            })
            .collect(),
        feed: v["feed"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| Blocked {
                ago: e["ago"].as_u64().unwrap_or(0),
                packets: e["packets"].as_u64().unwrap_or(0),
                text: e["text"].as_str().unwrap_or("").to_string(),
            })
            .collect(),
    }
}

/// A rate in the largest unit that keeps it readable: the number, the unit.
pub fn rate(bits: u64) -> (String, &'static str) {
    // Three figures at most: 2.5, 12.3, 415.
    let figures = |n: f64| -> String {
        if n >= 100.0 {
            format!("{n:.0}")
        } else {
            format!("{n:.1}")
        }
    };
    let b = bits as f64;
    if b >= 1e9 {
        (figures(b / 1e9), "Gb/s")
    } else if b >= 1e6 {
        (figures(b / 1e6), "Mb/s")
    } else if b >= 1e3 {
        (format!("{:.0}", b / 1e3), "kb/s")
    } else {
        (format!("{bits}"), "b/s")
    }
}

fn whole(bits: u64) -> String {
    let (n, unit) = rate(bits);
    format!("{n} {unit}")
}

fn last(q: &VecDeque<u64>) -> u64 {
    q.back().copied().unwrap_or(0)
}

fn peak(q: &VecDeque<u64>) -> u64 {
    q.iter().max().copied().unwrap_or(0)
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[allow(clippy::too_many_arguments)]
/// A tile: its name in the border, the value now, a sparkline if there is
/// room, and a line of detail under it.
fn tile(
    f: &mut Frame,
    area: Rect,
    title: &str,
    value: String,
    unit: &str,
    detail: String,
    data: &VecDeque<u64>,
    ramp: &Ramp,
) {
    let block = panel("").title(Span::styled(
        format!(" {title} "),
        Style::new().fg(ramp.base()).bold(),
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 2 || inner.width < 6 {
        return;
    }
    let used = value.chars().count() + 1 + unit.chars().count();
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(value, Style::new().bold()),
            Span::styled(format!(" {unit}"), Style::new().fg(DIM)),
        ])),
        Rect {
            x: inner.x + 1,
            y: inner.y,
            width: inner.width.saturating_sub(1),
            height: 1,
        },
    );
    let spark_w = (inner.width as usize).saturating_sub(used + 3);
    if spark_w >= 4 {
        let r = Rect {
            x: inner.x + inner.width - spark_w as u16,
            y: inner.y,
            width: spark_w as u16,
            height: 1,
        };
        spark::sparkline(f.buffer_mut(), r, data, ramp);
    }
    f.render_widget(
        Paragraph::new(Span::styled(detail, Style::new().fg(DIM))),
        Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(1),
            height: 1,
        },
    );
}

/// The mirrored chart: download grows up, upload grows down, one scale.
fn chart(f: &mut Frame, area: Rect, down: &VecDeque<u64>, up: &VecDeque<u64>, window: usize) {
    let (d_ramp, u_ramp) = (Ramp::new(DOWN), Ramp::new(UP));
    let title = Line::from(vec![
        Span::styled(" internet traffic   ", Style::new().bold()),
        Span::styled("▲ ", Style::new().fg(d_ramp.base())),
        Span::raw(format!("download {}   ", whole(last(down)))),
        Span::styled("▼ ", Style::new().fg(u_ramp.base())),
        Span::raw(format!("upload {} ", whole(last(up)))),
    ]);
    let both: Vec<u64> = down.iter().chain(up.iter()).copied().collect();
    let max = spark::robust_max(&both);
    let block = panel("").title(title).title_bottom(Span::styled(
        format!(" both halves share one scale · edge = {} ", whole(max)),
        Style::new().fg(DIM),
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 4 || inner.width < 20 {
        return;
    }
    let [plot, xlab] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(inner);
    let half = plot.height.saturating_sub(1) / 2;
    let top = Rect {
        height: half,
        ..plot
    };
    let axis = Rect {
        y: plot.y + half,
        height: 1,
        ..plot
    };
    let bottom = Rect {
        y: plot.y + half + 1,
        height: plot.height.saturating_sub(half + 1),
        ..plot
    };
    // Only the time that was measured is drawn. A history that is not full
    // yet sits at the right, where "now" is, and the rest stays empty.
    let cells = plot.width as usize * 2;
    let shown = ((cells * down.len().min(window)) / window.max(1)) & !1;
    let skip = ((cells - shown) / 2) as u16;
    let part = |r: Rect| Rect {
        x: r.x + skip,
        width: r.width - skip,
        ..r
    };
    if shown > 0 {
        spark::area(
            f.buffer_mut(),
            part(top),
            &spark::resample(down, shown),
            max,
            &d_ramp,
            false,
        );
        spark::area(
            f.buffer_mut(),
            part(bottom),
            &spark::resample(up, shown),
            max,
            &u_ramp,
            true,
        );
    }
    f.render_widget(
        Paragraph::new(Span::styled(
            "┈".repeat(axis.width as usize),
            Style::new().fg(Color::Rgb(70, 76, 90)),
        )),
        axis,
    );
    let secs = window;
    let ago = if secs.is_multiple_of(60) {
        format!("{} min ago", secs / 60)
    } else {
        format!("{secs} s ago")
    };
    f.render_widget(
        Paragraph::new(Span::styled(ago, Style::new().fg(DIM))),
        xlab,
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled("now", Style::new().fg(DIM))).right_aligned()),
        xlab,
    );
}

/// Rows of name, a sparkline, and the rates now.
fn network_rows(f: &mut Frame, area: Rect, networks: &[NetSeries]) {
    let block = panel("your networks · traffic now");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let label_w = networks
        .iter()
        .map(|n| n.name.chars().count())
        .max()
        .unwrap_or(8)
        .clamp(8, 18) as u16
        + 2;
    let value_w = 27u16;
    let ramp = Ramp::new(DOWN);
    for (i, net) in networks.iter().enumerate() {
        let y = inner.y + i as u16;
        if y >= inner.y + inner.height {
            break;
        }
        let name: String = net.name.chars().take(label_w as usize - 1).collect();
        f.render_widget(
            Paragraph::new(Span::styled(name, Style::new().bold())),
            Rect {
                x: inner.x,
                y,
                width: label_w.min(inner.width),
                height: 1,
            },
        );
        let spark_w = inner.width.saturating_sub(label_w + value_w + 1);
        if spark_w >= 4 {
            // Down and up together: how busy the network is.
            let total: VecDeque<u64> = net
                .down
                .iter()
                .zip(net.up.iter())
                .map(|(d, u)| d + u)
                .collect();
            spark::sparkline(
                f.buffer_mut(),
                Rect {
                    x: inner.x + label_w,
                    y,
                    width: spark_w,
                    height: 1,
                },
                &total,
                &ramp,
            );
        }
        let value = Line::from(vec![
            Span::styled("▲ ", Style::new().fg(Ramp::new(DOWN).base())),
            Span::raw(format!("{:<11}", whole(last(&net.down)))),
            Span::styled("▼ ", Style::new().fg(Ramp::new(UP).base())),
            Span::raw(whole(last(&net.up))),
        ]);
        f.render_widget(
            Paragraph::new(value),
            Rect {
                x: inner.x + inner.width.saturating_sub(value_w),
                y,
                width: value_w.min(inner.width),
                height: 1,
            },
        );
    }
}

fn feed(f: &mut Frame, area: Rect, data: &LiveData) {
    let Some(blocked) = &data.blocked else {
        return;
    };
    let lines: Vec<Line> = if data.feed.is_empty() {
        vec![Line::from(Span::styled(
            "Nothing has been blocked while you have been watching.",
            Style::new().fg(DIM),
        ))]
    } else {
        data.feed
            .iter()
            .map(|e| {
                let when = match e.ago {
                    0 => "now".to_string(),
                    s if s < 60 => format!("{s}s ago"),
                    s => format!("{}m ago", s / 60),
                };
                Line::from(vec![
                    Span::styled(format!("{when:>7} "), Style::new().fg(DIM)),
                    Span::styled(
                        format!("×{:<5}", thousands(e.packets)),
                        Style::new().fg(Color::Rgb(RED.0, RED.1, RED.2)).bold(),
                    ),
                    Span::raw(e.text.clone()),
                ])
            })
            .collect()
    };
    let total: u64 = blocked.iter().sum();
    f.render_widget(
        Paragraph::new(lines).block(panel("just blocked · × is packets").title_bottom(
            Span::styled(
                format!(
                    " {} packets blocked in the last {} ",
                    thousands(total),
                    span(blocked.len())
                ),
                Style::new().fg(DIM),
            ),
        )),
        area,
    );
}

/// A number of seconds in words.
fn span(secs: usize) -> String {
    match secs {
        s if s >= 60 && s % 60 == 0 => match s / 60 {
            1 => "minute".to_string(),
            m => format!("{m} minutes"),
        },
        1 => "second".to_string(),
        s => format!("{s} seconds"),
    }
}

pub fn draw(f: &mut Frame, data: Option<&LiveData>, paused: bool, area: Rect) {
    let Some(data) = data else {
        f.render_widget(
            Paragraph::new(Span::styled(
                "Taking the first reading…",
                Style::new().fg(DIM),
            ))
            .block(panel("live")),
            area,
        );
        return;
    };
    let have = data
        .download
        .as_ref()
        .or(data.networks.first().map(|n| &n.down))
        .map_or(0, VecDeque::len);
    let (dot, text) = if paused {
        (
            Span::styled(" ■ ", Style::new().fg(DIM)),
            "paused · the numbers are frozen · p to resume".to_string(),
        )
    } else if have < 2 {
        (
            Span::styled(" ● ", Style::new().fg(OK)),
            "live · taking the first readings, one a second".to_string(),
        )
    } else {
        (
            Span::styled(" ● ", Style::new().fg(OK)),
            format!(
                "live · one reading a second, the last {} shown · p to pause",
                span(have)
            ),
        )
    };

    // The tiles the box can fill, in the design's order.
    type Tile<'a> = (
        &'static str,
        String,
        String,
        String,
        &'a VecDeque<u64>,
        (u8, u8, u8),
    );
    let mut tiles: Vec<Tile> = vec![];
    for (name, series, color) in [
        ("download", &data.download, DOWN),
        ("upload", &data.upload, UP),
    ] {
        if let Some(q) = series {
            let (n, unit) = rate(last(q));
            tiles.push((
                name,
                n,
                unit.to_string(),
                format!("peak {}", whole(peak(q))),
                q,
                color,
            ));
        }
    }
    if let Some(q) = &data.connections {
        tiles.push((
            "connections",
            thousands(last(q)),
            "open".to_string(),
            format!("peak {}", thousands(peak(q))),
            q,
            TEAL,
        ));
    }
    if let Some(q) = &data.blocked {
        let recent: u64 = q.iter().rev().take(60).sum();
        tiles.push((
            "blocked",
            thousands(recent),
            "packets".to_string(),
            match q.len().min(60) {
                60 => "in the last minute".to_string(),
                n => format!("in {n} s"),
            },
            q,
            RED,
        ));
    }

    let wide = area.width >= 110;
    let nets_h = (data.networks.len() as u16).clamp(1, 6) + 2;
    let feed_h = if data.blocked.is_some() {
        if wide { nets_h.max(5) } else { 4 }
    } else {
        0
    };
    let low_h = if wide {
        nets_h.max(feed_h)
    } else {
        nets_h + feed_h
    };
    let [status, tile_row, chart_area, low] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(if tiles.is_empty() { 0 } else { 4 }),
        Constraint::Min(6),
        Constraint::Length(low_h),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            dot,
            Span::styled(text, Style::new().fg(DIM)),
        ])),
        status,
    );
    if !tiles.is_empty() {
        let n = tiles.len() as u32;
        let cells = Layout::horizontal(vec![Constraint::Ratio(1, n); tiles.len()]).split(tile_row);
        for (i, (name, value, unit, detail, q, color)) in tiles.into_iter().enumerate() {
            tile(
                f,
                cells[i],
                name,
                value,
                &unit,
                detail,
                q,
                &Ramp::new(color),
            );
        }
    }
    match (&data.download, &data.upload) {
        (Some(down), Some(up)) => chart(f, chart_area, down, up, data.window),
        _ => f.render_widget(
            Paragraph::new(Span::styled(
                "This box has no port that faces the internet, so there is no internet traffic to draw.",
                Style::new().fg(DIM),
            ))
            .wrap(Wrap { trim: true })
            .block(panel("internet traffic")),
            chart_area,
        ),
    }
    let (nets_area, feed_area) = if wide && feed_h > 0 {
        let [a, b] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(low);
        (a, b)
    } else {
        let [a, b] = Layout::vertical([Constraint::Length(nets_h), Constraint::Min(0)]).areas(low);
        (a, b)
    };
    network_rows(f, nets_area, &data.networks);
    feed(f, feed_area, data);
}
