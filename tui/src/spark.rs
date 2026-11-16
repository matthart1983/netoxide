//! Sparklines in the NetWatch style.
//!
//! - Braille area plots, two samples per cell column, 4 sub-rows per cell.
//!   A zero sample still draws its floor dot, so quiet reads as "measured and
//!   quiet", not "no data".
//! - Every cell is coloured by how high it sits (a magnitude ramp): dim at the
//!   baseline, the series colour through the body, bright at the peak.
//! - `flip` grows the plot down from the top edge, for mirrored up/down pairs
//!   that share one axis.
//! - Scales use a robust max (95th percentile), so one spike can't flatten
//!   the rest of the line.

use std::collections::VecDeque;

use ratatui::{buffer::Buffer, layout::Rect, style::Color};

/// Background the ramp is measured against: terminals don't report theirs, so
/// assume a typical dark one.
const BG: (u8, u8, u8) = (0x1a, 0x1b, 0x26);

/// Braille dot bit for each of the 4 sub-rows, left and right column.
const DOTS: [[u8; 4]; 2] = [[0, 1, 2, 6], [3, 4, 5, 7]];

#[derive(Clone, Copy)]
pub struct Ramp([(u8, u8, u8); 5]);

fn mix(a: (u8, u8, u8), b: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    (m(a.0, b.0), m(a.1, b.1), m(a.2, b.2))
}

impl Ramp {
    /// Five stops: faded floor, half-faded, the series colour, then two steps
    /// toward white for the peaks.
    pub fn new(base: (u8, u8, u8)) -> Self {
        let white = (255, 255, 255);
        Ramp([
            mix(BG, base, 0.40),
            mix(BG, base, 0.70),
            base,
            mix(base, white, 0.40),
            mix(base, white, 0.72),
        ])
    }

    pub fn at(&self, f: f32) -> Color {
        let t = f.clamp(0.0, 1.0) * 4.0;
        let i = (t.floor() as usize).min(3);
        let (r, g, b) = mix(self.0[i], self.0[i + 1], t - i as f32);
        Color::Rgb(r, g, b)
    }

    pub fn base(&self) -> Color {
        let (r, g, b) = self.0[2];
        Color::Rgb(r, g, b)
    }
}

/// The 95th-percentile value of `data`, with a little headroom, never 0.
pub fn robust_max(data: &[u64]) -> u64 {
    if data.is_empty() {
        return 1;
    }
    let mut v = data.to_vec();
    v.sort_unstable();
    let p = v[((v.len() - 1) as f64 * 0.95).round() as usize];
    ((p as f64) * 1.1).ceil().max(1.0) as u64
}

/// Fit `data` (oldest first) onto exactly `n` samples. Shrinking keeps the
/// max of each bucket so a spike survives; stretching repeats samples.
pub fn resample(data: &VecDeque<u64>, n: usize) -> Vec<u64> {
    let len = data.len();
    if len == 0 || n == 0 {
        return vec![0; n];
    }
    (0..n)
        .map(|i| {
            let a = i * len / n;
            let b = ((i + 1) * len / n).max(a + 1).min(len);
            (a..b).map(|j| data[j]).max().unwrap_or(0)
        })
        .collect()
}

fn sub_height(v: u64, max: u64, sub_h: usize) -> usize {
    if max == 0 {
        return 0;
    }
    ((v.min(max) as u128 * sub_h as u128 * 2 + max as u128) / (max as u128 * 2)) as usize
}

#[allow(clippy::needless_range_loop)]
/// Braille area plot. `samples` must be `2 × area.width` long, oldest first.
pub fn area(buf: &mut Buffer, area: Rect, samples: &[u64], max: u64, ramp: &Ramp, flip: bool) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let (w, h) = (area.width as usize, area.height as usize);
    let sub_h = h * 4;
    for cx in 0..w {
        let lh = sub_height(samples.get(cx * 2).copied().unwrap_or(0), max, sub_h).max(1);
        let rh = sub_height(samples.get(cx * 2 + 1).copied().unwrap_or(0), max, sub_h).max(1);
        for cy in 0..h {
            let mut bits = 0u8;
            for s in 0..4 {
                let from_top = cy * 4 + s;
                let depth = if flip { from_top + 1 } else { sub_h - from_top };
                if lh >= depth {
                    bits |= 1 << DOTS[0][s];
                }
                if rh >= depth {
                    bits |= 1 << DOTS[1][s];
                }
            }
            if bits == 0 {
                continue;
            }
            let mid = (cy * 4 + 2) as f32;
            let f = if flip {
                mid / sub_h as f32
            } else {
                (sub_h as f32 - mid) / sub_h as f32
            };
            if let Some(ch) = char::from_u32(0x2800 | bits as u32) {
                let cell = &mut buf[(area.x + cx as u16, area.y + cy as u16)];
                cell.set_char(ch);
                cell.set_fg(ramp.at(f));
            }
        }
    }
}

/// One-row (or taller) sparkline over a history, scaled to its own robust max.
pub fn sparkline(buf: &mut Buffer, rect: Rect, data: &VecDeque<u64>, ramp: &Ramp) {
    let s = resample(data, rect.width as usize * 2);
    let max = robust_max(&s);
    area(buf, rect, &s, max, ramp, false);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robust_max_ignores_a_single_spike() {
        let mut d: Vec<u64> = vec![10; 40];
        d[20] = 1000;
        assert!(robust_max(&d) < 100);
    }

    #[test]
    fn resample_keeps_spikes_when_shrinking() {
        let d: VecDeque<u64> = (0..90).map(|i| if i == 45 { 999 } else { 5 }).collect();
        assert!(resample(&d, 20).contains(&999));
        assert_eq!(resample(&d, 200).len(), 200);
    }

    #[test]
    fn zero_samples_still_draw_a_floor() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        area(
            &mut buf,
            Rect::new(0, 0, 4, 1),
            &[0; 8],
            10,
            &Ramp::new((42, 120, 214)),
            false,
        );
        assert!((0..4).all(|x| buf[(x, 0)].symbol() != " "));
    }
}
