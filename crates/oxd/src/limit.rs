//! A cap on how many connections the HTTPS listener holds at once.
//!
//! Every connection costs a file descriptor and some memory before the
//! caller has shown a token. Without a cap, anyone who can reach the
//! listener could open connections until the daemon had none left for its
//! own work. The cap is per source address as well as in total, so one
//! machine cannot take every place. IPv6 callers are counted by /64.
//!
//! A connection also gives its place back when nothing has moved on it for
//! a while. The HTTP library's own timeouts do not cover a caller that
//! connects and says nothing, or one that goes quiet between requests.

use std::{
    collections::HashMap,
    future::{Future, Ready, ready},
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum_server::accept::Accept;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, Sleep, sleep},
};

#[derive(Default)]
struct Counts {
    total: usize,
    by_address: HashMap<IpAddr, usize>,
}

/// Refuses connections past a total and a per-address count.
#[derive(Clone)]
pub struct Limit {
    counts: Arc<Mutex<Counts>>,
    total: usize,
    per_address: usize,
    idle: Duration,
}

impl Limit {
    /// `idle` is how long a connection may go with no bytes either way.
    pub fn new(total: usize, per_address: usize, idle: Duration) -> Limit {
        Limit {
            counts: Arc::default(),
            total,
            per_address,
            idle,
        }
    }

    /// Takes a place for a connection from `from`, if there is one.
    fn take(&self, from: IpAddr) -> Option<Place> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let mine = counts.by_address.get(&from).copied().unwrap_or(0);
        if counts.total >= self.total || mine >= self.per_address {
            return None;
        }
        counts.total += 1;
        counts.by_address.insert(from, mine + 1);
        Some(Place {
            counts: self.counts.clone(),
            from,
        })
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.counts.lock().unwrap().total
    }
}

/// A connection's place. Dropping it gives the place back.
struct Place {
    counts: Arc<Mutex<Counts>>,
    from: IpAddr,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.total = counts.total.saturating_sub(1);
        match counts.by_address.get_mut(&self.from) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                counts.by_address.remove(&self.from);
            }
        }
    }
}

/// A connection that holds its place for as long as it is open, and is
/// closed when nothing has been read or written for `idle`.
pub struct Counted {
    stream: TcpStream,
    idle: Duration,
    quiet: Pin<Box<Sleep>>,
    _place: Place,
}

impl Counted {
    /// Notes that bytes moved, or fails the connection if none have for too long.
    fn watch<T>(&mut self, cx: &mut Context<'_>, io: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match io {
            Poll::Ready(done) => {
                self.quiet.as_mut().reset(Instant::now() + self.idle);
                Poll::Ready(done)
            }
            // Polling the timer also arranges a wake-up when it runs out.
            Poll::Pending => match self.quiet.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the connection was quiet for too long",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let io = Pin::new(&mut self.stream).poll_read(cx, buf);
        self.watch(cx, io)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let io = Pin::new(&mut self.stream).poll_write(cx, buf);
        self.watch(cx, io)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The address a connection is counted under. An IPv4 caller on a
/// dual-stack listener is the same caller either way. One IPv6 machine
/// usually has a whole /64 to pick addresses from, so those count as one.
fn caller(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut parts = v6.segments();
            parts[4..].fill(0);
            IpAddr::V6(parts.into())
        }
        v4 => v4,
    }
}

impl<S> Accept<TcpStream, S> for Limit {
    type Stream = Counted;
    type Service = S;
    type Future = Ready<io::Result<(Counted, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let from = stream.peer_addr().map(|a| caller(a.ip()));
        ready(match from.ok().and_then(|ip| self.take(ip)) {
            Some(place) => Ok((
                Counted {
                    stream,
                    idle: self.idle,
                    quiet: Box::pin(sleep(self.idle)),
                    _place: place,
                },
                service,
            )),
            // Dropping the stream closes it. The caller can try again.
            None => Err(io::Error::other("too many connections")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_run_out_per_address_and_in_total_and_come_back() {
        let limit = Limit::new(3, 2, Duration::from_secs(1));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        let c: IpAddr = "192.0.2.3".parse().unwrap();

        let a1 = limit.take(a).unwrap();
        let _a2 = limit.take(a).unwrap();
        assert!(limit.take(a).is_none(), "one address is held to two");
        let _b1 = limit.take(b).unwrap();
        assert!(limit.take(c).is_none(), "three in total");
        assert_eq!(limit.held(), 3);

        drop(a1);
        assert_eq!(limit.held(), 2);
        let _c1 = limit.take(c).unwrap();
        assert!(limit.take(a).is_none(), "the total is used up again");
    }

    #[test]
    fn ipv6_callers_are_counted_by_their_network() {
        let ip = |s: &str| caller(s.parse().unwrap());
        assert_eq!(ip("2001:db8:1:2:aaaa::1"), ip("2001:db8:1:2:bbbb::2"));
        assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_ne!(ip("192.0.2.1"), ip("192.0.2.2"));
    }

    #[test]
    fn an_address_with_nothing_open_is_forgotten() {
        let limit = Limit::new(10, 2, Duration::from_secs(1));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        drop(limit.take(a).unwrap());
        assert!(limit.counts.lock().unwrap().by_address.is_empty());
    }
}
