//! Asks the network for the box's IPv4 address, as an internet provider's
//! modem expects (a DHCP client, RFC 2131).
//!
//! An interface with no address cannot use an ordinary UDP socket for this:
//! the kernel's reverse-path check drops the server's answer before any
//! socket sees it. So the client speaks in whole Ethernet frames on a packet
//! socket, like every other DHCP client. The socket is open only during an
//! exchange, a few seconds at a time, because while it is open it is handed
//! every IPv4 frame the interface receives.
//!
//! One code path serves a new lease and a renewal: both broadcast. A renewal
//! is sent the way RFC 2131 calls rebinding, which any server may answer.
//!
//! The lease's DNS servers are recorded and shown, and nothing uses them
//! yet: the box's resolver forwards to the servers the config names.

use std::{
    net::Ipv4Addr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use ipnet::{IpNet, Ipv4Net};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, bind, socket};
use serde::{Deserialize, Serialize};
use tokio::{task::JoinHandle, time::Instant};

use crate::net;

const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

/// What the server granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub address: Ipv4Net,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub server: Option<Ipv4Addr>,
    /// How long the address may be used, in seconds.
    pub seconds: u32,
    /// When to ask again, in seconds from the grant.
    pub renew: u32,
}

/// A server's answer, as far as the client needs it.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    kind: u8,
    lease: Lease,
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One broadcast DHCP message from this client, as an Ethernet frame.
/// `ciaddr` is the address the client already uses, when it renews.
fn frame(
    mac: [u8; 6],
    xid: u32,
    kind: u8,
    ciaddr: Option<Ipv4Addr>,
    requested: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut bootp = vec![0u8; 236];
    bootp[0] = 1; // request
    bootp[1] = 1; // Ethernet
    bootp[2] = 6; // hardware address length
    bootp[4..8].copy_from_slice(&xid.to_be_bytes());
    // Ask for the answer as a broadcast: the interface has no address yet
    // for a unicast answer to arrive at.
    bootp[10] = 0x80;
    if let Some(addr) = ciaddr {
        bootp[12..16].copy_from_slice(&addr.octets());
    }
    bootp[28..34].copy_from_slice(&mac);
    bootp.extend_from_slice(&MAGIC);
    bootp.extend_from_slice(&[53, 1, kind]);
    if let Some(addr) = requested {
        bootp.extend_from_slice(&[50, 4]);
        bootp.extend_from_slice(&addr.octets());
    }
    if let Some(addr) = server {
        bootp.extend_from_slice(&[54, 4]);
        bootp.extend_from_slice(&addr.octets());
    }
    // What the client wants to be told: mask, router, DNS, lease and renewal times.
    bootp.extend_from_slice(&[55, 5, 1, 3, 6, 51, 58]);
    bootp.push(255);
    // Some servers ignore messages shorter than the old BOOTP minimum.
    if bootp.len() < 300 {
        bootp.resize(300, 0);
    }

    let udp_len = (8 + bootp.len()) as u16;
    let source = ciaddr.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&(20 + udp_len).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&source.octets());
    ip.extend_from_slice(&[255; 4]);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());

    let mut out = vec![0xff; 6];
    out.extend_from_slice(&mac);
    out.extend_from_slice(&[0x08, 0x00]);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&68u16.to_be_bytes());
    out.extend_from_slice(&67u16.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    // A zero UDP checksum means "not computed", which IPv4 allows.
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&bootp);
    out
}

fn v4(bytes: &[u8]) -> Option<Ipv4Addr> {
    let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(b))
}

/// Reads a server's answer to this client out of an Ethernet frame. `None`
/// for anything else, which on a packet socket is nearly every frame.
fn parse(data: &[u8], mac: [u8; 6], xid: u32) -> Option<Reply> {
    if data.get(12..14)? != [0x08, 0x00] {
        return None;
    }
    let ip = data.get(14..)?;
    let header = usize::from(ip.first()? & 0x0f) * 4;
    if ip[0] >> 4 != 4 || header < 20 || *ip.get(9)? != 17 {
        return None;
    }
    // A fragment cannot be a DHCP answer this client can use.
    if u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x3fff != 0 {
        return None;
    }
    let udp = ip.get(header..)?;
    if udp.get(0..2)? != 67u16.to_be_bytes() || udp.get(2..4)? != 68u16.to_be_bytes() {
        return None;
    }
    let bootp = udp.get(8..)?;
    if bootp.len() < 240
        || bootp[0] != 2
        || bootp[4..8] != xid.to_be_bytes()
        || bootp[28..34] != mac
        || bootp[236..240] != MAGIC
    {
        return None;
    }
    let yiaddr = v4(&bootp[16..20])?;

    let (mut kind, mut mask, mut router, mut server) = (None, None, None, None);
    let (mut seconds, mut renew, mut dns) = (None, None, vec![]);
    let mut options = &bootp[240..];
    while let Some((&code, rest)) = options.split_first() {
        match code {
            0 => {
                options = rest;
                continue;
            }
            255 => break,
            _ => {}
        }
        let (&len, rest) = rest.split_first()?;
        let value = rest.get(..usize::from(len))?;
        options = &rest[usize::from(len)..];
        match code {
            53 => kind = value.first().copied(),
            1 => mask = v4(value),
            3 => router = v4(value),
            6 => {
                dns = value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Ipv4Addr::from(*b))
                    .collect()
            }
            51 => seconds = v4(value).map(u32::from),
            54 => server = v4(value),
            58 => renew = v4(value).map(u32::from),
            _ => {}
        }
    }
    let kind = kind?;
    // A mask that is not a run of ones is nonsense; fall back to /24.
    let prefix = mask
        .map(u32::from)
        .filter(|m| m.leading_ones() == m.count_ones())
        .map_or(24, |m| m.count_ones() as u8);
    let seconds = seconds.unwrap_or(3600).max(60);
    Some(Reply {
        kind,
        lease: Lease {
            address: Ipv4Net::new(yiaddr, prefix).ok()?,
            router,
            dns,
            server,
            seconds,
            renew: renew
                .filter(|r| *r < seconds)
                .unwrap_or(seconds / 2)
                .max(30),
        },
    })
}

/// A packet socket on one interface, and that interface's hardware address.
struct Link {
    /// tokio has no packet socket type and its wrapper for arbitrary file
    /// descriptors is an unsafe API. A UDP socket object only ever calls
    /// send and recv on its descriptor, which mean the same on a packet
    /// socket, so the descriptor is handed to one.
    socket: tokio::net::UdpSocket,
    mac: [u8; 6],
}

impl Link {
    fn open(iface: &str) -> Result<Link, String> {
        let link = nix::ifaddrs::getifaddrs()
            .map_err(|e| format!("cannot list interfaces: {e}"))?
            .filter(|a| a.interface_name == iface)
            .find_map(|a| a.address.and_then(|s| s.as_link_addr().copied()))
            .ok_or_else(|| format!("{iface} is not on this machine"))?;
        let mac = link
            .addr()
            .ok_or_else(|| format!("{iface} has no hardware address"))?;
        let fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::EthIp,
        )
        .map_err(|e| format!("cannot open a packet socket: {e}"))?;
        bind(fd.as_raw_fd(), &link).map_err(|e| format!("cannot bind to {iface}: {e}"))?;
        let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(fd))
            .map_err(|e| e.to_string())?;
        Ok(Link { socket, mac })
    }

    /// Sends one message and waits for an answer of one of the wanted kinds.
    async fn exchange(&self, xid: u32, out: &[u8], wanted: &[u8], wait: Duration) -> Option<Reply> {
        self.socket.send(out).await.ok()?;
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 2048];
        loop {
            let n = tokio::time::timeout_at(deadline, self.socket.recv(&mut buf))
                .await
                .ok()?
                .ok()?;
            if let Some(reply) = parse(&buf[..n], self.mac, xid)
                && wanted.contains(&reply.kind)
            {
                return Some(reply);
            }
        }
    }
}

fn random_xid() -> u32 {
    use std::io::Read;
    let mut b = [0u8; 4];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    if read.is_err() {
        // Uniqueness on one wire is all a transaction id needs.
        return std::process::id() ^ crate::now() as u32;
    }
    u32::from_be_bytes(b)
}

/// Gets a lease, however long it takes. `previous` is the address from the
/// last run, which the client asks to keep.
async fn acquire(iface: &str, mut previous: Option<Ipv4Addr>) -> Lease {
    let mut wait = Duration::from_secs(2);
    let mut tries = 0u32;
    loop {
        tries += 1;
        if let Ok(link) = Link::open(iface) {
            let xid = random_xid();
            if let Some(addr) = previous {
                let ask = frame(link.mac, xid, REQUEST, None, Some(addr), None);
                match link.exchange(xid, &ask, &[ACK, NAK], wait).await {
                    Some(r) if r.kind == ACK => return r.lease,
                    Some(_) => previous = None,
                    // No answer twice: the old server may be gone.
                    None if tries >= 2 => previous = None,
                    None => {}
                }
            } else {
                let ask = frame(link.mac, xid, DISCOVER, None, None, None);
                if let Some(offer) = link.exchange(xid, &ask, &[OFFER], wait).await {
                    let ask = frame(
                        link.mac,
                        xid,
                        REQUEST,
                        None,
                        Some(offer.lease.address.addr()),
                        offer.lease.server,
                    );
                    if let Some(r) = link.exchange(xid, &ask, &[ACK, NAK], wait).await
                        && r.kind == ACK
                    {
                        return r.lease;
                    }
                }
            }
        } else {
            tokio::time::sleep(wait).await;
        }
        wait = (wait * 2).min(Duration::from_secs(60));
    }
}

/// Asks to keep a lease. `Some(None)` means the server said no.
async fn renew(iface: &str, lease: &Lease) -> Option<Option<Lease>> {
    let link = Link::open(iface).ok()?;
    let xid = random_xid();
    let ask = frame(
        link.mac,
        xid,
        REQUEST,
        Some(lease.address.addr()),
        None,
        None,
    );
    for _ in 0..2 {
        if let Some(r) = link
            .exchange(xid, &ask, &[ACK, NAK], Duration::from_secs(4))
            .await
        {
            return Some((r.kind == ACK).then_some(r.lease));
        }
    }
    None
}

/// What the client is doing, for `ox status`.
#[derive(Default)]
struct Status {
    lease: Option<Lease>,
    /// Unix time at which the lease runs out.
    until: u64,
}

fn lease_file(dir: &Path, iface: &str) -> PathBuf {
    dir.join(format!("dhcp-{iface}.json"))
}

fn saved(dir: &Path, iface: &str) -> Option<Lease> {
    serde_json::from_slice(&std::fs::read(lease_file(dir, iface)).ok()?).ok()
}

async fn take_off(iface: &str, lease: &Lease) {
    // The kernel drops the default route with the address it goes out by.
    for problem in net::remove_addresses(&[(iface.to_string(), IpNet::V4(lease.address))]).await {
        eprintln!("oxd: {problem}");
    }
}

async fn put_on(iface: &str, lease: &Lease) -> Result<(), String> {
    net::ensure_addresses(&[(iface.to_string(), IpNet::V4(lease.address))]).await?;
    if let Some(router) = lease.router {
        net::set_default_routes(&[(iface.to_string(), router.into())]).await?;
    }
    Ok(())
}

async fn run(iface: String, dir: PathBuf, status: Arc<Mutex<Status>>) {
    let mut previous = saved(&dir, &iface);
    loop {
        let mut lease = acquire(&iface, previous.as_ref().map(|l| l.address.addr())).await;
        loop {
            if let Some(old) = previous.take().filter(|old| old.address != lease.address) {
                take_off(&iface, &old).await;
            }
            if let Err(e) = put_on(&iface, &lease).await {
                eprintln!("oxd: {iface}: {e}");
            }
            if let Ok(text) = serde_json::to_vec(&lease) {
                let _ = std::fs::write(lease_file(&dir, &iface), text);
            }
            eprintln!(
                "oxd: {iface} has {} from the network for {} seconds",
                lease.address, lease.seconds
            );
            let granted = Instant::now();
            let expires = granted + Duration::from_secs(lease.seconds.into());
            {
                let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
                s.lease = Some(lease.clone());
                s.until = crate::now() + u64::from(lease.seconds);
            }
            // Ask to keep the address from the renewal time on, less often
            // as the end comes closer, until the server answers.
            let mut next = granted + Duration::from_secs(lease.renew.into());
            let answer = loop {
                tokio::time::sleep_until(next.min(expires)).await;
                if Instant::now() >= expires {
                    break None;
                }
                match renew(&iface, &lease).await {
                    Some(answer) => break answer,
                    None => {
                        let left = expires.saturating_duration_since(Instant::now());
                        next = Instant::now() + (left / 2).max(Duration::from_secs(60));
                    }
                }
            };
            previous = Some(lease);
            match answer {
                Some(renewed) => lease = renewed,
                None => break,
            }
        }
        // The lease ran out or the server took it back.
        if let Some(old) = previous.take() {
            eprintln!("oxd: {iface} lost {} and is asking again", old.address);
            take_off(&iface, &old).await;
        }
        let _ = std::fs::remove_file(lease_file(&dir, &iface));
        status.lock().unwrap_or_else(|e| e.into_inner()).lease = None;
    }
}

/// A running client on one interface.
pub struct Client {
    iface: String,
    dir: PathBuf,
    status: Arc<Mutex<Status>>,
    task: JoinHandle<()>,
}

impl Client {
    /// Starts asking on `iface`. Must be called inside the tokio runtime.
    pub fn start(iface: &str, dir: &Path) -> Client {
        let status = Arc::new(Mutex::new(Status::default()));
        Client {
            iface: iface.to_string(),
            dir: dir.to_path_buf(),
            task: tokio::spawn(run(iface.to_string(), dir.to_path_buf(), status.clone())),
            status,
        }
    }

    /// One line for `ox status`.
    pub fn state(&self) -> String {
        let s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        match &s.lease {
            None => "asking the network for an address".to_string(),
            Some(l) => format!(
                "{} from the network{}, for another {}",
                l.address,
                l.router
                    .map(|r| format!(", router {r}"))
                    .unwrap_or_default(),
                span(s.until.saturating_sub(crate::now())),
            ),
        }
    }

    /// Stops asking and gives the address up, because the config no longer
    /// wants one here.
    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
        forget(&self.dir, &self.iface).await;
    }
}

impl Drop for Client {
    /// The daemon is going away. The address stays, so the box keeps
    /// forwarding; the next start asks for the same one.
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Takes off the address a client got on `iface`, in this run or an earlier one.
pub async fn forget(dir: &Path, iface: &str) {
    if let Some(lease) = saved(dir, iface) {
        take_off(iface, &lease).await;
    }
    let _ = std::fs::remove_file(lease_file(dir, iface));
}

/// Interfaces with a lease on disk, from this run or an earlier one.
pub fn remembered(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| Some(n.strip_prefix("dhcp-")?.strip_suffix(".json")?.to_string()))
        .collect()
}

fn span(seconds: u64) -> String {
    match seconds {
        s if s >= 7200 => format!("{} hours", s / 3600),
        s if s >= 120 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 9];

    /// A server's answer built by hand, wrapped the way it arrives.
    fn answer(kind: u8, xid: u32, mac: [u8; 6], options: &[u8]) -> Vec<u8> {
        let mut bootp = vec![0u8; 236];
        bootp[0] = 2;
        bootp[4..8].copy_from_slice(&xid.to_be_bytes());
        bootp[16..20].copy_from_slice(&[198, 51, 100, 7]);
        bootp[28..34].copy_from_slice(&mac);
        bootp.extend_from_slice(&MAGIC);
        bootp.extend_from_slice(&[53, 1, kind]);
        bootp.extend_from_slice(options);
        bootp.push(255);
        let mut out = vec![0xff; 6];
        out.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        out.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0]);
        out.extend_from_slice(&[198, 51, 100, 1, 255, 255, 255, 255]);
        out.extend_from_slice(&[0, 67, 0, 68, 0, 0, 0, 0]);
        out.extend_from_slice(&bootp);
        out
    }

    const OPTIONS: &[u8] = &[
        1, 4, 255, 255, 254, 0, // mask /23
        0, // padding between options
        3, 4, 198, 51, 100, 1, // router
        6, 8, 9, 9, 9, 9, 1, 1, 1, 1, // two DNS servers
        51, 4, 0, 0, 0x0e, 0x10, // one hour
        54, 4, 198, 51, 100, 1, // server
    ];

    #[test]
    fn an_answer_is_read() {
        let reply = parse(&answer(ACK, 77, MAC, OPTIONS), MAC, 77).unwrap();
        assert_eq!(reply.kind, ACK);
        assert_eq!(reply.lease.address.to_string(), "198.51.100.7/23");
        assert_eq!(reply.lease.router, Some("198.51.100.1".parse().unwrap()));
        assert_eq!(reply.lease.dns.len(), 2);
        assert_eq!(reply.lease.seconds, 3600);
        assert_eq!(
            reply.lease.renew, 1800,
            "half the lease when the server names no time"
        );
    }

    #[test]
    fn answers_for_someone_else_are_ignored() {
        assert!(
            parse(&answer(ACK, 78, MAC, OPTIONS), MAC, 77).is_none(),
            "other transaction"
        );
        let other = [0x52, 0x54, 0, 0, 0, 8];
        assert!(
            parse(&answer(ACK, 77, other, OPTIONS), MAC, 77).is_none(),
            "other machine"
        );
        // The client's own request, seen again on the wire, is not an answer.
        assert!(parse(&frame(MAC, 77, DISCOVER, None, None, None), MAC, 77).is_none());
    }

    #[test]
    fn broken_frames_are_ignored_not_fatal() {
        let good = answer(ACK, 77, MAC, OPTIONS);
        for cut in 0..good.len() {
            // Must not panic at any length. Most cuts are not an answer.
            let _ = parse(&good[..cut], MAC, 77);
        }
        // An option that claims more bytes than the frame has.
        assert!(parse(&answer(ACK, 77, MAC, &[51, 200, 1]), MAC, 77).is_none());
        // A mask with holes falls back to /24.
        let odd = parse(&answer(ACK, 77, MAC, &[1, 4, 255, 0, 255, 0]), MAC, 77).unwrap();
        assert_eq!(odd.lease.address.prefix_len(), 24);
    }

    #[test]
    fn a_request_is_a_valid_frame() {
        let f = frame(
            MAC,
            5,
            REQUEST,
            None,
            Some("198.51.100.7".parse().unwrap()),
            None,
        );
        assert_eq!(&f[..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &MAC);
        assert_eq!(checksum(&f[14..34]), 0, "the IP header checksum verifies");
        assert_eq!(u16::from_be_bytes([f[16], f[17]]) as usize, f.len() - 14);
        assert!(f.len() - 14 - 20 - 8 >= 300, "padded to the BOOTP minimum");
        assert_eq!(f[14 + 20 + 8 + 10], 0x80, "asks for a broadcast answer");
        // A renewal carries the address in use as its source.
        let r = frame(
            MAC,
            5,
            REQUEST,
            Some("198.51.100.7".parse().unwrap()),
            None,
            None,
        );
        assert_eq!(&r[26..30], &[198, 51, 100, 7]);
        assert_eq!(checksum(&r[14..34]), 0);
    }
}
