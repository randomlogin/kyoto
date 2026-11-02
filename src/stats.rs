//! Runtime network statistics for a running [`Node`](crate::Node).
//!
//! Enabled with the `stats` cargo feature. A [`Stats`] handle is cheap to clone and may be read from
//! any thread or task, typically obtained from [`Requester::stats`](crate::Requester::stats).
//! Nothing here does any I/O: exposing the numbers over HTTP, Prometheus, logs, etc. is up to the
//! application.
//!
//! Byte counts are application-layer wire sizes (V1: 24 byte header + payload, V2: 3 byte length
//! prefix + encrypted packet). The V2 handshake is not counted.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::header,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use bitcoin::p2p::address::AddrV2;
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Debug, Default)]
struct Counters {
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    messages_received: AtomicU64,
    messages_sent: AtomicU64,
}

#[derive(Debug)]
struct PeerEntry {
    addr: AddrV2,
    port: u16,
    connected_at: Instant,
    counters: Counters,
}

#[derive(Debug)]
struct Inner {
    started_at: Instant,
    totals: Counters,
    peers: Mutex<HashMap<u32, Arc<PeerEntry>>>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            totals: Counters::default(),
            peers: Mutex::default(),
        }
    }
}

/// A shared handle to the node's network statistics.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    inner: Arc<Inner>,
}

/// A point-in-time copy of the network statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    /// How long the statistics have been tracked, which is the age of the node.
    pub uptime: Duration,
    /// Total bytes read from peers since the node was built, including peers since disconnected.
    pub bytes_received: u64,
    /// Total bytes written to peers since the node was built, including peers since disconnected.
    pub bytes_sent: u64,
    /// Total peer-to-peer messages received since the node was built.
    pub messages_received: u64,
    /// Total peer-to-peer messages sent since the node was built.
    pub messages_sent: u64,
    /// The peers connected right now.
    pub peers: Vec<PeerStats>,
}

/// Statistics for a single, currently connected peer.
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// The address of the peer.
    pub addr: AddrV2,
    /// The port of the peer.
    pub port: u16,
    /// How long the connection to this peer has been open.
    pub uptime: Duration,
    /// Bytes read from this peer on this connection.
    pub bytes_received: u64,
    /// Bytes written to this peer on this connection.
    pub bytes_sent: u64,
    /// Messages received from this peer on this connection.
    pub messages_received: u64,
    /// Messages sent to this peer on this connection.
    pub messages_sent: u64,
}

impl Stats {
    /// Take a snapshot of all counters and the currently connected peers.
    pub fn snapshot(&self) -> StatsSnapshot {
        let totals = &self.inner.totals;
        let peers = self
            .inner
            .peers
            .lock()
            .expect("stats lock poisoned")
            .values()
            .map(|p| PeerStats {
                addr: p.addr.clone(),
                port: p.port,
                uptime: p.connected_at.elapsed(),
                bytes_received: p.counters.bytes_received.load(Ordering::Relaxed),
                bytes_sent: p.counters.bytes_sent.load(Ordering::Relaxed),
                messages_received: p.counters.messages_received.load(Ordering::Relaxed),
                messages_sent: p.counters.messages_sent.load(Ordering::Relaxed),
            })
            .collect();
        StatsSnapshot {
            uptime: self.inner.started_at.elapsed(),
            bytes_received: totals.bytes_received.load(Ordering::Relaxed),
            bytes_sent: totals.bytes_sent.load(Ordering::Relaxed),
            messages_received: totals.messages_received.load(Ordering::Relaxed),
            messages_sent: totals.messages_sent.load(Ordering::Relaxed),
            peers,
        }
    }

    // Start tracking a connection. The peer is removed again when the guard drops.
    pub(crate) fn register_peer(&self, id: u32, addr: AddrV2, port: u16) -> PeerStatsGuard {
        let entry = Arc::new(PeerEntry {
            addr,
            port,
            connected_at: Instant::now(),
            counters: Counters::default(),
        });
        self.inner
            .peers
            .lock()
            .expect("stats lock poisoned")
            .insert(id, Arc::clone(&entry));
        PeerStatsGuard {
            id,
            handle: PeerStatsHandle {
                inner: Arc::clone(&self.inner),
                entry,
            },
        }
    }
}

// Removes the peer from the live table on drop, whichever way the connection task exits.
pub(crate) struct PeerStatsGuard {
    id: u32,
    handle: PeerStatsHandle,
}

impl PeerStatsGuard {
    pub(crate) fn handle(&self) -> PeerStatsHandle {
        self.handle.clone()
    }
}

impl Drop for PeerStatsGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.handle.inner.peers.lock() {
            peers.remove(&self.id);
        }
    }
}

// Used by a connection's reader and writer to record traffic.
#[derive(Debug, Clone)]
pub(crate) struct PeerStatsHandle {
    inner: Arc<Inner>,
    entry: Arc<PeerEntry>,
}

impl PeerStatsHandle {
    pub(crate) fn record_received(&self, bytes: usize, messages: u64) {
        for c in [&self.entry.counters, &self.inner.totals] {
            c.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
            c.messages_received.fetch_add(messages, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_sent(&self, bytes: usize, messages: u64) {
        for c in [&self.entry.counters, &self.inner.totals] {
            c.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
            c.messages_sent.fetch_add(messages, Ordering::Relaxed);
        }
    }
}

impl Stats {
    /// The statistics in the Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut out = String::new();
        for (name, help, value) in [
            (
                "kyoto_bytes_received_total",
                "Bytes read from peers.",
                snapshot.bytes_received,
            ),
            (
                "kyoto_bytes_sent_total",
                "Bytes written to peers.",
                snapshot.bytes_sent,
            ),
            (
                "kyoto_messages_received_total",
                "Peer-to-peer messages received.",
                snapshot.messages_received,
            ),
            (
                "kyoto_messages_sent_total",
                "Peer-to-peer messages sent.",
                snapshot.messages_sent,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out.push_str(&format!(
            "# HELP kyoto_connected_peers Peers connected right now.\n\
             # TYPE kyoto_connected_peers gauge\n\
             kyoto_connected_peers {}\n",
            snapshot.peers.len()
        ));
        out.push_str(
            "# HELP kyoto_peer_uptime_seconds How long a connected peer has been connected.\n\
             # TYPE kyoto_peer_uptime_seconds gauge\n",
        );
        for peer in &snapshot.peers {
            out.push_str(&format!(
                "kyoto_peer_uptime_seconds{{addr=\"{}\"}} {}\n",
                escape_label(&addr_label(&peer.addr, peer.port)),
                peer.uptime.as_secs()
            ));
        }
        out
    }

    /// The statistics as JSON, the format the page served at `/` reads.
    pub fn render_json(&self) -> String {
        let snapshot = self.snapshot();
        let peers: Vec<String> = snapshot
            .peers
            .iter()
            .map(|peer| {
                format!(
                    "{{\"addr\":\"{}\",\"uptime_seconds\":{},\"bytes_received\":{},\
                     \"bytes_sent\":{},\"messages_received\":{},\"messages_sent\":{}}}",
                    escape_json(&addr_label(&peer.addr, peer.port)),
                    peer.uptime.as_secs(),
                    peer.bytes_received,
                    peer.bytes_sent,
                    peer.messages_received,
                    peer.messages_sent
                )
            })
            .collect();
        format!(
            "{{\"uptime_seconds\":{},\"connected_peers\":{},\"bytes_received\":{},\
             \"bytes_sent\":{},\"messages_received\":{},\"messages_sent\":{},\"peers\":[{}]}}",
            snapshot.uptime.as_secs(),
            snapshot.peers.len(),
            snapshot.bytes_received,
            snapshot.bytes_sent,
            snapshot.messages_received,
            snapshot.messages_sent,
            peers.join(",")
        )
    }
}

fn addr_label(addr: &AddrV2, port: u16) -> String {
    match addr {
        AddrV2::Ipv4(ip) => format!("{ip}:{port}"),
        AddrV2::Ipv6(ip) => format!("[{ip}]:{port}"),
        other => format!("{other:?}:{port}"),
    }
}

// Label values are quoted, so backslashes, quotes and newlines have to be escaped.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

// Quotes, backslashes and control characters cannot appear raw inside a JSON string.
fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

async fn metrics(State(stats): State<Stats>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        stats.render_prometheus(),
    )
}

async fn api_stats(State(stats): State<Stats>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        stats.render_json(),
    )
}

async fn page() -> impl IntoResponse {
    Html(include_str!("stats_page.html"))
}

fn router(stats: Stats) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/stats", get(api_stats))
        .route("/metrics", get(metrics))
        .with_state(stats)
}

// Stops the server when dropped, so it lives exactly as long as the node does.
pub(crate) struct ServerHandle(JoinHandle<()>);

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve the statistics on `addr` until the returned handle is dropped: `GET /metrics` for
/// Prometheus, `GET /api/stats` as JSON and a small page that reads it at `GET /`.
///
/// If the address cannot be bound the node carries on without the endpoint.
pub(crate) fn spawn_server(addr: SocketAddr, stats: Stats) -> ServerHandle {
    ServerHandle(tokio::spawn(async move {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                crate::debug!(format!("Serving statistics on http://{addr}/"));
                let _ = axum::serve(listener, router(stats)).await;
            }
            Err(e) => {
                crate::debug!(format!(
                    "Could not bind the statistics endpoint to {addr}: {e}"
                ));
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> AddrV2 {
        AddrV2::Ipv4(std::net::Ipv4Addr::new(10, 0, 0, last))
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_prometheus_metrics() {
        let stats = Stats::default();
        let peer = stats.register_peer(1, addr(7), 8333);
        peer.handle().record_received(1234, 3);
        peer.handle().record_sent(56, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router(stats)).await;
        });

        let response = http_get(bound, "/metrics").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("text/plain; version=0.0.4"), "{response}");
        assert!(
            response.contains("kyoto_bytes_received_total 1234\n"),
            "{response}"
        );
        assert!(
            response.contains("kyoto_bytes_sent_total 56\n"),
            "{response}"
        );
        assert!(
            response.contains("kyoto_messages_received_total 3\n"),
            "{response}"
        );
        assert!(
            response.contains("kyoto_messages_sent_total 2\n"),
            "{response}"
        );
        assert!(response.contains("kyoto_connected_peers 1\n"), "{response}");
        assert!(
            response.contains("kyoto_peer_uptime_seconds{addr=\"10.0.0.7:8333\"}"),
            "{response}"
        );

        let missing = http_get(bound, "/other").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        server.abort();
    }

    #[tokio::test]
    async fn serves_page_and_json() {
        let stats = Stats::default();
        let peer = stats.register_peer(1, addr(7), 8333);
        peer.handle().record_received(1234, 3);
        peer.handle().record_sent(56, 2);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router(stats)).await;
        });

        let index = http_get(bound, "/").await;
        assert!(index.starts_with("HTTP/1.1 200"), "{index}");
        assert!(index.contains("text/html"), "{index}");
        assert!(index.contains("/api/stats"), "{index}");

        let json = http_get(bound, "/api/stats").await;
        assert!(json.starts_with("HTTP/1.1 200"), "{json}");
        assert!(json.contains("application/json"), "{json}");
        assert!(json.contains("\"connected_peers\":1,"), "{json}");
        assert!(json.contains("\"bytes_received\":1234,"), "{json}");
        assert!(
            json.contains(
                "{\"addr\":\"10.0.0.7:8333\",\"uptime_seconds\":0,\"bytes_received\":1234,\
                 \"bytes_sent\":56,\"messages_received\":3,\"messages_sent\":2}"
            ),
            "{json}"
        );
        server.abort();
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(escape_json("a\"b\\c\nd"), "a\\\"b\\\\c\\u000ad");
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn totals_outlive_peers() {
        let stats = Stats::default();
        let a = stats.register_peer(1, addr(1), 8333);
        let b = stats.register_peer(2, addr(2), 8333);
        a.handle().record_received(100, 2);
        a.handle().record_sent(10, 1);
        b.handle().record_received(50, 1);
        let snap = stats.snapshot();
        assert_eq!(snap.peers.len(), 2);
        assert_eq!(snap.bytes_received, 150);
        assert_eq!(snap.messages_received, 3);
        assert_eq!(snap.bytes_sent, 10);
        assert_eq!(snap.messages_sent, 1);
        drop(a);
        let snap = stats.snapshot();
        assert_eq!(snap.peers.len(), 1);
        assert_eq!(snap.peers[0].addr, addr(2));
        assert_eq!(snap.peers[0].bytes_received, 50);
        assert_eq!(snap.bytes_received, 150);
    }
}
