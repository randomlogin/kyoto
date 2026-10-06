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

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
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
    connected_at: Instant,
    counters: Counters,
}

#[derive(Debug, Default)]
struct Inner {
    totals: Counters,
    peers: Mutex<HashMap<u32, Arc<PeerEntry>>>,
}

/// A shared handle to the node's network statistics.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    inner: Arc<Inner>,
}

/// A point-in-time copy of the network statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
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
                uptime: p.connected_at.elapsed(),
                bytes_received: p.counters.bytes_received.load(Ordering::Relaxed),
                bytes_sent: p.counters.bytes_sent.load(Ordering::Relaxed),
                messages_received: p.counters.messages_received.load(Ordering::Relaxed),
                messages_sent: p.counters.messages_sent.load(Ordering::Relaxed),
            })
            .collect();
        StatsSnapshot {
            bytes_received: totals.bytes_received.load(Ordering::Relaxed),
            bytes_sent: totals.bytes_sent.load(Ordering::Relaxed),
            messages_received: totals.messages_received.load(Ordering::Relaxed),
            messages_sent: totals.messages_sent.load(Ordering::Relaxed),
            peers,
        }
    }

    // Start tracking a connection. The peer is removed again when the guard drops.
    pub(crate) fn register_peer(&self, id: u32, addr: AddrV2) -> PeerStatsGuard {
        let entry = Arc::new(PeerEntry {
            addr,
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
                escape_label(&addr_label(&peer.addr)),
                peer.uptime.as_secs()
            ));
        }
        out
    }
}

fn addr_label(addr: &AddrV2) -> String {
    match addr {
        AddrV2::Ipv4(ip) => ip.to_string(),
        AddrV2::Ipv6(ip) => ip.to_string(),
        other => format!("{other:?}"),
    }
}

// Label values are quoted, so backslashes, quotes and newlines have to be escaped.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn metrics(State(stats): State<Stats>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        stats.render_prometheus(),
    )
}

fn router(stats: Stats) -> Router {
    Router::new()
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

/// Serve `GET /metrics` on `addr` until the returned handle is dropped.
///
/// If the address cannot be bound the node carries on without the endpoint.
pub(crate) fn spawn_server(addr: SocketAddr, stats: Stats) -> ServerHandle {
    ServerHandle(tokio::spawn(async move {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                crate::debug!(format!("Serving statistics on http://{addr}/metrics"));
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
        let peer = stats.register_peer(1, addr(7));
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
            response.contains("kyoto_peer_uptime_seconds{addr=\"10.0.0.7\"} "),
            "{response}"
        );

        let missing = http_get(bound, "/other").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        server.abort();
    }

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn totals_outlive_peers() {
        let stats = Stats::default();
        let a = stats.register_peer(1, addr(1));
        let b = stats.register_peer(2, addr(2));
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
