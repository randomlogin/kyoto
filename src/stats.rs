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
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

use axum::{
    extract::{RawQuery, State},
    http::header,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use bitcoin::p2p::address::AddrV2;
use tokio::{net::TcpListener, task::JoinHandle};

use crate::DisconnectReason;

// How many ended connections are remembered. The oldest are dropped first.
const HISTORY_CAPACITY: usize = 200;

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
    connected_at_wall: SystemTime,
    counters: Counters,
    // Why the connection ended, set by whoever decides to end it. The first reason wins.
    reason: Mutex<Option<DisconnectReason>>,
}

#[derive(Debug)]
struct Inner {
    started_at: Instant,
    totals: Counters,
    peers: Mutex<HashMap<u32, Arc<PeerEntry>>>,
    // Connections that have ended, oldest first.
    history: Mutex<VecDeque<PeerRecord>>,
    next_record_id: AtomicU64,
    // Every ended connection by the kind of its reason, which unlike the history is never trimmed.
    disconnects: Mutex<BTreeMap<&'static str, u64>>,
    // The height of the header chain, 0 until the node has announced one.
    tip_height: AtomicU32,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            totals: Counters::default(),
            peers: Mutex::default(),
            history: Mutex::default(),
            next_record_id: AtomicU64::new(1),
            disconnects: Mutex::default(),
            tip_height: AtomicU32::new(0),
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
    /// The height of the header chain, or `None` before the node has announced one.
    pub tip_height: Option<u32>,
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

/// A connection to a peer that has ended.
#[derive(Debug, Clone)]
pub struct PeerRecord {
    /// Increases with every ended connection, so a reader can ask for records after the last one it
    /// saw with [`Stats::history_since`] and miss none unless more than the buffer holds ended in
    /// between.
    pub id: u64,
    /// The address of the peer.
    pub addr: AddrV2,
    /// The port of the peer.
    pub port: u16,
    /// When the connection was opened.
    pub connected_at: SystemTime,
    /// How long the connection stayed open.
    pub lived: Duration,
    /// Bytes read from this peer on this connection.
    pub bytes_received: u64,
    /// Bytes written to this peer on this connection.
    pub bytes_sent: u64,
    /// Messages received from this peer on this connection.
    pub messages_received: u64,
    /// Messages sent to this peer on this connection.
    pub messages_sent: u64,
    /// Why the connection ended.
    pub reason: DisconnectReason,
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
            tip_height: Some(self.inner.tip_height.load(Ordering::Relaxed)).filter(|&h| h != 0),
            peers,
        }
    }

    // The header chain now has this height. It also goes down after a reorganization.
    pub(crate) fn set_tip_height(&self, height: u32) {
        self.inner.tip_height.store(height, Ordering::Relaxed);
    }

    /// The connections that have ended, oldest first, with an id greater than `id`. Pass `0` to get
    /// everything that is remembered, or the id of the last record seen to get only newer ones.
    pub fn history_since(&self, id: u64) -> Vec<PeerRecord> {
        self.inner
            .history
            .lock()
            .expect("stats lock poisoned")
            .iter()
            .filter(|record| record.id > id)
            .cloned()
            .collect()
    }

    // Remember why the connected peer at `addr` is going away, unless a reason is already known.
    pub(crate) fn note_disconnect(&self, addr: &AddrV2, reason: &DisconnectReason) {
        let peers = self.inner.peers.lock().expect("stats lock poisoned");
        for entry in peers.values().filter(|entry| &entry.addr == addr) {
            entry.set_reason(reason.clone());
        }
    }

    // Remember why the connection with this id is going away, unless a reason is already known.
    pub(crate) fn note_disconnect_id(&self, id: u32, reason: DisconnectReason) {
        let peers = self.inner.peers.lock().expect("stats lock poisoned");
        if let Some(entry) = peers.get(&id) {
            entry.set_reason(reason);
        }
    }

    // Remember why every connection is going away, unless a reason is already known.
    pub(crate) fn note_disconnect_all(&self, reason: DisconnectReason) {
        let peers = self.inner.peers.lock().expect("stats lock poisoned");
        for entry in peers.values() {
            entry.set_reason(reason.clone());
        }
    }

    // Start tracking a connection. The peer is removed again when the guard drops.
    pub(crate) fn register_peer(&self, id: u32, addr: AddrV2, port: u16) -> PeerStatsGuard {
        let entry = Arc::new(PeerEntry {
            addr,
            port,
            connected_at: Instant::now(),
            connected_at_wall: SystemTime::now(),
            counters: Counters::default(),
            reason: Mutex::new(None),
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

impl PeerEntry {
    fn set_reason(&self, reason: DisconnectReason) {
        if let Ok(mut slot) = self.reason.lock() {
            slot.get_or_insert(reason);
        }
    }
}

// Moves the peer from the live table to the history on drop, whichever way the connection task
// exits.
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
        let inner = &self.handle.inner;
        let entry = &self.handle.entry;
        if let Ok(mut peers) = inner.peers.lock() {
            peers.remove(&self.id);
        }
        // Every way a connection ends is meant to say why. If one did not, this shows it.
        let reason = entry
            .reason
            .lock()
            .ok()
            .and_then(|mut reason| reason.take())
            .unwrap_or(DisconnectReason::Unknown);
        if let Ok(mut disconnects) = inner.disconnects.lock() {
            *disconnects.entry(reason.kind()).or_default() += 1;
        }
        if let Ok(mut history) = inner.history.lock() {
            if history.len() == HISTORY_CAPACITY {
                history.pop_front();
            }
            history.push_back(PeerRecord {
                id: inner.next_record_id.fetch_add(1, Ordering::Relaxed),
                addr: entry.addr.clone(),
                port: entry.port,
                connected_at: entry.connected_at_wall,
                lived: entry.connected_at.elapsed(),
                bytes_received: entry.counters.bytes_received.load(Ordering::Relaxed),
                bytes_sent: entry.counters.bytes_sent.load(Ordering::Relaxed),
                messages_received: entry.counters.messages_received.load(Ordering::Relaxed),
                messages_sent: entry.counters.messages_sent.load(Ordering::Relaxed),
                reason,
            });
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
    // Remember why this connection is going away, unless a reason is already known.
    pub(crate) fn note_disconnect(&self, reason: DisconnectReason) {
        self.entry.set_reason(reason);
    }

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
        if let Some(height) = snapshot.tip_height {
            out.push_str(&format!(
                "# HELP kyoto_tip_height Height of the header chain.\n\
                 # TYPE kyoto_tip_height gauge\n\
                 kyoto_tip_height {height}\n"
            ));
        }
        out.push_str(
            "# HELP kyoto_peer_disconnects_total Ended peer connections, by the reason they ended.\n\
             # TYPE kyoto_peer_disconnects_total counter\n",
        );
        for (reason, count) in self
            .inner
            .disconnects
            .lock()
            .expect("stats lock poisoned")
            .iter()
        {
            out.push_str(&format!(
                "kyoto_peer_disconnects_total{{reason=\"{reason}\"}} {count}\n"
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
             \"bytes_sent\":{},\"messages_received\":{},\"messages_sent\":{},\
             \"tip_height\":{},\"peers\":[{}]}}",
            snapshot.uptime.as_secs(),
            snapshot.peers.len(),
            snapshot.bytes_received,
            snapshot.bytes_sent,
            snapshot.messages_received,
            snapshot.messages_sent,
            snapshot
                .tip_height
                .map_or("null".to_string(), |height| height.to_string()),
            peers.join(",")
        )
    }

    /// The ended connections newer than `since` as JSON, the format served at
    /// `/api/peers/history`. `connected_at` is in seconds since the Unix epoch.
    pub fn render_history_json(&self, since: u64) -> String {
        let records: Vec<String> = self
            .history_since(since)
            .iter()
            .map(|record| {
                let connected_at = record
                    .connected_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs());
                format!(
                    "{{\"id\":{},\"addr\":\"{}\",\"connected_at\":{},\"lived_seconds\":{},\
                     \"bytes_received\":{},\"bytes_sent\":{},\"messages_received\":{},\
                     \"messages_sent\":{},\"reason_kind\":\"{}\",\"reason\":\"{}\"}}",
                    record.id,
                    escape_json(&addr_label(&record.addr, record.port)),
                    connected_at,
                    record.lived.as_secs(),
                    record.bytes_received,
                    record.bytes_sent,
                    record.messages_received,
                    record.messages_sent,
                    record.reason.kind(),
                    escape_json(&record.reason.to_string())
                )
            })
            .collect();
        format!("{{\"history\":[{}]}}", records.join(","))
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

// `?since=<id>` limits the answer to connections that ended after the record with that id.
async fn api_peers_history(
    State(stats): State<Stats>,
    RawQuery(query): RawQuery,
) -> impl IntoResponse {
    let since = query
        .as_deref()
        .and_then(|query| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix("since="))
        })
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "application/json")],
        stats.render_history_json(since),
    )
}

async fn page() -> impl IntoResponse {
    Html(include_str!("stats_page.html"))
}

fn router(stats: Stats) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/api/stats", get(api_stats))
        .route("/api/peers/history", get(api_peers_history))
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
