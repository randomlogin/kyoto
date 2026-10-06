//! A local monitoring dashboard for a running kyoto node.
//!
//! Shows live peer count, chain tip, sync throughput, and a scrolling log of every
//! `Info`/`Warning`/`Event` the node emits (in particular *why* a peer was disconnected or
//! banned). Periodic samples of the key counters are persisted to a local SQLite file so the
//! page can also draw history graphs that survive a restart of this example. A `/metrics`
//! endpoint exposes the same counters in Prometheus text-exposition format, so nothing here is
//! throwaway: any Prometheus-compatible scraper can be pointed at it later without any changes.
//!
//! It runs against Mutinynet, a custom signet with 30 second blocks, using a local Mutinynet node
//! and the public seed as peers (see the constants below).
//!
//! Run with `cargo run --example dashboard --features stats`, then open <http://127.0.0.1:3000>.
//! With the `stats` feature the node also serves its own statistics at
//! <http://127.0.0.1:9332/metrics>.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use bip157::chain::{BlockHeaderChanges, ChainState};
use bip157::messages::{Event, Warning};
use bip157::{builder::Builder, chain::checkpoints::HashCheckpoint, Client, Info, Requester};
use bip157::{Address, BlockHash, Magic, Network, ServiceFlags, Stats, TrustedPeer};
use bitcoin::p2p::address::AddrV2;
use prometheus::{GaugeVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

// Mutinynet is a custom signet: same genesis block, but its P2P magic comes from its own challenge
// (the first four bytes of sha256d of the signet challenge, see BIP325).
const NETWORK: Network = Network::Signet;
const MAGIC: [u8; 4] = [0xa5, 0xdf, 0x2d, 0xcb];
// A local Mutinynet node, and the published public seed.
const PEERS: [&str; 2] = ["127.0.0.1:38333", "45.79.52.207:38333"];
// Blocks come every 30 seconds, so start near the tip instead of syncing from genesis. Replace
// this with a recent block (see https://mutinynet.com) if it is too old: the public seed does not
// answer header requests that span more than a few hundred blocks.
const RECOVERY_HEIGHT: u32 = 3_484_440;
const RECOVERY_HASH: &str = "0000024b162c3b8e95edc42ab5e734e4c89bc027c8b1135949da77b807290ddb";
// The script(s) a real wallet or LN node would actually care about. Swap this out (or take a
// list from configuration) for your own watched addresses/descriptors.
const WATCHED_ADDR: &str = "tb1q9pvjqz5u5sdgpatg3wn0ce438u5cyv85lly0pc";
const REQUIRED_PEERS: u8 = 2;

// Overridable with the `DASHBOARD_ADDR` and `DASHBOARD_DB` environment variables. The page has
// no authentication, so it only listens on loopback unless told otherwise.
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_DB_PATH: &str = "dashboard.sqlite";
const HISTORY_CAP: usize = 500;
const RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Clone, Serialize)]
struct LogEntry {
    ts_ms: i64,
    level: &'static str,
    message: String,
}

// The canonical counters/gauges. These are cheap to clone (internally `Arc`-backed) and safe to
// update from multiple tasks without any extra locking of our own.
struct Metrics {
    connected_peers: IntGauge,
    required_peers: IntGauge,
    tip_height: IntGauge,
    start_time_seconds: IntGauge,
    blocks_downloaded_total: IntCounter,
    filters_checked_total: IntCounter,
    filters_matched_total: IntCounter,
    peer_disconnects_total: IntCounterVec,
    peer_bans_total: IntCounterVec,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        let connected_peers =
            IntGauge::new("kyoto_connected_peers", "Currently connected peers").unwrap();
        let required_peers =
            IntGauge::new("kyoto_required_peers", "Configured required peer count").unwrap();
        let tip_height =
            IntGauge::new("kyoto_tip_height", "Height of the best known chain tip").unwrap();
        let start_time_seconds = IntGauge::new(
            "kyoto_start_time_seconds",
            "Unix timestamp this process started",
        )
        .unwrap();
        let blocks_downloaded_total =
            IntCounter::new("kyoto_blocks_downloaded_total", "Total blocks downloaded").unwrap();
        let filters_checked_total = IntCounter::new(
            "kyoto_filters_checked_total",
            "Total compact filters checked against the watched scripts",
        )
        .unwrap();
        let filters_matched_total = IntCounter::new(
            "kyoto_filters_matched_total",
            "Total compact filters that matched a watched script",
        )
        .unwrap();
        let peer_disconnects_total = IntCounterVec::new(
            Opts::new(
                "kyoto_peer_disconnects_total",
                "Total peer disconnects, by reason",
            ),
            &["reason"],
        )
        .unwrap();
        let peer_bans_total = IntCounterVec::new(
            Opts::new("kyoto_peer_bans_total", "Total peer bans, by reason"),
            &["reason"],
        )
        .unwrap();

        registry
            .register(Box::new(connected_peers.clone()))
            .unwrap();
        registry.register(Box::new(required_peers.clone())).unwrap();
        registry.register(Box::new(tip_height.clone())).unwrap();
        registry
            .register(Box::new(start_time_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(blocks_downloaded_total.clone()))
            .unwrap();
        registry
            .register(Box::new(filters_checked_total.clone()))
            .unwrap();
        registry
            .register(Box::new(filters_matched_total.clone()))
            .unwrap();
        registry
            .register(Box::new(peer_disconnects_total.clone()))
            .unwrap();
        registry
            .register(Box::new(peer_bans_total.clone()))
            .unwrap();

        Self {
            connected_peers,
            required_peers,
            tip_height,
            start_time_seconds,
            blocks_downloaded_total,
            filters_checked_total,
            filters_matched_total,
            peer_disconnects_total,
            peer_bans_total,
        }
    }
}

struct AppState {
    metrics: Metrics,
    // Live view into the node's network state, read straight from the library (`stats` feature).
    node_stats: Stats,
    registry: Registry,
    history: Mutex<VecDeque<LogEntry>>,
    // Kept alongside the Prometheus counters purely so the live page can show a reason
    // breakdown without decoding Prometheus's internal metric family representation.
    disconnect_reasons: Mutex<HashMap<String, u64>>,
    ban_reasons: Mutex<HashMap<String, u64>>,
    start_time: SystemTime,
    db: Mutex<Connection>,
}

// Each node log line goes to stdout (journald), the SQLite `logs` table, and the in-memory
// buffer the live page reads from.
fn push_log(state: &AppState, level: &'static str, message: String) {
    let ts_ms = now_unix() * 1000;
    match level {
        "warn" => tracing::warn!(target: "node", "{message}"),
        _ => tracing::info!(target: "node", "{message}"),
    }
    let _ = state.db.lock().unwrap().execute(
        "INSERT INTO logs (ts_ms, level, message) VALUES (?1, ?2, ?3)",
        params![ts_ms, level, message],
    );
    let mut history = state.history.lock().unwrap();
    if history.len() >= HISTORY_CAP {
        history.pop_front();
    }
    history.push_back(LogEntry {
        ts_ms,
        level,
        message,
    });
}

// The most recent persisted log lines, oldest first, to seed the live page after a restart.
fn load_recent_logs(db: &Connection) -> VecDeque<LogEntry> {
    let mut stmt = db
        .prepare("SELECT ts_ms, level, message FROM logs ORDER BY ts_ms DESC, rowid DESC LIMIT ?1")
        .unwrap();
    let mut entries: Vec<LogEntry> = stmt
        .query_map(params![HISTORY_CAP as i64], |row| {
            let level: String = row.get(1)?;
            Ok(LogEntry {
                ts_ms: row.get(0)?,
                level: match level.as_str() {
                    "warn" => "warn",
                    "event" => "event",
                    _ => "info",
                },
                message: row.get(2)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    entries.reverse();
    entries.into()
}

fn open_db() -> Connection {
    let path = std::env::var("DASHBOARD_DB").unwrap_or_else(|_| DEFAULT_DB_PATH.into());
    let db = Connection::open(&path).unwrap_or_else(|e| panic!("failed to open {path}: {e}"));
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS logs (
             ts_ms INTEGER NOT NULL,
             level TEXT NOT NULL,
             message TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts_ms);
         CREATE TABLE IF NOT EXISTS samples (
             ts INTEGER NOT NULL,
             metric TEXT NOT NULL,
             value REAL NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_samples_metric_ts ON samples(metric, ts);",
    )
    .expect("failed to initialize schema");
    db
}

#[tokio::main]
async fn main() {
    // Log level comes from `RUST_LOG` (e.g. `RUST_LOG=debug`), defaulting to `info`.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let checkpoint =
        HashCheckpoint::new(RECOVERY_HEIGHT, BlockHash::from_str(RECOVERY_HASH).unwrap());
    let watched_script = Address::from_str(WATCHED_ADDR)
        .unwrap()
        .require_network(NETWORK)
        .unwrap()
        .into();
    let mut watched = HashSet::new();
    watched.insert(watched_script);

    // Both peers support the encrypted V2 transport.
    let peers = PEERS.map(|addr| {
        let mut peer = TrustedPeer::from(addr.parse::<SocketAddr>().unwrap());
        peer.set_services(ServiceFlags::P2P_V2);
        peer
    });
    let builder = Builder::new(NETWORK);
    let (node, client) = builder
        .custom_magic(Magic::from_bytes(MAGIC))
        .chain_state(ChainState::Checkpoint(checkpoint))
        .add_peers(peers)
        .whitelist_only()
        .required_peers(REQUIRED_PEERS)
        .build();

    tokio::task::spawn(async move {
        if let Err(e) = node.run().await {
            tracing::error!("Node exited: {e}");
        }
    });

    let Client {
        requester,
        mut info_rx,
        mut warn_rx,
        mut event_rx,
    } = client;

    let db = open_db();
    let history = load_recent_logs(&db);
    let registry = Registry::new();
    let metrics = Metrics::new(&registry);
    metrics.required_peers.set(REQUIRED_PEERS as i64);
    let start_time = SystemTime::now();
    metrics.start_time_seconds.set(now_unix());

    let state = Arc::new(AppState {
        node_stats: requester.stats(),
        metrics,
        registry,
        history: Mutex::new(history),
        disconnect_reasons: Mutex::new(HashMap::new()),
        ban_reasons: Mutex::new(HashMap::new()),
        start_time,
        db: Mutex::new(db),
    });

    // Drain every Info/Warning/Event the node emits, forever, updating counters and the
    // scrolling log as we go.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    info = info_rx.recv() => {
                        let Some(info) = info else { break };
                        push_log(&state, "info", info.to_string());
                        if let Info::BlockReceived(_) = info {
                            state.metrics.blocks_downloaded_total.inc();
                        }
                    }
                    warn = warn_rx.recv() => {
                        let Some(warn) = warn else { break };
                        push_log(&state, "warn", warn.to_string());
                        match &warn {
                            Warning::PeerDisconnected { reason, .. } => {
                                let label = reason.to_string();
                                state
                                    .metrics
                                    .peer_disconnects_total
                                    .with_label_values(&[&label])
                                    .inc();
                                *state
                                    .disconnect_reasons
                                    .lock()
                                    .unwrap()
                                    .entry(label)
                                    .or_insert(0) += 1;
                            }
                            Warning::PeerBanned { reason, .. } => {
                                let label = reason.to_string();
                                state
                                    .metrics
                                    .peer_bans_total
                                    .with_label_values(&[&label])
                                    .inc();
                                *state
                                    .ban_reasons
                                    .lock()
                                    .unwrap()
                                    .entry(label)
                                    .or_insert(0) += 1;
                            }
                            _ => {}
                        }
                    }
                    event = event_rx.recv() => {
                        let Some(event) = event else { break };
                        match &event {
                            Event::IndexedFilter(filter) => {
                                state.metrics.filters_checked_total.inc();
                                if filter.contains_any(watched.iter()) {
                                    state.metrics.filters_matched_total.inc();
                                    push_log(
                                        &state,
                                        "event",
                                        format!(
                                            "Filter matched a watched script at height {}",
                                            filter.height()
                                        ),
                                    );
                                    // A real wallet/LN node would call
                                    // `requester.get_block(filter.block_hash())` here.
                                }
                            }
                            Event::ChainUpdate(BlockHeaderChanges::Connected(header)) => {
                                push_log(
                                    &state,
                                    "event",
                                    format!("New tip at height {}", header.height),
                                );
                            }
                            Event::ChainUpdate(BlockHeaderChanges::Reorganized {
                                accepted,
                                reorganized,
                            }) => {
                                push_log(
                                    &state,
                                    "event",
                                    format!(
                                        "Reorg: accepted {} block(s), removed {} block(s), new tip height {}",
                                        accepted.len(),
                                        reorganized.len(),
                                        accepted.last().map(|h| h.height).unwrap_or_default()
                                    ),
                                );
                            }
                            Event::ChainUpdate(BlockHeaderChanges::ForkAdded(header)) => {
                                push_log(
                                    &state,
                                    "event",
                                    format!("Fork candidate added at height {}", header.height),
                                );
                            }
                            Event::FiltersSynced(update) => {
                                push_log(
                                    &state,
                                    "event",
                                    format!(
                                        "Fully synced to tip {} at height {}",
                                        update.tip().hash,
                                        update.tip().height
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    // Poll for peer count and chain tip, since those are request/response, not push, APIs.
    {
        let state = Arc::clone(&state);
        let requester = requester.clone();
        tokio::spawn(async move { run_poller(state, requester).await });
    }

    // Periodically snapshot the counters into SQLite so the dashboard's graphs have history,
    // even across restarts of this example.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move { run_snapshotter(state).await });
    }

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/history", get(history_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let http_addr = std::env::var("DASHBOARD_ADDR").unwrap_or_else(|_| DEFAULT_HTTP_ADDR.into());
    tracing::info!("Dashboard listening on http://{http_addr}");
    let listener = tokio::net::TcpListener::bind(&http_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {http_addr}: {e}"));
    axum::serve(listener, app).await.unwrap();
}

async fn run_poller(state: Arc<AppState>, requester: Requester) {
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    loop {
        interval.tick().await;
        if let Ok(peers) = requester.peer_info().await {
            state.metrics.connected_peers.set(peers.len() as i64);
        }
        if let Ok(tip) = requester.chain_tip().await {
            state.metrics.tip_height.set(tip.height as i64);
        }
    }
}

async fn run_snapshotter(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(SNAPSHOT_INTERVAL);
    loop {
        interval.tick().await;
        let ts = now_unix();
        let disconnects: u64 = state.disconnect_reasons.lock().unwrap().values().sum();
        let bans: u64 = state.ban_reasons.lock().unwrap().values().sum();
        let samples: [(&str, f64); 7] = [
            (
                "connected_peers",
                state.metrics.connected_peers.get() as f64,
            ),
            ("tip_height", state.metrics.tip_height.get() as f64),
            (
                "blocks_downloaded_total",
                state.metrics.blocks_downloaded_total.get() as f64,
            ),
            (
                "filters_checked_total",
                state.metrics.filters_checked_total.get() as f64,
            ),
            (
                "filters_matched_total",
                state.metrics.filters_matched_total.get() as f64,
            ),
            ("peer_disconnects_total", disconnects as f64),
            ("peer_bans_total", bans as f64),
        ];
        let db = state.db.lock().unwrap();
        for (metric, value) in samples {
            let _ = db.execute(
                "INSERT INTO samples (ts, metric, value) VALUES (?1, ?2, ?3)",
                params![ts, metric, value],
            );
        }
        let _ = db.execute(
            "DELETE FROM samples WHERE ts < ?1",
            params![ts - RETENTION_SECS],
        );
        let _ = db.execute(
            "DELETE FROM logs WHERE ts_ms < ?1",
            params![(ts - RETENTION_SECS) * 1000],
        );
    }
}

#[derive(Serialize)]
struct StatsResponse {
    uptime_seconds: u64,
    connected_peers: i64,
    required_peers: i64,
    tip_height: i64,
    blocks_downloaded: i64,
    filters_checked: i64,
    filters_matched: i64,
    disconnect_reasons: Vec<(String, u64)>,
    ban_reasons: Vec<(String, u64)>,
    peers: Vec<PeerRow>,
    history: Vec<LogEntry>,
}

#[derive(Serialize)]
struct PeerRow {
    addr: String,
    uptime_seconds: u64,
}

fn format_addr(addr: &AddrV2) -> String {
    match addr {
        AddrV2::Ipv4(ip) => ip.to_string(),
        AddrV2::Ipv6(ip) => ip.to_string(),
        other => format!("{other:?}"),
    }
}

fn peer_rows(stats: &Stats) -> Vec<PeerRow> {
    stats
        .snapshot()
        .peers
        .iter()
        .map(|p| PeerRow {
            addr: format_addr(&p.addr),
            uptime_seconds: p.uptime.as_secs(),
        })
        .collect()
}

async fn stats_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime_seconds = SystemTime::now()
        .duration_since(state.start_time)
        .unwrap_or_default()
        .as_secs();
    let history: Vec<LogEntry> = state
        .history
        .lock()
        .unwrap()
        .iter()
        .rev()
        .cloned()
        .collect();
    let disconnect_reasons: Vec<(String, u64)> = state
        .disconnect_reasons
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    let ban_reasons: Vec<(String, u64)> = state
        .ban_reasons
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    Json(StatsResponse {
        uptime_seconds,
        connected_peers: state.metrics.connected_peers.get(),
        required_peers: state.metrics.required_peers.get(),
        tip_height: state.metrics.tip_height.get(),
        blocks_downloaded: state.metrics.blocks_downloaded_total.get() as i64,
        filters_checked: state.metrics.filters_checked_total.get() as i64,
        filters_matched: state.metrics.filters_matched_total.get() as i64,
        disconnect_reasons,
        ban_reasons,
        peers: peer_rows(&state.node_stats),
        history,
    })
}

#[derive(Deserialize)]
struct HistoryQuery {
    metric: String,
    #[serde(default = "default_hours")]
    hours: f64,
}

fn default_hours() -> f64 {
    6.0
}

async fn history_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let since = now_unix() - (q.hours * 3600.0) as i64;
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT ts, value FROM samples WHERE metric = ?1 AND ts >= ?2 ORDER BY ts")
        .unwrap();
    let points: Vec<(i64, f64)> = stmt
        .query_map(params![q.metric, since], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    Json(points)
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let families = state.registry.gather();
    let mut buf = String::new();
    TextEncoder::new().encode_utf8(&families, &mut buf).unwrap();
    // Peers come and go, so build this family fresh per scrape rather than leaving stale series
    // behind for peers that have disconnected.
    let peer_registry = Registry::new();
    let peer_uptime = GaugeVec::new(
        Opts::new(
            "kyoto_peer_uptime_seconds",
            "Seconds a currently connected peer has been connected",
        ),
        &["addr"],
    )
    .unwrap();
    peer_registry
        .register(Box::new(peer_uptime.clone()))
        .unwrap();
    for peer in peer_rows(&state.node_stats) {
        peer_uptime
            .with_label_values(&[&peer.addr])
            .set(peer.uptime_seconds as f64);
    }
    TextEncoder::new()
        .encode_utf8(&peer_registry.gather(), &mut buf)
        .unwrap();
    ([("Content-Type", "text/plain; version=0.0.4")], buf)
}

async fn index_handler() -> impl IntoResponse {
    Html(INDEX_HTML)
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Kyoto Node Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; padding: 24px; background: #0d1117; color: #e6edf3; }
  h1 { font-size: 1.4rem; margin-bottom: 4px; }
  #uptime { color: #8b949e; font-size: 0.9rem; margin-bottom: 20px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .tile { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; }
  .tile .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.03em; }
  .tile .value { font-size: 1.6rem; font-weight: 600; margin-top: 4px; }
  .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; }
  .panel h2 { font-size: 0.95rem; margin: 0 0 8px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  td, th { text-align: left; padding: 3px 6px; }
  .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .chart-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; height: 220px; }
  .chart-box h2 { font-size: 0.9rem; margin: 0 0 8px 0; }
  #log { max-height: 360px; overflow-y: auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
  #log table { width: 100%; }
  #log th { position: sticky; top: 0; background: #161b22; }
  .lvl-info { color: #58a6ff; }
  .lvl-warn { color: #d29922; }
  .lvl-event { color: #3fb950; }
</style>
</head>
<body>
<h1>Kyoto Node Dashboard</h1>
<div id="uptime">uptime: --</div>

<div class="tiles" id="tiles"></div>

<div class="panel" style="margin-bottom: 24px;">
  <h2>Connected peers</h2>
  <table>
    <thead><tr><th>address</th><th>uptime</th></tr></thead>
    <tbody id="peer-body"></tbody>
  </table>
</div>

<div class="panels">
  <div class="panel">
    <h2>Disconnect reasons</h2>
    <table id="disconnect-table"></table>
  </div>
  <div class="panel">
    <h2>Ban reasons</h2>
    <table id="ban-table"></table>
  </div>
</div>

<div class="charts">
  <div class="chart-box"><h2>Connected peers</h2><canvas id="chart-connected_peers"></canvas></div>
  <div class="chart-box"><h2>Tip height</h2><canvas id="chart-tip_height"></canvas></div>
  <div class="chart-box"><h2>Blocks downloaded</h2><canvas id="chart-blocks_downloaded_total"></canvas></div>
  <div class="chart-box"><h2>Filters checked / matched</h2><canvas id="chart-filters"></canvas></div>
  <div class="chart-box"><h2>Disconnects / bans</h2><canvas id="chart-disconnects"></canvas></div>
</div>

<div class="panel">
  <h2>Event log</h2>
  <div id="log">
    <table>
      <thead><tr><th>time</th><th>level</th><th>message</th></tr></thead>
      <tbody id="log-body"></tbody>
    </table>
  </div>
</div>

<script>
const tileDefs = [
  ["connected_peers", "Connected peers", v => `${v.connected_peers} / ${v.required_peers}`],
  ["tip_height", "Tip height", v => v.tip_height],
  ["blocks_downloaded", "Blocks downloaded", v => v.blocks_downloaded],
  ["filters_checked", "Filters checked", v => v.filters_checked],
  ["filters_matched", "Filters matched", v => v.filters_matched],
];
document.getElementById("tiles").innerHTML = tileDefs.map(([id, label]) =>
  `<div class="tile"><div class="label">${label}</div><div class="value" id="tile-${id}">--</div></div>`
).join("");

function fmtUptime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return `${h}h ${m}m ${sec}s`;
}

function renderReasonTable(elemId, rows) {
  const el = document.getElementById(elemId);
  if (!rows.length) { el.innerHTML = "<tr><td>none yet</td></tr>"; return; }
  el.innerHTML = rows.map(([reason, count]) => `<tr><td>${reason}</td><td>${count}</td></tr>`).join("");
}

async function fetchStats() {
  const res = await fetch("/api/stats");
  const data = await res.json();
  document.getElementById("uptime").textContent = `uptime: ${fmtUptime(data.uptime_seconds)}`;
  for (const [id, , fn] of tileDefs) {
    document.getElementById(`tile-${id}`).textContent = fn(data);
  }
  document.getElementById("peer-body").innerHTML = data.peers.length
    ? data.peers.map(p => `<tr><td>${p.addr}</td><td>${fmtUptime(p.uptime_seconds)}</td></tr>`).join("")
    : "<tr><td colspan=2>no peers connected</td></tr>";
  renderReasonTable("disconnect-table", data.disconnect_reasons);
  renderReasonTable("ban-table", data.ban_reasons);
  const body = document.getElementById("log-body");
  body.innerHTML = data.history.map(e => {
    const t = new Date(e.ts_ms).toLocaleTimeString();
    return `<tr class="lvl-${e.level}"><td>${t}</td><td>${e.level}</td><td>${e.message}</td></tr>`;
  }).join("");
}

const charts = {};
function makeChart(canvasId, labels) {
  const ctx = document.getElementById(canvasId).getContext("2d");
  charts[canvasId] = new Chart(ctx, {
    type: "line",
    data: { datasets: labels.map(label => ({ label, data: [], borderWidth: 1.5, pointRadius: 0, tension: 0.2 })) },
    options: {
      animation: false,
      maintainAspectRatio: false,
      scales: {
        x: { type: "linear", ticks: { callback: v => new Date(v * 1000).toLocaleTimeString() } },
        y: { beginAtZero: true },
      },
      plugins: { legend: { display: labels.length > 1 } },
    },
  });
}
makeChart("chart-connected_peers", ["connected"]);
makeChart("chart-tip_height", ["height"]);
makeChart("chart-blocks_downloaded_total", ["blocks"]);
makeChart("chart-filters", ["checked", "matched"]);
makeChart("chart-disconnects", ["disconnects", "bans"]);

async function points(metric) {
  const res = await fetch(`/api/history?metric=${encodeURIComponent(metric)}&hours=6`);
  const rows = await res.json();
  return rows.map(([ts, v]) => ({ x: ts, y: v }));
}

async function refreshCharts() {
  charts["chart-connected_peers"].data.datasets[0].data = await points("connected_peers");
  charts["chart-tip_height"].data.datasets[0].data = await points("tip_height");
  charts["chart-blocks_downloaded_total"].data.datasets[0].data = await points("blocks_downloaded_total");
  charts["chart-filters"].data.datasets[0].data = await points("filters_checked_total");
  charts["chart-filters"].data.datasets[1].data = await points("filters_matched_total");
  charts["chart-disconnects"].data.datasets[0].data = await points("peer_disconnects_total");
  charts["chart-disconnects"].data.datasets[1].data = await points("peer_bans_total");
  for (const c of Object.values(charts)) c.update("none");
}

fetchStats();
refreshCharts();
setInterval(fetchStats, 2000);
setInterval(refreshCharts, 10000);
</script>
</body>
</html>
"#;
