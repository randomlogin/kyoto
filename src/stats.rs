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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bitcoin::p2p::address::AddrV2;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> AddrV2 {
        AddrV2::Ipv4(std::net::Ipv4Addr::new(10, 0, 0, last))
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
