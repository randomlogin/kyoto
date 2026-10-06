//! Run a node on Mutinynet, a custom signet with 30 second blocks.
//!
//! Mutinynet shares the signet genesis block, but its P2P magic bytes come from its own
//! `signetchallenge`, so they have to be set explicitly. DNS seeds would return default signet
//! peers, so the node only talks to the two Mutinynet peers listed below.
//!
//! Run with `cargo run --example mutinynet`. With the `stats` feature, the node also serves its
//! statistics at http://127.0.0.1:9332/metrics.

use std::net::SocketAddr;
use std::str::FromStr;

use bip157::chain::{checkpoints::HashCheckpoint, BlockHeaderChanges, ChainState};
use bip157::messages::Event;
use bip157::{builder::Builder, Client};
use bip157::{BlockHash, Magic, Network, ServiceFlags, TrustedPeer};

// First four bytes of sha256d of the signet challenge (BIP325).
const MAGIC: [u8; 4] = [0xa5, 0xdf, 0x2d, 0xcb];
// A local Mutinynet node, and the published public seed.
const PEERS: [&str; 2] = ["127.0.0.1:38333", "45.79.52.207:38333"];
// Blocks come every 30 seconds, so start near the tip instead of syncing from genesis. Replace this
// with a recent block (see https://mutinynet.com) if it is too old: the public seed does not answer
// header requests that span more than a few hundred blocks.
const CHECKPOINT_HEIGHT: u32 = 3_484_440;
const CHECKPOINT_HASH: &str = "0000024b162c3b8e95edc42ab5e734e4c89bc027c8b1135949da77b807290ddb";

#[tokio::main]
async fn main() {
    tracing::subscriber::set_global_default(tracing_subscriber::FmtSubscriber::new()).unwrap();

    let checkpoint = HashCheckpoint::new(
        CHECKPOINT_HEIGHT,
        BlockHash::from_str(CHECKPOINT_HASH).unwrap(),
    );
    // Both peers support the encrypted V2 transport.
    let peers = PEERS.map(|addr| {
        let mut peer = TrustedPeer::from(addr.parse::<SocketAddr>().unwrap());
        peer.set_services(ServiceFlags::P2P_V2);
        peer
    });

    let (node, client) = Builder::new(Network::Signet)
        .custom_magic(Magic::from_bytes(MAGIC))
        .chain_state(ChainState::Checkpoint(checkpoint))
        .add_peers(peers)
        .whitelist_only()
        .required_peers(2)
        .build();
    tokio::task::spawn(async move { node.run().await });

    let Client {
        requester,
        mut info_rx,
        mut warn_rx,
        mut event_rx,
    } = client;
    loop {
        tokio::select! {
            Some(info) = info_rx.recv() => tracing::info!("{info}"),
            Some(warn) = warn_rx.recv() => tracing::warn!("{warn}"),
            Some(event) = event_rx.recv() => match event {
                Event::ChainUpdate(BlockHeaderChanges::Connected(at)) => {
                    tracing::info!("New best tip {}", at.height)
                }
                Event::FiltersSynced(update) => {
                    tracing::info!("Filters synced to height {}", update.tip().height)
                }
                _ => (),
            },
            _ = tokio::signal::ctrl_c() => break,
            else => break,
        }
    }
    let _ = requester.shutdown();
}
