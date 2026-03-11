// Serialize and deserialize BIP324 (V2 transport) messages.
//
// A subset of commands are represented with a single byte in V2 instead of the 12-byte ASCII
// encoding of V1. The message ID mappings are defined in BIP324:
// https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki#user-content-v2_Bitcoin_P2P_message_structure
//
// Adapted from the `serde` module of `bip324` (MIT OR Apache-2.0), which was removed in 0.11 when
// that crate dropped its `bitcoin` dependency. Unlike the original, malformed input from a peer is
// an error rather than a panic.

use core::fmt;

use bitcoin::{
    block,
    consensus::{encode, Decodable, Encodable},
    p2p::message::{CommandString, NetworkMessage},
    VarInt,
};

#[derive(Debug)]
pub(crate) enum Error {
    Serialize(bitcoin::io::Error),
    Deserialize(encode::Error),
    UnknownShortId(u8),
    // The packet was too short to hold the short ID, or the 12 byte command that follows a zero.
    Truncated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Serialize(e) => write!(f, "Unable to serialize {e}"),
            Error::Deserialize(e) => write!(f, "Unable to deserialize {e}"),
            Error::UnknownShortId(b) => write!(f, "Unrecognized short ID when deserializing {b}"),
            Error::Truncated => write!(f, "The message is too short to contain a command"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Serialize(e) => Some(e),
            Error::Deserialize(e) => Some(e),
            Error::UnknownShortId(_) | Error::Truncated => None,
        }
    }
}

// The single byte ID of a message, or `None` if the message is sent with a zero byte followed by
// the 12 byte ASCII command.
fn short_id(msg: &NetworkMessage) -> Option<u8> {
    match msg {
        NetworkMessage::Addr(_) => Some(1),
        NetworkMessage::Block(_) => Some(2),
        NetworkMessage::BlockTxn(_) => Some(3),
        NetworkMessage::CmpctBlock(_) => Some(4),
        NetworkMessage::FeeFilter(_) => Some(5),
        NetworkMessage::FilterAdd(_) => Some(6),
        NetworkMessage::FilterClear => Some(7),
        NetworkMessage::FilterLoad(_) => Some(8),
        NetworkMessage::GetBlocks(_) => Some(9),
        NetworkMessage::GetBlockTxn(_) => Some(10),
        NetworkMessage::GetData(_) => Some(11),
        NetworkMessage::GetHeaders(_) => Some(12),
        NetworkMessage::Headers(_) => Some(13),
        NetworkMessage::Inv(_) => Some(14),
        NetworkMessage::MemPool => Some(15),
        NetworkMessage::MerkleBlock(_) => Some(16),
        NetworkMessage::NotFound(_) => Some(17),
        NetworkMessage::Ping(_) => Some(18),
        NetworkMessage::Pong(_) => Some(19),
        NetworkMessage::SendCmpct(_) => Some(20),
        NetworkMessage::Tx(_) => Some(21),
        NetworkMessage::GetCFilters(_) => Some(22),
        NetworkMessage::CFilter(_) => Some(23),
        NetworkMessage::GetCFHeaders(_) => Some(24),
        NetworkMessage::CFHeaders(_) => Some(25),
        NetworkMessage::GetCFCheckpt(_) => Some(26),
        NetworkMessage::CFCheckpt(_) => Some(27),
        NetworkMessage::AddrV2(_) => Some(28),
        NetworkMessage::Version(_)
        | NetworkMessage::Verack
        | NetworkMessage::SendHeaders
        | NetworkMessage::GetAddr
        | NetworkMessage::WtxidRelay
        | NetworkMessage::SendAddrV2
        | NetworkMessage::Alert(_)
        | NetworkMessage::Reject(_)
        | NetworkMessage::Unknown { .. } => None,
    }
}

/// Serialize a [`NetworkMessage`] into the plaintext of a V2 packet.
pub(crate) fn serialize(msg: NetworkMessage) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    match short_id(&msg) {
        Some(id) => buffer.push(id),
        None => {
            buffer.push(0u8);
            // For `Unknown` this is the command carried by the message itself.
            msg.command()
                .consensus_encode(&mut buffer)
                .map_err(Error::Serialize)?;
        }
    }
    msg.consensus_encode(&mut buffer)
        .map_err(Error::Serialize)?;
    Ok(buffer)
}

fn decode<T: Decodable>(mut payload: &[u8]) -> Result<T, Error> {
    T::consensus_decode(&mut payload).map_err(Error::Deserialize)
}

/// Deserialize the plaintext of a V2 packet into a [`NetworkMessage`].
pub(crate) fn deserialize(buffer: &[u8]) -> Result<NetworkMessage, Error> {
    let (&id, rest) = buffer.split_first().ok_or(Error::Truncated)?;
    match id {
        // Zero means the command is encoded in the next 12 bytes.
        0 => {
            if rest.len() < 12 {
                return Err(Error::Truncated);
            }
            let (command_bytes, payload) = rest.split_at(12);
            let command: CommandString = decode(command_bytes)?;
            // A handful of messages never got a short ID, anything else is unknown.
            match command.as_ref() {
                "version" => Ok(NetworkMessage::Version(decode(payload)?)),
                "verack" => Ok(NetworkMessage::Verack),
                "sendheaders" => Ok(NetworkMessage::SendHeaders),
                "getaddr" => Ok(NetworkMessage::GetAddr),
                "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
                "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),
                "alert" => Ok(NetworkMessage::Alert(decode(payload)?)),
                "reject" => Ok(NetworkMessage::Reject(decode(payload)?)),
                _ => Ok(NetworkMessage::Unknown {
                    command,
                    payload: payload.to_vec(),
                }),
            }
        }
        1 => Ok(NetworkMessage::Addr(decode(rest)?)),
        2 => Ok(NetworkMessage::Block(decode(rest)?)),
        3 => Ok(NetworkMessage::BlockTxn(decode(rest)?)),
        4 => Ok(NetworkMessage::CmpctBlock(decode(rest)?)),
        5 => Ok(NetworkMessage::FeeFilter(decode(rest)?)),
        6 => Ok(NetworkMessage::FilterAdd(decode(rest)?)),
        7 => Ok(NetworkMessage::FilterClear),
        8 => Ok(NetworkMessage::FilterLoad(decode(rest)?)),
        9 => Ok(NetworkMessage::GetBlocks(decode(rest)?)),
        10 => Ok(NetworkMessage::GetBlockTxn(decode(rest)?)),
        11 => Ok(NetworkMessage::GetData(decode(rest)?)),
        12 => Ok(NetworkMessage::GetHeaders(decode(rest)?)),
        13 => Ok(NetworkMessage::Headers(
            decode::<HeaderDeserializationWrapper>(rest)?.0,
        )),
        14 => Ok(NetworkMessage::Inv(decode(rest)?)),
        15 => Ok(NetworkMessage::MemPool),
        16 => Ok(NetworkMessage::MerkleBlock(decode(rest)?)),
        17 => Ok(NetworkMessage::NotFound(decode(rest)?)),
        18 => Ok(NetworkMessage::Ping(decode(rest)?)),
        19 => Ok(NetworkMessage::Pong(decode(rest)?)),
        20 => Ok(NetworkMessage::SendCmpct(decode(rest)?)),
        21 => Ok(NetworkMessage::Tx(decode(rest)?)),
        22 => Ok(NetworkMessage::GetCFilters(decode(rest)?)),
        23 => Ok(NetworkMessage::CFilter(decode(rest)?)),
        24 => Ok(NetworkMessage::GetCFHeaders(decode(rest)?)),
        25 => Ok(NetworkMessage::CFHeaders(decode(rest)?)),
        26 => Ok(NetworkMessage::GetCFCheckpt(decode(rest)?)),
        27 => Ok(NetworkMessage::CFCheckpt(decode(rest)?)),
        28 => Ok(NetworkMessage::AddrV2(decode(rest)?)),
        unknown => Err(Error::UnknownShortId(unknown)),
    }
}

// Copied from rust-bitcoin internals. Only the deserialize side is needed, since serialization
// is applied at the `NetworkMessage` level.
struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // Cap the preallocation so a lying length prefix cannot force a huge allocation.
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(encode::Error::ParseFailed(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::p2p::message::NetworkMessage;

    use super::*;

    #[test]
    fn round_trips_short_id_and_command_messages() {
        let ping = deserialize(&serialize(NetworkMessage::Ping(7)).unwrap()).unwrap();
        assert!(matches!(ping, NetworkMessage::Ping(7)));
        let verack = deserialize(&serialize(NetworkMessage::Verack).unwrap()).unwrap();
        assert!(matches!(verack, NetworkMessage::Verack));
    }

    #[test]
    fn short_ids_match_bip324() {
        assert_eq!(serialize(NetworkMessage::Ping(0)).unwrap()[0], 18);
        assert_eq!(serialize(NetworkMessage::GetData(vec![])).unwrap()[0], 11);
        assert_eq!(serialize(NetworkMessage::Verack).unwrap()[0], 0);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert!(matches!(deserialize(&[]), Err(Error::Truncated)));
        assert!(matches!(deserialize(&[0, 1, 2]), Err(Error::Truncated)));
        assert!(matches!(
            deserialize(&[200]),
            Err(Error::UnknownShortId(200))
        ));
        assert!(deserialize(&[18, 1]).is_err());
    }
}
