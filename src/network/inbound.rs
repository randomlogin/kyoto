use bip324::futures::ProtocolReader;
use bip324::PacketType;
use bitcoin::consensus::{deserialize, deserialize_partial};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message::RawNetworkMessage;
use bitcoin::p2p::Magic;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::error::ReaderError;
use super::p2p_v2;
use super::V1Header;

const MAX_MESSAGE_BYTES: u32 = 1024 * 1024 * 32;

pub(crate) enum MessageParser<R: AsyncRead + Send + Sync + Unpin> {
    V2(ProtocolReader<R>),
    V1(R, Magic),
}

// The bytes a V2 packet occupies on the wire besides its contents: the 3 length bytes, the header
// byte, and the 16 byte authentication tag.
const V2_PACKET_OVERHEAD: usize = 3 + 1 + 16;

impl<R: AsyncRead + Send + Sync + Unpin> MessageParser<R> {
    // The next message, if there is one to act on (decoy packets have none), and how many bytes it
    // took on the wire.
    pub async fn read_message(&mut self) -> Result<(Option<NetworkMessage>, usize), ReaderError> {
        match self {
            MessageParser::V2(reader) => {
                let payload = reader.read().await?;
                let wire_bytes = payload.contents().len() + V2_PACKET_OVERHEAD;
                match payload.packet_type() {
                    PacketType::Genuine => {
                        let parsed = p2p_v2::deserialize(payload.contents())?;
                        Ok((Some(parsed), wire_bytes))
                    }
                    PacketType::Decoy => Ok((None, wire_bytes)),
                }
            }
            MessageParser::V1(stream, magic) => {
                let mut message_buf = vec![0_u8; 24];
                let _ = stream.read_exact(&mut message_buf).await?;
                let header: V1Header = deserialize_partial(&message_buf)?.0;
                // Nonsense for our network
                if header.magic != *magic {
                    return Err(ReaderError::InvalidDeserialization);
                }
                // Message is too long
                if header.length > MAX_MESSAGE_BYTES {
                    return Err(ReaderError::MessageTooLarge);
                }
                let mut contents_buf = vec![0_u8; header.length as usize];
                let _ = stream.read_exact(&mut contents_buf).await?;
                message_buf.extend_from_slice(&contents_buf);
                let wire_bytes = message_buf.len();
                let message: RawNetworkMessage = deserialize(&message_buf)?;
                Ok((Some(message.into_payload()), wire_bytes))
            }
        }
    }
}
