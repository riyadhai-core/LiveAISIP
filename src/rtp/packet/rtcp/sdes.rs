// Copyright 2026 RiyadhAI LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `LiveAISIP`.
//!
//! A high-performance SIP server developed by `RiyadhAI LLC` for large-scale
//! realtime AI telephony workloads.

//! Bounded RTCP Source Description parsing and serialization.
//!
//! SDES strings commonly contain hostnames, usernames, email addresses, and
//! locations. Public diagnostic formatting therefore exposes only item types,
//! counts, and lengths—not SSRCs or item contents.

use std::error::Error as StdError;
use std::fmt;

use super::header::{RTCP_HEADER_BYTES, RtcpHeader, RtcpHeaderError, RtcpPacketType};

/// Maximum SDES chunks representable by the five-bit source-count field.
pub const MAX_SDES_CHUNKS: usize = 31;
/// Operational maximum item count across one SDES packet.
pub const MAX_SDES_ITEMS: usize = 512;
/// Maximum item value carried by the one-octet length field.
pub const MAX_SDES_ITEM_BYTES: usize = 255;

/// An SDES item type, preserving unassigned values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SdesItemType {
    /// Canonical endpoint name.
    CanonicalName,
    /// Display name.
    Name,
    /// Email address.
    Email,
    /// Telephone number.
    Phone,
    /// Geographic location.
    Location,
    /// Application or tool name.
    Tool,
    /// Status note.
    Note,
    /// Private extension item.
    Private,
    /// Unassigned nonzero item type.
    Other(u8),
}

impl SdesItemType {
    /// Classifies a nonzero SDES item type.
    ///
    /// # Errors
    ///
    /// Zero is the chunk END marker and cannot represent an item.
    pub const fn from_raw(value: u8) -> Result<Self, SourceDescriptionError> {
        match value {
            0 => Err(SourceDescriptionError::EndMarkerIsNotItem),
            1 => Ok(Self::CanonicalName),
            2 => Ok(Self::Name),
            3 => Ok(Self::Email),
            4 => Ok(Self::Phone),
            5 => Ok(Self::Location),
            6 => Ok(Self::Tool),
            7 => Ok(Self::Note),
            8 => Ok(Self::Private),
            value => Ok(Self::Other(value)),
        }
    }

    /// Returns the nonzero wire item type.
    #[must_use]
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::CanonicalName => 1,
            Self::Name => 2,
            Self::Email => 3,
            Self::Phone => 4,
            Self::Location => 5,
            Self::Tool => 6,
            Self::Note => 7,
            Self::Private => 8,
            Self::Other(value) => value,
        }
    }
}

/// An owned SDES item.
#[derive(Clone, Eq, PartialEq)]
pub struct SdesItem {
    item_type: SdesItemType,
    value: Vec<u8>,
}

impl SdesItem {
    /// Constructs an SDES item and copies its bounded value.
    ///
    /// Private items use the RFC 3550 layout: a prefix-length octet, prefix,
    /// then private value. That inner length is validated here.
    ///
    /// # Errors
    ///
    /// Rejects type zero, values beyond 255 bytes, malformed private items, or
    /// allocation failure.
    pub fn new(item_type: SdesItemType, value: &[u8]) -> Result<Self, SourceDescriptionError> {
        SdesItemType::from_raw(item_type.as_raw())?;
        validate_item_value(item_type, value)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        owned.extend_from_slice(value);
        Ok(Self {
            item_type,
            value: owned,
        })
    }

    /// Returns the item type.
    #[must_use]
    pub const fn item_type(&self) -> SdesItemType {
        self.item_type
    }

    /// Returns the item value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for SdesItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdesItem")
            .field("item_type", &self.item_type)
            .field("value_bytes", &self.value.len())
            .finish()
    }
}

/// One owned SDES source chunk.
#[derive(Clone, Eq, PartialEq)]
pub struct SdesChunk {
    source_ssrc: u32,
    items: Vec<SdesItem>,
}

impl SdesChunk {
    /// Constructs one source chunk and takes ownership of its items.
    ///
    /// # Errors
    ///
    /// Rejects a packet-level item bound violation or allocation failure.
    pub fn new(source_ssrc: u32, items: &[SdesItem]) -> Result<Self, SourceDescriptionError> {
        if items.len() > MAX_SDES_ITEMS {
            return Err(SourceDescriptionError::TooManyItems {
                attempted: items.len(),
                maximum: MAX_SDES_ITEMS,
            });
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(items.len())
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        owned.extend_from_slice(items);
        Ok(Self {
            source_ssrc,
            items: owned,
        })
    }

    /// Returns the described synchronization source.
    #[must_use]
    pub const fn source_ssrc(&self) -> u32 {
        self.source_ssrc
    }

    /// Returns items in wire order.
    #[must_use]
    pub fn items(&self) -> &[SdesItem] {
        &self.items
    }

    fn encoded_len(&self) -> Result<usize, SourceDescriptionError> {
        let unaligned = self.items.iter().try_fold(5_usize, |length, item| {
            length
                .checked_add(2)
                .and_then(|value| value.checked_add(item.value.len()))
                .ok_or(SourceDescriptionError::LengthOverflow)
        })?;
        align_to_word(unaligned)
    }
}

impl fmt::Debug for SdesChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdesChunk")
            .field("item_count", &self.items.len())
            .field(
                "item_types",
                &self
                    .items
                    .iter()
                    .map(SdesItem::item_type)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// A validated, owned RTCP SDES packet.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceDescription {
    chunks: Vec<SdesChunk>,
    padding_bytes: u8,
}

impl SourceDescription {
    /// Parses one SDES packet from the start of `input`.
    ///
    /// # Errors
    ///
    /// Rejects wrong packet type, malformed items, missing END markers,
    /// nonzero chunk-alignment bytes, count/length mismatch, excessive items,
    /// and bounded allocation failure.
    pub fn parse(input: &[u8]) -> Result<(Self, usize), SourceDescriptionError> {
        let header = RtcpHeader::parse(input).map_err(SourceDescriptionError::Header)?;
        if header.packet_type() != RtcpPacketType::SourceDescription {
            return Err(SourceDescriptionError::WrongPacketType {
                actual: header.packet_type(),
            });
        }
        let body_end = RTCP_HEADER_BYTES
            .checked_add(header.unpadded_body_len())
            .ok_or(SourceDescriptionError::LengthOverflow)?;
        let packet = &input[..header.packet_len()];
        let chunk_count = usize::from(header.count());
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(chunk_count)
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        let mut offset = RTCP_HEADER_BYTES;
        let mut total_items = 0_usize;

        for chunk_index in 0..chunk_count {
            let (chunk, next_offset) =
                parse_chunk(packet, body_end, chunk_index, offset, &mut total_items)?;
            chunks.push(chunk);
            offset = next_offset;
        }
        if offset != body_end {
            return Err(SourceDescriptionError::TrailingBodyData {
                bytes: body_end - offset,
            });
        }
        Ok((
            Self {
                chunks,
                padding_bytes: header.padding_bytes(),
            },
            header.packet_len(),
        ))
    }

    /// Constructs an SDES packet from owned chunk copies.
    ///
    /// # Errors
    ///
    /// Rejects more than 31 chunks, more than 512 aggregate items, invalid
    /// external padding alignment, length overflow, or allocation failure.
    pub fn new(chunks: &[SdesChunk], padding_bytes: u8) -> Result<Self, SourceDescriptionError> {
        validate_chunks(chunks)?;
        let length = packet_len(chunks, padding_bytes)?;
        RtcpHeader::new(
            u8::try_from(chunks.len()).map_err(|_| SourceDescriptionError::LengthOverflow)?,
            RtcpPacketType::SourceDescription,
            length,
            padding_bytes,
        )
        .map_err(SourceDescriptionError::Header)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(chunks.len())
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        owned.extend_from_slice(chunks);
        Ok(Self {
            chunks: owned,
            padding_bytes,
        })
    }

    /// Returns chunks in wire order.
    #[must_use]
    pub fn chunks(&self) -> &[SdesChunk] {
        &self.chunks
    }

    /// Returns external RTCP padding bytes.
    #[must_use]
    pub const fn padding_bytes(&self) -> u8 {
        self.padding_bytes
    }

    /// Calculates exact encoded packet length.
    ///
    /// # Errors
    ///
    /// Returns checked length overflow.
    pub fn encoded_len(&self) -> Result<usize, SourceDescriptionError> {
        packet_len(&self.chunks, self.padding_bytes)
    }

    /// Serializes the complete SDES packet using one exact allocation.
    ///
    /// # Errors
    ///
    /// Returns validation or allocation failure without partial output.
    pub fn encode(&self) -> Result<Vec<u8>, SourceDescriptionError> {
        validate_chunks(&self.chunks)?;
        let length = packet_len(&self.chunks, self.padding_bytes)?;
        let header = RtcpHeader::new(
            u8::try_from(self.chunks.len()).map_err(|_| SourceDescriptionError::LengthOverflow)?,
            RtcpPacketType::SourceDescription,
            length,
            self.padding_bytes,
        )
        .map_err(SourceDescriptionError::Header)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        output.extend_from_slice(&header.encode().map_err(SourceDescriptionError::Header)?);
        for chunk in &self.chunks {
            let start = output.len();
            output.extend_from_slice(&chunk.source_ssrc.to_be_bytes());
            for item in &chunk.items {
                output.push(item.item_type.as_raw());
                output.push(
                    u8::try_from(item.value.len())
                        .map_err(|_| SourceDescriptionError::LengthOverflow)?,
                );
                output.extend_from_slice(&item.value);
            }
            output.push(0);
            let chunk_length = output.len() - start;
            let aligned = align_to_word(chunk_length)?;
            output.resize(start + aligned, 0);
        }
        if self.padding_bytes != 0 {
            output.resize(length, 0);
            let last = output
                .last_mut()
                .ok_or(SourceDescriptionError::LengthOverflow)?;
            *last = self.padding_bytes;
        }
        debug_assert_eq!(output.len(), length);
        Ok(output)
    }
}

fn parse_chunk(
    packet: &[u8],
    body_end: usize,
    chunk_index: usize,
    mut offset: usize,
    total_items: &mut usize,
) -> Result<(SdesChunk, usize), SourceDescriptionError> {
    let chunk_start = offset;
    if body_end.saturating_sub(offset) < 4 {
        return Err(SourceDescriptionError::ChunkTruncated {
            chunk_index,
            offset,
        });
    }
    let source_ssrc = read_u32(packet, offset);
    offset += 4;
    let mut items = Vec::new();
    let mut found_end = false;
    while offset < body_end {
        let item_type = packet[offset];
        offset += 1;
        if item_type == 0 {
            found_end = true;
            break;
        }
        if offset >= body_end {
            return Err(SourceDescriptionError::ItemHeaderTruncated {
                chunk_index,
                offset: offset - 1,
            });
        }
        let length = usize::from(packet[offset]);
        offset += 1;
        let end = offset
            .checked_add(length)
            .ok_or(SourceDescriptionError::LengthOverflow)?;
        if end > body_end {
            return Err(SourceDescriptionError::ItemTruncated {
                chunk_index,
                offset: offset - 2,
                required: length,
                available: body_end - offset,
            });
        }
        *total_items = total_items
            .checked_add(1)
            .ok_or(SourceDescriptionError::LengthOverflow)?;
        if *total_items > MAX_SDES_ITEMS {
            return Err(SourceDescriptionError::TooManyItems {
                attempted: *total_items,
                maximum: MAX_SDES_ITEMS,
            });
        }
        let item_type = SdesItemType::from_raw(item_type)?;
        let item = SdesItem::new(item_type, &packet[offset..end])?;
        items
            .try_reserve(1)
            .map_err(|_| SourceDescriptionError::AllocationFailed)?;
        items.push(item);
        offset = end;
    }
    if !found_end {
        return Err(SourceDescriptionError::MissingEndMarker { chunk_index });
    }
    let chunk_used = offset - chunk_start;
    let aligned = align_to_word(chunk_used)?;
    let padding = aligned - chunk_used;
    let padding_end = offset
        .checked_add(padding)
        .ok_or(SourceDescriptionError::LengthOverflow)?;
    if padding_end > body_end {
        return Err(SourceDescriptionError::ChunkPaddingTruncated {
            chunk_index,
            required: padding,
            available: body_end - offset,
        });
    }
    if packet[offset..padding_end].iter().any(|byte| *byte != 0) {
        return Err(SourceDescriptionError::NonZeroChunkPadding { chunk_index });
    }
    Ok((SdesChunk { source_ssrc, items }, padding_end))
}

impl fmt::Debug for SourceDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let item_count: usize = self.chunks.iter().map(|chunk| chunk.items.len()).sum();
        formatter
            .debug_struct("SourceDescription")
            .field("chunk_count", &self.chunks.len())
            .field("item_count", &item_count)
            .field("padding_bytes", &self.padding_bytes)
            .finish()
    }
}

fn validate_item_value(
    item_type: SdesItemType,
    value: &[u8],
) -> Result<(), SourceDescriptionError> {
    if value.len() > MAX_SDES_ITEM_BYTES {
        return Err(SourceDescriptionError::ItemTooLong {
            actual: value.len(),
            maximum: MAX_SDES_ITEM_BYTES,
        });
    }
    if item_type == SdesItemType::Private {
        let Some(prefix_length) = value.first().copied() else {
            return Err(SourceDescriptionError::PrivateItemMissingPrefixLength);
        };
        let available = value.len() - 1;
        if usize::from(prefix_length) > available {
            return Err(SourceDescriptionError::PrivatePrefixTruncated {
                required: usize::from(prefix_length),
                available,
            });
        }
    }
    Ok(())
}

fn validate_chunks(chunks: &[SdesChunk]) -> Result<(), SourceDescriptionError> {
    if chunks.len() > MAX_SDES_CHUNKS {
        return Err(SourceDescriptionError::TooManyChunks {
            actual: chunks.len(),
            maximum: MAX_SDES_CHUNKS,
        });
    }
    let item_count = chunks.iter().try_fold(0_usize, |count, chunk| {
        count
            .checked_add(chunk.items.len())
            .ok_or(SourceDescriptionError::LengthOverflow)
    })?;
    if item_count > MAX_SDES_ITEMS {
        return Err(SourceDescriptionError::TooManyItems {
            attempted: item_count,
            maximum: MAX_SDES_ITEMS,
        });
    }
    Ok(())
}

fn packet_len(chunks: &[SdesChunk], padding_bytes: u8) -> Result<usize, SourceDescriptionError> {
    let body_length = chunks.iter().try_fold(0_usize, |length, chunk| {
        length
            .checked_add(chunk.encoded_len()?)
            .ok_or(SourceDescriptionError::LengthOverflow)
    })?;
    let length = RTCP_HEADER_BYTES
        .checked_add(body_length)
        .and_then(|value| value.checked_add(usize::from(padding_bytes)))
        .ok_or(SourceDescriptionError::LengthOverflow)?;
    if !length.is_multiple_of(4) {
        return Err(SourceDescriptionError::PacketNotWordAligned { actual: length });
    }
    Ok(length)
}

fn align_to_word(length: usize) -> Result<usize, SourceDescriptionError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(SourceDescriptionError::LengthOverflow)
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

/// Failure while parsing, constructing, or serializing SDES.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceDescriptionError {
    /// RTCP common-header validation failed.
    Header(RtcpHeaderError),
    /// Packet type was not SDES.
    WrongPacketType {
        /// Actual packet type.
        actual: RtcpPacketType,
    },
    /// END marker zero was supplied as an item type.
    EndMarkerIsNotItem,
    /// A chunk ends before its SSRC is complete.
    ChunkTruncated {
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Packet byte offset.
        offset: usize,
    },
    /// An item type lacks its length octet.
    ItemHeaderTruncated {
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Packet byte offset of the item type.
        offset: usize,
    },
    /// An item value crosses the unpadded SDES body boundary.
    ItemTruncated {
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Packet byte offset of the item header.
        offset: usize,
        /// Declared item value bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
    /// Item exceeds its one-octet length capacity.
    ItemTooLong {
        /// Supplied value length.
        actual: usize,
        /// Maximum value length.
        maximum: usize,
    },
    /// A chunk has no END marker within its declared boundary.
    MissingEndMarker {
        /// Zero-based chunk index.
        chunk_index: usize,
    },
    /// Chunk alignment bytes extend beyond the body.
    ChunkPaddingTruncated {
        /// Zero-based chunk index.
        chunk_index: usize,
        /// Required alignment bytes.
        required: usize,
        /// Available alignment bytes.
        available: usize,
    },
    /// Chunk alignment contains nonzero data.
    NonZeroChunkPadding {
        /// Zero-based chunk index.
        chunk_index: usize,
    },
    /// Bytes remain after the declared chunk count.
    TrailingBodyData {
        /// Unexpected trailing byte count.
        bytes: usize,
    },
    /// Chunk count exceeds five-bit capacity.
    TooManyChunks {
        /// Supplied chunk count.
        actual: usize,
        /// Maximum chunk count.
        maximum: usize,
    },
    /// Aggregate item count exceeds the operational bound.
    TooManyItems {
        /// Count that would be accepted.
        attempted: usize,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// A private item has no prefix-length octet.
    PrivateItemMissingPrefixLength,
    /// A private prefix extends beyond its item value.
    PrivatePrefixTruncated {
        /// Declared prefix bytes.
        required: usize,
        /// Bytes following the prefix-length octet.
        available: usize,
    },
    /// Constructed packet length is not four-byte aligned.
    PacketNotWordAligned {
        /// Calculated packet length.
        actual: usize,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// Exact bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for SourceDescriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(_) => formatter.write_str("invalid RTCP SDES header"),
            Self::WrongPacketType { actual } => {
                write!(formatter, "expected RTCP SDES, received {actual:?}")
            }
            Self::EndMarkerIsNotItem => formatter.write_str("SDES END marker is not an item"),
            Self::ChunkTruncated { chunk_index, .. } => {
                write!(formatter, "truncated SDES chunk {chunk_index}")
            }
            Self::ItemHeaderTruncated { chunk_index, .. } => {
                write!(
                    formatter,
                    "truncated item header in SDES chunk {chunk_index}"
                )
            }
            Self::ItemTruncated { chunk_index, .. } => {
                write!(formatter, "truncated item in SDES chunk {chunk_index}")
            }
            Self::ItemTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "SDES item has {actual} bytes, maximum is {maximum}"
                )
            }
            Self::MissingEndMarker { chunk_index } => {
                write!(formatter, "SDES chunk {chunk_index} has no END marker")
            }
            Self::ChunkPaddingTruncated { chunk_index, .. } => {
                write!(formatter, "truncated alignment in SDES chunk {chunk_index}")
            }
            Self::NonZeroChunkPadding { chunk_index } => {
                write!(formatter, "nonzero alignment in SDES chunk {chunk_index}")
            }
            Self::TrailingBodyData { bytes } => {
                write!(formatter, "SDES packet has {bytes} trailing body bytes")
            }
            Self::TooManyChunks { actual, maximum } => {
                write!(formatter, "SDES has {actual} chunks, maximum is {maximum}")
            }
            Self::TooManyItems { attempted, maximum } => {
                write!(
                    formatter,
                    "SDES has {attempted} items, maximum is {maximum}"
                )
            }
            Self::PrivateItemMissingPrefixLength => {
                formatter.write_str("SDES PRIV item lacks prefix length")
            }
            Self::PrivatePrefixTruncated {
                required,
                available,
            } => write!(
                formatter,
                "SDES private prefix requires {required} bytes, has {available}"
            ),
            Self::PacketNotWordAligned { actual } => {
                write!(formatter, "SDES packet length {actual} is not word-aligned")
            }
            Self::LengthOverflow => formatter.write_str("SDES length overflow"),
            Self::AllocationFailed => formatter.write_str("SDES allocation failed"),
        }
    }
}

impl StdError for SourceDescriptionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Header(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SdesChunk, SdesItem, SdesItemType, SourceDescription, SourceDescriptionError};
    use crate::rtp::packet::rtcp::RtcpPacketType;

    fn cname() -> SdesItem {
        SdesItem::new(SdesItemType::CanonicalName, b"runtime@example")
            .unwrap_or_else(|_| panic!("item"))
    }

    #[test]
    fn round_trips_multiple_chunks_and_items() {
        let name = SdesItem::new(SdesItemType::Name, b"agent").unwrap_or_else(|_| panic!("name"));
        let first =
            SdesChunk::new(0xdead_beef, &[cname(), name]).unwrap_or_else(|_| panic!("chunk"));
        let second = SdesChunk::new(2, &[cname()]).unwrap_or_else(|_| panic!("chunk"));
        let original =
            SourceDescription::new(&[first, second], 0).unwrap_or_else(|_| panic!("SDES"));
        let mut bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        let consumed = bytes.len();
        bytes.extend_from_slice(&[0x80, 203, 0, 0]);
        let (parsed, parsed_length) =
            SourceDescription::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed, original);
        assert_eq!(parsed_length, consumed);
        assert_eq!(parsed.chunks()[0].items()[0].value(), b"runtime@example");
    }

    #[test]
    fn validates_private_prefix_layout() {
        let private = SdesItem::new(SdesItemType::Private, &[3, b'a', b'b', b'c', 9])
            .unwrap_or_else(|_| panic!("private"));
        assert_eq!(private.item_type(), SdesItemType::Private);
        assert_eq!(
            SdesItem::new(SdesItemType::Private, &[3, b'a']),
            Err(SourceDescriptionError::PrivatePrefixTruncated {
                required: 3,
                available: 1,
            })
        );
    }

    #[test]
    fn rejects_wrong_type_missing_end_and_nonzero_alignment() {
        let wrong = [0x80, 203, 0, 0];
        assert_eq!(
            SourceDescription::parse(&wrong),
            Err(SourceDescriptionError::WrongPacketType {
                actual: RtcpPacketType::Goodbye,
            })
        );

        let missing_end = [0x81, 202, 0, 1, 0, 0, 0, 1];
        assert_eq!(
            SourceDescription::parse(&missing_end),
            Err(SourceDescriptionError::MissingEndMarker { chunk_index: 0 })
        );

        let bad_padding = [0x81, 202, 0, 2, 0, 0, 0, 1, 1, 0, 0, 9];
        assert_eq!(
            SourceDescription::parse(&bad_padding),
            Err(SourceDescriptionError::NonZeroChunkPadding { chunk_index: 0 })
        );
    }

    #[test]
    fn supports_external_rtcp_padding() {
        let chunk = SdesChunk::new(1, &[cname()]).unwrap_or_else(|_| panic!("chunk"));
        let original = SourceDescription::new(&[chunk], 4).unwrap_or_else(|_| panic!("SDES"));
        let bytes = original.encode().unwrap_or_else(|_| panic!("encode"));
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        let (parsed, _) = SourceDescription::parse(&bytes).unwrap_or_else(|_| panic!("parse"));
        assert_eq!(parsed.padding_bytes(), 4);
    }

    #[test]
    fn debug_redacts_source_and_identity_values() {
        let chunk = SdesChunk::new(0xdead_beef, &[cname()]).unwrap_or_else(|_| panic!("chunk"));
        let packet = SourceDescription::new(&[chunk], 0).unwrap_or_else(|_| panic!("SDES"));
        let debug = format!("{packet:?}");
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("runtime"));
        assert!(!debug.contains("example"));
    }
}
