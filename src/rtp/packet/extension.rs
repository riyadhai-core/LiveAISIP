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

//! Bounded RTP header-extension parsing and serialization.
//!
//! The four-byte RFC 3550 extension preamble is parsed independently from the
//! RTP fixed header. RFC 8285 one-byte and two-byte profiles expose validated,
//! zero-copy element iteration. Unknown profiles remain opaque and lossless so
//! negotiated vendor extensions can cross the stack without reinterpretation.

use std::error::Error as StdError;
use std::fmt;

/// RFC 3550 extension preamble size.
pub const EXTENSION_PREAMBLE_BYTES: usize = 4;
/// RFC 8285 one-byte header profile identifier.
pub const ONE_BYTE_PROFILE: u16 = 0xbede;
/// Base value for RFC 8285 two-byte profiles.
pub const TWO_BYTE_PROFILE_BASE: u16 = 0x1000;
/// Maximum accepted extension data, excluding its preamble.
///
/// This operational bound prevents a forged length field from driving large
/// scans or allocations. It is intentionally far above normal audio usage.
pub const MAX_EXTENSION_DATA_BYTES: usize = 16 * 1024;
/// Maximum number of extension elements accepted in one block.
pub const MAX_EXTENSION_ELEMENTS: usize = 256;

/// Recognized interpretation of an RTP extension profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionFormat {
    /// RFC 8285 one-byte element headers (`0xBEDE`).
    OneByte,
    /// RFC 8285 two-byte element headers (`0x1000`–`0x100F`).
    TwoByte {
        /// Four application-defined bits carried in the profile identifier.
        app_bits: u8,
    },
    /// An unrecognized RFC 3550 profile, preserved as opaque bytes.
    Opaque,
}

/// One validated RFC 8285 extension element.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExtensionElement<'a> {
    id: u8,
    data: &'a [u8],
}

impl<'a> ExtensionElement<'a> {
    /// Returns the locally negotiated extension identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        self.id
    }

    /// Returns the borrowed element payload.
    #[must_use]
    pub const fn data(self) -> &'a [u8] {
        self.data
    }
}

impl fmt::Debug for ExtensionElement<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionElement")
            .field("id", &self.id)
            .field("data_bytes", &self.data.len())
            .finish()
    }
}

/// A borrowed, validated RTP header-extension block.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RtpExtension<'a> {
    profile: u16,
    data: &'a [u8],
    element_count: usize,
}

impl<'a> RtpExtension<'a> {
    /// Parses an extension block and returns its exact consumed length.
    ///
    /// `input` must begin at the extension profile identifier, immediately
    /// after the fixed RTP header and CSRC list.
    ///
    /// # Errors
    ///
    /// Rejects truncated blocks, the operational data bound, malformed RFC
    /// 8285 elements, reserved one-byte identifiers, and excessive elements.
    pub fn parse(input: &'a [u8]) -> Result<(Self, usize), RtpExtensionError> {
        if input.len() < EXTENSION_PREAMBLE_BYTES {
            return Err(RtpExtensionError::Truncated {
                required: EXTENSION_PREAMBLE_BYTES,
                available: input.len(),
            });
        }
        let profile = u16::from_be_bytes([input[0], input[1]]);
        let words = usize::from(u16::from_be_bytes([input[2], input[3]]));
        let data_length = words
            .checked_mul(4)
            .ok_or(RtpExtensionError::LengthOverflow)?;
        if data_length > MAX_EXTENSION_DATA_BYTES {
            return Err(RtpExtensionError::DataTooLarge {
                actual: data_length,
                maximum: MAX_EXTENSION_DATA_BYTES,
            });
        }
        let consumed = EXTENSION_PREAMBLE_BYTES
            .checked_add(data_length)
            .ok_or(RtpExtensionError::LengthOverflow)?;
        if input.len() < consumed {
            return Err(RtpExtensionError::Truncated {
                required: consumed,
                available: input.len(),
            });
        }
        let data = &input[EXTENSION_PREAMBLE_BYTES..consumed];
        let format = format_for_profile(profile);
        let element_count = validate_elements(format, data)?;
        Ok((
            Self {
                profile,
                data,
                element_count,
            },
            consumed,
        ))
    }

    /// Constructs an opaque extension from already padded data.
    ///
    /// # Errors
    ///
    /// Data must be four-byte aligned and within the operational bound. RFC
    /// 8285 profile identifiers are rejected because those require semantic
    /// element validation through [`Self::parse`].
    pub fn opaque(profile: u16, data: &'a [u8]) -> Result<Self, RtpExtensionError> {
        let format = format_for_profile(profile);
        if format != ExtensionFormat::Opaque {
            return Err(RtpExtensionError::StructuredProfileRequiresParsing { profile });
        }
        validate_data_shape(data)?;
        Ok(Self {
            profile,
            data,
            element_count: 0,
        })
    }

    /// Returns the raw profile identifier.
    #[must_use]
    pub const fn profile(self) -> u16 {
        self.profile
    }

    /// Returns the recognized profile format.
    #[must_use]
    pub const fn format(self) -> ExtensionFormat {
        format_for_profile(self.profile)
    }

    /// Returns the RFC 3550 extension data, including alignment padding.
    #[must_use]
    pub const fn data(self) -> &'a [u8] {
        self.data
    }

    /// Returns the validated element count, or zero for opaque profiles.
    #[must_use]
    pub const fn element_count(self) -> usize {
        self.element_count
    }

    /// Iterates RFC 8285 elements without allocation.
    ///
    /// Opaque profiles produce an empty iterator.
    #[must_use]
    pub const fn elements(self) -> ExtensionElementIter<'a> {
        ExtensionElementIter {
            format: self.format(),
            remaining: self.data,
            emitted: 0,
        }
    }

    /// Returns exact encoded size including the four-byte preamble.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        EXTENSION_PREAMBLE_BYTES + self.data.len()
    }

    /// Serializes the validated extension block.
    ///
    /// # Errors
    ///
    /// Reports allocation failure without returning partial output.
    pub fn encode(self) -> Result<Vec<u8>, RtpExtensionError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.encoded_len())
            .map_err(|_| RtpExtensionError::AllocationFailed)?;
        self.append_encoded(&mut output)?;
        Ok(output)
    }

    pub(crate) fn append_encoded(self, output: &mut Vec<u8>) -> Result<(), RtpExtensionError> {
        let words =
            u16::try_from(self.data.len() / 4).map_err(|_| RtpExtensionError::LengthOverflow)?;
        output.extend_from_slice(&self.profile.to_be_bytes());
        output.extend_from_slice(&words.to_be_bytes());
        output.extend_from_slice(self.data);
        Ok(())
    }
}

impl fmt::Debug for RtpExtension<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RtpExtension")
            .field("profile", &format_args!("{:#06x}", self.profile))
            .field("format", &self.format())
            .field("data_bytes", &self.data.len())
            .field("element_count", &self.element_count)
            .finish()
    }
}

/// Allocation-free iterator over validated RFC 8285 elements.
#[derive(Clone, Debug)]
pub struct ExtensionElementIter<'a> {
    format: ExtensionFormat,
    remaining: &'a [u8],
    emitted: usize,
}

impl<'a> Iterator for ExtensionElementIter<'a> {
    type Item = ExtensionElement<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.format {
            ExtensionFormat::OneByte => next_one_byte(self),
            ExtensionFormat::TwoByte { .. } => next_two_byte(self),
            ExtensionFormat::Opaque => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(MAX_EXTENSION_ELEMENTS.saturating_sub(self.emitted)))
    }
}

fn next_one_byte<'a>(iterator: &mut ExtensionElementIter<'a>) -> Option<ExtensionElement<'a>> {
    while let Some((&header, tail)) = iterator.remaining.split_first() {
        iterator.remaining = tail;
        if header == 0 {
            continue;
        }
        let id = header >> 4;
        if id == 15 {
            iterator.remaining = &[];
            return None;
        }
        let length = usize::from(header & 0x0f) + 1;
        let (data, remaining) = iterator.remaining.split_at(length);
        iterator.remaining = remaining;
        iterator.emitted += 1;
        return Some(ExtensionElement { id, data });
    }
    None
}

fn next_two_byte<'a>(iterator: &mut ExtensionElementIter<'a>) -> Option<ExtensionElement<'a>> {
    while let Some((&id, tail)) = iterator.remaining.split_first() {
        iterator.remaining = tail;
        if id == 0 {
            continue;
        }
        let (&length, tail) = iterator.remaining.split_first()?;
        let (data, remaining) = tail.split_at(usize::from(length));
        iterator.remaining = remaining;
        iterator.emitted += 1;
        return Some(ExtensionElement { id, data });
    }
    None
}

const fn format_for_profile(profile: u16) -> ExtensionFormat {
    if profile == ONE_BYTE_PROFILE {
        ExtensionFormat::OneByte
    } else if profile & 0xfff0 == TWO_BYTE_PROFILE_BASE {
        ExtensionFormat::TwoByte {
            app_bits: (profile & 0x000f) as u8,
        }
    } else {
        ExtensionFormat::Opaque
    }
}

fn validate_data_shape(data: &[u8]) -> Result<(), RtpExtensionError> {
    if data.len() > MAX_EXTENSION_DATA_BYTES {
        return Err(RtpExtensionError::DataTooLarge {
            actual: data.len(),
            maximum: MAX_EXTENSION_DATA_BYTES,
        });
    }
    if !data.len().is_multiple_of(4) {
        return Err(RtpExtensionError::DataNotWordAligned { actual: data.len() });
    }
    Ok(())
}

fn validate_elements(format: ExtensionFormat, data: &[u8]) -> Result<usize, RtpExtensionError> {
    match format {
        ExtensionFormat::OneByte => validate_one_byte(data),
        ExtensionFormat::TwoByte { .. } => validate_two_byte(data),
        ExtensionFormat::Opaque => Ok(0),
    }
}

fn validate_one_byte(mut data: &[u8]) -> Result<usize, RtpExtensionError> {
    let mut count = 0_usize;
    let mut offset = 0_usize;
    while let Some((&header, tail)) = data.split_first() {
        data = tail;
        if header == 0 {
            offset += 1;
            continue;
        }
        let id = header >> 4;
        if id == 15 {
            if data.iter().any(|byte| *byte != 0) {
                return Err(RtpExtensionError::NonPaddingAfterReservedId { offset });
            }
            return Ok(count);
        }
        let length = usize::from(header & 0x0f) + 1;
        if data.len() < length {
            return Err(RtpExtensionError::ElementTruncated {
                offset,
                required: length,
                available: data.len(),
            });
        }
        count = checked_element_count(count)?;
        data = &data[length..];
        offset += 1 + length;
    }
    Ok(count)
}

fn validate_two_byte(mut data: &[u8]) -> Result<usize, RtpExtensionError> {
    let mut count = 0_usize;
    let mut offset = 0_usize;
    while let Some((&id, tail)) = data.split_first() {
        data = tail;
        if id == 0 {
            offset += 1;
            continue;
        }
        let Some((&length, tail)) = data.split_first() else {
            return Err(RtpExtensionError::ElementHeaderTruncated { offset });
        };
        data = tail;
        let length = usize::from(length);
        if data.len() < length {
            return Err(RtpExtensionError::ElementTruncated {
                offset,
                required: length,
                available: data.len(),
            });
        }
        count = checked_element_count(count)?;
        data = &data[length..];
        offset += 2 + length;
    }
    Ok(count)
}

fn checked_element_count(current: usize) -> Result<usize, RtpExtensionError> {
    let attempted = current
        .checked_add(1)
        .ok_or(RtpExtensionError::LengthOverflow)?;
    if attempted > MAX_EXTENSION_ELEMENTS {
        return Err(RtpExtensionError::TooManyElements {
            attempted,
            maximum: MAX_EXTENSION_ELEMENTS,
        });
    }
    Ok(attempted)
}

/// Failure while parsing or serializing an RTP header extension.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RtpExtensionError {
    /// The input ends before the declared extension boundary.
    Truncated {
        /// Minimum byte count required to continue.
        required: usize,
        /// Byte count available in the supplied input.
        available: usize,
    },
    /// Checked extension-length arithmetic overflowed.
    LengthOverflow,
    /// The extension exceeds the operational data bound.
    DataTooLarge {
        /// Declared or supplied extension-data length.
        actual: usize,
        /// Maximum accepted extension-data length.
        maximum: usize,
    },
    /// Constructed opaque data is not aligned to a 32-bit word.
    DataNotWordAligned {
        /// Supplied extension-data length.
        actual: usize,
    },
    /// An RFC 8285 profile was passed to the opaque constructor.
    StructuredProfileRequiresParsing {
        /// Structured profile identifier.
        profile: u16,
    },
    /// A two-byte element is missing its length octet.
    ElementHeaderTruncated {
        /// Zero-based byte offset within extension data.
        offset: usize,
    },
    /// An element payload ends beyond the declared extension data.
    ElementTruncated {
        /// Zero-based header offset within extension data.
        offset: usize,
        /// Payload bytes declared by the element header.
        required: usize,
        /// Payload bytes remaining inside the extension block.
        available: usize,
    },
    /// Non-padding bytes follow reserved one-byte identifier 15.
    NonPaddingAfterReservedId {
        /// Zero-based offset of the reserved identifier.
        offset: usize,
    },
    /// The extension exceeds the operational element-count bound.
    TooManyElements {
        /// Count that would have been accepted.
        attempted: usize,
        /// Maximum accepted element count.
        maximum: usize,
    },
    /// Exact output allocation could not be reserved.
    AllocationFailed,
}

impl fmt::Display for RtpExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                required,
                available,
            } => write!(
                formatter,
                "truncated RTP extension: requires {required} bytes, has {available}"
            ),
            Self::LengthOverflow => formatter.write_str("RTP extension length overflow"),
            Self::DataTooLarge { actual, maximum } => write!(
                formatter,
                "RTP extension data has {actual} bytes, maximum is {maximum}"
            ),
            Self::DataNotWordAligned { actual } => write!(
                formatter,
                "RTP extension data length {actual} is not four-byte aligned"
            ),
            Self::StructuredProfileRequiresParsing { profile } => write!(
                formatter,
                "structured RTP extension profile {profile:#06x} requires validated parsing"
            ),
            Self::ElementHeaderTruncated { offset } => {
                write!(
                    formatter,
                    "truncated RTP extension element header at byte {offset}"
                )
            }
            Self::ElementTruncated {
                offset,
                required,
                available,
            } => write!(
                formatter,
                "truncated RTP extension element at byte {offset}: requires {required} data bytes, has {available}"
            ),
            Self::NonPaddingAfterReservedId { offset } => write!(
                formatter,
                "non-padding data follows reserved RTP extension identifier at byte {offset}"
            ),
            Self::TooManyElements { attempted, maximum } => write!(
                formatter,
                "RTP extension has {attempted} elements, maximum is {maximum}"
            ),
            Self::AllocationFailed => formatter.write_str("RTP extension allocation failed"),
        }
    }
}

impl StdError for RtpExtensionError {}

#[cfg(test)]
mod tests {
    use super::{
        EXTENSION_PREAMBLE_BYTES, ExtensionFormat, ONE_BYTE_PROFILE, RtpExtension,
        RtpExtensionError,
    };

    #[test]
    fn parses_one_byte_elements_and_padding_without_copying() {
        let bytes = [0xbe, 0xde, 0x00, 0x02, 0x10, 0xaa, 0x32, 1, 2, 3, 0, 0];
        let (extension, consumed) =
            RtpExtension::parse(&bytes).unwrap_or_else(|_| panic!("extension"));
        assert_eq!(consumed, bytes.len());
        assert_eq!(extension.format(), ExtensionFormat::OneByte);
        assert_eq!(extension.element_count(), 2);
        assert!(std::ptr::eq(extension.data().as_ptr(), bytes[4..].as_ptr()));
        let elements: Vec<_> = extension.elements().collect();
        assert_eq!(elements[0].id(), 1);
        assert_eq!(elements[0].data(), &[0xaa]);
        assert_eq!(elements[1].id(), 3);
        assert_eq!(elements[1].data(), &[1, 2, 3]);
        assert_eq!(
            extension.encode().unwrap_or_else(|_| panic!("encode")),
            bytes
        );
    }

    #[test]
    fn parses_two_byte_zero_length_element() {
        let bytes = [0x10, 0x05, 0x00, 0x01, 7, 0, 0, 0];
        let (extension, _) = RtpExtension::parse(&bytes).unwrap_or_else(|_| panic!("extension"));
        assert_eq!(extension.format(), ExtensionFormat::TwoByte { app_bits: 5 });
        let elements: Vec<_> = extension.elements().collect();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].id(), 7);
        assert!(elements[0].data().is_empty());
    }

    #[test]
    fn preserves_unknown_profile_as_opaque() {
        let bytes = [0xab, 0xcd, 0, 1, 1, 2, 3, 4];
        let (extension, _) = RtpExtension::parse(&bytes).unwrap_or_else(|_| panic!("extension"));
        assert_eq!(extension.format(), ExtensionFormat::Opaque);
        assert_eq!(extension.data(), &[1, 2, 3, 4]);
        assert_eq!(extension.elements().count(), 0);
        assert_eq!(
            RtpExtension::opaque(0xabcd, &[1, 2, 3, 4]).unwrap_or_else(|_| panic!("opaque")),
            extension
        );
    }

    #[test]
    fn rejects_truncated_block_before_slicing() {
        let bytes = [0xbe, 0xde, 0, 2, 0, 0, 0, 0];
        assert_eq!(
            RtpExtension::parse(&bytes),
            Err(RtpExtensionError::Truncated {
                required: EXTENSION_PREAMBLE_BYTES + 8,
                available: 8,
            })
        );
    }

    #[test]
    fn rejects_malformed_one_byte_element_and_reserved_tail() {
        let truncated = [0xbe, 0xde, 0, 1, 0x13, 1, 2, 3];
        assert_eq!(
            RtpExtension::parse(&truncated),
            Err(RtpExtensionError::ElementTruncated {
                offset: 0,
                required: 4,
                available: 3,
            })
        );
        let reserved = [0xbe, 0xde, 0, 1, 0xf0, 1, 0, 0];
        assert_eq!(
            RtpExtension::parse(&reserved),
            Err(RtpExtensionError::NonPaddingAfterReservedId { offset: 0 })
        );
    }

    #[test]
    fn rejects_malformed_two_byte_element() {
        let bytes = [0x10, 0, 0, 1, 7, 3, 1, 2];
        assert_eq!(
            RtpExtension::parse(&bytes),
            Err(RtpExtensionError::ElementTruncated {
                offset: 0,
                required: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn opaque_constructor_enforces_shape_and_profile() {
        assert_eq!(
            RtpExtension::opaque(0xabcd, &[1]),
            Err(RtpExtensionError::DataNotWordAligned { actual: 1 })
        );
        assert_eq!(
            RtpExtension::opaque(ONE_BYTE_PROFILE, &[0; 4]),
            Err(RtpExtensionError::StructuredProfileRequiresParsing {
                profile: ONE_BYTE_PROFILE,
            })
        );
    }

    #[test]
    fn debug_does_not_expose_extension_payload() {
        let extension = RtpExtension::opaque(0xabcd, &[222, 173, 190, 239])
            .unwrap_or_else(|_| panic!("opaque"));
        let debug = format!("{extension:?}");
        assert!(!debug.contains("222"));
        assert!(!debug.contains("173"));
    }
}
