use core::fmt;

use minicbor::{Decoder, Encoder, encode::Write};
use zeroize::Zeroizing;

use crate::message::ProtocolError;

pub(crate) struct SecretWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretWriter {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(capacity)),
        }
    }

    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

#[derive(Debug)]
pub(crate) struct SecretWriterOverflow;

impl Write for SecretWriter {
    type Error = SecretWriterOverflow;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(SecretWriterOverflow)?;
        if required > self.bytes.capacity() {
            return Err(SecretWriterOverflow);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

pub(crate) fn encode_array<W>(encoder: &mut Encoder<W>, length: u64)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .array(length)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_u8<W>(encoder: &mut Encoder<W>, value: u8)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u8(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_u16<W>(encoder: &mut Encoder<W>, value: u16)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u16(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_u32<W>(encoder: &mut Encoder<W>, value: u32)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u32(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_u64<W>(encoder: &mut Encoder<W>, value: u64)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .u64(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_bytes<W>(encoder: &mut Encoder<W>, value: &[u8])
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .bytes(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_text<W>(encoder: &mut Encoder<W>, value: &str)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder
        .str(value)
        .expect("encoding into a vector cannot fail");
}

pub(crate) fn encode_null<W>(encoder: &mut Encoder<W>)
where
    W: Write,
    W::Error: fmt::Debug,
{
    encoder.null().expect("encoding into a vector cannot fail");
}

pub(crate) fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    let length = decoder
        .array()
        .map_err(|_| ProtocolError::Malformed)?
        .ok_or(ProtocolError::Malformed)?;
    if length != expected {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

pub(crate) fn decode_array_length(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let length = decoder
        .array()
        .map_err(|_| ProtocolError::Malformed)?
        .ok_or(ProtocolError::Malformed)?;
    let length = usize::try_from(length).map_err(|_| ProtocolError::TooLarge)?;
    if length > maximum {
        return Err(ProtocolError::TooLarge);
    }
    Ok(length)
}

pub(crate) fn decode_u8(decoder: &mut Decoder<'_>) -> Result<u8, ProtocolError> {
    decoder.u8().map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn decode_u16(decoder: &mut Decoder<'_>) -> Result<u16, ProtocolError> {
    decoder.u16().map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn decode_u32(decoder: &mut Decoder<'_>) -> Result<u32, ProtocolError> {
    decoder.u32().map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn decode_u64(decoder: &mut Decoder<'_>) -> Result<u64, ProtocolError> {
    decoder.u64().map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn decode_fixed_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; SIZE], ProtocolError> {
    let bytes = decoder.bytes().map_err(|_| ProtocolError::Malformed)?;
    bytes.try_into().map_err(|_| ProtocolError::Malformed)
}

pub(crate) fn decode_bounded_bytes(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let bytes = decoder.bytes().map_err(|_| ProtocolError::Malformed)?;
    if bytes.len() > maximum {
        return Err(ProtocolError::TooLarge);
    }
    Ok(bytes.to_vec())
}

pub(crate) fn decode_bounded_text(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<String, ProtocolError> {
    let text = decoder.str().map_err(|_| ProtocolError::Malformed)?;
    if text.len() > maximum {
        return Err(ProtocolError::TooLarge);
    }
    Ok(text.to_owned())
}

pub(crate) fn decode_optional_fixed_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; SIZE]>, ProtocolError> {
    if decoder.datatype().map_err(|_| ProtocolError::Malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(|_| ProtocolError::Malformed)?;
        return Ok(None);
    }
    decode_fixed_bytes(decoder).map(Some)
}

pub(crate) fn require_end(decoder: &Decoder<'_>, original: &[u8]) -> Result<(), ProtocolError> {
    if decoder.position() != original.len() {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}
