//! This modules handles the wire format of the BufferEntry nodes.

use std::collections::VecDeque;

use bytes::Buf;
use bytes::{BufMut, Bytes, BytesMut};
use integer_encoding::VarInt;

use super::BufferEntry;
use crate::{Error, State};
use crate::Result;

impl BufferEntry {
    /// Encodes a node into bytes.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut tmp = [0u8; 8];
        let mut bytes_len = 0;

        // Encode the hashes.
        // The decoding is responsible to know the number of hashes in the buffer
        // since it knows the scheme.
        for hash in self.hashes.iter() {
            buf.put(&hash[..]);
            bytes_len += 32;
        }

        // Encode the signature, if there is one.
        if let Some(signature) = self.signature.as_ref() {
            buf.put(&signature[..]);
            bytes_len += 64;
        }

        // Encode the length.
        let len = (bytes_len as u64).encode_var(&mut tmp);

        // Reverse the buffer to read by the end.
        tmp.reverse();
        buf.put(&tmp[tmp.len() - len..]);

        // Encode ID.
        // We finish by the ID so that we know exactly, by infering from
        // the scheme, where is the boundary of the payload.
        tmp = [0u8; 8];
        let len = self.id.encode_var(&mut tmp);

        // Reverse the buffer to read by the end.
        tmp.reverse();
        buf.put(&tmp[tmp.len() - len..]);
    }

    /// Decodes a node from bytes.
    pub fn decode(mut buf: Bytes) -> Result<Self> {
        // Start by decoding the ID.
        // The ID is encoded in the last bytes of the buffer, in reverse order.
        // The maximum length is 8 bytes.
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[buf.len() - 8..]);
        tmp.reverse();
        let (id, len_id) = u64::decode_var(&tmp[..]).ok_or(Error::Decoding)?;

        // Get the length.
        tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[buf.len() - len_id - 8..buf.len() - len_id]);
        tmp.reverse();
        let (bytes_len, len_len) = u64::decode_var(&tmp[..]).ok_or(Error::Decoding)?;

        // Read remaining, infering the total length.
        let split_idx = buf.len() - len_id - len_len - bytes_len as usize;
        let mut buf_alta = buf.split_off(split_idx);

        // Further need to split the buf_alta to remove the ID and length previously read.
        let _ = buf_alta.split_off(buf_alta.len() - len_id - len_len);

        // Get the number of hashes by infering from the ID.
        let nb_hashes = BufferEntry::dependencies_in(id).len();

        // Get the hashes.
        let mut hashes: VecDeque<[u8; 32]> = VecDeque::with_capacity(nb_hashes);
        for _ in 0..nb_hashes {
            let hash = buf_alta
                .get(0..32)
                .ok_or(Error::Decoding)?
                .try_into()
                .map_err(|_| Error::Decoding)?;
            hashes.push_back(hash);
            buf_alta.advance(32);
        }

        // Get the signature, if there is one.
        let signature = if !buf_alta.is_empty() {
            let sign = buf_alta.get(0..64).ok_or(Error::Decoding)?.try_into().map_err(|_| Error::Decoding)?;
            Some(sign)
        } else {
            None
        };

        Ok(Self {
            id,
            hashes,
            signature,
            payload: Some(buf.to_vec()),
            dependencies: BufferEntry::dependencies_in(id),
            state: State::NotReady,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        for do_sign in [true, false] {
            let id = 56;
            let dependencies = BufferEntry::dependencies_in(id);
    
            let mut hashes = VecDeque::new();
            for &i in dependencies.iter() {
                hashes.push_back([i as u8; 32]);
            }
    
            // Encode a packet with its payload.
            let payload = vec![id as u8 * 2; id as usize];
            let mut buffer = [0; 1500];
            buffer[..payload.len()].copy_from_slice(&payload[..]);

            let signature = if do_sign {
                Some([77; 64])
            } else {
                None
            };
    
            let mut entry = BufferEntry {
                id,
                hashes,
                signature,
                payload: None,
                dependencies,
                state: State::NotReady,
            };
    
            let mut buf = BytesMut::from(&buffer[..payload.len()]);
            entry.encode(&mut buf);
    
            // Now we update the entry to match the decoded value by adding the payload.
            entry.payload = Some(payload);
    
            let buf = buf.freeze();
            let decoded_entry = BufferEntry::decode(buf).unwrap();
    
            assert_eq!(entry, decoded_entry);
        }
    }
}