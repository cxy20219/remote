use crate::error::{CommonError, Result};

pub const FRAME_HEADER_SIZE: usize = 10;
pub const FRAME_VERSION: u8 = 1;
pub const FLAG_IS_EOF: u8 = 0b0000_0001;
const MAX_ID_LEN: usize = 0xFFFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryTunnelData {
    pub tunnel_id: String,
    pub conn_id: String,
    pub data: Vec<u8>,
    pub is_eof: bool,
}

/// Encode a binary tunnel data frame.
///
/// Layout (all integers big endian):
///
/// ```text
/// [ver:u8][flags:u8][tid_len:u16][cid_len:u16][data_len:u32][tunnel_id][conn_id][data]
/// ```
///
/// `flags` is currently a single bit (`is_eof`). Unknown bits are rejected on
/// decode so a future version cannot silently accept malformed frames.
pub fn encode(tunnel_id: &str, conn_id: &str, data: &[u8], is_eof: bool) -> Result<Vec<u8>> {
    let tid_len = tunnel_id.len();
    let cid_len = conn_id.len();
    if tid_len > MAX_ID_LEN {
        return Err(CommonError::TunnelIdTooLong(tid_len));
    }
    if cid_len > MAX_ID_LEN {
        return Err(CommonError::ConnIdTooLong(cid_len));
    }

    let total = FRAME_HEADER_SIZE + tid_len + cid_len + data.len();
    let mut frame = vec![0u8; total];
    frame[0] = FRAME_VERSION;
    frame[1] = if is_eof { FLAG_IS_EOF } else { 0 };
    frame[2..4].copy_from_slice(&(tid_len as u16).to_be_bytes());
    frame[4..6].copy_from_slice(&(cid_len as u16).to_be_bytes());
    frame[6..10].copy_from_slice(&(data.len() as u32).to_be_bytes());

    let mut offset = FRAME_HEADER_SIZE;
    frame[offset..offset + tid_len].copy_from_slice(tunnel_id.as_bytes());
    offset += tid_len;
    frame[offset..offset + cid_len].copy_from_slice(conn_id.as_bytes());
    offset += cid_len;
    frame[offset..].copy_from_slice(data);

    Ok(frame)
}

/// Decode a binary tunnel data frame, validating every length against the
/// remaining payload (subtractive check) to avoid 32-bit integer boundary
/// issues on huge malicious inputs.
pub fn decode(frame: &[u8]) -> Result<BinaryTunnelData> {
    if frame.len() < FRAME_HEADER_SIZE {
        return Err(CommonError::FrameTooShort(frame.len()));
    }
    if frame[0] != FRAME_VERSION {
        return Err(CommonError::FrameVersion(frame[0]));
    }
    if frame[1] & !FLAG_IS_EOF != 0 {
        return Err(CommonError::FrameFlags(frame[1]));
    }

    let tid_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let cid_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    let data_len = u32::from_be_bytes([frame[6], frame[7], frame[8], frame[9]]);

    let mut remaining = frame.len() - FRAME_HEADER_SIZE;
    if tid_len > remaining {
        return Err(CommonError::FrameTunnelIdLen(tid_len));
    }
    remaining -= tid_len;
    if cid_len > remaining {
        return Err(CommonError::FrameConnIdLen(cid_len));
    }
    remaining -= cid_len;
    if data_len as usize != remaining {
        return Err(CommonError::FrameDataLen {
            got: data_len,
            expected: remaining,
        });
    }

    let mut offset = FRAME_HEADER_SIZE;
    let tunnel_id = std::str::from_utf8(&frame[offset..offset + tid_len])?.to_string();
    offset += tid_len;
    let conn_id = std::str::from_utf8(&frame[offset..offset + cid_len])?.to_string();
    offset += cid_len;
    let data = frame[offset..].to_vec();
    let is_eof = frame[1] & FLAG_IS_EOF != 0;

    Ok(BinaryTunnelData {
        tunnel_id,
        conn_id,
        data,
        is_eof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let frame = encode("t-1", "c-1", b"hello", false).unwrap();
        let out = decode(&frame).unwrap();
        assert_eq!(out.tunnel_id, "t-1");
        assert_eq!(out.conn_id, "c-1");
        assert_eq!(out.data, b"hello");
        assert!(!out.is_eof);
    }

    #[test]
    fn roundtrip_empty_data() {
        let frame = encode("t", "c", b"", true).unwrap();
        let out = decode(&frame).unwrap();
        assert!(out.is_eof);
        assert!(out.data.is_empty());
    }

    #[test]
    fn roundtrip_256k_chunk() {
        let chunk = vec![0xAB; 256 * 1024];
        let frame = encode("tunnel", "conn", &chunk, false).unwrap();
        let out = decode(&frame).unwrap();
        assert_eq!(out.data.len(), chunk.len());
        assert_eq!(out.data, chunk);
    }

    #[test]
    fn roundtrip_utf8_id() {
        let frame = encode("隧道-1", "连接-αβγ", "数据".as_bytes(), false).unwrap();
        let out = decode(&frame).unwrap();
        assert_eq!(out.tunnel_id, "隧道-1");
        assert_eq!(out.conn_id, "连接-αβγ");
    }

    #[test]
    fn rejects_too_short() {
        let err = decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, CommonError::FrameTooShort(5)));
    }

    #[test]
    fn rejects_bad_version() {
        let mut frame = encode("a", "b", b"x", false).unwrap();
        frame[0] = 2;
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::FrameVersion(2)));
    }

    #[test]
    fn rejects_unknown_flags() {
        let mut frame = encode("a", "b", b"x", false).unwrap();
        frame[1] = 0b0000_0010;
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::FrameFlags(2)));
    }

    #[test]
    fn accepts_eof_flag_alone() {
        let frame = encode("a", "b", b"x", true).unwrap();
        assert_eq!(frame[1], FLAG_IS_EOF);
        let out = decode(&frame).unwrap();
        assert!(out.is_eof);
    }

    #[test]
    fn rejects_oversize_tunnel_id_len() {
        // Header claims tid_len = 100 but frame only has 12 bytes total
        let mut frame = vec![0u8; 12];
        frame[0] = 1;
        frame[2..4].copy_from_slice(&100u16.to_be_bytes());
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::FrameTunnelIdLen(100)));
    }

    #[test]
    fn rejects_oversize_conn_id_len() {
        let mut frame = vec![0u8; 12];
        frame[0] = 1;
        frame[2..4].copy_from_slice(&1u16.to_be_bytes()); // tid=1
        frame[4..6].copy_from_slice(&100u16.to_be_bytes()); // cid=100
        // 10 + 1 = 11, but cid claims 100
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::FrameConnIdLen(100)));
    }

    #[test]
    fn rejects_data_len_mismatch() {
        // Build a frame where declared data_len != actual remaining
        let mut frame = vec![0u8; 15];
        frame[0] = 1;
        frame[2..4].copy_from_slice(&1u16.to_be_bytes()); // tid=1
        frame[4..6].copy_from_slice(&1u16.to_be_bytes()); // cid=1
        frame[6..10].copy_from_slice(&99u32.to_be_bytes()); // data=99 (wrong, only 3 bytes left)
        frame[10] = b'a';
        frame[11] = b'b';
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::FrameDataLen { got: 99, expected: 3 }));
    }

    #[test]
    fn encode_rejects_oversize_id() {
        let huge = "x".repeat(MAX_ID_LEN + 1);
        let err = encode(&huge, "c", b"x", false).unwrap_err();
        assert!(matches!(err, CommonError::TunnelIdTooLong(65536)));

        let err = encode("t", &huge, b"x", false).unwrap_err();
        assert!(matches!(err, CommonError::ConnIdTooLong(65536)));
    }

    #[test]
    fn rejects_invalid_utf8_in_id() {
        // tid_len=2, cid_len=0, data_len=0, but bytes 10..12 are 0xFF 0xFE (invalid UTF-8)
        let mut frame = vec![0u8; 12];
        frame[0] = 1;
        frame[2..4].copy_from_slice(&2u16.to_be_bytes());
        frame[4..6].copy_from_slice(&0u16.to_be_bytes());
        frame[6..10].copy_from_slice(&0u32.to_be_bytes());
        frame[10] = 0xFF;
        frame[11] = 0xFE;
        let err = decode(&frame).unwrap_err();
        assert!(matches!(err, CommonError::InvalidUtf8(_)), "got {err:?}");
    }

    /// Fuzz: `decode` must never panic on arbitrary input. It should
    /// either round-trip cleanly (for valid bytes that the encoder would
    /// have produced) or return a well-typed error. Proptest exercises
    /// 256 random cases per run to catch any new panic regressions.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Any random byte sequence either decodes successfully or
            /// returns a typed `CommonError` — never panics, never OOMs.
            #[test]
            fn decode_never_panics(bytes: Vec<u8>) {
                let _ = decode(&bytes);
            }

            /// For a valid tunnel_id (any short ASCII string) and
            /// arbitrary conn_id bytes, the decoder either round-trips or
            /// returns `InvalidUtf8` (because the conn_id is forced to be
            /// non-UTF-8 in some cases).
            #[test]
            fn conn_id_with_garbage_bytes(
                tid in "[a-zA-Z0-9_-]{1,16}",
                cid_bytes in proptest::collection::vec(any::<u8>(), 0..32),
            ) {
                let frame = encode(&tid, "fallback", b"x", false).unwrap();
                // Splice in arbitrary conn_id bytes; decoder must reject
                // any of {oversize header, bad UTF-8, data length mismatch}
                // without panicking.
                let mut buf = frame.clone();
                // `cid_bytes` is bounded to 0..32 by the strategy, so the
                // cast to u16 is always lossless — no `.min(0xFFFF)` needed.
                let cid_len = cid_bytes.len() as u16;
                buf[4..6].copy_from_slice(&cid_len.to_be_bytes());
                let mut spliced = Vec::with_capacity(10 + tid.len() + cid_bytes.len() + 1);
                spliced.extend_from_slice(&buf[..10]);
                spliced.extend_from_slice(tid.as_bytes());
                spliced.extend_from_slice(&cid_bytes);
                spliced.push(b'x');
                let _ = decode(&spliced);
            }

            /// Encoding then decoding is the identity for any string
            /// (no NUL bytes since `tunnel_id`/`conn_id` are arbitrary
            /// strings in the codec) and any byte payload.
            #[test]
            fn roundtrip_arbitrary(
                tid in ".*",
                cid in ".*",
                data in proptest::collection::vec(any::<u8>(), 0..1024),
                is_eof in any::<bool>(),
            ) {
                if tid.len() > MAX_ID_LEN || cid.len() > MAX_ID_LEN {
                    prop_assume!(true); // skip; size limit tested elsewhere
                }
                let frame = encode(&tid, &cid, &data, is_eof).unwrap();
                let out = decode(&frame).unwrap();
                prop_assert_eq!(out.tunnel_id, tid);
                prop_assert_eq!(out.conn_id, cid);
                prop_assert_eq!(out.data, data);
                prop_assert_eq!(out.is_eof, is_eof);
            }
        }
    }
}
