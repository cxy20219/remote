use serde::de::DeserializeOwned;

use crate::error::{CommonError, Result};

/// Strict JSON decoder mirroring Go's `common.DecodeStrictJSON`:
///
/// 1. Reject unknown fields — enforced by `#[serde(deny_unknown_fields)]` on the
///    target type. The caller is responsible for picking a struct that opts in.
/// 2. Reject trailing values (e.g. `{"a":1}{"a":2}`) by feeding the bytes
///    through a `serde_json::Deserializer` backed by a `&[u8]` reader. After
///    deserialising the first value, the reader's remaining length tells us
///    how many bytes were consumed.
/// 3. Wrap `serde_json` errors in [`CommonError::Json`].
///
/// Use this for every WebSocket control message and HTTP API body so the wire
/// protocol matches the Go server byte-for-byte.
pub fn decode_strict_json<T>(data: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut input: &[u8] = data;
    let mut de = serde_json::Deserializer::from_reader(&mut input);
    let value = T::deserialize(&mut de)?;
    let consumed = data.len() - input.len();
    if !data[consumed..].iter().all(|b| b.is_ascii_whitespace()) {
        return Err(CommonError::JsonMultipleValues);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        name: String,
        #[serde(default)]
        count: u32,
    }

    #[test]
    fn decodes_known_fields() {
        let v: Sample = decode_strict_json(br#"{"name":"alice","count":3}"#).unwrap();
        assert_eq!(v, Sample { name: "alice".into(), count: 3 });
    }

    #[test]
    fn fills_defaults() {
        let v: Sample = decode_strict_json(br#"{"name":"bob"}"#).unwrap();
        assert_eq!(v, Sample { name: "bob".into(), count: 0 });
    }

    #[test]
    fn rejects_unknown_field() {
        let err = decode_strict_json::<Sample>(br#"{"name":"x","extra":1}"#).unwrap_err();
        assert!(matches!(err, CommonError::Json(_)), "got {err:?}");
    }

    #[test]
    fn rejects_trailing_value() {
        let err = decode_strict_json::<Sample>(br#"{"name":"x"}{"name":"y"}"#).unwrap_err();
        assert!(matches!(err, CommonError::JsonMultipleValues), "got {err:?}");
    }

    #[test]
    fn rejects_trailing_whitespace_with_value() {
        // trailing space then a second value
        let err = decode_strict_json::<Sample>(br#"{"name":"x"} {"name":"y"}"#).unwrap_err();
        assert!(matches!(err, CommonError::JsonMultipleValues), "got {err:?}");
    }

    #[test]
    fn rejects_type_mismatch() {
        let err = decode_strict_json::<Sample>(br#"{"name":42}"#).unwrap_err();
        assert!(matches!(err, CommonError::Json(_)), "got {err:?}");
    }

    #[test]
    fn rejects_malformed() {
        let err = decode_strict_json::<Sample>(br#"{"name": "#).unwrap_err();
        assert!(matches!(err, CommonError::Json(_)), "got {err:?}");
    }
}
