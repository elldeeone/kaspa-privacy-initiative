//! Strict private witness syntax; the caller selects and authenticates the role
//! and proving material before opening its private input. No witness logging,
//! serialization, filesystem access or proof execution belongs in this module.
use crate::{Error, ExitWitness, Note, OutputWitness, SpendWitness};
use serde::{
    Deserialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, io::Read, marker::PhantomData};

pub const SPEND_SCHEMA: &str = "kpx8-owner-private-spend-witness/v1";
pub const OUTPUT_SCHEMA: &str = "kpx8-owner-private-output-witness/v1";
pub const EXIT_SCHEMA: &str = "kpx8-owner-private-exit-witness/v1";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

// A derived struct visitor also accepts a sequence in field order. Require an
// actual JSON object while preserving Serde's duplicate-field checks.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }

        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

// Private request fields must never acquire Debug or Serialize implementations.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendRequest {
    schema: String,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    blind_hex32: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputRequest {
    schema: String,
    note_hex168: String,
    blind_hex32: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitRequest {
    schema: String,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
}

fn fixed<const N: usize>(value: &str) -> crate::Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Request);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Request)?;
    Ok(bytes)
}

fn blinding(value: &str) -> crate::Result<[u8; 32]> {
    let bytes = fixed(value)?;
    // Reject noncanonical subgroup scalars; never reduce private wire values.
    crate::scalar_from_bytes(&bytes).map_err(|_| Error::Request)?;
    Ok(bytes)
}

fn parse<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> crate::Result<T> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(Error::Request);
    }
    // Never propagate Serde errors: field names and malformed values can be
    // private. from_slice rejects trailing non-whitespace payloads as well.
    let Object(request): Object<T> = serde_json::from_slice(raw).map_err(|_| Error::Request)?;
    Ok(request)
}

/// Parse one Spend witness. Membership, authorization, note ranges and the
/// high sixteen position bits remain independently constrained by the relation.
pub fn parse_spend(raw: &[u8]) -> crate::Result<SpendWitness> {
    let request: SpendRequest = parse(raw)?;
    if request.schema != SPEND_SCHEMA {
        return Err(Error::Request);
    }
    let mut path = [[0; 32]; 16];
    for (to, from) in path.iter_mut().zip(&request.cm_path_hex) {
        *to = fixed(from)?;
    }
    Ok(SpendWitness {
        note: Note::parse(&fixed::<168>(&request.note_hex168)?).map_err(|_| Error::Request)?,
        owner_secret: fixed(&request.s_hex32)?,
        nullifier_secret: fixed(&request.k_hex32)?,
        position: request.position,
        path,
        blinding: blinding(&request.blind_hex32)?,
    })
}

/// Parse one Output witness without claiming that its financial relation holds.
pub fn parse_output(raw: &[u8]) -> crate::Result<OutputWitness> {
    let request: OutputRequest = parse(raw)?;
    if request.schema != OUTPUT_SCHEMA {
        return Err(Error::Request);
    }
    Ok(OutputWitness {
        note: Note::parse(&fixed::<168>(&request.note_hex168)?).map_err(|_| Error::Request)?,
        blinding: blinding(&request.blind_hex32)?,
    })
}
pub fn parse_exit(raw: &[u8]) -> crate::Result<ExitWitness> {
    let request: ExitRequest = parse(raw)?;
    if request.schema != EXIT_SCHEMA {
        return Err(Error::Request);
    }
    let mut path = [[0; 32]; 16];
    for (to, from) in path.iter_mut().zip(&request.cm_path_hex) {
        *to = fixed(from)?;
    }
    Ok(ExitWitness {
        note: Note::parse(&fixed::<168>(&request.note_hex168)?).map_err(|_| Error::Request)?,
        owner_secret: fixed(&request.s_hex32)?,
        nullifier_secret: fixed(&request.k_hex32)?,
        position: request.position,
        path,
    })
}

fn read<R: Read>(reader: &mut R) -> crate::Result<Vec<u8>> {
    let mut raw = Vec::new();
    reader
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| Error::Io)?;
    Ok(raw)
}

/// Read at most the message cap plus its one-byte excess detector. The caller
/// owns the private file descriptor and decides when private ingress may begin.
pub fn read_spend<R: Read>(reader: &mut R) -> crate::Result<SpendWitness> {
    parse_spend(&read(reader)?)
}

pub fn read_output<R: Read>(reader: &mut R) -> crate::Result<OutputWitness> {
    parse_output(&read(reader)?)
}
pub fn read_exit<R: Read>(reader: &mut R) -> crate::Result<ExitWitness> {
    parse_exit(&read(reader)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::Fr;
    use ark_ff::{BigInteger, Field, PrimeField};
    use serde_json::{Value, json};
    use std::io::{self, Cursor};

    // Deliberately public synthetic syntax fixtures, never actual witnesses.
    fn note_hex() -> String {
        let mut bytes = [0x11; 168];
        bytes[64..72].copy_from_slice(&60_000_000_u64.to_le_bytes());
        hex::encode(bytes)
    }

    fn scalar_hex(value: u8) -> String {
        let mut bytes = [0; 32];
        bytes[0] = value;
        hex::encode(bytes)
    }

    fn spend() -> Value {
        json!({
            "schema": SPEND_SCHEMA,
            "note_hex168": note_hex(),
            "s_hex32": "12".repeat(32),
            "k_hex32": "34".repeat(32),
            "position": 65_535,
            "cm_path_hex": (0_u8..16).map(|i| hex::encode([i; 32])).collect::<Vec<_>>(),
            "blind_hex32": scalar_hex(1),
        })
    }

    fn output() -> Value {
        json!({
            "schema": OUTPUT_SCHEMA,
            "note_hex168": note_hex(),
            "blind_hex32": scalar_hex(1),
        })
    }

    fn invalid(raw: &[u8], is_spend: bool) {
        let rejected = if is_spend {
            matches!(parse_spend(raw), Err(Error::Request))
        } else {
            matches!(parse_output(raw), Err(Error::Request))
        };
        assert!(rejected, "invalid synthetic request accepted");
    }

    fn invalid_value(value: &Value, is_spend: bool) {
        invalid(&serde_json::to_vec(value).unwrap(), is_spend);
    }

    #[test]
    fn accepted_syntax_preserves_secrets_path_order_and_external_role() {
        let raw = serde_json::to_vec(&spend()).unwrap();
        let parsed = parse_spend(&raw).unwrap();
        assert_eq!(parsed.owner_secret, [0x12; 32]);
        assert_eq!(parsed.nullifier_secret, [0x34; 32]);
        assert_eq!(parsed.position, 65_535);
        for (i, sibling) in parsed.path.iter().enumerate() {
            assert_eq!(*sibling, [i as u8; 32]);
        }
        assert_eq!(parsed.blinding[0], 1);
        assert!(read_spend(&mut Cursor::new(&raw)).is_ok());
        invalid(&raw, false);

        let raw = serde_json::to_vec(&output()).unwrap();
        let parsed = parse_output(&raw).unwrap();
        assert_eq!(parsed.blinding[0], 1);
        assert!(read_output(&mut Cursor::new(&raw)).is_ok());
        invalid(&raw, true);
    }

    #[test]
    fn missing_unknown_duplicate_and_wrong_schema_fields_reject() {
        for (original, is_spend) in [(spend(), true), (output(), false)] {
            for field in original.as_object().unwrap().keys() {
                let mut value = original.clone();
                value.as_object_mut().unwrap().remove(field);
                invalid_value(&value, is_spend);
            }
            let mut value = original.clone();
            value["unknown_private_field"] = "private-canary".into();
            invalid_value(&value, is_spend);
            let mut value = original.clone();
            value["schema"] = "another-private-schema/v1".into();
            invalid_value(&value, is_spend);

            let raw = serde_json::to_string(&original).unwrap();
            for (field, value) in original.as_object().unwrap() {
                let duplicate = format!("{{\"{field}\":{value},{}", &raw[1..]);
                invalid(duplicate.as_bytes(), is_spend);
            }
            // Escaped spelling must not evade decoded duplicate-field checks.
            let duplicate = format!("{{\"\\u0073chema\":\"unused\",{}", &raw[1..]);
            invalid(duplicate.as_bytes(), is_spend);
        }
    }

    #[test]
    fn object_arrays_wrong_json_types_and_wrong_path_arity_reject() {
        for (original, is_spend) in [(spend(), true), (output(), false)] {
            // Use declaration order: a derived struct visitor without Object<T>
            // would otherwise accept this exact array as a valid witness.
            let array = if is_spend {
                json!([
                    original["schema"],
                    original["note_hex168"],
                    original["s_hex32"],
                    original["k_hex32"],
                    original["position"],
                    original["cm_path_hex"],
                    original["blind_hex32"],
                ])
            } else {
                json!([
                    original["schema"],
                    original["note_hex168"],
                    original["blind_hex32"],
                ])
            };
            invalid_value(&array, is_spend);
            for value in [json!(null), json!(true), json!(0), json!("private-canary")] {
                invalid_value(&value, is_spend);
            }
            for field in ["schema", "note_hex168", "blind_hex32"] {
                for bad in [json!(null), json!(1), json!([]), json!({})] {
                    let mut value = original.clone();
                    value[field] = bad;
                    invalid_value(&value, is_spend);
                }
            }
        }
        for count in [0, 15, 17] {
            let mut value = spend();
            value["cm_path_hex"] = json!(vec!["00".repeat(32); count]);
            invalid_value(&value, true);
        }
        for bad in [json!({}), json!(null), json!("00")] {
            let mut value = spend();
            value["cm_path_hex"] = bad;
            invalid_value(&value, true);
        }
        let mut value = spend();
        value["cm_path_hex"][15] = json!(null);
        invalid_value(&value, true);
    }

    #[test]
    fn all_hex_fields_require_exact_lowercase_ascii_width() {
        for (original, is_spend, pointers) in [
            (
                spend(),
                true,
                vec![
                    "/note_hex168",
                    "/s_hex32",
                    "/k_hex32",
                    "/blind_hex32",
                    "/cm_path_hex/0",
                    "/cm_path_hex/15",
                ],
            ),
            (output(), false, vec!["/note_hex168", "/blind_hex32"]),
        ] {
            for pointer in pointers {
                let good = original.pointer(pointer).unwrap().as_str().unwrap();
                for bad in [
                    good[..good.len() - 2].to_owned(),
                    good[..good.len() - 1].to_owned(),
                    format!("{good}00"),
                    format!("AF{}", &good[2..]),
                    "gg".repeat(good.len() / 2),
                    "é".repeat(good.len() / 2),
                ] {
                    let mut value = original.clone();
                    *value.pointer_mut(pointer).unwrap() = bad.into();
                    invalid_value(&value, is_spend);
                }
            }
        }
    }

    #[test]
    fn scalar_boundary_rejects_reduction_and_unused_high_bits() {
        let modulus = Fr::MODULUS.to_bytes_le();
        let mut above_modulus = modulus.clone();
        for byte in &mut above_modulus {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        let maximum = (-Fr::ONE).into_bigint().to_bytes_le();
        for (mut value, is_spend) in [(spend(), true), (output(), false)] {
            for good in [vec![0; 32], maximum.clone()] {
                value["blind_hex32"] = hex::encode(good).into();
                let raw = serde_json::to_vec(&value).unwrap();
                assert!(if is_spend {
                    parse_spend(&raw).is_ok()
                } else {
                    parse_output(&raw).is_ok()
                });
            }
            for bad in [modulus.clone(), above_modulus.clone(), vec![0xff; 32]] {
                value["blind_hex32"] = hex::encode(bad).into();
                invalid_value(&value, is_spend);
            }
            let mut high_bit = [0; 32];
            high_bit[31] = 0x08;
            value["blind_hex32"] = hex::encode(high_bit).into();
            invalid_value(&value, is_spend);
        }
    }

    #[test]
    fn position_is_u32_without_replacing_circuit_tree_checks() {
        for bad in [
            json!(-1),
            json!(4_294_967_296_u64),
            json!(0.5),
            json!("0"),
            json!(null),
        ] {
            let mut value = spend();
            value["position"] = bad;
            invalid_value(&value, true);
        }
        for position in [0, u32::MAX] {
            let mut value = spend();
            value["position"] = position.into();
            assert!(parse_spend(&serde_json::to_vec(&value).unwrap()).is_ok());
        }
    }

    #[test]
    fn trailing_payload_rejects_while_whitespace_is_allowed() {
        for (value, is_spend) in [(spend(), true), (output(), false)] {
            let raw = serde_json::to_string(&value).unwrap();
            for suffix in ["{}", "[]", "true", "private-canary"] {
                invalid(format!("{raw}{suffix}").as_bytes(), is_spend);
            }
            let raw = format!("{raw}\n \t\r");
            assert!(if is_spend {
                parse_spend(raw.as_bytes()).is_ok()
            } else {
                parse_output(raw.as_bytes()).is_ok()
            });
        }
        invalid(b"", true);
        invalid(b"\xff", false);
    }

    #[test]
    fn parse_and_read_cap_at_one_mib_plus_one_byte() {
        for (value, is_spend) in [(spend(), true), (output(), false)] {
            let mut raw = serde_json::to_vec(&value).unwrap();
            raw.resize(MAX_REQUEST_BYTES, b' ');
            assert!(if is_spend {
                parse_spend(&raw).is_ok()
            } else {
                parse_output(&raw).is_ok()
            });
            let mut reader = Cursor::new(&raw);
            assert!(if is_spend {
                read_spend(&mut reader).is_ok()
            } else {
                read_output(&mut reader).is_ok()
            });
            raw.extend_from_slice(b"  ");
            invalid(&raw, is_spend);
            let mut reader = Cursor::new(&raw);
            let rejected = if is_spend {
                matches!(read_spend(&mut reader), Err(Error::Request))
            } else {
                matches!(read_output(&mut reader), Err(Error::Request))
            };
            assert!(rejected);
            assert_eq!(reader.position(), (MAX_REQUEST_BYTES + 1) as u64);
        }
    }

    #[test]
    fn private_parse_and_io_details_are_discarded() {
        let mut value = spend();
        value["position"] = "private-value-canary".into();
        invalid_value(&value, true);
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private-io-canary"))
            }
        }
        assert!(matches!(read_spend(&mut Failing), Err(Error::Io)));
        assert!(matches!(read_output(&mut Failing), Err(Error::Io)));
    }
}
