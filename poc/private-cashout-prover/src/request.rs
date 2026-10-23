//! Private witness syntax only. The caller authenticates parameters before read.
//! This module has no witness serialization, logging, hashing or filesystem API.
use crate::{
    Authorization, Note,
    circuit::{ActionCircuit, InputWitness},
};
use serde::{
    Deserialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, io::Read, marker::PhantomData};

pub const SCHEMA: &str = "kpx3-private-action-witness/v1";
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Fixed codes deliberately discard parser and IO details containing private data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    Invalid,
    TooLarge,
    Io,
}

impl RequestError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "private_request_invalid",
            Self::TooLarge => "private_request_too_large",
            Self::Io => "private_request_io",
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RequestError {}

// Serde's derived struct visitor also accepts arrays. Require actual JSON
// objects at every schema object boundary without losing duplicate-field checks.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

// No Debug or Serialize implementation may expose these private request fields.
// Derived struct deserializers reject duplicate fields as well as unknown ones.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    real: bool,
    note_hex168: String,
    s_hex32: String,
    k_hex32: String,
    position: u32,
    cm_path_hex: [String; 16],
    dummy_key_hex32: String,
    dummy_seed_hex32: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    note_hex168: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    auth_hex528: String,
    inputs: [Object<Input>; 2],
    outputs: [Object<Output>; 2],
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], RequestError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RequestError::Invalid);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| RequestError::Invalid)?;
    Ok(bytes)
}

fn input(value: Input) -> Result<InputWitness, RequestError> {
    let mut path = [[0; 32]; 16];
    for (to, from) in path.iter_mut().zip(&value.cm_path_hex) {
        *to = fixed(from)?;
    }
    Ok(InputWitness {
        real: value.real,
        note: Note::parse(&fixed::<168>(&value.note_hex168)?).map_err(|_| RequestError::Invalid)?,
        owner_secret: fixed(&value.s_hex32)?,
        nullifier_secret: fixed(&value.k_hex32)?,
        position: value.position,
        path,
        dummy_key: fixed(&value.dummy_key_hex32)?,
        dummy_seed: fixed(&value.dummy_seed_hex32)?,
    })
}

fn output(value: Output) -> Result<Note, RequestError> {
    Note::parse(&fixed::<168>(&value.note_hex168)?).map_err(|_| RequestError::Invalid)
}

/// Parse one private message. Relation and public-context checks remain separate.
pub fn parse(raw: &[u8]) -> Result<ActionCircuit, RequestError> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }
    // from_slice also rejects trailing non-whitespace payloads. Never propagate
    // its errors: an invalid value or unknown field name may itself be private.
    let Object(request): Object<Request> =
        serde_json::from_slice(raw).map_err(|_| RequestError::Invalid)?;
    if request.schema != SCHEMA {
        return Err(RequestError::Invalid);
    }
    let authorization = Authorization::parse(&fixed::<528>(&request.auth_hex528)?)
        .map_err(|_| RequestError::Invalid)?;
    let [first_input, second_input] = request.inputs;
    let [first_output, second_output] = request.outputs;
    Ok(ActionCircuit {
        authorization,
        inputs: [input(first_input.0)?, input(second_input.0)?],
        outputs: [output(first_output.0)?, output(second_output.0)?],
    })
}

/// Read at most the generous message cap plus one byte needed to detect excess.
/// Opening an FD and deciding when this function may run belong to the caller.
pub fn read<R: Read>(reader: &mut R) -> Result<ActionCircuit, RequestError> {
    let mut raw = Vec::new();
    reader
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| RequestError::Io)?;
    parse(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DOMAIN, State};
    use serde_json::{Value, json};
    use std::io::{self, Cursor};

    // Synthetic syntax data only. Never serialize an actual ActionCircuit.
    fn syntax_request() -> Value {
        let state = State {
            domain: DOMAIN,
            cm_root: [0; 32],
            n: 0,
            nf_root: [0; 32],
            m: 0,
        };
        let auth = Authorization {
            domain: DOMAIN,
            previous_outpoint: [0; 36],
            prior: state.clone(),
            reserve: 0,
            fee: 0,
            nfs: [[0; 32]; 2],
            outputs: [[0; 32]; 2],
            cipher_hash: [0; 32],
            next: state,
            reserve_after: 0,
            payout: 0,
            payout_spk: [0; 36],
        };
        let input = json!({
            "real": false,
            "note_hex168": hex::encode(Note::zero().bytes()),
            "s_hex32": "00".repeat(32),
            "k_hex32": "00".repeat(32),
            "position": 0,
            "cm_path_hex": vec!["00".repeat(32); 16],
            "dummy_key_hex32": "00".repeat(32),
            "dummy_seed_hex32": "00".repeat(32),
        });
        let output = json!({"note_hex168": hex::encode(Note::zero().bytes())});
        json!({
            "schema": SCHEMA,
            "auth_hex528": hex::encode(auth.bytes()),
            "inputs": [input.clone(), input],
            "outputs": [output.clone(), output],
        })
    }

    fn invalid(value: &Value) {
        assert!(matches!(
            parse(&serde_json::to_vec(value).unwrap()),
            Err(RequestError::Invalid)
        ));
    }

    #[test]
    fn syntax_accepts_without_claiming_relation_validity() {
        let raw = serde_json::to_vec(&syntax_request()).unwrap();
        let circuit = parse(&raw).unwrap();
        assert_eq!(circuit.authorization.domain, DOMAIN);
        assert_eq!(circuit.inputs[0].note, Note::zero());
        assert_eq!(circuit.outputs[1], Note::zero());
        assert!(circuit.authorization.validate_public().is_err());
        assert!(read(&mut Cursor::new(raw)).is_ok());
    }

    #[test]
    fn schema_missing_fields_and_unknown_fields_reject() {
        let original = syntax_request();
        let mut value = original.clone();
        value["schema"] = "another-private-witness/v1".into();
        invalid(&value);
        for pointer in ["", "/inputs/0", "/outputs/0"] {
            let mut value = original.clone();
            value.pointer_mut(pointer).unwrap()["unknown_private_field"] = true.into();
            invalid(&value);
        }
        let mut value = original;
        value.as_object_mut().unwrap().remove("auth_hex528");
        invalid(&value);
    }

    #[test]
    fn duplicate_fields_reject_at_every_object_level() {
        let raw = serde_json::to_string(&syntax_request()).unwrap();
        let note_member = format!("\"note_hex168\":\"{}\"", "00".repeat(168));
        for member in [
            format!("\"schema\":\"{SCHEMA}\""),
            "\"real\":false".to_owned(),
            note_member,
        ] {
            // Last note member belongs to an output, not an input.
            let mut duplicate = raw.clone();
            let end = duplicate.rfind(&member).unwrap() + member.len();
            duplicate.insert_str(end, &format!(",{member}"));
            assert!(matches!(
                parse(duplicate.as_bytes()),
                Err(RequestError::Invalid)
            ));
        }
    }

    #[test]
    fn schema_objects_cannot_be_replaced_by_struct_field_arrays() {
        let original = syntax_request();
        let root_array = json!([
            original["schema"],
            original["auth_hex528"],
            original["inputs"],
            original["outputs"],
        ]);
        invalid(&root_array);
        let mut value = original.clone();
        let input = &original["inputs"][0];
        value["inputs"][0] = json!([
            input["real"],
            input["note_hex168"],
            input["s_hex32"],
            input["k_hex32"],
            input["position"],
            input["cm_path_hex"],
            input["dummy_key_hex32"],
            input["dummy_seed_hex32"],
        ]);
        invalid(&value);
        let mut value = original.clone();
        value["outputs"][0] = json!([original["outputs"][0]["note_hex168"]]);
        invalid(&value);
    }

    #[test]
    fn exact_input_output_and_path_arities_are_required() {
        let original = syntax_request();
        for (pointer, counts) in [
            ("/inputs", [1, 3]),
            ("/outputs", [1, 3]),
            ("/inputs/0/cm_path_hex", [15, 17]),
        ] {
            for count in counts {
                let mut value = original.clone();
                let first = value.pointer(pointer).unwrap()[0].clone();
                *value.pointer_mut(pointer).unwrap() = vec![first; count].into();
                invalid(&value);
            }
        }
    }

    #[test]
    fn every_hex_field_requires_lowercase_exact_width() {
        let original = syntax_request();
        for pointer in [
            "/auth_hex528",
            "/inputs/0/note_hex168",
            "/inputs/0/s_hex32",
            "/inputs/0/k_hex32",
            "/inputs/0/cm_path_hex/0",
            "/inputs/0/dummy_key_hex32",
            "/inputs/0/dummy_seed_hex32",
            "/outputs/0/note_hex168",
        ] {
            let good = original.pointer(pointer).unwrap().as_str().unwrap();
            for bad in [
                good[..good.len() - 2].to_owned(),
                good[..good.len() - 1].to_owned(),
                format!("{good}00"),
                "AA".repeat(good.len() / 2),
                "gg".repeat(good.len() / 2),
            ] {
                let mut value = original.clone();
                *value.pointer_mut(pointer).unwrap() = bad.into();
                invalid(&value);
            }
        }
        assert_eq!(fixed::<1>("af").unwrap(), [0xaf]);
    }

    #[test]
    fn positions_are_u32_and_embedded_auth_encoding_is_checked() {
        let original = syntax_request();
        for bad in [json!(-1), json!(4_294_967_296_u64), json!(0.5), json!("0")] {
            let mut value = original.clone();
            value["inputs"][0]["position"] = bad;
            invalid(&value);
        }
        let mut value = original.clone();
        value["inputs"][0]["position"] = u32::MAX.into();
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_ok());
        let mut value = original;
        value["auth_hex528"] = "00".repeat(528).into();
        invalid(&value);
    }

    #[test]
    fn trailing_payload_rejects_but_whitespace_is_allowed() {
        let raw = serde_json::to_string(&syntax_request()).unwrap();
        for suffix in ["{}", "[]", "true", "private-canary"] {
            assert!(matches!(
                parse(format!("{raw}{suffix}").as_bytes()),
                Err(RequestError::Invalid)
            ));
        }
        assert!(parse(format!("{raw}\n \t\r").as_bytes()).is_ok());
    }

    #[test]
    fn read_and_parse_enforce_the_cap_without_unbounded_reads() {
        let mut raw = serde_json::to_vec(&syntax_request()).unwrap();
        raw.resize(MAX_REQUEST_BYTES, b' ');
        assert!(parse(&raw).is_ok());
        assert!(read(&mut Cursor::new(&raw)).is_ok());
        raw.extend_from_slice(b"  ");
        assert!(matches!(parse(&raw), Err(RequestError::TooLarge)));
        let mut reader = Cursor::new(&raw);
        assert!(matches!(read(&mut reader), Err(RequestError::TooLarge)));
        assert_eq!(reader.position(), (MAX_REQUEST_BYTES + 1) as u64);
    }

    #[test]
    fn parser_and_io_errors_never_include_private_details() {
        let mut value = syntax_request();
        value["inputs"][0]["real"] = "private-value-canary".into();
        let error = match parse(&serde_json::to_vec(&value).unwrap()) {
            Err(error) => error,
            Ok(_) => panic!("invalid private request accepted"),
        };
        assert_eq!(error.to_string(), "private_request_invalid");
        assert_eq!(format!("{error:?}"), "Invalid");

        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private-io-canary"))
            }
        }
        let error = match read(&mut Failing) {
            Err(error) => error,
            Ok(_) => panic!("failing witness reader accepted"),
        };
        assert_eq!(error.to_string(), "private_request_io");
        assert_eq!(format!("{error:?}"), "Io");
        assert_eq!(
            RequestError::TooLarge.to_string(),
            "private_request_too_large"
        );
    }
}
