//! Wire format parsing and serialization

mod parser;
mod serializer;
mod headers;

pub use parser::{parse, parse_batch, parse_header_line, split_message};
pub use serializer::serialize;
pub use headers::HeaderMap;

#[cfg(test)]
mod related_tests {
    use crate::message::{Message, Related, Action, ObjectType, Id, Path};
    use crate::crypto::{SigningKey, Signature};

    fn msg(related: Option<Vec<Related>>) -> Message {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut m = Message {
            action: Action::Post,
            path: Path::parse("/communities/agents/spaces/needs/").unwrap(),
            id: Id::new("post_1").unwrap(),
            object_type: ObjectType::Object,
            signing_key: key.public_key(),
            signature: Signature([0u8; 64]),
            content_type: Some("application/json".into()),
            content_hash: None,
            payload: Some(b"{}".to_vec()),
            owner: None, creator: None, content_encoding: None,
            content_schema: Some("post.v1".into()),
            policy_ref: None,
            related,
            hlc: None, prev: None, auth_cert: None, auth_evidence: None, auth_warrant: None,
        };
        m.sign(&key);
        m
    }

    /// The `Related` header must survive serialize → parse. It did not: the
    /// serializer listed it in HEADER_ORDER without emitting it and the parser
    /// hard-coded `None`, so a reference written there vanished silently
    /// (sbo-hj98).
    #[test]
    fn related_round_trips_through_the_wire() {
        let want = vec![
            Related { rel: "agreement".into(), reference: "/agreements/agr_x/".into() },
            Related { rel: "license".into(), reference: "sbo+raw://avail:mainnet:13/licenses/cc-by".into() },
        ];
        let bytes = super::serialize(&msg(Some(want.clone())));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains(r#"Related: [{"rel":"agreement","ref":"/agreements/agr_x/"}"#),
            "the spec's field name is `ref`, not `reference`:\n{text}");
        let got = super::parse(&bytes).expect("parses");
        assert_eq!(got.related, Some(want));
    }

    /// Covered by the signature: tampering with it must invalidate the message.
    #[test]
    fn related_is_signed() {
        let m = msg(Some(vec![Related { rel: "agreement".into(), reference: "/agreements/a/".into() }]));
        let bytes = super::serialize(&m);
        let tampered = String::from_utf8_lossy(&bytes)
            .replace("/agreements/a/", "/agreements/b/");
        let parsed = super::parse(tampered.as_bytes()).expect("parses");
        assert!(crate::message::verify_message(&parsed).is_err(), "a swapped ref must break the signature");
    }

    /// Absent and malformed both mean "no references" — the header is
    /// descriptive, so a bad value must not fail an otherwise valid message.
    #[test]
    fn absent_or_malformed_related_is_simply_none() {
        let got = super::parse(&super::serialize(&msg(None))).expect("parses");
        assert_eq!(got.related, None);
        assert_eq!(Related::parse_header("not json"), None);
        assert_eq!(Related::parse_header("[]"), None);
        assert_eq!(Related::header_value(&[]), None, "an empty array is never emitted");
    }
}
