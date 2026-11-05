#[test]
fn test_parse_single_header() {
    let line = b"Content-Type: application/json";
    let (name, value) = sbo_core::wire::parse_header_line(line).unwrap();
    assert_eq!(name, "Content-Type");
    assert_eq!(value, "application/json");
}

#[test]
fn test_parse_header_rejects_crlf() {
    let line = b"Content-Type: application/json\r";
    let result = sbo_core::wire::parse_header_line(line);
    assert!(result.is_err());
}

#[test]
fn test_split_message() {
    let msg = b"SBO-Version: 0.5\nAction: post\n\n{\"hello\":\"world\"}";
    let (headers, payload) = sbo_core::wire::split_message(msg).unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(payload, b"{\"hello\":\"world\"}");
}

#[test]
fn test_split_message_no_blank_line() {
    let msg = b"SBO-Version: 0.5\nAction: post";
    let result = sbo_core::wire::split_message(msg);
    assert!(result.is_err());
}

#[test]
fn test_parse_minimal_message() {
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588\n\
Public-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let result = sbo_core::wire::parse(msg);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let message = result.unwrap();
    assert_eq!(message.path.to_string(), "/test/");
    assert_eq!(message.id.as_str(), "hello");
}

#[test]
fn test_roundtrip_message() {
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: hello\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 17\n\
Content-Hash: sha256:93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588\n\
Public-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"hello\":\"world\"}";

    let msg_parsed = sbo_core::wire::parse(msg).unwrap();
    let serialized = sbo_core::wire::serialize(&msg_parsed);
    let reparsed = sbo_core::wire::parse(&serialized).unwrap();

    assert_eq!(msg_parsed.path.to_string(), reparsed.path.to_string());
    assert_eq!(msg_parsed.id.as_str(), reparsed.id.as_str());
}

#[test]
fn test_parse_batch() {
    // Create two messages concatenated directly (no separator)
    // Payload {"a":"b"} is 9 bytes
    let msg1 = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: first\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 9\n\
Content-Hash: sha256:db4a7ecb114bc66c623a06c4ff6fe8daa2f49cc270ebbf7a1f81e22ab061c837\n\
Public-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"a\":\"b\"}";

    // Payload {"c":"d"} is 9 bytes
    let msg2 = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: second\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 9\n\
Content-Hash: sha256:44b601ca630eafcddd257452f3fa699f0c98cee534c0578e26cbeb5e09542a58\n\
Public-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{\"c\":\"d\"}";

    // Concatenate directly - no separator needed
    let mut batch = msg1.to_vec();
    batch.extend_from_slice(msg2);

    let messages = sbo_core::wire::parse_batch(&batch).unwrap();

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id.as_str(), "first");
    assert_eq!(messages[1].id.as_str(), "second");
}

#[test]
fn test_parse_batch_single_message() {
    // A batch with one message should work
    let msg = b"SBO-Version: 0.5\n\
Action: post\n\
Path: /test/\n\
ID: only\n\
Type: object\n\
Content-Type: application/json\n\
Content-Length: 2\n\
Content-Hash: sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n\
Public-Key: ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
Signature: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
\n\
{}";

    let messages = sbo_core::wire::parse_batch(msg).unwrap();

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id.as_str(), "only");
}
