//! Cross-implementation signing vectors, copied verbatim from the backend
//! repo (`pkg/wire/testdata/vectors.json`). Both the Go and Rust sides must
//! pass these exact vectors; regenerate them there (`go test ./pkg/wire
//! -run TestSigningVectors -update`) and re-copy on any protocol change.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    /// Absent in the report vectors from before there were other purposes.
    #[serde(default)]
    purpose: Option<String>,
    seed_hex: String,
    pubkey_b64: String,
    host_id: String,
    timestamp: i64,
    body: String,
    body_sha256_hex: String,
    canonical: String,
    signature_b64: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn signing_vectors() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    assert!(!vectors.is_empty());

    for v in &vectors {
        let seed: [u8; 32] = unhex(&v.seed_hex).try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        let body = v.body.as_bytes();
        let purpose = v.purpose.as_deref().unwrap_or(minsec_proto::sign::PURPOSE_REPORT);

        assert_eq!(
            B64.encode(key.verifying_key().to_bytes()),
            v.pubkey_b64,
            "{}: pubkey",
            v.name
        );

        let canonical = minsec_proto::sign::canonical_string_for(purpose, &v.host_id, v.timestamp, body);
        assert_eq!(canonical, v.canonical, "{}: canonical string", v.name);
        assert!(canonical.ends_with(&v.body_sha256_hex), "{}: body digest", v.name);

        let sig = minsec_proto::sign::sign_for(purpose, &key, &v.host_id, v.timestamp, body);
        assert_eq!(B64.encode(sig), v.signature_b64, "{}: signature", v.name);

        let pubkey = key.verifying_key();
        assert!(minsec_proto::sign::verify_for(
            purpose,
            &pubkey,
            &v.host_id,
            v.timestamp,
            body,
            &sig
        ));

        // Any mutation must break verification.
        assert!(!minsec_proto::sign::verify_for(
            purpose,
            &pubkey,
            &v.host_id,
            v.timestamp + 1,
            body,
            &sig
        ));
        assert!(!minsec_proto::sign::verify_for(
            purpose,
            &pubkey,
            "018f3c00-dead-7000-8000-000000000009",
            v.timestamp,
            body,
            &sig
        ));
        let mut tampered = body.to_vec();
        tampered.push(b' ');
        assert!(!minsec_proto::sign::verify_for(
            purpose,
            &pubkey,
            &v.host_id,
            v.timestamp,
            &tampered,
            &sig
        ));
        for other in [
            minsec_proto::sign::PURPOSE_REPORT,
            minsec_proto::sign::PURPOSE_FINDINGS,
            minsec_proto::sign::PURPOSE_HASHCHECK,
        ] {
            if other != purpose {
                assert!(
                    !minsec_proto::sign::verify_for(other, &pubkey, &v.host_id, v.timestamp, body, &sig),
                    "{}: verifies as {other}",
                    v.name
                );
            }
        }
        let mut badsig = sig;
        badsig[0] ^= 1;
        assert!(!minsec_proto::sign::verify_for(
            purpose,
            &pubkey,
            &v.host_id,
            v.timestamp,
            body,
            &badsig
        ));
    }
}

/// The typical-batch vector body must round-trip through our serde types —
/// this pins field names against the Go wire structs.
#[test]
fn vector_body_matches_types() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let v = vectors.iter().find(|v| v.name == "typical-batch").unwrap();
    let batch: minsec_proto::types::ReportBatch = serde_json::from_str(&v.body).unwrap();
    assert_eq!(batch.seq, 42);
    assert_eq!(batch.reports.len(), 2);
    assert_eq!(batch.reports[0].ip, "203.0.113.7/32");
    assert_eq!(batch.reports[1].filter, "postfix-sasl");
    assert_eq!(batch.reports[0].escalation, 0);
    assert_eq!(batch.reports[1].escalation, 2);
    // Re-serialization is byte-identical: field order and names match.
    assert_eq!(serde_json::to_string(&batch).unwrap(), v.body);
}

/// The minsec-id vector bodies round-trip through our types byte for byte.
#[test]
fn minsec_id_bodies_match_types() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let v = vectors.iter().find(|v| v.name == "minsec-id-findings").unwrap();
    let r: minsec_proto::types::FindingsReport = serde_json::from_str(&v.body).unwrap();
    assert_eq!(r.os.id, "fedora");
    assert_eq!(r.counts[0].check, "pkg-modified");
    assert_eq!(serde_json::to_string(&r).unwrap(), v.body);

    let v = vectors.iter().find(|v| v.name == "minsec-id-hashcheck").unwrap();
    let r: minsec_proto::types::HashCheckRequest = serde_json::from_str(&v.body).unwrap();
    assert_eq!(r.items[0].manager, "rpm");
    assert_eq!(serde_json::to_string(&r).unwrap(), v.body);
}
