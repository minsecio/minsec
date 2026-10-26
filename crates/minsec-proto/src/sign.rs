//! Detached Ed25519 request signing.
//!
//! The signature covers the canonical string (newline-separated, no
//! trailing newline):
//!
//! ```text
//! <purpose>
//! <host_id>
//! <timestamp>
//! <hex(sha256(request body bytes))>
//! ```
//!
//! The purpose names the endpoint the signature authorizes
//! (`minsec-report-v1` for `POST /v1/reports`), so a body signed for one
//! endpoint can never be replayed against another. The digest is over the
//! exact body bytes sent — there is no JSON canonicalization anywhere in the
//! protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const CANONICAL_PREFIX: &str = PURPOSE_REPORT;

/// `POST /v1/reports` (minsec).
pub const PURPOSE_REPORT: &str = "minsec-report-v1";
/// `POST /v1/findings` (minsec-id).
pub const PURPOSE_FINDINGS: &str = "minsec-id-findings-v1";
/// `POST /v1/hashcheck` (minsec-id).
pub const PURPOSE_HASHCHECK: &str = "minsec-id-hashcheck-v1";

pub fn canonical_string(host_id: &str, timestamp: i64, body: &[u8]) -> String {
    canonical_string_for(PURPOSE_REPORT, host_id, timestamp, body)
}

pub fn canonical_string_for(purpose: &str, host_id: &str, timestamp: i64, body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("{purpose}\n{host_id}\n{timestamp}\n{}", crate::hex(&digest))
}

/// Sign a report batch; the result goes base64 (std) into
/// `X-Minsec-Signature`.
pub fn sign(key: &SigningKey, host_id: &str, timestamp: i64, body: &[u8]) -> [u8; 64] {
    sign_for(PURPOSE_REPORT, key, host_id, timestamp, body)
}

/// Sign a request for `purpose`.
pub fn sign_for(purpose: &str, key: &SigningKey, host_id: &str, timestamp: i64, body: &[u8]) -> [u8; 64] {
    key.sign(canonical_string_for(purpose, host_id, timestamp, body).as_bytes())
        .to_bytes()
}

pub fn verify(key: &VerifyingKey, host_id: &str, timestamp: i64, body: &[u8], signature: &[u8; 64]) -> bool {
    verify_for(PURPOSE_REPORT, key, host_id, timestamp, body, signature)
}

pub fn verify_for(
    purpose: &str,
    key: &VerifyingKey,
    host_id: &str,
    timestamp: i64,
    body: &[u8],
    signature: &[u8; 64],
) -> bool {
    let sig = Signature::from_bytes(signature);
    key.verify(canonical_string_for(purpose, host_id, timestamp, body).as_bytes(), &sig)
        .is_ok()
}
