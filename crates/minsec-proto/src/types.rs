//! JSON request/response bodies, field-for-field with `pkg/wire` in the
//! minsec.io repo.

use serde::{Deserialize, Serialize};

/// One reported automatic ban. `ip` is a CIDR string: IPv4 `/24`–`/32`,
/// IPv6 `/48`–`/64`. Manual bans and unbans are never reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub ts: i64,
    pub ip: String,
    pub filter: String,
    pub count: i64,
    pub ban_ttl: i64,
    /// Repeat-offender depth from the daemon's escalation ladder: 0 on a
    /// first ban, incrementing each time the address is re-banned inside
    /// the escalation memory.
    pub escalation: u32,
}

/// Body of `POST /v1/reports`. `seq` must strictly increase per agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBatch {
    pub seq: u64,
    pub agent_version: String,
    pub reports: Vec<Report>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportResponse {
    #[serde(default)]
    pub accepted: u64,
    #[serde(default)]
    pub rejected: u64,
    #[serde(default)]
    pub duplicate: bool,
}

/// Body of `POST /v1/enroll/challenge`. An install token is optional; a
/// valid one moves the challenge from the per-address enrollment limit to
/// the token's own, so a fleet behind one NAT address can enroll at once.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChallengeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_token: Option<String>,
}

/// Response of `POST /v1/enroll/challenge`.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_in: u64,
    pub algo: String,
}

pub const POW_ALGO: &str = "sha256-pow-v1";

/// Body of `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollRequest {
    pub challenge: String,
    pub pow_nonce: String,
    /// base64 (std) 32-byte Ed25519 public key.
    pub pubkey: String,
    pub agent_version: String,
    /// Binds the enrollment to the organization that issued the token
    /// (fleet management). Null for an anonymous crowd agent.
    pub install_token: Option<String>,
    /// The host's name in its organization's fleet views and alerts; see
    /// [`sanitize_label`]. Stored only for an enrollment bound to an
    /// organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// [`PRODUCT_MINSEC`] (the server's default when absent) or
    /// [`PRODUCT_MINSEC_ID`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

/// Products an agent enrolls as. Each product's agents may use only that
/// product's signed endpoints.
pub const PRODUCT_MINSEC: &str = "minsec";
pub const PRODUCT_MINSEC_ID: &str = "minsec-id";

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub host_id: String,
    pub report_url: String,
    pub feed_url: String,
    /// Minimum seconds between report submissions.
    pub min_report_interval: u64,
    /// The organization an install token bound this enrollment to.
    #[serde(default)]
    pub org: Option<String>,
}

/// Longest label the backend stores.
pub const LABEL_MAX: usize = 64;

/// A host label as the backend accepts it: ASCII letters, digits, `.`, `_`
/// and `-`, starting with a letter or digit, at most [`LABEL_MAX`] bytes;
/// a hostname fits. Other characters are dropped and the result truncated.
/// `None` when nothing usable is left.
pub fn sanitize_label(s: &str) -> Option<String> {
    let mut out: String = s
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let start = out.find(|c: char| c.is_ascii_alphanumeric())?;
    out.drain(..start);
    out.truncate(LABEL_MAX);
    Some(out)
}

/// Error body used by every non-2xx JSON response.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub message: String,
}

/// A distribution release: os-release `ID` and `VERSION_ID`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsInfo {
    pub id: String,
    pub version_id: String,
}

/// The number of a minsec-id host's open findings of one check at one
/// severity. Accepted findings are counted apart from open ones; `new`
/// counts findings first seen since the host's previous report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingCount {
    pub check: String,
    pub severity: String,
    pub open: u32,
    pub accepted: u32,
    pub new: u32,
}

/// Body of `POST /v1/findings`: counts only, never a finding's subject or
/// detail. It doubles as the heartbeat. `seq` must strictly increase per
/// agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsReport {
    pub seq: u64,
    pub agent_version: String,
    pub os: OsInfo,
    /// The checks the host ran: the denominator for the counts.
    pub checks: Vec<String>,
    pub counts: Vec<FindingCount>,
    /// The host's current label, sent by an agent bound to an
    /// organization so a renamed host is renamed in its fleet views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingsResponse {
    #[serde(default)]
    pub accepted: u64,
    #[serde(default)]
    pub duplicate: bool,
}

/// One package-owned file whose content differs from the digest its
/// package database records. Digests are lowercase hex in `algo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashCheckItem {
    /// `rpm` or `dpkg`.
    pub manager: String,
    /// The rpm NEVRA or the dpkg `name:arch=version`.
    pub package: String,
    pub path: String,
    pub algo: String,
    pub expected: String,
    pub actual: String,
}

/// Body of `POST /v1/hashcheck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCheckRequest {
    pub agent_version: String,
    pub items: Vec<HashCheckItem>,
}

/// A quorum of other hosts report the same content.
pub const VERDICT_SHARED: &str = "shared";
/// Fewer do.
pub const VERDICT_RARE: &str = "rare";
/// The item was invalid and was not counted.
pub const VERDICT_REJECTED: &str = "rejected";

/// The answer for one [`HashCheckItem`]. Counts are of other hosts, counted
/// once per enrollment network, and never say which hosts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashCheckResult {
    pub verdict: String,
    /// Hosts reporting the same content for this package and path.
    #[serde(default)]
    pub same: u32,
    /// Hosts reporting other content for it.
    #[serde(default)]
    pub different: u32,
    /// Hosts whose package database records a different expected digest.
    #[serde(default)]
    pub expected_disputed: u32,
}

/// Response of `POST /v1/hashcheck`: results in the order of the items.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HashCheckResponse {
    #[serde(default)]
    pub results: Vec<HashCheckResult>,
}

/// The default label: this host's name (`/proc/sys/kernel/hostname`),
/// sanitized.
pub fn host_label() -> Option<String> {
    sanitize_label(&std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(sanitize_label("web1.example.com").as_deref(), Some("web1.example.com"));
        assert_eq!(sanitize_label("  -db 2\n").as_deref(), Some("db2"));
        assert_eq!(sanitize_label("--- ..").as_deref(), None);
        assert_eq!(sanitize_label("").as_deref(), None);
        assert_eq!(sanitize_label(&"a".repeat(100)).map(|l| l.len()), Some(LABEL_MAX));
    }
}
