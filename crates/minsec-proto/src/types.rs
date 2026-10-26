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
    /// Reserved for Virtualmin licensing; always null in v1.
    pub install_token: Option<String>,
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
