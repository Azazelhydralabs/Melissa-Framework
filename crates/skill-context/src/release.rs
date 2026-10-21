//! External release attestations preserve immutable skill version bytes.
//! An explicit host-pinned public key, not a manifest trust string, is the root.
use crate::{Result, digest, json, package::Package, require};
use melissa_core_contracts::{design::SkillPin, validation::Validate};
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReceipt {
    pub pin: SkillPin,
    pub provider_model: String,
    pub prompt_digest: String,
    pub source_digest: String,
    pub test_receipt_digest: String,
    pub evaluation_digest: String,
    pub review_digest: String,
    pub verifier_digest: String,
    pub environment_digest: String,
    pub passed: u64,
    pub total: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseStatement {
    pub schema_version: String,
    pub receipt: EvaluationReceipt,
    pub definition_digest: String,
    pub version_record_digest: String,
    pub publisher: String,
    pub key_id: String,
    pub epoch: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub statement: ReleaseStatement,
    pub signature: Vec<u8>,
}
pub struct PublisherKey(Ed25519KeyPair);
impl PublisherKey {
    pub fn generate() -> Result<Self> {
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| crate::Error("publisher key generation failed".into()))?;
        Ok(Self(Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(
            |_| crate::Error("publisher key initialization failed".into()),
        )?))
    }
    pub fn public_key(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.0.public_key().as_ref().to_vec()
    }
    /// Host-only release final step after independent test/evaluation/review.
    /// Possessing this key is never exposed through an agent tool.
    pub fn sign(&self, statement: ReleaseStatement) -> Result<SignedRelease> {
        check_statement(&statement)?;
        let bytes = serde_json::to_vec(&statement)?;
        Ok(SignedRelease {
            statement,
            signature: self.0.sign(&bytes).as_ref().to_vec(),
        })
    }
}
#[derive(Clone)]
pub struct PublisherPolicy {
    pub keys: BTreeMap<String, (String, Vec<u8>)>,
    pub revoked_keys: BTreeSet<String>,
    pub revoked_publishers: BTreeSet<String>,
    pub revoked_pins: BTreeSet<String>,
    pub epoch: u64,
    pub now_ms: u64,
    /// Independently authenticated host receipt digests, not package claims.
    pub accepted_receipts: BTreeSet<String>,
}
pub struct VerifiedRelease {
    pub pin: SkillPin,
    pub attestation_digest: String,
}
impl SignedRelease {
    pub fn verify(&self, package: &Package, policy: &PublisherPolicy) -> Result<VerifiedRelease> {
        let s = &self.statement;
        check_statement(s)?;
        require(
            s.receipt.pin == package.version().pin
                && s.definition_digest == package.version().definition_digest
                && s.version_record_digest == digest(&serde_json::to_vec(package.version())?)
                && matches!(
                    package.version().state,
                    melissa_core_contracts::design::SkillReleaseState::Tested
                        | melissa_core_contracts::design::SkillReleaseState::Evaluated
                        | melissa_core_contracts::design::SkillReleaseState::Reviewed
                )
                && policy.epoch == s.epoch
                && policy.now_ms < s.expires_at_ms
                && !policy.revoked_keys.contains(&s.key_id)
                && !policy.revoked_publishers.contains(&s.publisher)
                && !policy.revoked_pins.contains(&s.receipt.pin.content_digest),
            "release stale, revoked or bound to different bytes",
        )?;
        let (publisher, key) = policy
            .keys
            .get(&s.key_id)
            .ok_or_else(|| crate::Error("untrusted publisher key".into()))?;
        require(
            publisher == &s.publisher && package.version().publisher_id == s.publisher,
            "publisher identity mismatch",
        )?;
        for d in [
            &s.receipt.test_receipt_digest,
            &s.receipt.evaluation_digest,
            &s.receipt.review_digest,
        ] {
            require(
                policy.accepted_receipts.contains(d),
                "release lacks an independently admitted test/evaluation/review receipt",
            )?;
        }
        require(
            (s.receipt.passed as f64) / (s.receipt.total as f64)
                >= package.definition().manifest.evaluation.min_success_rate,
            "skill evaluation threshold failed",
        )?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&serde_json::to_vec(s)?, &self.signature)
            .map_err(|_| crate::Error("publisher signature verification failed".into()))?;
        Ok(VerifiedRelease {
            pin: s.receipt.pin.clone(),
            attestation_digest: digest(&serde_json::to_vec(self)?),
        })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        json(bytes)
    }
}
fn check_statement(s: &ReleaseStatement) -> Result<()> {
    s.receipt.pin.validate()?;
    require(
        s.schema_version == "melissa.signed-skill-release/v1"
            && s.receipt.total > 0
            && s.receipt.passed <= s.receipt.total
            && s.epoch > 0
            && s.expires_at_ms > 0
            && !s.receipt.provider_model.trim().is_empty()
            && !s.publisher.is_empty()
            && !s.key_id.is_empty(),
        "invalid release statement",
    )?;
    for d in [
        &s.receipt.test_receipt_digest,
        &s.receipt.evaluation_digest,
        &s.receipt.review_digest,
        &s.receipt.prompt_digest,
        &s.receipt.source_digest,
        &s.receipt.verifier_digest,
        &s.receipt.environment_digest,
        &s.definition_digest,
        &s.version_record_digest,
    ] {
        require(
            d.strip_prefix("blake3:").is_some_and(|h| {
                h.len() == 64
                    && h.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            }),
            "invalid release evidence digest",
        )?;
    }
    Ok(())
}
