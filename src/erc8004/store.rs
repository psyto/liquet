//! Evidence store — pin a signed-decision bundle at a stable, content-addressed
//! `responseURI` (ERC-8004 `validationResponse`'s off-chain evidence pointer).
//!
//! The URI is content-addressed by the `responseHash` (the
//! [`crate::attest::DecisionBinding::digest`]). That makes the pointer itself
//! tamper-evident: a relying party fetches the URI, recomputes the bundle digest,
//! and it must reproduce the hash embedded in the URI *and* the on-chain
//! `responseHash`. See [`crate::erc8004::verify_bundle`] for the check.
//!
//! Std-only (no IPFS/network deps). [`MemStore`] backs tests and the offline
//! demo; [`FileStore`] writes real files a local gateway can serve. The IPFS /
//! HTTP-gateway backend is a drop-in `EvidenceStore` impl behind `wire-erc8004`.

use super::evidence_bundle_json;
use crate::attest::SignedDecision;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A content-addressed location for an evidence bundle. The trailing hash equals
/// the `responseHash`, so the URI cannot silently point at different evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseUri(pub String);

impl ResponseUri {
    /// The `responseHash` embedded in the URI (`.../{hash}.json` or
    /// `mem://{hash}`), if present.
    pub fn embedded_hash(&self) -> Option<&str> {
        let tail = self.0.rsplit('/').next().unwrap_or(&self.0);
        Some(tail.strip_suffix(".json").unwrap_or(tail))
    }
}

/// Store and retrieve evidence bundles by their `responseHash`.
pub trait EvidenceStore {
    /// Pin the bundle for `signed`; return its `responseURI`. The hash embedded
    /// in the returned URI MUST equal `signed.binding.digest()` hex.
    fn put(&mut self, signed: &SignedDecision) -> std::io::Result<ResponseUri>;
    /// Fetch the raw bundle previously stored at `uri`.
    fn get(&self, uri: &ResponseUri) -> std::io::Result<String>;
}

/// The `responseHash` hex for a signed decision — the content address.
fn content_hash(signed: &SignedDecision) -> String {
    hex::encode(signed.binding.digest())
}

/// In-memory store — the default for tests and the offline demo.
#[derive(Default)]
pub struct MemStore {
    by_uri: HashMap<String, String>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of distinct bundles pinned (content-addressed, so re-`put`ting the
    /// same decision does not grow this).
    pub fn len(&self) -> usize {
        self.by_uri.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_uri.is_empty()
    }
}

impl EvidenceStore for MemStore {
    fn put(&mut self, signed: &SignedDecision) -> std::io::Result<ResponseUri> {
        let uri = format!("mem://{}", content_hash(signed));
        self.by_uri.insert(uri.clone(), evidence_bundle_json(signed));
        Ok(ResponseUri(uri))
    }
    fn get(&self, uri: &ResponseUri) -> std::io::Result<String> {
        self.by_uri.get(&uri.0).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("no bundle at {}", uri.0))
        })
    }
}

/// File-backed store — writes `{root}/{responseHash}.json`, which a local static
/// gateway (or IPFS add) can serve. `get` reads back through a `file://` URI.
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// A store rooted at `root` (created lazily on first `put`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    /// A store under the OS temp dir — for the demo / manual inspection.
    pub fn temp() -> Self {
        Self::new(std::env::temp_dir().join("liquet-erc8004-evidence"))
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.root.join(format!("{hash}.json"))
    }

    fn uri_for(path: &Path) -> ResponseUri {
        ResponseUri(format!("file://{}", path.display()))
    }
}

impl EvidenceStore for FileStore {
    fn put(&mut self, signed: &SignedDecision) -> std::io::Result<ResponseUri> {
        std::fs::create_dir_all(&self.root)?;
        let path = self.path_for(&content_hash(signed));
        std::fs::write(&path, evidence_bundle_json(signed))?;
        Ok(Self::uri_for(&path))
    }
    fn get(&self, uri: &ResponseUri) -> std::io::Result<String> {
        let path = uri.0.strip_prefix("file://").unwrap_or(&uri.0);
        std::fs::read_to_string(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{sign_decision, DecisionBinding};
    use crate::decide::{GatePolicy, LiquetDecision};
    use crate::erc8004::{verify_bundle, ValidationResponse, PASS, TAG_MATCHED};
    use crate::seam::{CrossVmProof, FactsSource, InvariantVerdict, ReconcileVerdict, ReexecProof, Vm};
    use ed25519_dalek::SigningKey;

    fn matched_signed() -> SignedDecision {
        let leg = |vm, d: &str| ReexecProof {
            vm,
            executed: true,
            poststate_digest: d.into(),
            covered_accounts: vec![],
            facts_source: FactsSource::ProducerRecovered,
            asset: None,
            amount: None,
            recipient: None,
            unverifiable_reason: None,
        };
        let proof = CrossVmProof {
            reconcile: ReconcileVerdict::Matched,
            reasons: vec![],
            legs: vec![leg(Vm::Evm, "evm-dig"), leg(Vm::Svm, "svm-dig")],
            claim_hash: "claim-abc".into(),
            settlement_id: "settlement-1".into(),
        };
        let binding = DecisionBinding::new(
            &proof,
            &InvariantVerdict::green(),
            &GatePolicy::default(),
            &LiquetDecision::Settle { caveats: vec![] },
        );
        sign_decision(binding, &SigningKey::from_bytes(&[7u8; 32]))
    }

    /// The property that makes the pointer trustworthy: store → fetch → verify,
    /// with the URI itself carrying the responseHash.
    fn assert_store_fetch_verify(store: &mut impl EvidenceStore) {
        let signed = matched_signed();
        let onchain_hash = hex::encode(signed.binding.digest());
        let signer = signed.signer.clone();

        let uri = store.put(&signed).expect("put");
        // URI is content-addressed by the responseHash.
        assert_eq!(uri.embedded_hash(), Some(onchain_hash.as_str()));

        let bundle = store.get(&uri).expect("get");
        // The fetched bundle verifies against the on-chain hash + trusted signer.
        let vr: ValidationResponse =
            verify_bundle(&bundle, &onchain_hash, &signer).expect("bundle verifies");
        assert_eq!(vr.response, Some(PASS));
        assert_eq!(vr.tag, TAG_MATCHED);
    }

    #[test]
    fn mem_store_closes_the_loop() {
        assert_store_fetch_verify(&mut MemStore::new());
    }

    #[test]
    fn file_store_closes_the_loop() {
        let mut store = FileStore::new(std::env::temp_dir().join("liquet-erc8004-test-loop"));
        assert_store_fetch_verify(&mut store);
    }

    #[test]
    fn mem_store_put_is_idempotent_content_addressed() {
        let mut store = MemStore::new();
        let s = matched_signed();
        store.put(&s).unwrap();
        store.put(&s).unwrap();
        assert_eq!(store.len(), 1, "same decision → same address, no duplicate");
    }

    #[test]
    fn get_missing_uri_errors() {
        let store = MemStore::new();
        let err = store.get(&ResponseUri("mem://deadbeef".into())).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
