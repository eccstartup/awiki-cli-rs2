//! Strict AWiki-local wire contract for root-authorized device rebind.
//!
//! The replacement DID Document and its DataIntegrityProof are first-party
//! control-plane fields. This module does not define or extend ANP wire
//! schemas.

use anp::proof::{CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Signer as _;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

pub(crate) const DEVICE_REBIND_METHOD: &str = "device_rebind";
pub(crate) const DEVICE_REBIND_PURPOSE: &str = "awiki.identity.device-rebind.v1";

const PROOF_PURPOSE_ASSERTION_METHOD: &str = "assertionMethod";

#[derive(Clone, PartialEq)]
pub(crate) struct PreparedDeviceRebind {
    pub(crate) did: String,
    pub(crate) operation_id: String,
    pub(crate) expected_document_hash: String,
    pub(crate) expected_document_version: Option<u64>,
    pub(crate) expected_registry_version: Option<u64>,
    pub(crate) new_document: Value,
    pub(crate) new_device_id: String,
    pub(crate) new_signing_key_id: String,
    pub(crate) new_e2ee_key_id: String,
    pub(crate) replaced_device_ids: Vec<String>,
    pub(crate) new_device_object_proof: Value,
}

impl std::fmt::Debug for PreparedDeviceRebind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedDeviceRebind")
            .field("did", &self.did)
            .field("operation_id", &self.operation_id)
            .field("expected_document_hash", &self.expected_document_hash)
            .field("expected_document_version", &self.expected_document_version)
            .field("expected_registry_version", &self.expected_registry_version)
            .field("new_document", &"<redacted-root-signed-document>")
            .field("new_device_id", &self.new_device_id)
            .field("new_signing_key_id", &self.new_signing_key_id)
            .field("new_e2ee_key_id", &self.new_e2ee_key_id)
            .field("replaced_device_ids", &self.replaced_device_ids)
            .field(
                "new_device_object_proof",
                &"<redacted-device-possession-proof>",
            )
            .finish()
    }
}

pub(crate) struct DeviceRebindWireCall {
    pub(crate) endpoint: &'static str,
    pub(crate) method: &'static str,
    pub(crate) params: Value,
}

impl std::fmt::Debug for DeviceRebindWireCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRebindWireCall")
            .field("endpoint", &self.endpoint)
            .field("method", &self.method)
            .field("params", &"<redacted-root-signed-control-request>")
            .finish()
    }
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceRebindRemoteResult {
    pub(crate) did: String,
    pub(crate) document: Value,
    pub(crate) document_version: u64,
    pub(crate) registry_version: u64,
    pub(crate) auth_generation: u64,
    pub(crate) device_id: String,
    pub(crate) signing_key_id: String,
    pub(crate) replaced_device_ids: Vec<String>,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) replayed: bool,
}

impl std::fmt::Debug for DeviceRebindRemoteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRebindRemoteResult")
            .field("did", &self.did)
            .field("document", &"<redacted-root-signed-document>")
            .field("document_version", &self.document_version)
            .field("registry_version", &self.registry_version)
            .field("auth_generation", &self.auth_generation)
            .field("device_id", &self.device_id)
            .field("signing_key_id", &self.signing_key_id)
            .field("replaced_device_ids", &self.replaced_device_ids)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("replayed", &self.replayed)
            .finish()
    }
}

/// `sha256:<base64url-no-pad>` over the JCS canonical form of `value`.
pub(crate) fn canonical_digest(value: &Value) -> crate::ImResult<String> {
    let canonical = serde_json_canonicalizer::to_vec(value).map_err(|error| {
        crate::ImError::Serialization {
            detail: format!("canonicalize DID document value: {error}"),
        }
    })?;
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
    ))
}

/// Sign a `DataIntegrityProof` over an unsigned DID Document with the root key.
///
/// `proofValue` is base58-btc multibase, which is what the AWiki User Service
/// requires. The ANP SDK signer emits base64url instead, so the proof object is
/// built here and only the signing input comes from the shared canonical form.
pub(crate) fn sign_document_proof(
    unsigned_document: &Value,
    root_signing_key: &ed25519_dalek::SigningKey,
    root_key_id: &str,
    created: &str,
) -> crate::ImResult<Value> {
    let document = unsigned_document
        .as_object()
        .ok_or_else(|| crate::ImError::Serialization {
            detail: "replacement DID document must be an object".to_owned(),
        })?;
    if document.contains_key("proof") {
        return Err(crate::ImError::Serialization {
            detail: "replacement DID document is already signed".to_owned(),
        });
    }
    let proof_options = proof_options(root_key_id, created);
    let signature = root_signing_key.sign(&signing_input(&proof_options, unsigned_document)?);
    let mut proof = proof_options;
    proof.insert(
        "proofValue".to_owned(),
        Value::String(format!("z{}", bs58::encode(signature.to_bytes()).into_string())),
    );
    let mut signed = unsigned_document.clone();
    signed
        .as_object_mut()
        .ok_or_else(|| crate::ImError::Serialization {
            detail: "replacement DID document must be an object".to_owned(),
        })?
        .insert("proof".to_owned(), Value::Object(proof));
    Ok(signed)
}

/// Build the new device's possession proof for `awiki.identity.device-rebind.v1`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_possession_proof(
    did: &str,
    operation_id: &str,
    new_document: &Value,
    device_id: &str,
    signing_key_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    created: &str,
) -> crate::ImResult<Value> {
    let intent = json!({
        "purpose": DEVICE_REBIND_PURPOSE,
        "did": did,
        "operationId": operation_id,
        "documentHash": canonical_digest(new_document)?,
        "deviceId": device_id,
        "signingKeyId": signing_key_id,
    });
    let proof_options = proof_options(signing_key_id, created);
    let signature = signing_key.sign(&signing_input(&proof_options, &intent)?);
    let mut proof = proof_options;
    proof.insert(
        "proofValue".to_owned(),
        Value::String(format!("z{}", bs58::encode(signature.to_bytes()).into_string())),
    );
    Ok(Value::Object(proof))
}

pub(crate) fn build_rebind_call(
    prepared: &PreparedDeviceRebind,
) -> crate::ImResult<DeviceRebindWireCall> {
    let mut params = Map::new();
    params.insert("did".to_owned(), Value::String(prepared.did.clone()));
    params.insert(
        "operation_id".to_owned(),
        Value::String(prepared.operation_id.clone()),
    );
    params.insert(
        "expected_document_hash".to_owned(),
        Value::String(prepared.expected_document_hash.clone()),
    );
    if let Some(version) = prepared.expected_document_version {
        params.insert("expected_document_version".to_owned(), json!(version));
    }
    if let Some(version) = prepared.expected_registry_version {
        params.insert("expected_registry_version".to_owned(), json!(version));
    }
    params.insert(
        "new_document".to_owned(),
        prepared.new_document.clone(),
    );
    params.insert(
        "new_device".to_owned(),
        json!({
            "device_id": prepared.new_device_id,
            "signing_key_id": prepared.new_signing_key_id,
            "e2ee_key_id": prepared.new_e2ee_key_id,
        }),
    );
    params.insert(
        "replaced_device_ids".to_owned(),
        json!(prepared.replaced_device_ids),
    );
    params.insert(
        "new_device_object_proof".to_owned(),
        prepared.new_device_object_proof.clone(),
    );
    Ok(DeviceRebindWireCall {
        endpoint: super::DID_AUTH_RPC_ENDPOINT,
        method: DEVICE_REBIND_METHOD,
        params: Value::Object(params),
    })
}

pub(crate) fn parse_rebind_result(
    raw: Value,
    expected_did: &str,
    expected_device_id: &str,
) -> crate::ImResult<DeviceRebindRemoteResult> {
    let raw: RawRebindResult = serde_json::from_value(raw).map_err(|_| invalid_wire())?;
    if raw.did != expected_did
        || raw.device_id != expected_device_id
        || raw.did_document != raw.document
        || raw.document.get("id").and_then(Value::as_str) != Some(expected_did)
        || raw.token != raw.access_token
        || raw.token_type != "Bearer"
        || raw.access_token.trim().is_empty()
        || raw.refresh_token.trim().is_empty()
        || raw.document_version == 0
        || raw.auth_generation == 0
        || raw.registry_version != raw.auth_generation
    {
        return Err(invalid_wire());
    }
    Ok(DeviceRebindRemoteResult {
        did: raw.did,
        document: raw.document,
        document_version: raw.document_version,
        registry_version: raw.registry_version,
        auth_generation: raw.auth_generation,
        device_id: raw.device_id,
        signing_key_id: raw.signing_key_id,
        replaced_device_ids: raw.replaced_device_ids,
        access_token: raw.access_token,
        refresh_token: raw.refresh_token,
        replayed: raw.replayed,
    })
}

fn proof_options(verification_method: &str, created: &str) -> Map<String, Value> {
    let mut proof = Map::new();
    proof.insert(
        "type".to_owned(),
        Value::String(PROOF_TYPE_DATA_INTEGRITY.to_owned()),
    );
    proof.insert("created".to_owned(), Value::String(created.to_owned()));
    proof.insert(
        "verificationMethod".to_owned(),
        Value::String(verification_method.to_owned()),
    );
    proof.insert(
        "proofPurpose".to_owned(),
        Value::String(PROOF_PURPOSE_ASSERTION_METHOD.to_owned()),
    );
    proof.insert(
        "cryptosuite".to_owned(),
        Value::String(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
    );
    proof
}

/// `sha256(JCS(proof options)) ++ sha256(JCS(unsigned document))`.
fn signing_input(
    proof_options: &Map<String, Value>,
    unsigned_document: &Value,
) -> crate::ImResult<Vec<u8>> {
    let proof_canonical = serde_json_canonicalizer::to_vec(&Value::Object(proof_options.clone()))
        .map_err(|error| crate::ImError::Serialization {
            detail: format!("canonicalize proof options: {error}"),
        })?;
    let document_canonical = serde_json_canonicalizer::to_vec(unsigned_document).map_err(|error| {
        crate::ImError::Serialization {
            detail: format!("canonicalize proof document: {error}"),
        }
    })?;
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&Sha256::digest(proof_canonical));
    input.extend_from_slice(&Sha256::digest(document_canonical));
    Ok(input)
}

fn invalid_wire() -> crate::ImError {
    crate::ImError::Serialization {
        detail: "device rebind response was invalid".to_owned(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRebindResult {
    did: String,
    document: Value,
    did_document: Value,
    document_version: u64,
    registry_version: u64,
    auth_generation: u64,
    device_id: String,
    signing_key_id: String,
    replaced_device_ids: Vec<String>,
    #[allow(dead_code)]
    token: String,
    access_token: String,
    refresh_token: String,
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
    #[allow(dead_code)]
    expires_at: String,
    #[allow(dead_code)]
    refresh_expires_at: String,
    replayed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn multikey(key: &SigningKey) -> String {
        let mut encoded = vec![0xed, 0x01];
        encoded.extend_from_slice(key.verifying_key().as_bytes());
        format!("z{}", bs58::encode(encoded).into_string())
    }

    fn test_document(did: &str, root: &SigningKey, device: &SigningKey) -> Value {
        json!({
            "id": did,
            "alsoKnownAs": ["alice@awiki.test"],
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multikey(root),
            }, {
                "id": format!("{did}#dev-new-sign"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multikey(device),
            }],
            "authentication": [format!("{did}#key-1"), format!("{did}#dev-new-sign")],
            "assertionMethod": [format!("{did}#key-1"), format!("{did}#dev-new-sign")],
            "service": [{
                "id": format!("{did}#anp-message"),
                "type": "ANPMessageService",
                "serviceEndpoint": "https://awiki.test/anp-im/rpc",
            }],
            "deviceManifest": {
                "devices": [{
                    "device_id": "dev-new",
                    "signing_key_id": format!("{did}#dev-new-sign"),
                    "e2ee_key_id": format!("{did}#dev-new-e2ee"),
                    "profiles": ["core-binding.v1"],
                }]
            }
        })
    }

    #[test]
    fn document_proof_is_base58_and_verifies_with_sdk_profile() {
        let did = "did:wba:awiki.test:user:alice:e1_test";
        let root = test_key(7);
        let device = test_key(9);
        let unsigned = test_document(did, &root, &device);
        let signed = sign_document_proof(
            &unsigned,
            &root,
            &format!("{did}#key-1"),
            "2026-11-15T00:00:00Z",
        )
        .unwrap();
        let proof_value = signed["proof"]["proofValue"].as_str().unwrap();
        assert!(proof_value.starts_with('z'));
        let signature: [u8; 64] = bs58::decode(&proof_value[1..])
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(signature.len(), 64);
        let mut proof = signed["proof"].as_object().unwrap().clone();
        proof.remove("proofValue");
        let input = signing_input(&proof, &unsigned).unwrap();
        assert!(root
            .verifying_key()
            .verify_strict(&input, &ed25519_dalek::Signature::from_bytes(&signature))
            .is_ok());
        // The document carries no `@context`, so the SDK's base58 verification
        // path hashes exactly this input.
        assert!(anp::proof::verify_w3c_proof(
            &signed,
            &anp::PublicKeyMaterial::Ed25519(root.verifying_key()),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some(PROOF_PURPOSE_ASSERTION_METHOD.to_owned()),
                ..Default::default()
            },
        ));
    }

    #[test]
    fn possession_proof_binds_operation_and_document_hash() {
        let did = "did:wba:awiki.test:user:alice:e1_test";
        let root = test_key(7);
        let device = test_key(9);
        let document = sign_document_proof(
            &test_document(did, &root, &device),
            &root,
            &format!("{did}#key-1"),
            "2026-11-15T00:00:00Z",
        )
        .unwrap();
        let proof = build_possession_proof(
            did,
            "rebind-op",
            &document,
            "dev-new",
            &format!("{did}#dev-new-sign"),
            &device,
            "2026-11-15T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            proof["verificationMethod"],
            format!("{did}#dev-new-sign")
        );
        let intent = json!({
            "purpose": DEVICE_REBIND_PURPOSE,
            "did": did,
            "operationId": "rebind-op",
            "documentHash": canonical_digest(&document).unwrap(),
            "deviceId": "dev-new",
            "signingKeyId": format!("{did}#dev-new-sign"),
        });
        let mut options = proof.as_object().unwrap().clone();
        options.remove("proofValue");
        let signature: [u8; 64] =
            bs58::decode(&proof["proofValue"].as_str().unwrap()[1..])
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap();
        assert!(device
            .verifying_key()
            .verify_strict(
                &signing_input(&options, &intent).unwrap(),
                &ed25519_dalek::Signature::from_bytes(&signature)
            )
            .is_ok());
    }

    #[test]
    fn call_debug_redacts_document_and_proof() {
        let prepared = PreparedDeviceRebind {
            did: "did:wba:awiki.test:user:alice:e1_test".to_owned(),
            operation_id: "rebind-op".to_owned(),
            expected_document_hash: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_owned(),
            expected_document_version: Some(3),
            expected_registry_version: Some(2),
            new_document: json!({"proof": {"proofValue": "root-proof-secret-shape"}}),
            new_device_id: "dev-new".to_owned(),
            new_signing_key_id: "did:wba:awiki.test:user:alice:e1_test#dev-new-sign".to_owned(),
            new_e2ee_key_id: "did:wba:awiki.test:user:alice:e1_test#dev-new-e2ee".to_owned(),
            replaced_device_ids: vec!["dev-old".to_owned()],
            new_device_object_proof: json!({"proofValue": "possession-proof-secret-shape"}),
        };
        let call = build_rebind_call(&prepared).unwrap();
        let debug = format!("{call:?} {prepared:?}");
        assert!(!debug.contains("root-proof-secret-shape"));
        assert!(!debug.contains("possession-proof-secret-shape"));
    }

    #[test]
    fn request_matches_awiki_rebind_contract_without_cross_domain_fields() {
        let prepared = PreparedDeviceRebind {
            did: "did:wba:awiki.test:user:alice:e1_test".to_owned(),
            operation_id: "rebind-op".to_owned(),
            expected_document_hash: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_owned(),
            expected_document_version: None,
            expected_registry_version: None,
            new_document: json!({"id": "did:wba:awiki.test:user:alice:e1_test", "proof": {"proofValue": "zroot"}}),
            new_device_id: "dev-new".to_owned(),
            new_signing_key_id: "did:wba:awiki.test:user:alice:e1_test#dev-new-sign".to_owned(),
            new_e2ee_key_id: "did:wba:awiki.test:user:alice:e1_test#dev-new-e2ee".to_owned(),
            replaced_device_ids: vec!["dev-old".to_owned()],
            new_device_object_proof: json!({"proofValue": "zpossession"}),
        };
        let call = build_rebind_call(&prepared).unwrap();
        assert_eq!(call.endpoint, super::super::DID_AUTH_RPC_ENDPOINT);
        assert_eq!(call.method, DEVICE_REBIND_METHOD);
        let keys = call
            .params
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "did",
                "expected_document_hash",
                "new_device",
                "new_device_object_proof",
                "new_document",
                "operation_id",
                "replaced_device_ids",
            ]
        );
        assert_eq!(
            call.params["new_device"],
            json!({
                "device_id": "dev-new",
                "signing_key_id": "did:wba:awiki.test:user:alice:e1_test#dev-new-sign",
                "e2ee_key_id": "did:wba:awiki.test:user:alice:e1_test#dev-new-e2ee",
            })
        );
        for forbidden in ["handle", "otp_code", "otp_session_id", "proof", "root_private_key"] {
            assert!(!call.params.as_object().unwrap().contains_key(forbidden));
        }
        let mut with_versions = prepared;
        with_versions.expected_document_version = Some(4);
        with_versions.expected_registry_version = Some(3);
        let call = build_rebind_call(&with_versions).unwrap();
        assert_eq!(call.params["expected_document_version"], json!(4));
        assert_eq!(call.params["expected_registry_version"], json!(3));
    }

    #[test]
    fn response_is_closed_and_exact() {
        let did = "did:wba:awiki.test:user:alice:e1_test";
        let value = json!({
            "did": did,
            "document": {"id": did},
            "did_document": {"id": did},
            "document_version": 2,
            "registry_version": 2,
            "auth_generation": 2,
            "device_id": "dev-new",
            "signing_key_id": format!("{did}#dev-new-sign"),
            "replaced_device_ids": ["dev-old"],
            "token": "token-value",
            "access_token": "token-value",
            "refresh_token": "refresh-value",
            "token_type": "Bearer",
            "expires_in": 900,
            "expires_at": "2026-11-15T00:15:00Z",
            "refresh_expires_at": "2026-12-15T00:00:00Z",
            "replayed": false,
        });
        let parsed = parse_rebind_result(value.clone(), did, "dev-new").unwrap();
        assert_eq!(parsed.document_version, 2);
        assert!(!format!("{parsed:?}").contains("token-value"));
        let mut wrong_did = value.clone();
        wrong_did["did"] = json!("did:wba:awiki.test:user:mallory:e1_test");
        assert!(parse_rebind_result(wrong_did, did, "dev-new").is_err());
        let mut cross_document = value.clone();
        cross_document["did_document"] = json!({"id": "did:wba:awiki.test:user:mallory:e1_test"});
        assert!(parse_rebind_result(cross_document, did, "dev-new").is_err());
        let mut extra = value;
        extra["root_private_key"] = json!("forbidden");
        assert!(parse_rebind_result(extra, did, "dev-new").is_err());
    }
}
