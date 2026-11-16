//! Vault-only exact-retry intent for root-authorized device rebind.
//!
//! The record is the crash journal for one destructive local transition: the
//! imported root identity is replaced by a freshly generated device identity
//! for the same DID. It therefore holds the exported root PKCS#8 and the new
//! device seeds until the replacement is installed and indexed, and it is
//! deleted only after that local commit.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::internal::identity_wire::device_rebind::DeviceRebindRemoteResult;
use crate::internal::platform_secret::SecretBytes;
use crate::internal::secret_vault::policy::SecretAccessPolicy;
use crate::internal::secret_vault::record::{SecretKind, SecretMetadata, SecretRef};
use crate::internal::secret_vault::{SealSecretRequest, SecretVault};

const SCHEMA_VERSION: u32 = 1;
const KEY_VERSION: u32 = 1;
const MAX_PENDING_REBINDS_PER_IDENTITY: usize = 8;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingDeviceRebind {
    schema_version: u32,
    pub(crate) did: crate::ids::Did,
    pub(crate) local_alias: String,
    pub(crate) unique_id: String,
    pub(crate) operation_id: String,
    pub(crate) expected_document_hash: String,
    pub(crate) root_key_id: String,
    pub(crate) root_pkcs8_b64u: String,
    pub(crate) new_device_id: String,
    pub(crate) new_signing_key_id: String,
    pub(crate) new_e2ee_key_id: String,
    pub(crate) new_signing_seed_b64u: String,
    pub(crate) new_e2ee_seed_b64u: String,
    pub(crate) new_document: Value,
    pub(crate) replaced_device_ids: Vec<String>,
    pub(crate) remote_result: Option<DeviceRebindRemoteResult>,
    #[serde(default)]
    pub(crate) rejected: bool,
}

impl std::fmt::Debug for PendingDeviceRebind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingDeviceRebind")
            .field("schema_version", &self.schema_version)
            .field("did", &self.did)
            .field("local_alias", &self.local_alias)
            .field("unique_id", &self.unique_id)
            .field("operation_id", &self.operation_id)
            .field("expected_document_hash", &self.expected_document_hash)
            .field("root_key_id", &self.root_key_id)
            .field("new_device_id", &self.new_device_id)
            .field("new_signing_key_id", &self.new_signing_key_id)
            .field("new_e2ee_key_id", &self.new_e2ee_key_id)
            .field("new_document", &"<redacted-root-signed-document>")
            .field("replaced_device_ids", &self.replaced_device_ids)
            .field("has_remote_result", &self.remote_result.is_some())
            .field("rejected", &self.rejected)
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
impl PendingDeviceRebind {
    pub(crate) fn new(
        did: crate::ids::Did,
        local_alias: String,
        unique_id: String,
        operation_id: String,
        expected_document_hash: String,
        root_key_id: String,
        root_pkcs8: &[u8],
        new_device_id: String,
        new_signing_key_id: String,
        new_e2ee_key_id: String,
        new_signing_seed: &[u8; 32],
        new_e2ee_seed: &[u8; 32],
        new_document: Value,
        replaced_device_ids: Vec<String>,
    ) -> crate::ImResult<Self> {
        let record = Self {
            schema_version: SCHEMA_VERSION,
            did,
            local_alias,
            unique_id,
            operation_id,
            expected_document_hash,
            root_key_id,
            root_pkcs8_b64u: URL_SAFE_NO_PAD.encode(root_pkcs8),
            new_device_id,
            new_signing_key_id,
            new_e2ee_key_id,
            new_signing_seed_b64u: URL_SAFE_NO_PAD.encode(new_signing_seed),
            new_e2ee_seed_b64u: URL_SAFE_NO_PAD.encode(new_e2ee_seed),
            new_document,
            replaced_device_ids,
            remote_result: None,
            rejected: false,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn root_pkcs8(&self) -> crate::ImResult<Zeroizing<Vec<u8>>> {
        decode_secret(&self.root_pkcs8_b64u)
    }

    pub(crate) fn new_signing_seed(&self) -> crate::ImResult<Zeroizing<Vec<u8>>> {
        decode_secret(&self.new_signing_seed_b64u)
    }

    pub(crate) fn new_e2ee_seed(&self) -> crate::ImResult<Zeroizing<Vec<u8>>> {
        decode_secret(&self.new_e2ee_seed_b64u)
    }

    pub(crate) fn validate(&self) -> crate::ImResult<()> {
        if (self.rejected && self.remote_result.is_some())
            || self.schema_version != SCHEMA_VERSION
            || self.local_alias.trim().is_empty()
            || self.unique_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || !self.expected_document_hash.starts_with("sha256:")
            || self.expected_document_hash.len() != 50
            || !self.root_key_id.starts_with(&format!("{}#", self.did.as_str()))
            || self
                .new_document
                .get("id")
                .and_then(Value::as_str)
                != Some(self.did.as_str())
            || self.new_document.pointer("/proof/verificationMethod").and_then(Value::as_str)
                != Some(self.root_key_id.as_str())
            || !crate::internal::identity_wire::document::validate_control_document_method(
                &self.new_document,
            )
        {
            return Err(crate::ImError::PermissionDenied);
        }
        crate::ids::ProtocolDeviceId::parse(&self.new_device_id)?;
        if self.root_pkcs8().map(|value| value.is_empty()).unwrap_or(true)
            || self.new_signing_seed().map(|value| value.len()).unwrap_or(0) != 32
            || self.new_e2ee_seed().map(|value| value.len()).unwrap_or(0) != 32
        {
            return Err(crate::ImError::PermissionDenied);
        }
        if !self
            .new_signing_key_id
            .starts_with(&format!("{}#", self.did.as_str()))
            || !self
                .new_e2ee_key_id
                .starts_with(&format!("{}#", self.did.as_str()))
        {
            return Err(crate::ImError::PermissionDenied);
        }
        let manifest = anp::authentication::validate_device_manifest(&self.new_document)
            .map_err(|_| crate::ImError::PermissionDenied)?
            .ok_or(crate::ImError::PermissionDenied)?;
        if manifest.devices.len() != 1 {
            return Err(crate::ImError::PermissionDenied);
        }
        let device = &manifest.devices[0];
        if device.device_id != self.new_device_id
            || device.signing_key_id != self.new_signing_key_id
            || device.e2ee_key_id != self.new_e2ee_key_id
        {
            return Err(crate::ImError::PermissionDenied);
        }
        if !is_strictly_sorted(&self.replaced_device_ids)
            || self.replaced_device_ids.contains(&self.new_device_id)
        {
            return Err(crate::ImError::PermissionDenied);
        }
        for replaced in &self.replaced_device_ids {
            crate::ids::ProtocolDeviceId::parse(replaced)?;
        }
        if let Some(result) = self.remote_result.as_ref() {
            if result.did != self.did.as_str()
                || result.device_id != self.new_device_id
                || result.signing_key_id != self.new_signing_key_id
                || result.replaced_device_ids != self.replaced_device_ids
                || result.registry_version != result.auth_generation
                || result.document_version == 0
                || crate::internal::identity_wire::device_rebind::canonical_digest(
                    &result.document,
                )? != crate::internal::identity_wire::device_rebind::canonical_digest(
                    &self.new_document,
                )?
            {
                return Err(crate::ImError::PermissionDenied);
            }
        }
        Ok(())
    }
}

fn decode_secret(value: &str) -> crate::ImResult<Zeroizing<Vec<u8>>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map(Zeroizing::new)
        .map_err(|_| crate::ImError::PermissionDenied)
}

fn is_strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(crate) struct PendingDeviceRebindStore {
    workspace_id: String,
    vault_context_device_id: String,
    vault: std::sync::Arc<dyn SecretVault + Send + Sync>,
}

impl std::fmt::Debug for PendingDeviceRebindStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingDeviceRebindStore")
            .field("workspace_id", &self.workspace_id)
            .field("vault_context_device_id", &self.vault_context_device_id)
            .field("vault", &"<redacted-secret-vault>")
            .finish()
    }
}

impl PendingDeviceRebindStore {
    pub(crate) fn from_core(core: &crate::core::ImCore) -> crate::ImResult<Self> {
        if core.inner().identity_secret_storage_policy()
            != crate::core::IdentitySecretStoragePolicy::VaultRequired
        {
            return Err(crate::ImError::LocalStateUnavailable {
                detail: "device rebind requires IdentitySecretStoragePolicy::VaultRequired"
                    .to_owned(),
            });
        }
        let context =
            core.inner()
                .identity_vault()
                .ok_or_else(|| crate::ImError::LocalStateUnavailable {
                    detail: "device rebind requires an available identity secret vault".to_owned(),
                })?;
        Ok(Self {
            workspace_id: context.workspace_id().to_owned(),
            vault_context_device_id: context.vault_context_device_id().as_str().to_owned(),
            vault: context.vault(),
        })
    }

    pub(crate) fn load(
        &self,
        did: &crate::ids::Did,
    ) -> crate::ImResult<Option<(SecretRef, PendingDeviceRebind)>> {
        let key_id = pending_key_id(did);
        let mut matches = self.vault.list()?.into_iter().filter(|secret_ref| {
            secret_ref.workspace_id == self.workspace_id
                && secret_ref.device_id == self.vault_context_device_id
                && secret_ref.kind == SecretKind::IdentityDeviceRebindPending
                && secret_ref.key_id == key_id
                && secret_ref.did.as_deref() == Some(did.as_str())
        });
        let found = matches.next();
        if matches.next().is_some() {
            return Err(crate::ImError::PermissionDenied);
        }
        found
            .map(|secret_ref| {
                let plaintext = self.vault.open(&secret_ref)?;
                let record: PendingDeviceRebind = serde_json::from_slice(plaintext.expose_secret())
                    .map_err(|_| crate::ImError::PermissionDenied)?;
                record.validate()?;
                if record.did != *did {
                    return Err(crate::ImError::PermissionDenied);
                }
                Ok((secret_ref, record))
            })
            .transpose()
    }

    pub(crate) fn save(&self, record: &PendingDeviceRebind) -> crate::ImResult<SecretRef> {
        record.validate()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(record).map_err(|error| {
            crate::ImError::Serialization {
                detail: error.to_string(),
            }
        })?);
        let secret_ref = self.vault.seal(SealSecretRequest {
            metadata: SecretMetadata {
                workspace_id: self.workspace_id.clone(),
                device_id: self.vault_context_device_id.clone(),
                identity_id: Some(identity_suffix(&record.did)),
                did: Some(record.did.as_str().to_owned()),
                kind: SecretKind::IdentityDeviceRebindPending,
                key_id: pending_key_id(&record.did),
                key_version: KEY_VERSION,
                policy: SecretAccessPolicy::no_prompt_local_secret(),
            },
            plaintext: SecretBytes::from_vec(plaintext.as_slice().to_vec()),
        })?;
        if self.vault.open(&secret_ref)?.expose_secret() != plaintext.as_slice() {
            return Err(crate::ImError::PermissionDenied);
        }
        Ok(secret_ref)
    }

    pub(crate) fn list_for_identity(
        &self,
        did: &crate::ids::Did,
    ) -> crate::ImResult<Vec<(SecretRef, PendingDeviceRebind)>> {
        let mut references = self
            .vault
            .list()?
            .into_iter()
            .filter(|secret_ref| {
                secret_ref.workspace_id == self.workspace_id
                    && secret_ref.device_id == self.vault_context_device_id
                    && secret_ref.kind == SecretKind::IdentityDeviceRebindPending
                    && secret_ref.did.as_deref() == Some(did.as_str())
            })
            .collect::<Vec<_>>();
        references.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        if references.len() > MAX_PENDING_REBINDS_PER_IDENTITY {
            return Err(crate::ImError::LocalStateUnavailable {
                detail: "too many pending device rebind records".to_owned(),
            });
        }
        let mut records = Vec::with_capacity(references.len());
        for secret_ref in references {
            let plaintext = self.vault.open(&secret_ref)?;
            let record: PendingDeviceRebind = serde_json::from_slice(plaintext.expose_secret())
                .map_err(|_| crate::ImError::PermissionDenied)?;
            record.validate()?;
            if record.did != *did {
                return Err(crate::ImError::PermissionDenied);
            }
            records.push((secret_ref, record));
        }
        Ok(records)
    }

    pub(crate) fn delete(&self, secret_ref: &SecretRef) -> crate::ImResult<()> {
        if secret_ref.workspace_id != self.workspace_id
            || secret_ref.device_id != self.vault_context_device_id
            || secret_ref.kind != SecretKind::IdentityDeviceRebindPending
        {
            return Err(crate::ImError::PermissionDenied);
        }
        self.vault.delete(secret_ref)
    }
}

fn pending_key_id(did: &crate::ids::Did) -> String {
    format!(
        "device-rebind-{}",
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(did.as_str().as_bytes()))
    )
}

fn identity_suffix(did: &crate::ids::Did) -> String {
    did.as_str()
        .rsplit(':')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(did.as_str())
        .to_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_does_not_render_document_or_secrets() {
        let source = include_str!("identity_device_rebind_pending.rs");
        let forbidden_root = ["root", "_private", "_key"].concat();
        let forbidden_seed = ["signing", "_private", "_pem"].concat();
        assert!(!source.contains(&forbidden_root));
        assert!(!source.contains(&forbidden_seed));
        assert!(source.contains("<redacted-root-signed-document>"));
    }
}
