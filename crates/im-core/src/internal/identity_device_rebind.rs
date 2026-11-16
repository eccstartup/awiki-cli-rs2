//! Root-authorized device rebind orchestration.
//!
//! An imported root-only backup carries the RootControl key of an already
//! published DID but no device keys and no server device record. This module
//! replaces that placeholder with a freshly generated device for the same DID:
//! it root-signs the replacement DID Document, invokes the root-authenticated
//! `device_rebind` RPC, and only after a validated remote result installs the
//! new device keys and the Index projection.
//!
//! The DID, Handle, root key and account never change. Every network step is
//! preceded by a Vault-sealed exact-retry record that also carries the root
//! material, so a crash between the remote commit and the local projection can
//! resume even though the imported root-only identity is replaced in the
//! process. That record is deleted only after the projection commit.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore as _;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::internal::access_token::{validate_device_access_token, ExpectedDeviceAccess};
use crate::internal::identity_custody::controller_custody_provider;
use crate::internal::identity_device_rebind_pending::{
    PendingDeviceRebind, PendingDeviceRebindStore,
};
use crate::internal::identity_device_state::{
    DeviceAuthorizationProjection, DeviceAuthorizationRole, DeviceAuthorizationStatus,
    IdentityDeviceMode, IdentityDeviceState, IdentityInternalCheckpoint,
    IDENTITY_DEVICE_STATE_SCHEMA_VERSION,
};
use crate::internal::identity_generation::public_key_multibase;
use crate::internal::identity_legacy_upgrade::{
    append_daemon_method, legacy_base_document, unique_verification_method,
    validated_legacy_daemon_method, VNEXT_DEVICE_PROFILES,
};
use crate::internal::identity_provider::{
    map_provider_error, IdentityCustody, ProviderIdentityMaterialImportRequest,
    ProviderIdentityMaterialKey, ProviderIdentityRef, ProviderIdentityState, ProviderKeyPurpose,
    ProviderKeySelector, ProviderLegacyRootExportRequest, ProviderPrivateKeyEncoding,
    ProviderPublicationEvidence, ProviderPublicIdentity, ProviderVerifiedRemoteDocument,
};
use crate::internal::identity_store::{
    AnpIdentityProjectionReplacement, AnpIdentityProjectionStorage, IdentityStore,
    SaveIdentityInput, SaveIdentityKeyMode,
};
use crate::internal::identity_wire::device_rebind::{
    build_possession_proof, build_rebind_call, canonical_digest, parse_rebind_result,
    sign_document_proof, DeviceRebindRemoteResult, PreparedDeviceRebind,
};
use crate::internal::secret_vault::record::SecretRef;
use crate::internal::transport::CorePlainTransport;

const MAX_REBIND_ATTEMPTS: usize = 2;

struct ImportedRootIdentity {
    did: crate::ids::Did,
    alias: String,
    unique_id: String,
    user_id: String,
    display_name: String,
    handle: String,
    full_handle: String,
    binding_generation: Option<String>,
    store_id: String,
    identity_id: String,
    is_default: bool,
}

struct RootAuthority {
    key_id: String,
    material: anp::PrivateKeyMaterial,
}

fn is_root_only_entry(entry: &crate::internal::identity_store::IndexEntry) -> bool {
    entry.identity_custody_backend.as_deref() == Some("anp_identity")
        && entry.anp_identity_store_id.is_some()
        && entry.anp_identity_id.is_some()
        && entry.device_state.is_none()
}

pub(crate) async fn rebind(
    core: &crate::core::ImCore,
    selector: crate::identity::IdentitySelector,
) -> crate::ImResult<crate::identity::DeviceRebindResult> {
    // Serialize same-process management mutations: one pending record and one
    // remote operation per DID.
    let _guard = core.inner().device_rebind_lock.lock().await;
    // Require the authenticated Vault exact-retry boundary before any Registry,
    // document or rebind network access.
    let pending_store = PendingDeviceRebindStore::from_core(core)?;
    let summary = core.identities().resolve_async(selector).await?;
    let alias = summary
        .local_alias
        .clone()
        .ok_or(crate::ImError::PermissionDenied)?;
    let store = IdentityStore::new(&core.inner().sdk_paths().identities);
    let index = store.load_index()?;
    let entry = index
        .credentials
        .get(&alias)
        .ok_or(crate::ImError::PermissionDenied)?;
    if entry.did != summary.did.as_str() || entry.unique_id.trim().is_empty() {
        return Err(crate::ImError::PermissionDenied);
    }
    let did = crate::ids::Did::parse(&entry.did)?;
    if !did.as_str().starts_with("did:wba:") {
        return Err(crate::ImError::PermissionDenied);
    }
    let active_device = entry
        .device_state
        .as_ref()
        .filter(|state| state.mode == IdentityDeviceMode::VNext)
        .and_then(|state| state.authorization.as_ref())
        .filter(|authorization| {
            authorization.status == DeviceAuthorizationStatus::Active
                && authorization.auth_generation > 0
        })
        .map(|authorization| authorization.protocol_device_id.clone());
    if let Some(device_id) = active_device {
        // Already bound: the only work left is dropping stale retry records.
        if let Ok(records) = pending_store.list_for_identity(&did) {
            for (secret_ref, _) in records {
                let _ = pending_store.delete(&secret_ref);
            }
        }
        return Ok(crate::identity::DeviceRebindResult {
            did,
            device_id,
            already_bound: true,
        });
    }
    if !is_root_only_entry(entry) {
        return Err(crate::ImError::PermissionDenied);
    }
    let identity = ImportedRootIdentity {
        did,
        alias,
        unique_id: entry.unique_id.clone(),
        user_id: entry.user_id.clone(),
        display_name: entry.name.clone(),
        handle: entry.handle.clone(),
        full_handle: entry.full_handle.clone(),
        binding_generation: entry.binding_generation.clone(),
        store_id: entry
            .anp_identity_store_id
            .clone()
            .ok_or(crate::ImError::PermissionDenied)?,
        identity_id: entry
            .anp_identity_id
            .clone()
            .ok_or(crate::ImError::PermissionDenied)?,
        is_default: entry.is_default,
    };
    drop(index);

    let mut current = match pending_store.load(&identity.did)? {
        Some((secret_ref, record))
            if record.local_alias == identity.alias
                && record.unique_id == identity.unique_id =>
        {
            Some((secret_ref, record))
        }
        Some((secret_ref, _)) => {
            pending_store.delete(&secret_ref)?;
            None
        }
        None => None,
    };

    // A remote result that was already committed needs no network: finish the
    // local transition, which also restores custody from the sealed record.
    if let Some((secret_ref, record)) = current.as_ref() {
        if record.remote_result.is_some() {
            return converge(core, &store, &identity, &pending_store, record, secret_ref).await;
        }
    }

    let mut live_document = resolve_live_document(core, &identity.did).await?;
    let mut live_digest = canonical_digest(&live_document)?;
    if let Some((secret_ref, record)) = current.take() {
        if pending_matches_live(&record, &live_document, &live_digest)? {
            current = Some((secret_ref, record));
        } else {
            pending_store.delete(&secret_ref)?;
        }
    }

    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let (secret_ref, mut record) = match current.take() {
            Some(value) => value,
            None => {
                prepare_and_save(core, &pending_store, &identity, &live_document, &live_digest)
                    .await?
            }
        };
        let (secret_ref, record) = if record.remote_result.is_some() {
            (secret_ref, record)
        } else {
            let root = root_authority(&record)?;
            match send_rebind(core, &live_document, &record, &root).await {
                Ok(remote) => {
                    if remote.replaced_device_ids != record.replaced_device_ids
                        || remote.signing_key_id != record.new_signing_key_id
                    {
                        pending_store.delete(&secret_ref)?;
                        return Err(crate::ImError::PermissionDenied);
                    }
                    record.remote_result = Some(remote);
                    let refreshed = pending_store.save(&record)?;
                    (refreshed, record)
                }
                Err(error) => match classify_rebind_error(&error) {
                    Some(RebindFailure::Resync) if attempts < MAX_REBIND_ATTEMPTS => {
                        live_document = resolve_live_document(core, &identity.did).await?;
                        live_digest = canonical_digest(&live_document)?;
                        // A committed replacement is resumable with the same
                        // operation ID; anything else is a stale intent.
                        if pending_matches_live(&record, &live_document, &live_digest)? {
                            current = Some((secret_ref, record));
                        } else {
                            pending_store.delete(&secret_ref)?;
                        }
                        continue;
                    }
                    Some(RebindFailure::Conflict) => {
                        pending_store.delete(&secret_ref)?;
                        return Err(crate::ImError::IdentityBindingConflict {
                            detail: rebind_server_code(&error).to_owned(),
                        });
                    }
                    Some(RebindFailure::Resync) | Some(RebindFailure::Fatal) => {
                        pending_store.delete(&secret_ref)?;
                        return Err(redact_rebind_error(&error));
                    }
                    None => return Err(redact_rebind_error(&error)),
                },
            }
        };
        return converge(core, &store, &identity, &pending_store, &record, &secret_ref).await;
    }
}

fn root_authority(record: &PendingDeviceRebind) -> crate::ImResult<RootAuthority> {
    let pkcs8 = record.root_pkcs8()?;
    let material = anp::PrivateKeyMaterial::from_pkcs8_der(&pkcs8)
        .map_err(|_| crate::ImError::PermissionDenied)?;
    if !matches!(material, anp::PrivateKeyMaterial::Ed25519(_)) {
        return Err(crate::ImError::PermissionDenied);
    }
    Ok(RootAuthority {
        key_id: record.root_key_id.clone(),
        material,
    })
}

async fn resolve_live_document(
    core: &crate::core::ImCore,
    did: &crate::ids::Did,
) -> crate::ImResult<Value> {
    let mut transport = CorePlainTransport::new(core);
    crate::internal::discovery::did_document::resolve_did_document_async(
        &mut transport,
        did.as_str(),
    )
    .await
}

fn pending_matches_live(
    record: &PendingDeviceRebind,
    live_document: &Value,
    live_digest: &str,
) -> crate::ImResult<bool> {
    if live_document
        .pointer("/proof/verificationMethod")
        .and_then(Value::as_str)
        != Some(record.root_key_id.as_str())
    {
        return Ok(false);
    }
    Ok(live_digest == record.expected_document_hash
        || canonical_digest(&record.new_document)? == live_digest)
}

async fn prepare_and_save(
    core: &crate::core::ImCore,
    pending_store: &PendingDeviceRebindStore,
    identity: &ImportedRootIdentity,
    live_document: &Value,
    live_digest: &str,
) -> crate::ImResult<(SecretRef, PendingDeviceRebind)> {
    let custody = controller_custody_provider(core).await?;
    let session = custody
        .open_identity(&ProviderIdentityRef {
            store_id: identity.store_id.clone(),
            identity_id: identity.identity_id.clone(),
            did: identity.did.as_str().to_owned(),
        })
        .await
        .map_err(map_provider_error)?;
    let public = session.public_identity().await.map_err(map_provider_error)?;
    if !public.did_wba
        || public.state != ProviderIdentityState::Active
        || public.reference.store_id != identity.store_id
        || public.reference.identity_id != identity.identity_id
        || public.reference.did != identity.did.as_str()
        || !crate::internal::identity_wire::document::validate_control_document_method(
            &public.document,
        )
    {
        return Err(crate::ImError::PermissionDenied);
    }
    let root_key_id = public
        .document
        .pointer("/proof/verificationMethod")
        .and_then(Value::as_str)
        .filter(|key_id| key_id.starts_with(&format!("{}#", identity.did.as_str())))
        .ok_or(crate::ImError::PermissionDenied)?
        .to_owned();
    let exported = session
        .export_root_for_legacy_envelope(ProviderLegacyRootExportRequest {
            key: ProviderKeySelector::Kid(root_key_id.clone()),
            user_presence_confirmed: true,
        })
        .await
        .map_err(map_provider_error)?;
    let pkcs8 = Zeroizing::new(exported.as_pkcs8_der().to_vec());
    let record = prepare_rebind(identity, live_document, live_digest, &root_key_id, &pkcs8)?;
    let secret_ref = pending_store.save(&record)?;
    Ok((secret_ref, record))
}

fn prepare_rebind(
    identity: &ImportedRootIdentity,
    live_document: &Value,
    live_digest: &str,
    root_key_id: &str,
    root_pkcs8: &[u8],
) -> crate::ImResult<PendingDeviceRebind> {
    if live_document
        .pointer("/proof/verificationMethod")
        .and_then(Value::as_str)
        != Some(root_key_id)
    {
        // The live root changed: this imported key can no longer authorize the
        // DID, and silently re-signing with a non-root key would be a forgery.
        return Err(crate::ImError::PermissionDenied);
    }
    let root_method = unique_verification_method(live_document, root_key_id)?.clone();
    let root_material = anp::PrivateKeyMaterial::from_pkcs8_der(root_pkcs8)
        .map_err(|_| crate::ImError::PermissionDenied)?;
    let anp::PrivateKeyMaterial::Ed25519(root_signing_key) = &root_material else {
        return Err(crate::ImError::PermissionDenied);
    };
    let document_root_public =
        crate::internal::identity_wire::document::extract_identity_public_key(&root_method)?;
    if root_material.public_key().to_pem() != document_root_public.to_pem() {
        return Err(crate::ImError::PermissionDenied);
    }
    let old_manifest = anp::authentication::validate_device_manifest(live_document)
        .map_err(|_| crate::ImError::PermissionDenied)?
        .filter(|manifest| manifest.devices.len() == 1)
        .ok_or(crate::ImError::PermissionDenied)?;
    let old_device_id = old_manifest.devices[0].device_id.clone();
    crate::ids::ProtocolDeviceId::parse(&old_device_id)?;

    let new_device_id = crate::ids::ProtocolDeviceId::generate()?;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let e2ee_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let signing_material = anp::PrivateKeyMaterial::Ed25519(signing_key.clone());
    let e2ee_material = anp::PrivateKeyMaterial::X25519(e2ee_secret.clone());
    let signing_key_id = format!("{}#{}-sign", identity.did.as_str(), new_device_id.as_str());
    let e2ee_key_id = format!("{}#{}-e2ee", identity.did.as_str(), new_device_id.as_str());
    let signing_method = json!({
        "id": signing_key_id,
        "type": "Multikey",
        "controller": identity.did.as_str(),
        "publicKeyMultibase": public_key_multibase(&signing_material.public_key())?,
    });
    let e2ee_method = json!({
        "id": e2ee_key_id,
        "type": "X25519KeyAgreementKey2019",
        "controller": identity.did.as_str(),
        "publicKeyMultibase": public_key_multibase(&e2ee_material.public_key())?,
    });
    if !matches!(
        crate::internal::identity_wire::document::extract_identity_public_key(&signing_method)?,
        anp::PublicKeyMaterial::Ed25519(_)
    ) || !matches!(
        crate::internal::identity_wire::document::extract_identity_public_key(&e2ee_method)?,
        anp::PublicKeyMaterial::X25519(_)
    ) {
        return Err(crate::ImError::PermissionDenied);
    }
    let daemon_method = validated_legacy_daemon_method(live_document, &identity.did)?.cloned();
    let device = anp::authentication::DeviceManifestEntry {
        device_id: new_device_id.as_str().to_owned(),
        signing_key_id: signing_key_id.clone(),
        e2ee_key_id: e2ee_key_id.clone(),
        profiles: VNEXT_DEVICE_PROFILES
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    };
    let base_document = legacy_base_document(live_document)?;
    let mut unsigned = anp::authentication::build_vnext_did_document(
        &base_document,
        root_key_id,
        &root_method,
        &device,
        &signing_method,
        &e2ee_method,
    )
    .map_err(|_| crate::ImError::PermissionDenied)?;
    if let Some(method) = daemon_method.as_ref() {
        append_daemon_method(&mut unsigned, &identity.did, method)?;
    }
    let new_document =
        sign_document_proof(&unsigned, root_signing_key, root_key_id, &now_rfc3339()?)?;
    let new_manifest = anp::authentication::validate_device_manifest(&new_document)
        .map_err(|_| crate::ImError::PermissionDenied)?
        .filter(|manifest| manifest.devices.len() == 1)
        .ok_or(crate::ImError::PermissionDenied)?;
    let new_device = &new_manifest.devices[0];
    if new_device.device_id != new_device_id.as_str()
        || new_device.signing_key_id != signing_key_id
        || new_device.e2ee_key_id != e2ee_key_id
    {
        return Err(crate::ImError::PermissionDenied);
    }
    // The generated material must reproduce the published methods; this is the
    // same equality the custody import re-checks before it stores anything.
    if crate::internal::identity_wire::document::extract_identity_public_key(
        unique_verification_method(&new_document, &signing_key_id)?,
    )?
    .to_pem()
        != signing_material.public_key().to_pem()
        || crate::internal::identity_wire::document::extract_identity_public_key(
            unique_verification_method(&new_document, &e2ee_key_id)?,
        )?
        .to_pem()
            != e2ee_material.public_key().to_pem()
    {
        return Err(crate::ImError::PermissionDenied);
    }
    PendingDeviceRebind::new(
        identity.did.clone(),
        identity.alias.clone(),
        identity.unique_id.clone(),
        format!("device-rebind-{}", random_token()),
        live_digest.to_owned(),
        root_key_id.to_owned(),
        root_pkcs8,
        new_device_id.as_str().to_owned(),
        signing_key_id,
        e2ee_key_id,
        &signing_key.to_bytes(),
        &e2ee_secret.to_bytes(),
        new_document,
        vec![old_device_id],
    )
}

async fn send_rebind(
    core: &crate::core::ImCore,
    live_document: &Value,
    record: &PendingDeviceRebind,
    root: &RootAuthority,
) -> crate::ImResult<DeviceRebindRemoteResult> {
    let seed = record.new_signing_seed()?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| crate::ImError::PermissionDenied)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let possession = build_possession_proof(
        record.did.as_str(),
        &record.operation_id,
        &record.new_document,
        &record.new_device_id,
        &record.new_signing_key_id,
        &signing_key,
        &now_rfc3339()?,
    )?;
    let prepared = PreparedDeviceRebind {
        did: record.did.as_str().to_owned(),
        operation_id: record.operation_id.clone(),
        expected_document_hash: record.expected_document_hash.clone(),
        expected_document_version: None,
        expected_registry_version: None,
        new_document: record.new_document.clone(),
        new_device_id: record.new_device_id.clone(),
        new_signing_key_id: record.new_signing_key_id.clone(),
        new_e2ee_key_id: record.new_e2ee_key_id.clone(),
        replaced_device_ids: record.replaced_device_ids.clone(),
        new_device_object_proof: possession,
    };
    let call = build_rebind_call(&prepared)?;
    let transport = CorePlainTransport::new(core);
    let raw = transport
        .root_signed_rpc_async(
            call.endpoint,
            call.method,
            call.params,
            live_document,
            &root.key_id,
            &root.material,
        )
        .await?;
    parse_rebind_result(raw, record.did.as_str(), &record.new_device_id)
}

async fn converge(
    core: &crate::core::ImCore,
    store: &IdentityStore<'_>,
    identity: &ImportedRootIdentity,
    pending_store: &PendingDeviceRebindStore,
    record: &PendingDeviceRebind,
    secret_ref: &SecretRef,
) -> crate::ImResult<crate::identity::DeviceRebindResult> {
    let remote = record
        .remote_result
        .as_ref()
        .ok_or(crate::ImError::PermissionDenied)?;
    let document_digest = canonical_digest(&remote.document)?;
    let custody = controller_custody_provider(core).await?;
    let provider_public =
        ensure_provider_identity(custody.as_ref(), identity, record, remote, &document_digest)
            .await?;
    let user_id = jwt_user_id(&remote.access_token)?;
    validate_device_access_token(
        &remote.access_token,
        &ExpectedDeviceAccess {
            did: identity.did.as_str(),
            user_id: &user_id,
            device_id: &remote.device_id,
            key_id: &record.new_signing_key_id,
            auth_generation: remote.auth_generation,
            role: DeviceAuthorizationRole::Admin,
            management_ready: true,
        },
    )?;
    let projection = AnpIdentityProjectionStorage::from_core(
        core,
        provider_public.reference.store_id.clone(),
        provider_public.reference.identity_id.clone(),
    )?;
    let authorization = DeviceAuthorizationProjection {
        protocol_device_id: crate::ids::ProtocolDeviceId::parse(&remote.device_id)?,
        signing_key_id: record.new_signing_key_id.clone(),
        e2ee_key_id: record.new_e2ee_key_id.clone(),
        status: DeviceAuthorizationStatus::Active,
        role: DeviceAuthorizationRole::Admin,
        management_ready: true,
        auth_generation: remote.auth_generation,
    };
    let device_id = crate::ids::ProtocolDeviceId::parse(&remote.device_id)?;
    store.save_anp_identity_transition_projection(
        SaveIdentityInput {
            local_alias: identity.alias.clone(),
            did: identity.did.clone(),
            unique_id: identity.unique_id.clone(),
            user_id,
            display_name: identity.display_name.clone(),
            handle: identity.handle.clone(),
            full_handle: identity.full_handle.clone(),
            binding_generation: identity.binding_generation.clone(),
            jwt_token: remote.access_token.clone(),
            did_document: Some(remote.document.clone()),
            key_mode: SaveIdentityKeyMode::VNext {
                root_key_id: Some(record.root_key_id.clone()),
                device_signing_key_id: record.new_signing_key_id.clone(),
                device_e2ee_key_id: record.new_e2ee_key_id.clone(),
            },
            device_state: Some(IdentityDeviceState {
                schema_version: IDENTITY_DEVICE_STATE_SCHEMA_VERSION,
                mode: IdentityDeviceMode::VNext,
                authorization: Some(authorization),
                checkpoint: Some(IdentityInternalCheckpoint {
                    document_version: remote.document_version,
                    document_hash: document_digest,
                    registry_version: remote.registry_version,
                }),
            }),
            key1_private_pem: String::new(),
            key1_public_pem: String::new(),
            e2ee_signing_private_pem: String::new(),
            e2ee_agreement_private_pem: String::new(),
            daemon_subkey_package: None,
            make_default: identity.is_default,
        },
        projection,
        AnpIdentityProjectionReplacement {
            expected_did: identity.did.as_str(),
            expected_unique_id: identity.unique_id.as_str(),
        },
    )?;
    // The exact-retry record is the only copy of the root material once the
    // root-only custody entry is gone; drop it only after the local commit.
    pending_store.delete(secret_ref)?;
    Ok(crate::identity::DeviceRebindResult {
        did: identity.did.clone(),
        device_id,
        already_bound: false,
    })
}

async fn ensure_provider_identity(
    custody: &dyn IdentityCustody,
    identity: &ImportedRootIdentity,
    record: &PendingDeviceRebind,
    remote: &DeviceRebindRemoteResult,
    document_digest: &str,
) -> crate::ImResult<ProviderPublicIdentity> {
    let descriptors = custody.list_identities().await.map_err(map_provider_error)?;
    for descriptor in &descriptors {
        if descriptor.reference.did != identity.did.as_str()
            || descriptor.state != ProviderIdentityState::Active
        {
            continue;
        }
        let session = custody
            .open_identity(&descriptor.reference)
            .await
            .map_err(map_provider_error)?;
        let public = session.public_identity().await.map_err(map_provider_error)?;
        if public.did_wba
            && public.state == ProviderIdentityState::Active
            && public.reference.did == identity.did.as_str()
            && canonical_digest(&public.document)? == document_digest
        {
            return Ok(public);
        }
    }
    // The root-only placeholder (and any half-installed replacement) must go
    // before the same DID can be imported again.
    for descriptor in &descriptors {
        if descriptor.reference.did == identity.did.as_str() {
            custody
                .delete_identity(&descriptor.reference)
                .await
                .map_err(map_provider_error)?;
        }
    }
    let root_pkcs8 = record.root_pkcs8()?;
    let signing_seed = record.new_signing_seed()?;
    let e2ee_seed = record.new_e2ee_seed()?;
    let session = custody
        .import_identity_material(ProviderIdentityMaterialImportRequest {
            remote: ProviderVerifiedRemoteDocument {
                document: remote.document.clone(),
                evidence: ProviderPublicationEvidence {
                    document_version: remote.document_version,
                    registry_version: remote.registry_version,
                    document_digest: document_digest.to_owned(),
                },
            },
            did_wba: true,
            keys: vec![
                ProviderIdentityMaterialKey {
                    kid: record.root_key_id.clone(),
                    purpose: ProviderKeyPurpose::RootControl,
                    encoding: ProviderPrivateKeyEncoding::Pkcs8Der,
                    secret: root_pkcs8,
                },
                ProviderIdentityMaterialKey {
                    kid: record.new_signing_key_id.clone(),
                    purpose: ProviderKeyPurpose::DeviceAssertion,
                    encoding: ProviderPrivateKeyEncoding::Raw32,
                    secret: signing_seed,
                },
                ProviderIdentityMaterialKey {
                    kid: record.new_e2ee_key_id.clone(),
                    purpose: ProviderKeyPurpose::KeyAgreement,
                    encoding: ProviderPrivateKeyEncoding::Raw32,
                    secret: e2ee_seed,
                },
            ],
            request_id: format!("awiki-device-rebind:{}", record.operation_id),
        })
        .await
        .map_err(map_provider_error)?;
    let public = session.public_identity().await.map_err(map_provider_error)?;
    if public.state != ProviderIdentityState::Active
        || !public.did_wba
        || public.reference.did != identity.did.as_str()
        || canonical_digest(&public.document)? != document_digest
    {
        return Err(crate::ImError::PermissionDenied);
    }
    Ok(public)
}

fn jwt_user_id(token: &str) -> crate::ImResult<String> {
    crate::internal::auth::state::decode_jwt_payload(token)
        .and_then(|payload| {
            payload
                .get("user_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|value| !value.trim().is_empty())
        .ok_or(crate::ImError::PermissionDenied)
}

enum RebindFailure {
    Resync,
    Fatal,
    Conflict,
}

fn rebind_server_code(error: &crate::ImError) -> &str {
    match error {
        crate::ImError::Service { message, .. } => message.trim(),
        _ => "device_rebind_conflict",
    }
}

fn classify_rebind_error(error: &crate::ImError) -> Option<RebindFailure> {
    if !matches!(error, crate::ImError::Service { .. }) {
        return None;
    }
    Some(match rebind_server_code(error) {
        "document_digest_mismatch" | "did_document_changed" => RebindFailure::Resync,
        "operation_replayed" | "root_change_not_supported" => RebindFailure::Fatal,
        "device_rebind_unchanged"
        | "new_device_manifest_mismatch"
        | "replaced_device_ids_mismatch"
        | "document_version_exhausted"
        | "registry_version_exhausted" => RebindFailure::Conflict,
        _ => return None,
    })
}

fn redact_rebind_error(error: &crate::ImError) -> crate::ImError {
    match error {
        crate::ImError::Service { .. } => crate::ImError::Service {
            status_code: None,
            code: None,
            message: "device rebind request failed".to_owned(),
            data: None,
        },
        crate::ImError::TransportUnavailable { .. } => crate::ImError::TransportUnavailable {
            detail: "device rebind transport failed".to_owned(),
        },
        crate::ImError::Serialization { .. } => crate::ImError::Serialization {
            detail: "device rebind response was invalid".to_owned(),
        },
        other => other.clone(),
    }
}

fn now_rfc3339() -> crate::ImResult<String> {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| crate::ImError::Serialization {
            detail: error.to_string(),
        })
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_error(message: &str) -> crate::ImError {
        crate::ImError::Service {
            status_code: Some(409),
            code: Some("conflict".to_owned()),
            message: message.to_owned(),
            data: Some(json!({"secret": "must-not-leak"})),
        }
    }

    #[test]
    fn classifies_retryable_and_terminal_server_codes() {
        assert!(matches!(
            classify_rebind_error(&service_error("document_digest_mismatch")),
            Some(RebindFailure::Resync)
        ));
        assert!(matches!(
            classify_rebind_error(&service_error("root_change_not_supported")),
            Some(RebindFailure::Fatal)
        ));
        assert!(matches!(
            classify_rebind_error(&service_error("operation_replayed")),
            Some(RebindFailure::Fatal)
        ));
        assert!(matches!(
            classify_rebind_error(&service_error("replaced_device_ids_mismatch")),
            Some(RebindFailure::Conflict)
        ));
        assert!(classify_rebind_error(&service_error("something_else")).is_none());
        assert!(classify_rebind_error(&crate::ImError::PermissionDenied).is_none());
    }

    #[test]
    fn redaction_drops_server_detail() {
        let redacted = redact_rebind_error(&service_error("document_digest_mismatch"));
        let rendered = format!("{redacted:?}");
        assert!(!rendered.contains("document_digest_mismatch"));
        assert!(!rendered.contains("must-not-leak"));
        assert!(matches!(
            redact_rebind_error(&crate::ImError::PermissionDenied),
            crate::ImError::PermissionDenied
        ));
    }
}
