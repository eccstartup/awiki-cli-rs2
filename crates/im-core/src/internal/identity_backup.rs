use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const BACKUP_MAGIC: &[u8; 8] = b"AWIKIBK1";
pub(crate) const BACKUP_FILE_EXTENSION: &str = "awiki-backup";
pub(crate) const BACKUP_MIME_TYPE: &str = "application/vnd.awiki.identity-backup";
pub(crate) const BACKUP_PASSPHRASE_MIN_BYTES: usize = 8;
pub(crate) const BACKUP_PASSPHRASE_MAX_BYTES: usize = 1024;

const BACKUP_VERSION: u16 = 1;
const HEADER_LEN: usize = 64;
const AAD_LEN: usize = 56;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KDF_ID_ARGON2ID: u8 = 1;
const AEAD_ID_XCHACHA20_POLY1305: u8 = 1;
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const BACKUP_PAYLOAD_SCHEMA: &str = "awiki.identity-backup.v1";

pub(crate) struct IdentityBackupMaterial {
    pub(crate) identity_id: String,
    pub(crate) did: String,
    pub(crate) handle: Option<String>,
    pub(crate) full_handle: Option<String>,
    pub(crate) credential_name: String,
    pub(crate) created_at: Option<String>,
    pub(crate) custody: &'static str,
    pub(crate) did_document: Option<serde_json::Value>,
    pub(crate) signing_private_pem: Option<Zeroizing<String>>,
    pub(crate) did_document_root_private_pem: Option<Zeroizing<String>>,
    pub(crate) e2ee_signing_private_pem: Option<Zeroizing<String>>,
    pub(crate) e2ee_agreement_private_pem: Option<Zeroizing<String>>,
}

const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Encodes a 32-byte Ed25519 seed already wrapped in PKCS#8 as the single-line
/// PEM the identity store's root material parser accepts. Custody providers
/// hand back opaque DER, so the shape is re-validated here instead of trusted.
pub(crate) fn pem_encode_ed25519_pkcs8(der: &[u8]) -> crate::ImResult<Zeroizing<String>> {
    if der.len() != 48 || der[..ED25519_PKCS8_PREFIX.len()] != ED25519_PKCS8_PREFIX {
        return Err(crate::ImError::Internal {
            message: "identity backup root key encoding is invalid".to_owned(),
        });
    }
    use base64::Engine as _;
    Ok(Zeroizing::new(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )))
}

#[derive(Serialize)]
struct BackupPayload<'a> {
    schema: &'static str,
    identity: BackupIdentity<'a>,
    keys: BackupKeys<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_document: Option<&'a serde_json::Value>,
    excluded: &'static [&'static str],
    metadata: BackupMetadata,
}

#[derive(Serialize)]
struct BackupIdentity<'a> {
    local_identity_id: &'a str,
    did: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_handle: Option<&'a str>,
    credential_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<&'a str>,
    custody: &'static str,
}

#[derive(Serialize)]
struct BackupKeys<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_private_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_document_root_private_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e2ee_signing_private_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e2ee_agreement_private_pem: Option<&'a str>,
}

#[derive(Serialize)]
struct BackupMetadata {
    exported_at: String,
    core_version: &'static str,
    container: &'static str,
    kdf: BackupKdfMetadata,
    aead: BackupAeadMetadata,
}

#[derive(Serialize)]
struct BackupKdfMetadata {
    id: &'static str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Serialize)]
struct BackupAeadMetadata {
    id: &'static str,
    nonce_bytes: usize,
}

const EXCLUDED_MATERIAL: &[&str] = &[
    "auth_jwt",
    "daemon_subkey_private",
    "device_certificates",
    "identity_vault_root",
    "mls_device_state",
    "messages",
    "read_state",
    "attachments",
    "product_overlay",
];

pub(crate) fn validate_passphrase(passphrase: &str) -> crate::ImResult<()> {
    let len = passphrase.len();
    if !(BACKUP_PASSPHRASE_MIN_BYTES..=BACKUP_PASSPHRASE_MAX_BYTES).contains(&len) {
        return Err(crate::ImError::invalid_input(
            Some("passphrase".to_owned()),
            format!(
                "passphrase must be between {BACKUP_PASSPHRASE_MIN_BYTES} and \
                 {BACKUP_PASSPHRASE_MAX_BYTES} UTF-8 bytes"
            ),
        ));
    }
    Ok(())
}

pub(crate) fn seal_identity_backup(
    material: &IdentityBackupMaterial,
    passphrase: &str,
    exported_at: String,
) -> crate::ImResult<Vec<u8>> {
    if material.signing_private_pem.is_none()
        && material.did_document_root_private_pem.is_none()
        && material.e2ee_signing_private_pem.is_none()
        && material.e2ee_agreement_private_pem.is_none()
    {
        return Err(crate::ImError::IdentityNotReady {
            identity: material.identity_id.clone(),
            missing: vec!["identity_private_key".to_owned()],
        });
    }
    let payload = BackupPayload {
        schema: BACKUP_PAYLOAD_SCHEMA,
        identity: BackupIdentity {
            local_identity_id: &material.identity_id,
            did: &material.did,
            handle: material.handle.as_deref(),
            full_handle: material.full_handle.as_deref(),
            credential_name: &material.credential_name,
            created_at: material.created_at.as_deref(),
            custody: material.custody,
        },
        keys: BackupKeys {
            signing_private_pem: material
                .signing_private_pem
                .as_deref()
                .map(String::as_str),
            did_document_root_private_pem: material
                .did_document_root_private_pem
                .as_deref()
                .map(String::as_str),
            e2ee_signing_private_pem: material
                .e2ee_signing_private_pem
                .as_deref()
                .map(String::as_str),
            e2ee_agreement_private_pem: material
                .e2ee_agreement_private_pem
                .as_deref()
                .map(String::as_str),
        },
        did_document: material.did_document.as_ref(),
        excluded: EXCLUDED_MATERIAL,
        metadata: BackupMetadata {
            exported_at,
            core_version: env!("CARGO_PKG_VERSION"),
            container: "AWIKIBK1",
            kdf: BackupKdfMetadata {
                id: "argon2id",
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
            },
            aead: BackupAeadMetadata {
                id: "xchacha20-poly1305",
                nonce_bytes: NONCE_LEN,
            },
        },
    };
    let mut plaintext =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|error| {
            crate::ImError::Serialization {
                detail: error.to_string(),
            }
        })?);

    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_backup_key(passphrase.as_bytes(), &salt)?;
    let ciphertext_len = plaintext
        .len()
        .checked_add(16)
        .ok_or_else(|| crate::ImError::Serialization {
            detail: "identity backup payload is too large".to_owned(),
        })?;
    let mut header = [0_u8; HEADER_LEN];
    header[0..8].copy_from_slice(BACKUP_MAGIC);
    header[8..10].copy_from_slice(&BACKUP_VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    header[12] = KDF_ID_ARGON2ID;
    header[13] = AEAD_ID_XCHACHA20_POLY1305;
    header[14..16].copy_from_slice(&0_u16.to_le_bytes());
    header[16..32].copy_from_slice(&salt);
    header[32..56].copy_from_slice(&nonce);
    header[56..64].copy_from_slice(&(ciphertext_len as u64).to_le_bytes());

    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
        crate::ImError::Internal {
            message: "identity backup cipher initialization failed".to_owned(),
        }
    })?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &header[..AAD_LEN],
            },
        )
        .map_err(|_| crate::ImError::Internal {
            message: "identity backup encryption failed".to_owned(),
        })?;
    plaintext.zeroize();
    key.zeroize();

    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn derive_backup_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
) -> crate::ImResult<[u8; 32]> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|_| crate::ImError::Internal {
        message: "identity backup KDF parameters are invalid".to_owned(),
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| crate::ImError::Internal {
            message: "identity backup key derivation failed".to_owned(),
        })?;
    Ok(key)
}

pub(crate) fn backup_file_name(
    handle: Option<&str>,
    identity_id: &str,
    exported_at: &chrono::DateTime<chrono::Utc>,
) -> String {
    let raw = handle
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(identity_id);
    let mut component: String = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while component.starts_with('-') || component.ends_with('-') {
        component = component
            .trim_start_matches('-')
            .trim_end_matches('-')
            .to_string();
    }
    component.truncate(48);
    if component.is_empty() {
        component = "identity".to_owned();
    }
    format!(
        "awiki-identity-{}-{}.{}",
        component,
        exported_at.format("%Y%m%d-%H%M%S"),
        BACKUP_FILE_EXTENSION
    )
}

#[cfg(test)]
pub(crate) fn open_identity_backup(
    container: &[u8],
    passphrase: &str,
) -> crate::ImResult<Zeroizing<Vec<u8>>> {
    if container.len() < HEADER_LEN {
        return Err(crate::ImError::invalid_input(
            None,
            "identity backup container is truncated",
        ));
    }
    let header = &container[..HEADER_LEN];
    if &header[0..8] != BACKUP_MAGIC {
        return Err(crate::ImError::invalid_input(
            None,
            "identity backup magic is invalid",
        ));
    }
    if u16::from_le_bytes([header[8], header[9]]) != BACKUP_VERSION {
        return Err(crate::ImError::invalid_input(
            None,
            "identity backup version is unsupported",
        ));
    }
    if usize::from(u16::from_le_bytes([header[10], header[11]])) != HEADER_LEN
        || header[12] != KDF_ID_ARGON2ID
        || header[13] != AEAD_ID_XCHACHA20_POLY1305
        || header[14] != 0
        || header[15] != 0
    {
        return Err(crate::ImError::invalid_input(
            None,
            "identity backup header is unsupported",
        ));
    }
    let ciphertext_len = u64::from_le_bytes(
        header[56..64]
            .try_into()
            .map_err(|_| crate::ImError::invalid_input(None, "identity backup length is invalid"))?,
    ) as usize;
    if ciphertext_len
        != container
            .len()
            .checked_sub(HEADER_LEN)
            .ok_or_else(|| {
                crate::ImError::invalid_input(None, "identity backup length is invalid")
            })?
    {
        return Err(crate::ImError::invalid_input(
            None,
            "identity backup length does not match its header",
        ));
    }
    let mut salt = [0_u8; SALT_LEN];
    salt.copy_from_slice(&header[16..32]);
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(&header[32..56]);
    let mut key = derive_backup_key(passphrase.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
        crate::ImError::Internal {
            message: "identity backup cipher initialization failed".to_owned(),
        }
    })?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &container[HEADER_LEN..],
                aad: &header[..AAD_LEN],
            },
        )
        .map_err(|_| {
            crate::ImError::invalid_input(None, "identity backup authentication failed")
        })?;
    key.zeroize();
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> IdentityBackupMaterial {
        IdentityBackupMaterial {
            identity_id: "identity-1".to_owned(),
            did: "did:wba:awiki.ai:alice".to_owned(),
            handle: Some("alice.awiki.ai".to_owned()),
            full_handle: Some("alice.awiki.ai".to_owned()),
            credential_name: "alice".to_owned(),
            created_at: Some("2026-01-02T03:04:05Z".to_owned()),
            custody: "vnext",
            did_document: Some(serde_json::json!({"id": "did:wba:awiki.ai:alice"})),
            signing_private_pem: Some(Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nsigning\n-----END PRIVATE KEY-----\n"
                    .to_owned(),
            )),
            did_document_root_private_pem: Some(Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nroot\n-----END PRIVATE KEY-----\n".to_owned(),
            )),
            e2ee_signing_private_pem: None,
            e2ee_agreement_private_pem: Some(Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nagreement\n-----END PRIVATE KEY-----\n"
                    .to_owned(),
            )),
        }
    }

    fn seal() -> Vec<u8> {
        seal_identity_backup(
            &material(),
            "correct horse battery",
            "2026-11-15T00:00:00Z".to_owned(),
        )
        .expect("seal")
    }

    #[test]
    fn round_trip_preserves_material_and_excludes_session_secrets() {
        let container = seal();
        assert_eq!(&container[..8], BACKUP_MAGIC);
        assert_eq!(
            u16::from_le_bytes([container[8], container[9]]),
            BACKUP_VERSION
        );
        assert_eq!(
            usize::from(u16::from_le_bytes([container[10], container[11]])),
            HEADER_LEN
        );
        assert_eq!(container[12], KDF_ID_ARGON2ID);
        assert_eq!(container[13], AEAD_ID_XCHACHA20_POLY1305);

        let plaintext = open_identity_backup(&container, "correct horse battery").expect("open");
        let payload: serde_json::Value =
            serde_json::from_slice(plaintext.as_slice()).expect("json");
        assert_eq!(payload["schema"], BACKUP_PAYLOAD_SCHEMA);
        assert_eq!(payload["identity"]["did"], "did:wba:awiki.ai:alice");
        assert_eq!(payload["identity"]["local_identity_id"], "identity-1");
        assert_eq!(
            payload["keys"]["signing_private_pem"].as_str(),
            material().signing_private_pem.as_deref().map(String::as_str)
        );
        assert_eq!(
            payload["keys"]["e2ee_agreement_private_pem"].as_str(),
            material()
                .e2ee_agreement_private_pem
                .as_deref()
                .map(String::as_str)
        );
        assert!(payload["keys"].get("e2ee_signing_private_pem").is_none());
        assert_eq!(payload["did_document"]["id"], "did:wba:awiki.ai:alice");
        let excluded = payload["excluded"].as_array().expect("excluded");
        assert!(excluded.iter().any(|value| value == "auth_jwt"));
        assert!(excluded.iter().any(|value| value == "daemon_subkey_private"));
        assert!(!payload.to_string().contains("jwt_token"));
    }

    #[test]
    fn anp_root_only_material_keeps_the_root_key_and_omits_device_keys() {
        let mut root_only = material();
        root_only.custody = "anp_root";
        root_only.signing_private_pem = None;
        root_only.e2ee_signing_private_pem = None;
        root_only.e2ee_agreement_private_pem = None;
        root_only.did_document_root_private_pem =
            Some(pem_encode_ed25519_pkcs8(&ed25519_pkcs8_der()).expect("pem"));
        let expected_pem = root_only
            .did_document_root_private_pem
            .as_deref()
            .map(String::as_str)
            .expect("root pem")
            .to_owned();

        let container = seal_identity_backup(
            &root_only,
            "correct horse battery",
            "2026-11-15T00:00:00Z".to_owned(),
        )
        .expect("seal");
        let plaintext = open_identity_backup(&container, "correct horse battery").expect("open");
        let payload: serde_json::Value =
            serde_json::from_slice(plaintext.as_slice()).expect("json");
        assert_eq!(payload["identity"]["custody"], "anp_root");
        assert_eq!(
            payload["keys"]["did_document_root_private_pem"],
            expected_pem.as_str()
        );
        assert!(payload["keys"].get("signing_private_pem").is_none());
        assert!(payload["keys"].get("e2ee_signing_private_pem").is_none());
        assert!(payload["keys"].get("e2ee_agreement_private_pem").is_none());
    }

    #[test]
    fn material_without_any_key_fails_closed() {
        let mut empty = material();
        empty.signing_private_pem = None;
        empty.did_document_root_private_pem = None;
        empty.e2ee_signing_private_pem = None;
        empty.e2ee_agreement_private_pem = None;
        assert!(matches!(
            seal_identity_backup(
                &empty,
                "correct horse battery",
                "2026-11-15T00:00:00Z".to_owned()
            ),
            Err(crate::ImError::IdentityNotReady { .. })
        ));
    }

    #[test]
    fn pem_encoding_accepts_only_ed25519_pkcs8() {
        let pem = pem_encode_ed25519_pkcs8(&ed25519_pkcs8_der()).expect("pem");
        let lines = pem.split('\n').collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "-----BEGIN PRIVATE KEY-----");
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2], "-----END PRIVATE KEY-----");
        assert_eq!(lines[3], "");

        assert!(pem_encode_ed25519_pkcs8(&[0_u8; 48]).is_err());
        assert!(pem_encode_ed25519_pkcs8(&ed25519_pkcs8_der()[..47]).is_err());
    }

    fn ed25519_pkcs8_der() -> Vec<u8> {
        let mut der = ED25519_PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&[7_u8; 32]);
        der
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let container = seal();
        assert!(open_identity_backup(&container, "wrong passphrase").is_err());
    }

    #[test]
    fn tampering_with_header_or_ciphertext_is_rejected() {
        let container = seal();
        let mut header_tampered = container.clone();
        header_tampered[16] ^= 0x01;
        assert!(open_identity_backup(&header_tampered, "correct horse battery").is_err());

        let mut ciphertext_tampered = container.clone();
        let last = ciphertext_tampered.len() - 1;
        ciphertext_tampered[last] ^= 0x01;
        assert!(open_identity_backup(&ciphertext_tampered, "correct horse battery").is_err());

        assert!(open_identity_backup(&container[..HEADER_LEN - 1], "correct horse battery").is_err());
    }

    #[test]
    fn each_export_uses_fresh_salt_and_nonce() {
        let first = seal();
        let second = seal();
        assert_ne!(first[16..32], second[16..32]);
        assert_ne!(first[32..56], second[32..56]);
        assert_ne!(first, second);
    }

    #[test]
    fn file_name_uses_sanitized_handle_and_timestamp() {
        let stamp = chrono::DateTime::parse_from_rfc3339("2026-11-15T08:09:10Z")
            .expect("time")
            .with_timezone(&chrono::Utc);
        assert_eq!(
            backup_file_name(Some("Alice.Awiki.AI"), "identity-1", &stamp),
            "awiki-identity-alice-awiki-ai-20261115-080910.awiki-backup"
        );
        assert_eq!(
            backup_file_name(None, "identity-1", &stamp),
            "awiki-identity-identity-1-20261115-080910.awiki-backup"
        );
    }
}
