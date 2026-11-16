//! Safe public boundary for binding this device to an imported root-only identity.
//!
//! The imported backup carries the RootControl key of an already published DID
//! but no device keys and no server device record. Rebinding root-signs a
//! replacement DID Document for the same DID and installs the new device; the
//! DID, Handle and root key never change. Exact-retry state, the root-signed
//! document and bearer credentials remain internal.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRebindRequest {
    pub identity: super::IdentitySelector,
    /// Set only after foreground OS/user-presence confirmation.
    pub user_presence_confirmed: bool,
}

/// Safe host-facing projection. It deliberately excludes operation IDs,
/// checkpoints, proofs, documents, keys and bearer credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRebindResult {
    pub did: crate::ids::Did,
    pub device_id: crate::ids::ProtocolDeviceId,
    /// True when this device was already bound and nothing was submitted.
    pub already_bound: bool,
}

pub struct DeviceRebindService<'a> {
    core: &'a crate::core::ImCore,
}

impl<'a> DeviceRebindService<'a> {
    pub(crate) fn new(core: &'a crate::core::ImCore) -> Self {
        Self { core }
    }

    /// Binds this device to the imported root-only identity.
    ///
    /// Repeating the same call after a transport failure resumes the exact
    /// persisted operation; a committed rebind is not repeated remotely.
    pub async fn rebind(
        &self,
        request: DeviceRebindRequest,
    ) -> crate::ImResult<DeviceRebindResult> {
        if !self.core.inner().device_rebind_enabled() {
            return Err(crate::ImError::unsupported("awiki-device-rebind-disabled"));
        }
        if !request.user_presence_confirmed {
            return Err(crate::ImError::PermissionDenied);
        }
        crate::internal::identity_device_rebind::rebind(self.core, request.identity).await
    }
}
