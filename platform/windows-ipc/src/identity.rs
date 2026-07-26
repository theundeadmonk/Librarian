use std::{fmt, path::PathBuf};

use librarian_agent_protocol::ClientRole;

/// Installed component identity derived exclusively from the observed process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentRole {
    Agent,
    Desktop,
    NativeHost,
    PasskeyProvider,
}

impl ComponentRole {
    #[must_use]
    pub const fn client_role(self) -> Option<ClientRole> {
        match self {
            Self::Agent => None,
            Self::Desktop => Some(ClientRole::Desktop),
            Self::NativeHost => Some(ClientRole::NativeHost),
            Self::PasskeyProvider => Some(ClientRole::PasskeyProvider),
        }
    }
}

impl From<ClientRole> for ComponentRole {
    fn from(role: ClientRole) -> Self {
        match role {
            ClientRole::Desktop => Self::Desktop,
            ClientRole::NativeHost => Self::NativeHost,
            ClientRole::PasskeyProvider => Self::PasskeyProvider,
        }
    }
}

/// Kernel- and token-derived process facts. Debug output is always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerObservation {
    pub process_id: u32,
    pub process_creation_time: u64,
    pub session_id: u32,
    pub user_sid: String,
    pub logon_sid: String,
    pub integrity_rid: u32,
    pub elevated: bool,
    pub app_container: bool,
    pub image_path: PathBuf,
    pub package_full_name: Option<String>,
    pub package_family_name: Option<String>,
    pub application_user_model_id: Option<String>,
}

impl fmt::Debug for PeerObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerObservation(REDACTED)")
    }
}

/// Immutable production identity policy for exactly one component role.
pub struct PeerPolicy {
    pub role: ComponentRole,
    pub session_id: u32,
    pub user_sid: String,
    pub logon_sid: String,
    pub maximum_integrity_rid: u32,
    pub image_path: PathBuf,
    pub package_full_name: String,
    pub package_family_name: String,
    pub application_user_model_id: Option<String>,
}

impl fmt::Debug for PeerPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerPolicy")
            .field("role", &self.role)
            .field("identity", &"REDACTED")
            .finish_non_exhaustive()
    }
}

/// Stable peer rejection categories. They contain no observed values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAuthorizationError {
    InvalidPolicySet,
    NoMatchingPolicy,
    AmbiguousRole,
    ProcessExited,
    WrongUser,
    WrongLogon,
    WrongSession,
    Elevated,
    AppContainer,
    WrongIntegrity,
    MissingPackageIdentity,
    WrongPackage,
    WrongApplication,
    WrongImage,
}

/// Derives exactly one protocol client role from a bounded installed-policy
/// set. Message claims are deliberately absent.
///
/// # Errors
///
/// Rejects malformed policy sets, no identity match, or more than one match.
pub fn authorize_client_role(
    observation: &PeerObservation,
    policies: &[PeerPolicy],
) -> Result<ClientRole, PeerAuthorizationError> {
    if policies.is_empty()
        || policies.len() > 3
        || policies
            .iter()
            .any(|policy| policy.role == ComponentRole::Agent)
    {
        return Err(PeerAuthorizationError::InvalidPolicySet);
    }
    let mut matched = None;
    for policy in policies {
        if let Ok(component) = authorize_peer(observation, policy) {
            let role = component
                .client_role()
                .ok_or(PeerAuthorizationError::InvalidPolicySet)?;
            if matched.replace(role).is_some() {
                return Err(PeerAuthorizationError::AmbiguousRole);
            }
        }
    }
    matched.ok_or(PeerAuthorizationError::NoMatchingPolicy)
}

/// Applies the complete production policy. Endpoint discovery and process ID
/// are deliberately absent from authorization inputs.
///
/// # Errors
///
/// Returns one redacted category for the first failed invariant.
pub fn authorize_peer(
    observation: &PeerObservation,
    policy: &PeerPolicy,
) -> Result<ComponentRole, PeerAuthorizationError> {
    if observation.user_sid != policy.user_sid {
        return Err(PeerAuthorizationError::WrongUser);
    }
    if observation.logon_sid != policy.logon_sid {
        return Err(PeerAuthorizationError::WrongLogon);
    }
    if observation.session_id != policy.session_id {
        return Err(PeerAuthorizationError::WrongSession);
    }
    if observation.elevated {
        return Err(PeerAuthorizationError::Elevated);
    }
    if observation.app_container {
        return Err(PeerAuthorizationError::AppContainer);
    }
    if observation.integrity_rid > policy.maximum_integrity_rid {
        return Err(PeerAuthorizationError::WrongIntegrity);
    }
    let (Some(package_full_name), Some(package_family_name)) = (
        observation.package_full_name.as_deref(),
        observation.package_family_name.as_deref(),
    ) else {
        return Err(PeerAuthorizationError::MissingPackageIdentity);
    };
    if package_full_name != policy.package_full_name
        || package_family_name != policy.package_family_name
    {
        return Err(PeerAuthorizationError::WrongPackage);
    }
    if policy.application_user_model_id.as_deref()
        != observation.application_user_model_id.as_deref()
    {
        return Err(PeerAuthorizationError::WrongApplication);
    }
    if !paths_equal(&observation.image_path, &policy.image_path) {
        return Err(PeerAuthorizationError::WrongImage);
    }
    Ok(policy.role)
}

fn paths_equal(left: &std::path::Path, right: &std::path::Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> PeerObservation {
        PeerObservation {
            process_id: 17,
            process_creation_time: 81,
            session_id: 4,
            user_sid: "S-1-5-21-user".to_owned(),
            logon_sid: "S-1-5-5-logon".to_owned(),
            integrity_rid: 0x2000,
            elevated: false,
            app_container: false,
            image_path: PathBuf::from(r"C:\Program Files\WindowsApps\Librarian.Agent.exe"),
            package_full_name: Some("Librarian_1.0.0.0_x64__publisher".to_owned()),
            package_family_name: Some("Librarian_publisher".to_owned()),
            application_user_model_id: Some("Librarian.Agent".to_owned()),
        }
    }

    fn policy() -> PeerPolicy {
        let expected = observation();
        PeerPolicy {
            role: ComponentRole::Desktop,
            session_id: expected.session_id,
            user_sid: expected.user_sid,
            logon_sid: expected.logon_sid,
            maximum_integrity_rid: 0x2000,
            image_path: expected.image_path,
            package_full_name: expected
                .package_full_name
                .expect("fixture has package identity"),
            package_family_name: expected
                .package_family_name
                .expect("fixture has package family"),
            application_user_model_id: expected.application_user_model_id,
        }
    }

    #[test]
    fn production_policy_fails_closed_for_every_identity_dimension() {
        let expected = policy();
        assert_eq!(
            authorize_peer(&observation(), &expected),
            Ok(ComponentRole::Desktop)
        );

        let mut cases: Vec<(PeerObservation, PeerAuthorizationError)> = Vec::new();
        let mut changed = observation();
        changed.user_sid.push_str("-other");
        cases.push((changed, PeerAuthorizationError::WrongUser));
        let mut changed = observation();
        changed.logon_sid.push_str("-other");
        cases.push((changed, PeerAuthorizationError::WrongLogon));
        let mut changed = observation();
        changed.session_id += 1;
        cases.push((changed, PeerAuthorizationError::WrongSession));
        let mut changed = observation();
        changed.elevated = true;
        cases.push((changed, PeerAuthorizationError::Elevated));
        let mut changed = observation();
        changed.app_container = true;
        cases.push((changed, PeerAuthorizationError::AppContainer));
        let mut changed = observation();
        changed.integrity_rid += 1;
        cases.push((changed, PeerAuthorizationError::WrongIntegrity));
        let mut changed = observation();
        changed.package_full_name = None;
        cases.push((changed, PeerAuthorizationError::MissingPackageIdentity));
        let mut changed = observation();
        changed.package_full_name = Some("Librarian_older".to_owned());
        cases.push((changed, PeerAuthorizationError::WrongPackage));
        let mut changed = observation();
        changed.application_user_model_id = Some("Librarian.Other".to_owned());
        cases.push((changed, PeerAuthorizationError::WrongApplication));
        let mut changed = observation();
        changed.image_path.push("copied.exe");
        cases.push((changed, PeerAuthorizationError::WrongImage));

        for (changed, error) in cases {
            assert_eq!(authorize_peer(&changed, &expected), Err(error));
        }
    }

    #[test]
    fn observations_and_policies_redact_identity_data() {
        let observation = observation();
        let policy = policy();
        let text = format!("{observation:?} {policy:?}");
        assert!(!text.contains("S-1-5"));
        assert!(!text.contains("WindowsApps"));
        assert!(!text.contains("publisher"));
    }

    #[test]
    fn client_role_derivation_requires_exactly_one_installed_policy_match() {
        assert_eq!(
            authorize_client_role(&observation(), &[policy()]),
            Ok(ClientRole::Desktop)
        );
        assert_eq!(
            authorize_client_role(&observation(), &[]),
            Err(PeerAuthorizationError::InvalidPolicySet)
        );
        assert_eq!(
            authorize_client_role(&observation(), &[policy(), policy()]),
            Err(PeerAuthorizationError::AmbiguousRole)
        );

        let mut unmatched = policy();
        unmatched.image_path.push("other.exe");
        assert_eq!(
            authorize_client_role(&observation(), &[unmatched]),
            Err(PeerAuthorizationError::NoMatchingPolicy)
        );

        let mut agent = policy();
        agent.role = ComponentRole::Agent;
        assert_eq!(
            authorize_client_role(&observation(), &[agent]),
            Err(PeerAuthorizationError::InvalidPolicySet)
        );
    }
}
