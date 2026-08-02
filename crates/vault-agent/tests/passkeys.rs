use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use librarian_vault_agent::{AccountError, PasskeyInput, VaultAgent};
use librarian_vault_core::{CancellationFlag, MasterPassword};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "librarian-passkey-integration-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("integration-test directory must be created");
        Self(path)
    }

    fn vault_path(&self) -> PathBuf {
        self.0.join("vault.sqlite3")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn password() -> MasterPassword {
    MasterPassword::new("disposable passkey integration password")
        .expect("integration-test password")
}

fn passkey() -> PasskeyInput {
    passkey_for_rp("example.com", 0x21)
}

fn passkey_for_rp(rp_id: &str, marker: u8) -> PasskeyInput {
    PasskeyInput::new(
        rp_id,
        &[marker; 32],
        "person@example.com",
        "Disposable Person",
    )
    .expect("integration-test passkey input")
}

fn verify_assertion(
    public_key: &[u8],
    client_data_hash: &[u8; 32],
    authenticator_data: &[u8],
    signature_der: &[u8],
) {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).expect("public key is P-256");
    let signature = Signature::from_der(signature_der).expect("signature is canonical DER");
    let mut signed = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(client_data_hash);
    verifying_key
        .verify(&signed, &signature)
        .expect("assertion signature must verify");
}

fn assert_passkey_summary(
    summary: &librarian_vault_agent::PasskeySummary,
    credential_id: &[u8; 32],
) {
    assert_eq!(summary.credential_id(), credential_id);
    assert_eq!(summary.rp_id(), "example.com");
    assert_eq!(summary.user_handle(), &[0x21; 32]);
    assert_eq!(summary.user_name(), "person@example.com");
    assert_eq!(summary.user_display_name(), "Disposable Person");
}

#[test]
fn vault_backed_passkey_survives_restart_signs_and_deletes() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password()).expect("vault must be created");

    let credential = agent
        .add_passkey(passkey(), &[])
        .expect("passkey must be created");
    let credential_id = *credential.credential_id();
    let public_key = *credential.public_key();
    assert_eq!(credential.user_handle(), &[0x21; 32]);
    let summaries = agent
        .list_passkeys_for_assertion("example.com", &[])
        .expect("discoverable passkey metadata must list");
    assert_eq!(summaries.len(), 1);
    assert_passkey_summary(&summaries[0], &credential_id);
    let management = agent
        .list_passkeys()
        .expect("desktop passkey metadata must list");
    assert_eq!(management.len(), 1);
    assert_passkey_summary(&management[0], &credential_id);
    assert!(
        agent
            .list_passkeys_for_assertion("other.example", &[])
            .expect("other RP lookup must authenticate")
            .is_empty()
    );
    assert!(
        agent
            .list_passkeys_for_assertion("example.com", &[[0x99; 32]])
            .expect("allow-list miss must authenticate")
            .is_empty()
    );
    assert!(
        agent
            .list_website_accounts()
            .expect("mixed record snapshot must authenticate")
            .is_empty()
    );
    assert_eq!(
        agent.add_passkey(passkey(), &[credential_id]).err(),
        Some(AccountError::Conflict)
    );

    let first_hash: [u8; 32] = Sha256::digest(b"first disposable client data").into();
    let first = agent
        .sign_passkey_assertion("example.com", &credential_id, &first_hash)
        .expect("first assertion must sign");
    assert_eq!(first.credential_id(), &credential_id);
    assert_eq!(first.user_handle(), &[0x21; 32]);
    let expected_rp_hash: [u8; 32] = Sha256::digest(b"example.com").into();
    assert_eq!(&first.authenticator_data()[..32], &expected_rp_hash);
    assert_eq!(first.authenticator_data()[32], 0x1D);
    assert_eq!(&first.authenticator_data()[33..], &1_u32.to_be_bytes());
    verify_assertion(
        &public_key,
        &first_hash,
        first.authenticator_data(),
        first.signature_der(),
    );
    drop(first);

    assert_eq!(
        agent
            .sign_passkey_assertion("other.example", &credential_id, &first_hash)
            .err(),
        Some(AccountError::Conflict)
    );
    assert!(agent.is_unlocked());

    agent.lock();
    drop(agent);
    let mut restarted = VaultAgent::open_locked(&path);
    restarted
        .unlock(password(), &CancellationFlag::new())
        .expect("passkey vault must unlock after restart");
    let second_hash: [u8; 32] = Sha256::digest(b"second disposable client data").into();
    let second = restarted
        .sign_passkey_assertion("example.com", &credential_id, &second_hash)
        .expect("second assertion must sign after restart");
    assert_eq!(&second.authenticator_data()[33..], &2_u32.to_be_bytes());
    verify_assertion(
        &public_key,
        &second_hash,
        second.authenticator_data(),
        second.signature_der(),
    );
    drop(second);

    restarted
        .delete_passkey(&credential_id)
        .expect("passkey must delete");
    assert!(
        restarted
            .list_passkeys_for_assertion("example.com", &[])
            .expect("deleted passkey metadata must be absent")
            .is_empty()
    );
    assert_eq!(
        restarted
            .sign_passkey_assertion("example.com", &credential_id, &second_hash)
            .err(),
        Some(AccountError::NotFound)
    );
    assert!(restarted.is_unlocked());
}

#[test]
fn passkey_exclusions_are_scoped_to_the_relying_party() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password()).expect("vault must be created");
    let credential = agent
        .add_passkey(passkey(), &[])
        .expect("first RP passkey must be created");
    let credential_id = *credential.credential_id();

    assert_eq!(
        agent.add_passkey(passkey(), &[credential_id]).err(),
        Some(AccountError::Conflict),
        "a same-RP exclusion must remain a conflict"
    );
    assert!(
        agent
            .add_passkey(passkey_for_rp("other.example", 0x22), &[credential_id])
            .is_ok(),
        "an exclusion from another RP must not reveal a vault-wide credential match"
    );
}

#[test]
fn locked_agent_releases_no_passkey_operation() {
    let directory = TestDirectory::new();
    let path = directory.vault_path();
    let (mut agent, _recovery) =
        VaultAgent::create(&path, password()).expect("vault must be created");
    let credential = agent
        .add_passkey(passkey(), &[])
        .expect("passkey must be created");
    let credential_id = *credential.credential_id();
    agent.lock();

    assert_eq!(
        agent.add_passkey(passkey(), &[]).err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent
            .sign_passkey_assertion("example.com", &credential_id, &[0x31; 32])
            .err(),
        Some(AccountError::Locked)
    );
    assert_eq!(
        agent.delete_passkey(&credential_id),
        Err(AccountError::Locked)
    );
    assert!(matches!(
        agent.list_passkeys_for_assertion("example.com", &[]),
        Err(AccountError::Locked)
    ));
    assert!(matches!(agent.list_passkeys(), Err(AccountError::Locked)));
}
