use librarian_vault_core::{
    EncryptedRecord, PasskeyAssertion, PasskeyCredential, PasskeyInput, PasskeySummary,
    PreparedRecordMutation, RecordId, RecordOperationError, WebsiteAccount, WebsiteAccountInput,
};
use librarian_vault_format::{PASSKEY_CREDENTIAL_ID_BYTES, PasskeyCreationState};

use crate::{
    errors::{AccountError, StorageError},
    lifecycle::{OperationPermit, VaultAgent, unix_time_ms},
    sqlite::{GuardedVault, apply_record_mutation, read_guarded_vault},
};

struct AuthenticatedSnapshot {
    header: Vec<u8>,
    manifest: Vec<u8>,
    records: Vec<EncryptedRecord>,
}

impl VaultAgent {
    /// Creates one vault-backed passkey using an authenticated snapshot.
    ///
    /// # Errors
    ///
    /// Returns the same bounded categories as the request-aware variant.
    pub fn add_passkey(
        &mut self,
        input: PasskeyInput,
        excluded_credential_ids: &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]],
    ) -> Result<PasskeyCredential, AccountError> {
        self.add_passkey_with_before_commit_and_check(
            input,
            excluded_credential_ids,
            PasskeyCreationState::Confirmed,
            || false,
            || Ok(()),
        )
    }

    /// Signs one exact passkey assertion and durably advances its counter.
    ///
    /// # Errors
    ///
    /// Returns the same bounded categories as the request-aware variant.
    pub fn sign_passkey_assertion(
        &mut self,
        rp_id: &str,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        client_data_hash: &[u8; 32],
    ) -> Result<PasskeyAssertion, AccountError> {
        self.sign_passkey_assertion_with_before_commit_and_check(
            rp_id,
            credential_id,
            client_data_hash,
            || false,
            || Ok(()),
        )
    }

    /// Deletes one vault-backed passkey.
    ///
    /// # Errors
    ///
    /// Returns the same bounded categories as the request-aware variant.
    pub fn delete_passkey(
        &mut self,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
    ) -> Result<(), AccountError> {
        self.delete_passkey_with_before_commit_and_check(credential_id, || false, || Ok(()))
    }

    /// Lists public passkey metadata matching one exact RP and allow-list.
    /// An empty slice is discoverable for this direct API; the request-aware
    /// variant separately preserves whether Windows supplied an allow-list.
    ///
    /// # Errors
    ///
    /// Returns `Locked` without touching storage and fails closed on malformed,
    /// stale, or unauthenticated state.
    pub fn list_passkeys_for_assertion(
        &mut self,
        rp_id: &str,
        allowed_credential_ids: &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]],
    ) -> Result<Vec<PasskeySummary>, AccountError> {
        self.list_passkeys_for_assertion_with_check(
            rp_id,
            allowed_credential_ids,
            !allowed_credential_ids.is_empty(),
            || false,
        )
    }

    /// Lists public metadata for every vault-backed passkey.
    ///
    /// # Errors
    ///
    /// Returns `Locked` without touching storage and fails closed on malformed,
    /// stale, or unauthenticated state.
    pub fn list_passkeys(&mut self) -> Result<Vec<PasskeySummary>, AccountError> {
        self.list_passkeys_with_check(|| false)
    }

    pub(crate) fn list_passkeys_with_check(
        &mut self,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<Vec<PasskeySummary>, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_passkeys_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                should_cancel,
            )
        };
        let passkeys = self.map_read(result)?;
        if !self.operation_is_authorized(permit) {
            drop(passkeys);
            return Err(AccountError::Locked);
        }
        Ok(passkeys)
    }

    pub(crate) fn list_passkeys_for_assertion_with_check(
        &mut self,
        rp_id: &str,
        allowed_credential_ids: &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]],
        allow_list_present: bool,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<Vec<PasskeySummary>, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_passkeys_for_assertion_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                rp_id,
                allow_list_present.then_some(allowed_credential_ids),
                should_cancel,
            )
        };
        let passkeys = self.map_read(result)?;
        if !self.operation_is_authorized(permit) {
            drop(passkeys);
            return Err(AccountError::Locked);
        }
        Ok(passkeys)
    }

    /// Creates and durably stores one vault-backed passkey.
    ///
    /// # Errors
    ///
    /// Returns `Locked` without touching storage, `Conflict` when an excluded
    /// credential exists, and a uniform failure for capacity, integrity, or
    /// storage errors. Cancellation is checked throughout authentication and
    /// before the atomic commit.
    pub(crate) fn add_passkey_with_before_commit_and_check(
        &mut self,
        input: PasskeyInput,
        excluded_credential_ids: &[[u8; PASSKEY_CREDENTIAL_ID_BYTES]],
        creation_state: PasskeyCreationState,
        mut should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<PasskeyCredential, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_add_passkey_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                input,
                excluded_credential_ids,
                creation_state,
                committed_at_ms,
                &mut should_cancel,
            )
        };
        let (prepared, credential) = self.map_preparation_pair(result)?;
        if should_cancel() {
            return Err(AccountError::Aborted);
        }
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(credential)
    }

    pub(crate) fn pending_passkey_credential_ids_with_check(
        &mut self,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<Vec<[u8; PASSKEY_CREDENTIAL_ID_BYTES]>, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_pending_passkey_credential_ids_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                should_cancel,
            )
        };
        let credential_ids = self.map_read(result)?;
        if !self.operation_is_authorized(permit) {
            return Err(AccountError::Locked);
        }
        Ok(credential_ids)
    }

    pub(crate) fn confirm_passkey_creation_with_before_commit_and_check(
        &mut self,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        mut should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_confirm_passkey_creation_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                credential_id,
                committed_at_ms,
                &mut should_cancel,
            )
        };
        let prepared = self.map_preparation(result)?;
        if should_cancel() {
            return Err(AccountError::Aborted);
        }
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(())
    }

    /// Produces a transaction-bound assertion and commits its signature count.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only after complete authentication, `Conflict` for
    /// an exact RP mismatch, and no signature when lock or cancellation wins.
    pub(crate) fn sign_passkey_assertion_with_before_commit_and_check(
        &mut self,
        rp_id: &str,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        client_data_hash: &[u8; 32],
        mut should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<PasskeyAssertion, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_passkey_assertion_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                rp_id,
                credential_id,
                client_data_hash,
                committed_at_ms,
                &mut should_cancel,
            )
        };
        let (prepared, assertion) = self.map_preparation_pair(result)?;
        if should_cancel() {
            return Err(AccountError::Aborted);
        }
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(assertion)
    }

    /// Deletes one passkey by public credential identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only for an authenticated snapshot and fails closed
    /// on lock, cancellation, corruption, or storage conflict.
    pub(crate) fn delete_passkey_with_before_commit_and_check(
        &mut self,
        credential_id: &[u8; PASSKEY_CREDENTIAL_ID_BYTES],
        mut should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_delete_passkey_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                credential_id,
                committed_at_ms,
                &mut should_cancel,
            )
        };
        let prepared = self.map_preparation(result)?;
        if should_cancel() {
            return Err(AccountError::Aborted);
        }
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(())
    }

    /// Adds one encrypted website account and atomically commits its manifest.
    ///
    /// # Errors
    ///
    /// Returns `Locked` when no unlocked session exists. Every storage,
    /// cryptographic, integrity, conflict, or clock failure returns `Failed`
    /// and invalidates the current session.
    pub fn add_website_account(
        &mut self,
        input: WebsiteAccountInput,
    ) -> Result<RecordId, AccountError> {
        self.add_website_account_with_before_commit(input, || Ok(()))
    }

    /// Retrieves one account only after the complete current snapshot
    /// authenticates.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only for an authenticated snapshot. Corruption or
    /// stale state returns `Failed` and locks the agent.
    pub fn get_website_account(&mut self, id: RecordId) -> Result<WebsiteAccount, AccountError> {
        self.get_website_account_with_before_return(id, |_| {})
    }

    /// Lists every account only after the complete current snapshot
    /// authenticates.
    ///
    /// # Errors
    ///
    /// Returns `Locked` without touching storage. Corruption or stale state
    /// returns `Failed` and locks the agent.
    pub fn list_website_accounts(&mut self) -> Result<Vec<WebsiteAccount>, AccountError> {
        self.list_website_accounts_with_before_return(|_| {})
    }

    /// Authenticates the complete snapshot while retaining at most `limit`
    /// decrypted accounts.
    ///
    /// # Errors
    ///
    /// Returns `Locked` without touching storage. Corruption, stale state, or
    /// an invalid page range returns `Failed` and locks the agent.
    pub fn list_website_account_page(
        &mut self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<WebsiteAccount>, bool), AccountError> {
        self.list_website_account_page_with_check(offset, limit, || false)
    }

    pub(crate) fn list_website_account_page_with_check(
        &mut self,
        offset: usize,
        limit: usize,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<(Vec<WebsiteAccount>, bool), AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_website_account_page_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                offset,
                limit,
                should_cancel,
            )
        };
        let page = self.map_read(result)?;
        if !self.operation_is_authorized(permit) {
            drop(page);
            return Err(AccountError::Locked);
        }
        Ok(page)
    }

    /// Replaces the user-authored fields of one authenticated account.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only for an authenticated snapshot. Every other
    /// unsuccessful mutation invalidates the current session.
    pub fn update_website_account(
        &mut self,
        id: RecordId,
        input: WebsiteAccountInput,
    ) -> Result<(), AccountError> {
        self.update_website_account_with_before_commit(id, input, || Ok(()))
    }

    pub(crate) fn update_website_account_with_before_commit(
        &mut self,
        id: RecordId,
        input: WebsiteAccountInput,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        self.update_website_account_with_before_commit_and_check(id, input, || false, before_commit)
    }

    pub(crate) fn update_website_account_with_before_commit_and_check(
        &mut self,
        id: RecordId,
        input: WebsiteAccountInput,
        should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_update_website_account_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                id,
                input,
                committed_at_ms,
                should_cancel,
            )
        };
        let prepared = self.map_preparation(prepared)?;
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(())
    }

    /// Deletes one authenticated account and its manifest commitment.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` only for an authenticated snapshot. Every other
    /// unsuccessful mutation invalidates the current session.
    pub fn delete_website_account(&mut self, id: RecordId) -> Result<(), AccountError> {
        self.delete_website_account_with_before_commit(id, || Ok(()))
    }

    pub(crate) fn delete_website_account_with_before_commit(
        &mut self,
        id: RecordId,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        self.delete_website_account_with_before_commit_and_check(id, || false, before_commit)
    }

    pub(crate) fn delete_website_account_with_before_commit_and_check(
        &mut self,
        id: RecordId,
        should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<(), AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_delete_website_account_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                id,
                committed_at_ms,
                should_cancel,
            )
        };
        let prepared = self.map_preparation(prepared)?;
        self.persist_mutation(permit, &snapshot, prepared, before_commit)?;
        Ok(())
    }

    pub(crate) fn add_website_account_with_before_commit(
        &mut self,
        input: WebsiteAccountInput,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<RecordId, AccountError> {
        self.add_website_account_with_before_commit_and_check(input, || false, before_commit)
    }

    pub(crate) fn add_website_account_with_before_commit_and_check(
        &mut self,
        input: WebsiteAccountInput,
        should_cancel: impl FnMut() -> bool,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<RecordId, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_add_website_account_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                input,
                committed_at_ms,
                should_cancel,
            )
        };
        let prepared = self.map_preparation(prepared)?;
        self.persist_mutation(permit, &snapshot, prepared, before_commit)
    }

    pub(crate) fn get_website_account_with_before_return(
        &mut self,
        id: RecordId,
        before_return: impl FnOnce(&mut Self),
    ) -> Result<WebsiteAccount, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.get_website_account(&snapshot.header, &snapshot.manifest, &snapshot.records, id)
        };
        let account = self.map_read(result)?;
        before_return(self);
        if !self.operation_is_authorized(permit) {
            drop(account);
            return Err(AccountError::Locked);
        }
        Ok(account)
    }

    pub(crate) fn get_website_account_with_check(
        &mut self,
        id: RecordId,
        should_cancel: impl FnMut() -> bool,
    ) -> Result<WebsiteAccount, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.get_website_account_with_check(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                id,
                should_cancel,
            )
        };
        let account = self.map_read(result)?;
        if !self.operation_is_authorized(permit) {
            drop(account);
            return Err(AccountError::Locked);
        }
        Ok(account)
    }

    pub(crate) fn list_website_accounts_with_before_return(
        &mut self,
        before_return: impl FnOnce(&mut Self),
    ) -> Result<Vec<WebsiteAccount>, AccountError> {
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_website_accounts(&snapshot.header, &snapshot.manifest, &snapshot.records)
        };
        let accounts = self.map_read(result)?;
        before_return(self);
        if !self.operation_is_authorized(permit) {
            drop(accounts);
            return Err(AccountError::Locked);
        }
        Ok(accounts)
    }

    fn require_operation(&self) -> Result<OperationPermit, AccountError> {
        self.begin_operation().ok_or(AccountError::Locked)
    }

    fn load_authenticated_snapshot(&mut self) -> Result<AuthenticatedSnapshot, AccountError> {
        let path = self.path.clone().ok_or(AccountError::Failed)?;
        let Ok(snapshot) = read_guarded_vault(&path) else {
            self.lock();
            return Err(AccountError::Failed);
        };
        let GuardedVault {
            header,
            manifest,
            records,
            input_guards,
        } = snapshot;
        let raw_state_matches = self
            .authenticated_header
            .as_ref()
            .is_some_and(|expected| expected == &header)
            && self
                .authenticated_manifest
                .as_ref()
                .is_some_and(|expected| expected == &manifest);
        drop(input_guards);
        if !raw_state_matches {
            self.lock();
            return Err(AccountError::Failed);
        }
        Ok(AuthenticatedSnapshot {
            header,
            manifest,
            records,
        })
    }

    fn persist_mutation(
        &mut self,
        permit: OperationPermit,
        snapshot: &AuthenticatedSnapshot,
        prepared: PreparedRecordMutation,
        before_commit: impl FnOnce() -> Result<(), StorageError>,
    ) -> Result<RecordId, AccountError> {
        if !self.operation_is_authorized(permit) {
            return Err(AccountError::Locked);
        }
        let path = self.path.clone().ok_or(AccountError::Failed)?;
        let next_manifest = prepared.manifest_envelope().to_vec();
        match apply_record_mutation(
            &path,
            &snapshot.header,
            &snapshot.manifest,
            &snapshot.records,
            &prepared,
            before_commit,
        ) {
            Ok(()) => {}
            Err(StorageError::Aborted) => return Err(AccountError::Aborted),
            Err(_) => {
                self.lock();
                return Err(AccountError::Failed);
            }
        }
        if !self.operation_is_authorized(permit) {
            self.lock();
            return Err(AccountError::Locked);
        }
        let id = self
            .session
            .as_mut()
            .ok_or(AccountError::Locked)?
            .commit_record_mutation(prepared)
            .map_err(|_| {
                self.lock();
                AccountError::Failed
            })?;
        self.authenticated_manifest = Some(next_manifest);
        Ok(id)
    }

    fn map_preparation(
        &mut self,
        result: Result<PreparedRecordMutation, RecordOperationError>,
    ) -> Result<PreparedRecordMutation, AccountError> {
        match result {
            Ok(prepared) => Ok(prepared),
            Err(RecordOperationError::NotFound) => Err(AccountError::NotFound),
            Err(RecordOperationError::Conflict) => Err(AccountError::Conflict),
            Err(RecordOperationError::Cancelled) => Err(AccountError::Aborted),
            Err(RecordOperationError::Failed) => {
                self.lock();
                Err(AccountError::Failed)
            }
        }
    }

    fn map_preparation_pair<T>(
        &mut self,
        result: Result<(PreparedRecordMutation, T), RecordOperationError>,
    ) -> Result<(PreparedRecordMutation, T), AccountError> {
        match result {
            Ok(value) => Ok(value),
            Err(RecordOperationError::NotFound) => Err(AccountError::NotFound),
            Err(RecordOperationError::Conflict) => Err(AccountError::Conflict),
            Err(RecordOperationError::Cancelled) => Err(AccountError::Aborted),
            Err(RecordOperationError::Failed) => {
                self.lock();
                Err(AccountError::Failed)
            }
        }
    }

    fn map_read<T>(&mut self, result: Result<T, RecordOperationError>) -> Result<T, AccountError> {
        match result {
            Ok(value) => Ok(value),
            Err(RecordOperationError::NotFound) => Err(AccountError::NotFound),
            Err(RecordOperationError::Conflict) => Err(AccountError::Conflict),
            Err(RecordOperationError::Cancelled) => Err(AccountError::Aborted),
            Err(RecordOperationError::Failed) => {
                self.lock();
                Err(AccountError::Failed)
            }
        }
    }
}
