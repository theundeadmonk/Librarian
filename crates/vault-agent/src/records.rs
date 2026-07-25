use librarian_vault_core::{
    EncryptedRecord, PreparedRecordMutation, RecordId, RecordOperationError, WebsiteAccount,
    WebsiteAccountInput,
};

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
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let result = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.list_website_account_page(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                offset,
                limit,
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
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_update_website_account(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                id,
                input,
                committed_at_ms,
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
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_delete_website_account(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                id,
                committed_at_ms,
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
        let permit = self.require_operation()?;
        let snapshot = self.load_authenticated_snapshot()?;
        let committed_at_ms = unix_time_ms().map_err(|_| {
            self.lock();
            AccountError::Failed
        })?;
        let prepared = {
            let session = self.session.as_ref().ok_or(AccountError::Locked)?;
            session.prepare_add_website_account(
                &snapshot.header,
                &snapshot.manifest,
                &snapshot.records,
                input,
                committed_at_ms,
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
            Err(RecordOperationError::Failed) => {
                self.lock();
                Err(AccountError::Failed)
            }
        }
    }
}
