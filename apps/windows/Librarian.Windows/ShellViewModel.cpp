#include "ShellViewModel.h"

#include <stdexcept>
#include <utility>

namespace librarian::windows
{
    namespace
    {
        constexpr wchar_t FirstRunMessage[] =
            L"Create a local vault to get started.";
        constexpr wchar_t LockedMessage[] =
            L"Unlock Librarian with your master password.";
        constexpr wchar_t UnlockingMessage[] =
            L"Librarian is completing a security-sensitive request.";
        constexpr wchar_t WindowsHelloMessage[] =
            L"Complete the Windows Hello prompt to continue.";
        constexpr wchar_t WindowsHelloFallbackMessage[] =
            L"Windows Hello could not complete the request. The vault is unchanged, and your master password still works.";
        constexpr wchar_t WindowsHelloCancelledMessage[] =
            L"Windows Hello was canceled. The vault is unchanged, and your master password still works.";
        constexpr wchar_t WindowsHelloEnrolledMessage[] =
            L"Windows Hello unlock is enabled. Your master password remains available.";
        constexpr wchar_t WindowsHelloRemovedMessage[] =
            L"Windows Hello unlock was removed. Your master password and vault are unchanged.";
        constexpr wchar_t LockingMessage[] =
            L"Librarian is locking the vault through the local vault agent.";
        constexpr wchar_t SavingMessage[] =
            L"Librarian is saving the account through the local vault agent.";
        constexpr wchar_t DeletingPasskeyMessage[] =
            L"Librarian is removing the passkey from Windows and the local vault.";
        constexpr wchar_t LoadingAccountsMessage[] =
            L"Librarian is loading the requested account page.";
        constexpr wchar_t EmptyAccountsMessage[] =
            L"No accounts are stored in this vault yet.";
        constexpr wchar_t AgentUnavailableMessage[] =
            L"The vault agent is unavailable. Start or repair Librarian, then try again.";
        constexpr wchar_t BusyMessage[] =
            L"Librarian is busy with another security transition. Try again.";
        constexpr wchar_t CancelledMessage[] =
            L"The request was canceled.";
        constexpr wchar_t InvalidCredentialsMessage[] =
            L"Librarian could not complete that request. Check your password and try again.";
        constexpr wchar_t LockedDuringRequestMessage[] =
            L"The vault locked before the request completed.";
        constexpr wchar_t LockStatusUnknownMessage[] =
            L"Librarian could not confirm that the vault locked. Access remains hidden until the vault confirms it is locked.";
        constexpr wchar_t AccountLoadCancelledMessage[] =
            L"Librarian could not confirm the account list. Retry vault status.";
        constexpr wchar_t UnexpectedMessage[] =
            L"Librarian could not complete the request. No changes were made.";
    }

    ShellViewModel::ShellViewModel(std::shared_ptr<IDesktopClient> client) :
        client_(std::move(client))
    {
        if (!client_)
        {
            throw std::invalid_argument("desktop client is required");
        }
    }

    bool ShellViewModel::BeginInitialize()
    {
        return BeginStatusRequest(PendingAction::Initialize);
    }

    void ShellViewModel::CompleteInitialize(ShellRequestOutcome outcome)
    {
        CompleteStatusRequest(PendingAction::Initialize, std::move(outcome));
    }

    bool ShellViewModel::BeginRetry()
    {
        if (state_ != ShellState::Error && state_ != ShellState::AgentUnavailable)
        {
            return false;
        }

        if (lock_intent_pending_)
        {
            return BeginLockRequest();
        }

        return BeginStatusRequest(PendingAction::RetryStatus);
    }

    void ShellViewModel::CompleteRetry(ShellRequestOutcome outcome)
    {
        if (pending_action_ == PendingAction::Lock)
        {
            CompleteLock(std::move(outcome));
            return;
        }

        CompleteStatusRequest(PendingAction::RetryStatus, std::move(outcome));
    }

    bool ShellViewModel::BeginRefresh()
    {
        return BeginStatusRequest(PendingAction::RefreshStatus);
    }

    void ShellViewModel::CompleteRefresh(ShellRequestOutcome outcome)
    {
        CompleteStatusRequest(PendingAction::RefreshStatus, std::move(outcome));
    }

    bool ShellViewModel::BeginCreate()
    {
        if (state_ != ShellState::FirstRun)
        {
            return false;
        }

        resume_state_ = state_;
        pending_action_ = PendingAction::Create;
        state_ = ShellState::Unlocking;
        message_ = UnlockingMessage;
        return true;
    }

    void ShellViewModel::CompleteCreate(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::Create)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        Apply(std::move(outcome));
    }

    bool ShellViewModel::BeginUnlock()
    {
        if (state_ != ShellState::Locked)
        {
            return false;
        }

        resume_state_ = state_;
        pending_action_ = PendingAction::Unlock;
        state_ = ShellState::Unlocking;
        message_ = UnlockingMessage;
        return true;
    }

    void ShellViewModel::CompleteUnlock(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::Unlock)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        Apply(std::move(outcome));
    }

    bool ShellViewModel::BeginWindowsHelloUnlock()
    {
        if (state_ != ShellState::Locked)
        {
            return false;
        }
        return BeginWindowsHelloRequest(PendingAction::UnlockWindowsHello);
    }

    void ShellViewModel::CompleteWindowsHelloUnlock(ShellRequestOutcome outcome)
    {
        CompleteWindowsHelloRequest(
            PendingAction::UnlockWindowsHello,
            std::move(outcome));
    }

    bool ShellViewModel::BeginWindowsHelloEnrollment()
    {
        if (state_ != ShellState::Unlocked)
        {
            return false;
        }
        return BeginWindowsHelloRequest(PendingAction::EnrollWindowsHello);
    }

    void ShellViewModel::CompleteWindowsHelloEnrollment(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::EnrollWindowsHello)
        {
            return;
        }
        bool const succeeded = outcome.request.error == ClientError::None &&
            outcome.request.status == VaultStatus::Unlocked;
        CompleteWindowsHelloRequest(
            PendingAction::EnrollWindowsHello,
            std::move(outcome));
        if (succeeded && state_ == ShellState::Unlocked)
        {
            message_ = WindowsHelloEnrolledMessage;
        }
    }

    bool ShellViewModel::BeginWindowsHelloRemoval()
    {
        if (state_ != ShellState::Unlocked)
        {
            return false;
        }
        return BeginWindowsHelloRequest(PendingAction::RemoveWindowsHello);
    }

    void ShellViewModel::CompleteWindowsHelloRemoval(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::RemoveWindowsHello)
        {
            return;
        }
        bool const succeeded = outcome.request.error == ClientError::None &&
            outcome.request.status == VaultStatus::Unlocked;
        CompleteWindowsHelloRequest(
            PendingAction::RemoveWindowsHello,
            std::move(outcome));
        if (succeeded && state_ == ShellState::Unlocked)
        {
            message_ = WindowsHelloRemovedMessage;
        }
    }

    bool ShellViewModel::BeginLock()
    {
        if (
            state_ != ShellState::Unlocked ||
            pending_action_ != PendingAction::None)
        {
            return false;
        }

        lock_intent_pending_ = true;
        return BeginLockRequest();
    }

    void ShellViewModel::CompleteLock(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::Lock)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        auto const& result = outcome.request;
        if (
            (result.error == ClientError::None &&
                result.status == VaultStatus::Locked) ||
            result.error == ClientError::Locked)
        {
            lock_intent_pending_ = false;
            SetVaultStatus(VaultStatus::Locked);
            return;
        }

        ApplyLockFailure(result.error);
    }

    void ShellViewModel::ShowAccountEditor()
    {
        if (state_ == ShellState::Unlocked)
        {
            account_editor_visible_ = true;
        }
    }

    void ShellViewModel::CancelAccountEditor()
    {
        account_editor_visible_ = false;
    }

    bool ShellViewModel::BeginSaveAccount()
    {
        if (state_ != ShellState::Unlocked || !account_editor_visible_)
        {
            return false;
        }

        resume_state_ = state_;
        pending_action_ = PendingAction::SaveAccount;
        state_ = ShellState::Saving;
        message_ = SavingMessage;
        return true;
    }

    void ShellViewModel::CompleteSaveAccount(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::SaveAccount)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        if (outcome.request.error == ClientError::None)
        {
            account_editor_visible_ = false;
        }
        Apply(std::move(outcome));
    }

    bool ShellViewModel::BeginDeletePasskey()
    {
        if (state_ != ShellState::Unlocked || pending_action_ != PendingAction::None)
        {
            return false;
        }
        resume_state_ = state_;
        pending_action_ = PendingAction::DeletePasskey;
        account_editor_visible_ = false;
        state_ = ShellState::Saving;
        message_ = DeletingPasskeyMessage;
        return true;
    }

    void ShellViewModel::CompleteDeletePasskey(ShellRequestOutcome outcome)
    {
        if (pending_action_ != PendingAction::DeletePasskey)
        {
            return;
        }
        pending_action_ = PendingAction::None;
        Apply(std::move(outcome));
    }

    std::optional<std::uint32_t> ShellViewModel::BeginNextAccountPage()
    {
        if (!next_account_offset_.has_value())
        {
            return std::nullopt;
        }
        return BeginAccountPageRequest(
            PendingAction::NextAccountPage,
            *next_account_offset_);
    }

    std::optional<std::uint32_t> ShellViewModel::BeginPreviousAccountPage()
    {
        if (previous_account_offsets_.empty())
        {
            return std::nullopt;
        }
        return BeginAccountPageRequest(
            PendingAction::PreviousAccountPage,
            previous_account_offsets_.back());
    }

    void ShellViewModel::CompleteNextAccountPage(AccountListResult result)
    {
        CompleteAccountPageRequest(PendingAction::NextAccountPage, std::move(result));
    }

    void ShellViewModel::CompletePreviousAccountPage(AccountListResult result)
    {
        CompleteAccountPageRequest(
            PendingAction::PreviousAccountPage,
            std::move(result));
    }

    ShellRequestOutcome ShellViewModel::ExecuteStatusRequest() const
    {
        try
        {
            return AddAccountRefresh(client_->GetStatus());
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteCreateRequest(
        SecretText const& master_password) const
    {
        if (master_password.empty())
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }

        try
        {
            return AddAccountRefresh(client_->CreateVault(master_password));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteUnlockRequest(
        SecretText const& master_password) const
    {
        if (master_password.empty())
        {
            return {
                { ClientError::InvalidCredentials, VaultStatus::Locked },
                std::nullopt,
            };
        }

        try
        {
            return AddAccountRefresh(client_->Unlock(master_password));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteWindowsHelloUnlockRequest(
        std::uintptr_t const parent_window) const
    {
        try
        {
            return AddAccountRefresh(client_->UnlockWindowsHello(parent_window));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteWindowsHelloEnrollmentRequest(
        std::uintptr_t const parent_window) const
    {
        try
        {
            return AddAccountRefresh(client_->EnrollWindowsHello(parent_window));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteWindowsHelloRemovalRequest() const
    {
        try
        {
            return AddAccountRefresh(client_->RemoveWindowsHello());
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteLockRequest() const
    {
        try
        {
            return { client_->Lock(), std::nullopt };
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteSaveAccountRequest(
        AccountDraft const& account) const
    {
        try
        {
            return AddAccountRefresh(client_->SaveAccount(account));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt };
        }
    }

    AccountListResult ShellViewModel::ExecuteAccountPageRequest(
        std::uint32_t const offset) const
    {
        try
        {
            return client_->ListAccounts(offset);
        }
        catch (...)
        {
            return { ClientError::Unexpected, {} };
        }
    }

    ShellRequestOutcome ShellViewModel::ExecuteDeletePasskeyRequest(
        std::wstring_view const credential_id) const
    {
        try
        {
            return AddAccountRefresh(client_->DeletePasskey(credential_id));
        }
        catch (...)
        {
            return { { ClientError::Unexpected, VaultStatus::Locked }, std::nullopt, std::nullopt };
        }
    }

    void ShellViewModel::Close() noexcept
    {
        client_->Close();
    }

    ShellState ShellViewModel::State() const noexcept
    {
        return state_;
    }

    std::wstring const& ShellViewModel::Message() const noexcept
    {
        return message_;
    }

    std::vector<AccountSummary> const& ShellViewModel::Accounts() const noexcept
    {
        return accounts_;
    }

    std::vector<PasskeySummary> const& ShellViewModel::Passkeys() const noexcept
    {
        return passkeys_;
    }

    bool ShellViewModel::IsAccountEditorVisible() const noexcept
    {
        return account_editor_visible_;
    }

    bool ShellViewModel::IsLockRequestPending() const noexcept
    {
        return pending_action_ == PendingAction::Lock;
    }

    bool ShellViewModel::HasNextAccountPage() const noexcept
    {
        return next_account_offset_.has_value();
    }

    bool ShellViewModel::HasPreviousAccountPage() const noexcept
    {
        return !previous_account_offsets_.empty();
    }

    bool ShellViewModel::BeginStatusRequest(PendingAction const action)
    {
        if (pending_action_ != PendingAction::None)
        {
            return false;
        }

        resume_state_ = state_;
        pending_action_ = action;
        account_editor_visible_ = false;
        accounts_.clear();
        passkeys_.clear();
        state_ = ShellState::Unlocking;
        message_ = UnlockingMessage;
        return true;
    }

    bool ShellViewModel::BeginWindowsHelloRequest(PendingAction const action)
    {
        if (pending_action_ != PendingAction::None)
        {
            return false;
        }
        resume_state_ = state_;
        pending_action_ = action;
        account_editor_visible_ = false;
        state_ = ShellState::Unlocking;
        message_ = WindowsHelloMessage;
        return true;
    }

    void ShellViewModel::CompleteWindowsHelloRequest(
        PendingAction const action,
        ShellRequestOutcome outcome)
    {
        if (pending_action_ != action)
        {
            return;
        }
        bool const cancelled = outcome.request.error == ClientError::Cancelled;
        pending_action_ = PendingAction::None;
        Apply(std::move(outcome));
        if (cancelled)
        {
            message_ = WindowsHelloCancelledMessage;
        }
    }

    void ShellViewModel::CompleteStatusRequest(
        PendingAction const action,
        ShellRequestOutcome outcome)
    {
        if (pending_action_ != action)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        Apply(std::move(outcome));
    }

    bool ShellViewModel::BeginLockRequest()
    {
        if (pending_action_ != PendingAction::None)
        {
            return false;
        }

        resume_state_ = state_;
        pending_action_ = PendingAction::Lock;
        account_editor_visible_ = false;
        accounts_.clear();
        state_ = ShellState::Unlocking;
        message_ = LockingMessage;
        return true;
    }

    std::optional<std::uint32_t> ShellViewModel::BeginAccountPageRequest(
        PendingAction const action,
        std::uint32_t const offset)
    {
        if (
            state_ != ShellState::Unlocked ||
            pending_action_ != PendingAction::None)
        {
            return std::nullopt;
        }

        resume_state_ = state_;
        pending_action_ = action;
        pending_account_offset_ = offset;
        account_editor_visible_ = false;
        accounts_.clear();
        state_ = ShellState::Unlocking;
        message_ = LoadingAccountsMessage;
        return offset;
    }

    void ShellViewModel::CompleteAccountPageRequest(
        PendingAction const action,
        AccountListResult result)
    {
        if (pending_action_ != action || !pending_account_offset_.has_value())
        {
            return;
        }

        auto const offset = *pending_account_offset_;
        pending_action_ = PendingAction::None;
        pending_account_offset_.reset();
        if (result.error != ClientError::None)
        {
            ApplyAccounts(std::move(result));
            return;
        }

        if (action == PendingAction::NextAccountPage)
        {
            previous_account_offsets_.push_back(current_account_offset_);
        }
        else
        {
            previous_account_offsets_.pop_back();
        }
        current_account_offset_ = offset;
        state_ = ShellState::Unlocked;
        message_.clear();
        accounts_ = std::move(result.accounts);
        next_account_offset_ = result.next_offset;
        if (accounts_.empty())
        {
            message_ = EmptyAccountsMessage;
        }
    }

    ShellRequestOutcome ShellViewModel::AddAccountRefresh(ClientResult result) const
    {
        ShellRequestOutcome outcome{ result, std::nullopt, std::nullopt };
        if (
            result.error != ClientError::None ||
            result.status != VaultStatus::Unlocked)
        {
            return outcome;
        }

        try
        {
            outcome.accounts = client_->ListAccounts(0U);
        }
        catch (...)
        {
            outcome.accounts = AccountListResult{ ClientError::Unexpected, {} };
        }
        try
        {
            outcome.passkeys = client_->ListPasskeys();
        }
        catch (...)
        {
            outcome.passkeys = PasskeyListResult{ ClientError::Unexpected, {} };
        }
        return outcome;
    }

    void ShellViewModel::ApplyLockFailure(ClientError const error)
    {
        account_editor_visible_ = false;
        accounts_.clear();
        passkeys_.clear();

        if (error == ClientError::AgentUnavailable)
        {
            state_ = ShellState::AgentUnavailable;
            message_ = AgentUnavailableMessage;
            return;
        }

        state_ = ShellState::Error;
        message_ = LockStatusUnknownMessage;
    }

    void ShellViewModel::Apply(ShellRequestOutcome outcome)
    {
        if (outcome.request.error != ClientError::None)
        {
            ApplyError(outcome.request.error);
            return;
        }

        SetVaultStatus(outcome.request.status);
        if (state_ != ShellState::Unlocked)
        {
            return;
        }

        if (!outcome.accounts.has_value() || !outcome.passkeys.has_value())
        {
            ApplyError(ClientError::Unexpected);
            return;
        }

        ApplyAccounts(std::move(*outcome.accounts));
        if (state_ == ShellState::Unlocked)
        {
            ApplyPasskeys(std::move(*outcome.passkeys));
        }
    }

    void ShellViewModel::ApplyAccounts(AccountListResult result)
    {
        if (result.error != ClientError::None)
        {
            if (result.error == ClientError::Cancelled)
            {
                account_editor_visible_ = false;
                accounts_.clear();
                state_ = ShellState::Error;
                message_ = AccountLoadCancelledMessage;
                return;
            }

            ApplyError(result.error);
            return;
        }

        accounts_ = std::move(result.accounts);
        current_account_offset_ = 0U;
        previous_account_offsets_.clear();
        next_account_offset_ = result.next_offset;
        if (accounts_.empty())
        {
            message_ = EmptyAccountsMessage;
        }
    }

    void ShellViewModel::ApplyPasskeys(PasskeyListResult result)
    {
        if (result.error != ClientError::None)
        {
            ApplyError(result.error);
            return;
        }
        passkeys_ = std::move(result.passkeys);
    }

    void ShellViewModel::ApplyError(ClientError const error)
    {
        if (error == ClientError::Cancelled)
        {
            state_ = resume_state_;
            message_ = CancelledMessage;
            if (state_ != ShellState::Unlocked)
            {
                account_editor_visible_ = false;
                accounts_.clear();
                passkeys_.clear();
            }
            return;
        }

        if (error == ClientError::WindowsHelloUnavailable)
        {
            state_ = resume_state_;
            message_ = WindowsHelloFallbackMessage;
            if (state_ != ShellState::Unlocked)
            {
                account_editor_visible_ = false;
                accounts_.clear();
                passkeys_.clear();
            }
            return;
        }

        account_editor_visible_ = false;
        accounts_.clear();
        passkeys_.clear();

        switch (error)
        {
        case ClientError::None:
            SetVaultStatus(VaultStatus::Locked);
            break;
        case ClientError::AgentUnavailable:
            state_ = ShellState::AgentUnavailable;
            message_ = AgentUnavailableMessage;
            break;
        case ClientError::Busy:
            state_ = ShellState::Error;
            message_ = BusyMessage;
            break;
        case ClientError::Cancelled:
            break;
        case ClientError::InvalidCredentials:
            state_ = ShellState::Locked;
            message_ = InvalidCredentialsMessage;
            break;
        case ClientError::WindowsHelloUnavailable:
            break;
        case ClientError::Locked:
            state_ = ShellState::Locked;
            message_ = LockedDuringRequestMessage;
            break;
        case ClientError::Unexpected:
            state_ = ShellState::Error;
            message_ = UnexpectedMessage;
            break;
        }
    }

    void ShellViewModel::SetVaultStatus(VaultStatus const status)
    {
        account_editor_visible_ = false;
        accounts_.clear();
        passkeys_.clear();
        pending_account_offset_.reset();
        current_account_offset_ = 0U;
        previous_account_offsets_.clear();
        next_account_offset_.reset();

        if (lock_intent_pending_ && status != VaultStatus::Locked)
        {
            state_ = ShellState::Error;
            message_ = LockStatusUnknownMessage;
            return;
        }

        switch (status)
        {
        case VaultStatus::FirstRun:
            state_ = ShellState::FirstRun;
            message_ = FirstRunMessage;
            break;
        case VaultStatus::Locked:
            lock_intent_pending_ = false;
            state_ = ShellState::Locked;
            message_ = LockedMessage;
            break;
        case VaultStatus::Unlocked:
            state_ = ShellState::Unlocked;
            message_.clear();
            resume_state_ = state_;
            break;
        }
    }
}
