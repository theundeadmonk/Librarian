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
        constexpr wchar_t SavingMessage[] =
            L"Librarian is saving the account through the local vault agent.";
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
            L"Librarian could not confirm that the vault locked. Access remains hidden until status is rechecked.";
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

    void ShellViewModel::Initialize()
    {
        RefreshStatus();
    }

    void ShellViewModel::Retry()
    {
        RefreshStatus();
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

    void ShellViewModel::CompleteCreate(SecretText const& master_password)
    {
        if (pending_action_ != PendingAction::Create)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        if (master_password.empty())
        {
            state_ = ShellState::Error;
            message_ = UnexpectedMessage;
            return;
        }

        try
        {
            Apply(client_->CreateVault(master_password));
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
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

    void ShellViewModel::CompleteUnlock(SecretText const& master_password)
    {
        if (pending_action_ != PendingAction::Unlock)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        if (master_password.empty())
        {
            state_ = ShellState::Error;
            message_ = InvalidCredentialsMessage;
            return;
        }

        try
        {
            Apply(client_->Unlock(master_password));
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
    }

    void ShellViewModel::Lock()
    {
        if (state_ != ShellState::Unlocked)
        {
            return;
        }

        resume_state_ = state_;
        try
        {
            auto const result = client_->Lock();
            if (result.error == ClientError::Cancelled)
            {
                account_editor_visible_ = false;
                accounts_.clear();
                state_ = ShellState::Error;
                message_ = LockStatusUnknownMessage;
                return;
            }

            Apply(result);
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
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

    void ShellViewModel::CompleteSaveAccount(AccountDraft const& account)
    {
        if (pending_action_ != PendingAction::SaveAccount)
        {
            return;
        }

        pending_action_ = PendingAction::None;
        try
        {
            auto const result = client_->SaveAccount(account);
            if (result.error == ClientError::None)
            {
                account_editor_visible_ = false;
            }
            Apply(result);
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
    }

    void ShellViewModel::CancelPendingOperations() noexcept
    {
        client_->CancelPendingOperations();
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

    bool ShellViewModel::IsAccountEditorVisible() const noexcept
    {
        return account_editor_visible_;
    }

    void ShellViewModel::RefreshStatus()
    {
        resume_state_ = state_;
        pending_action_ = PendingAction::None;
        account_editor_visible_ = false;

        try
        {
            Apply(client_->GetStatus());
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
    }

    void ShellViewModel::Apply(ClientResult const& result)
    {
        if (result.error != ClientError::None)
        {
            ApplyError(result.error);
            return;
        }

        SetVaultStatus(result.status);
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
            }
            return;
        }

        account_editor_visible_ = false;
        accounts_.clear();

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

        switch (status)
        {
        case VaultStatus::FirstRun:
            state_ = ShellState::FirstRun;
            message_ = FirstRunMessage;
            break;
        case VaultStatus::Locked:
            state_ = ShellState::Locked;
            message_ = LockedMessage;
            break;
        case VaultStatus::Unlocked:
            state_ = ShellState::Unlocked;
            message_.clear();
            resume_state_ = state_;
            LoadAccounts();
            break;
        }
    }

    void ShellViewModel::LoadAccounts()
    {
        try
        {
            auto result = client_->ListAccounts();
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
            if (accounts_.empty())
            {
                message_ = EmptyAccountsMessage;
            }
        }
        catch (...)
        {
            ApplyError(ClientError::Unexpected);
        }
    }
}
