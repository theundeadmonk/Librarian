#pragma once

#include "DesktopClient.h"

#include <memory>
#include <string>
#include <vector>

namespace librarian::windows
{
    enum class ShellState
    {
        FirstRun,
        Locked,
        Unlocking,
        Saving,
        Unlocked,
        Error,
        AgentUnavailable,
    };

    class ShellViewModel final
    {
    public:
        explicit ShellViewModel(std::shared_ptr<IDesktopClient> client);

        [[nodiscard]] bool BeginInitialize();
        void CompleteInitialize();

        [[nodiscard]] bool BeginRetry();
        void CompleteRetry();

        [[nodiscard]] bool BeginCreate();
        void CompleteCreate(SecretText const& master_password);

        [[nodiscard]] bool BeginUnlock();
        void CompleteUnlock(SecretText const& master_password);

        [[nodiscard]] bool BeginLock();
        void CompleteLock();

        void ShowAccountEditor();
        void CancelAccountEditor();
        [[nodiscard]] bool BeginSaveAccount();
        void CompleteSaveAccount(AccountDraft const& account);
        void Close() noexcept;

        [[nodiscard]] ShellState State() const noexcept;
        [[nodiscard]] std::wstring const& Message() const noexcept;
        [[nodiscard]] std::vector<AccountSummary> const& Accounts() const noexcept;
        [[nodiscard]] bool IsAccountEditorVisible() const noexcept;
        [[nodiscard]] bool IsLockRequestPending() const noexcept;

    private:
        enum class PendingAction
        {
            None,
            Initialize,
            RetryStatus,
            Create,
            Unlock,
            Lock,
            SaveAccount,
        };

        [[nodiscard]] bool BeginStatusRequest(PendingAction action);
        void CompleteStatusRequest(PendingAction action);
        [[nodiscard]] bool BeginLockRequest();
        void ApplyLockFailure(ClientError error);
        void Apply(ClientResult const& result);
        void ApplyError(ClientError error);
        void SetVaultStatus(VaultStatus status);
        void LoadAccounts();

        std::shared_ptr<IDesktopClient> client_;
        ShellState state_{ ShellState::AgentUnavailable };
        ShellState resume_state_{ ShellState::Locked };
        PendingAction pending_action_{ PendingAction::None };
        std::wstring message_;
        std::vector<AccountSummary> accounts_;
        bool account_editor_visible_{ false };
        bool lock_intent_pending_{ false };
    };
}
