#pragma once

#include "DesktopClient.h"

#include <memory>
#include <optional>
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

    struct ShellRequestOutcome
    {
        ClientResult request;
        std::optional<AccountListResult> accounts;
    };

    class ShellViewModel final
    {
    public:
        explicit ShellViewModel(std::shared_ptr<IDesktopClient> client);

        [[nodiscard]] bool BeginInitialize();
        void CompleteInitialize(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginRetry();
        void CompleteRetry(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginCreate();
        void CompleteCreate(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginUnlock();
        void CompleteUnlock(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginLock();
        void CompleteLock(ShellRequestOutcome outcome);

        void ShowAccountEditor();
        void CancelAccountEditor();
        [[nodiscard]] bool BeginSaveAccount();
        void CompleteSaveAccount(ShellRequestOutcome outcome);

        [[nodiscard]] ShellRequestOutcome ExecuteStatusRequest() const;
        [[nodiscard]] ShellRequestOutcome ExecuteCreateRequest(
            SecretText const& master_password) const;
        [[nodiscard]] ShellRequestOutcome ExecuteUnlockRequest(
            SecretText const& master_password) const;
        [[nodiscard]] ShellRequestOutcome ExecuteLockRequest() const;
        [[nodiscard]] ShellRequestOutcome ExecuteSaveAccountRequest(
            AccountDraft const& account) const;

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
        void CompleteStatusRequest(PendingAction action, ShellRequestOutcome outcome);
        [[nodiscard]] bool BeginLockRequest();
        [[nodiscard]] ShellRequestOutcome AddAccountRefresh(ClientResult result) const;
        void ApplyLockFailure(ClientError error);
        void Apply(ShellRequestOutcome outcome);
        void ApplyAccounts(AccountListResult result);
        void ApplyError(ClientError error);
        void SetVaultStatus(VaultStatus status);

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
