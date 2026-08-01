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

        [[nodiscard]] bool BeginRefresh();
        void CompleteRefresh(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginCreate();
        void CompleteCreate(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginUnlock();
        void CompleteUnlock(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginWindowsHelloUnlock();
        void CompleteWindowsHelloUnlock(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginWindowsHelloEnrollment();
        void CompleteWindowsHelloEnrollment(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginWindowsHelloRemoval();
        void CompleteWindowsHelloRemoval(ShellRequestOutcome outcome);

        [[nodiscard]] bool BeginLock();
        void CompleteLock(ShellRequestOutcome outcome);

        void ShowAccountEditor();
        void CancelAccountEditor();
        [[nodiscard]] bool BeginSaveAccount();
        void CompleteSaveAccount(ShellRequestOutcome outcome);
        [[nodiscard]] std::optional<std::uint32_t> BeginNextAccountPage();
        [[nodiscard]] std::optional<std::uint32_t> BeginPreviousAccountPage();
        void CompleteNextAccountPage(AccountListResult result);
        void CompletePreviousAccountPage(AccountListResult result);

        [[nodiscard]] ShellRequestOutcome ExecuteStatusRequest() const;
        [[nodiscard]] ShellRequestOutcome ExecuteCreateRequest(
            SecretText const& master_password) const;
        [[nodiscard]] ShellRequestOutcome ExecuteUnlockRequest(
            SecretText const& master_password) const;
        [[nodiscard]] ShellRequestOutcome ExecuteWindowsHelloUnlockRequest(
            std::uintptr_t parent_window) const;
        [[nodiscard]] ShellRequestOutcome ExecuteWindowsHelloEnrollmentRequest(
            std::uintptr_t parent_window) const;
        [[nodiscard]] ShellRequestOutcome ExecuteWindowsHelloRemovalRequest() const;
        [[nodiscard]] ShellRequestOutcome ExecuteLockRequest() const;
        [[nodiscard]] ShellRequestOutcome ExecuteSaveAccountRequest(
            AccountDraft const& account) const;
        [[nodiscard]] AccountListResult ExecuteAccountPageRequest(
            std::uint32_t offset) const;

        void Close() noexcept;

        [[nodiscard]] ShellState State() const noexcept;
        [[nodiscard]] std::wstring const& Message() const noexcept;
        [[nodiscard]] std::vector<AccountSummary> const& Accounts() const noexcept;
        [[nodiscard]] bool IsAccountEditorVisible() const noexcept;
        [[nodiscard]] bool IsLockRequestPending() const noexcept;
        [[nodiscard]] bool HasNextAccountPage() const noexcept;
        [[nodiscard]] bool HasPreviousAccountPage() const noexcept;

    private:
        enum class PendingAction
        {
            None,
            Initialize,
            RetryStatus,
            RefreshStatus,
            Create,
            Unlock,
            UnlockWindowsHello,
            EnrollWindowsHello,
            RemoveWindowsHello,
            Lock,
            SaveAccount,
            NextAccountPage,
            PreviousAccountPage,
        };

        [[nodiscard]] bool BeginStatusRequest(PendingAction action);
        [[nodiscard]] bool BeginWindowsHelloRequest(PendingAction action);
        void CompleteWindowsHelloRequest(PendingAction action, ShellRequestOutcome outcome);
        void CompleteStatusRequest(PendingAction action, ShellRequestOutcome outcome);
        [[nodiscard]] bool BeginLockRequest();
        [[nodiscard]] std::optional<std::uint32_t> BeginAccountPageRequest(
            PendingAction action,
            std::uint32_t offset);
        void CompleteAccountPageRequest(
            PendingAction action,
            AccountListResult result);
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
        std::optional<std::uint32_t> next_account_offset_;
        std::optional<std::uint32_t> pending_account_offset_;
        std::vector<std::uint32_t> previous_account_offsets_;
        std::uint32_t current_account_offset_{ 0U };
        bool account_editor_visible_{ false };
        bool lock_intent_pending_{ false };
    };
}
