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
        Unlocked,
        Error,
        AgentUnavailable,
    };

    class ShellViewModel final
    {
    public:
        explicit ShellViewModel(std::shared_ptr<IDesktopClient> client);

        void Initialize();
        void Retry();

        [[nodiscard]] bool BeginCreate();
        void CompleteCreate(SecretText const& master_password);

        [[nodiscard]] bool BeginUnlock();
        void CompleteUnlock(SecretText const& master_password);

        void Lock();

        void ShowAccountEditor();
        void CancelAccountEditor();
        void SaveAccount(AccountDraft const& account);

        [[nodiscard]] ShellState State() const noexcept;
        [[nodiscard]] std::wstring const& Message() const noexcept;
        [[nodiscard]] std::vector<AccountSummary> const& Accounts() const noexcept;
        [[nodiscard]] bool IsAccountEditorVisible() const noexcept;

    private:
        enum class PendingAction
        {
            None,
            Create,
            Unlock,
        };

        void RefreshStatus();
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
    };
}
