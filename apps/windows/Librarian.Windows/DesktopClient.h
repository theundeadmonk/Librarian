#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace librarian::windows
{
    enum class ClientError
    {
        None,
        AgentUnavailable,
        Busy,
        Cancelled,
        InvalidCredentials,
        Locked,
        Unexpected,
    };

    enum class VaultStatus
    {
        FirstRun,
        Locked,
        Unlocked,
    };

    struct ClientResult
    {
        ClientError error{ ClientError::None };
        VaultStatus status{ VaultStatus::Locked };
    };

    struct AccountSummary
    {
        std::wstring id;
        std::wstring service_name;
        std::wstring origin;
        std::wstring username;
    };

    struct AccountListResult
    {
        ClientError error{ ClientError::None };
        std::vector<AccountSummary> accounts;
    };

    class SecretText final
    {
    public:
        SecretText() = default;
        explicit SecretText(std::wstring_view value);
        ~SecretText() noexcept;

        SecretText(SecretText const&) = delete;
        SecretText& operator=(SecretText const&) = delete;

        SecretText(SecretText&& other) noexcept;
        SecretText& operator=(SecretText&& other) noexcept;

        [[nodiscard]] bool empty() const noexcept;
        [[nodiscard]] std::wstring_view value() const noexcept;

    private:
        void Clear() noexcept;

        std::vector<wchar_t> value_;
    };

    struct AccountDraft
    {
        AccountDraft(
            std::wstring service_name,
            std::wstring origin,
            std::wstring username,
            SecretText password);

        AccountDraft(AccountDraft const&) = delete;
        AccountDraft& operator=(AccountDraft const&) = delete;
        AccountDraft(AccountDraft&&) noexcept = default;
        AccountDraft& operator=(AccountDraft&&) noexcept = default;

        std::wstring service_name;
        std::wstring origin;
        std::wstring username;
        SecretText password;
    };

    class IDesktopClient
    {
    public:
        virtual ~IDesktopClient() = default;

        [[nodiscard]] virtual ClientResult GetStatus() = 0;
        [[nodiscard]] virtual ClientResult CreateVault(SecretText const& master_password) = 0;
        [[nodiscard]] virtual ClientResult Unlock(SecretText const& master_password) = 0;
        [[nodiscard]] virtual ClientResult Lock() = 0;
        [[nodiscard]] virtual AccountListResult ListAccounts() = 0;
        [[nodiscard]] virtual ClientResult SaveAccount(AccountDraft const& account) = 0;
    };

    [[nodiscard]] std::shared_ptr<IDesktopClient> MakeDesktopClient();
}
