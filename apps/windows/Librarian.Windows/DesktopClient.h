#pragma once

#include <memory>
#include <cstdint>
#include <optional>
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
        WindowsHelloUnavailable,
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
        std::optional<std::uint32_t> next_offset;
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
        [[nodiscard]] virtual ClientResult UnlockWindowsHello(std::uintptr_t parent_window) = 0;
        [[nodiscard]] virtual ClientResult EnrollWindowsHello(std::uintptr_t parent_window) = 0;
        [[nodiscard]] virtual ClientResult RemoveWindowsHello() = 0;
        [[nodiscard]] virtual ClientResult Lock() = 0;
        [[nodiscard]] virtual AccountListResult ListAccounts(std::uint32_t offset) = 0;
        [[nodiscard]] virtual ClientResult SaveAccount(AccountDraft const& account) = 0;
        // Close is permanent and must linearize with request startup: an
        // in-flight request is cancelled and every later request fails closed.
        // It affects only this client connection and is not a global vault lock.
        virtual void Close() noexcept = 0;
    };

    [[nodiscard]] std::shared_ptr<IDesktopClient> MakeDesktopClient();
}
