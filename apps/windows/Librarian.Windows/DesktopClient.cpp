#include "DesktopClient.h"

#include <Windows.h>

#include <atomic>
#include <utility>

namespace librarian::windows
{
    namespace
    {
        class UnavailableDesktopClient final : public IDesktopClient
        {
        public:
            [[nodiscard]] ClientResult GetStatus() override
            {
                return ClosedOrUnavailable();
            }

            [[nodiscard]] ClientResult CreateVault(
                [[maybe_unused]] SecretText const& master_password) override
            {
                return ClosedOrUnavailable();
            }

            [[nodiscard]] ClientResult Unlock(
                [[maybe_unused]] SecretText const& master_password) override
            {
                return ClosedOrUnavailable();
            }

            [[nodiscard]] ClientResult Lock() override
            {
                return ClosedOrUnavailable();
            }

            [[nodiscard]] AccountListResult ListAccounts() override
            {
                if (closed_.load(std::memory_order_acquire))
                {
                    return { ClientError::Cancelled, {} };
                }
                return { ClientError::AgentUnavailable, {} };
            }

            [[nodiscard]] ClientResult SaveAccount(
                [[maybe_unused]] AccountDraft const& account) override
            {
                return ClosedOrUnavailable();
            }

            void Close() noexcept override
            {
                closed_.store(true, std::memory_order_release);
            }

        private:
            [[nodiscard]] ClientResult ClosedOrUnavailable() const noexcept
            {
                if (closed_.load(std::memory_order_acquire))
                {
                    return { ClientError::Cancelled, VaultStatus::Locked };
                }
                return { ClientError::AgentUnavailable, VaultStatus::Locked };
            }

            std::atomic_bool closed_{ false };
        };
    }

    SecretText::SecretText(std::wstring_view const value) :
        value_(value.begin(), value.end())
    {
    }

    SecretText::~SecretText() noexcept
    {
        Clear();
    }

    SecretText::SecretText(SecretText&& other) noexcept :
        value_(std::move(other.value_))
    {
        other.Clear();
    }

    SecretText& SecretText::operator=(SecretText&& other) noexcept
    {
        if (this != &other)
        {
            Clear();
            value_ = std::move(other.value_);
            other.Clear();
        }

        return *this;
    }

    bool SecretText::empty() const noexcept
    {
        return value_.empty();
    }

    std::wstring_view SecretText::value() const noexcept
    {
        if (value_.empty())
        {
            return {};
        }

        return { value_.data(), value_.size() };
    }

    void SecretText::Clear() noexcept
    {
        if (!value_.empty())
        {
            SecureZeroMemory(value_.data(), value_.size() * sizeof(wchar_t));
            value_.clear();
        }
    }

    AccountDraft::AccountDraft(
        std::wstring service_name_value,
        std::wstring origin_value,
        std::wstring username_value,
        SecretText password_value) :
        service_name(std::move(service_name_value)),
        origin(std::move(origin_value)),
        username(std::move(username_value)),
        password(std::move(password_value))
    {
    }

    std::shared_ptr<IDesktopClient> MakeDesktopClient()
    {
        return std::make_shared<UnavailableDesktopClient>();
    }
}
