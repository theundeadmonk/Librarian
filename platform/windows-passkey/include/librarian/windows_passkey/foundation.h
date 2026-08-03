#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace librarian::windows_passkey
{
    inline constexpr std::size_t transaction_id_bytes = 16;
    inline constexpr std::size_t agent_challenge_bytes = 16;
    inline constexpr std::size_t request_hash_bytes = 32;
    inline constexpr std::size_t credential_id_bytes = 32;
    inline constexpr std::string_view user_verification_binding_prefix{
        "Librarian.Passkey.UV.v3"};

    struct user_verification_binding final
    {
        std::array<
            std::uint8_t,
            user_verification_binding_prefix.size() + 1 + transaction_id_bytes +
                agent_challenge_bytes + request_hash_bytes + 1 + credential_id_bytes>
            bytes{};
        std::size_t size{};
    };

    [[nodiscard]] constexpr bool build_user_verification_binding(
        std::uint8_t const operation,
        std::span<std::uint8_t const> const transaction_id,
        std::span<std::uint8_t const> const agent_challenge,
        std::span<std::uint8_t const> const request_hash,
        std::span<std::uint8_t const> const selected_credential,
        user_verification_binding& output) noexcept
    {
        output = {};
        if (transaction_id.size() != transaction_id_bytes ||
            agent_challenge.size() != agent_challenge_bytes ||
            request_hash.size() != request_hash_bytes ||
            (!selected_credential.empty() &&
             selected_credential.size() != credential_id_bytes))
        {
            return false;
        }

        auto append = [&](std::span<std::uint8_t const> const value) constexpr {
            for (auto const byte : value)
            {
                output.bytes[output.size++] = byte;
            }
        };
        for (auto const character : user_verification_binding_prefix)
        {
            output.bytes[output.size++] = static_cast<std::uint8_t>(character);
        }
        output.bytes[output.size++] = operation;
        append(transaction_id);
        append(agent_challenge);
        append(request_hash);
        output.bytes[output.size++] = selected_credential.empty() ? 0 : 1;
        append(selected_credential);
        return true;
    }

    enum class readiness : std::uint8_t
    {
        scaffold_only = 0,
    };

    [[nodiscard]] constexpr readiness current_readiness() noexcept
    {
        return readiness::scaffold_only;
    }
}
