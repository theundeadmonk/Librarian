#pragma once

#include "librarian/windows_hello/client.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace librarian::windows_hello::detail
{
    inline constexpr std::size_t relying_party_hash_bytes = 32;

    struct PrfView final
    {
        std::span<std::uint8_t const> first;
        std::span<std::uint8_t const> second;
    };

    struct AttestationView final
    {
        std::uint32_t version;
        std::span<std::uint8_t const> credential_id;
        std::span<std::uint8_t const> authenticator_data;
        bool prf_enabled;
        std::uint32_t used_transport;
        PrfView prf;
    };

    struct AssertionView final
    {
        std::uint32_t version;
        std::span<std::uint8_t const> credential_id;
        std::wstring_view credential_type;
        std::span<std::uint8_t const> authenticator_data;
        PrfView prf;
    };

    struct ValidationResult final
    {
        Error error{Error::InvalidResponse};
        std::optional<PrfOutput> output;
    };

    [[nodiscard]] ValidationResult ValidateAttestation(
        AttestationView const& value,
        std::span<
            std::uint8_t const,
            relying_party_hash_bytes> expected_relying_party_hash) noexcept;

    [[nodiscard]] ValidationResult ValidateAssertion(
        AssertionView const& value,
        std::span<std::uint8_t const> expected_credential_id,
        std::span<
            std::uint8_t const,
            relying_party_hash_bytes> expected_relying_party_hash) noexcept;
}
