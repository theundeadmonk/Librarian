#include "validation.h"

#include <webauthn.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace librarian::windows_hello::detail
{
    namespace
    {
        constexpr std::size_t authenticator_data_minimum_bytes = 37;
        constexpr std::size_t authenticator_flags_offset = 32;
        constexpr std::uint8_t authenticator_user_present_flag = 0x01;
        constexpr std::uint8_t authenticator_user_verified_flag = 0x04;
        constexpr std::uint8_t authenticator_attested_data_flag = 0x40;
        constexpr std::size_t attested_aaguid_bytes = 16;
        constexpr std::size_t attested_credential_length_bytes = 2;
        constexpr std::size_t attested_credential_length_offset =
            authenticator_data_minimum_bytes + attested_aaguid_bytes;
        constexpr std::size_t attested_credential_offset =
            attested_credential_length_offset +
            attested_credential_length_bytes;
        constexpr std::uint32_t minimum_attestation_version =
            WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7;
        constexpr std::uint32_t minimum_assertion_version =
            WEBAUTHN_ASSERTION_VERSION_3;
        constexpr std::uint32_t internal_transport =
            WEBAUTHN_CTAP_TRANSPORT_INTERNAL;
        constexpr std::wstring_view public_key_type = L"public-key";

        [[nodiscard]] bool valid_authenticator_data(
            std::span<std::uint8_t const> const data,
            std::span<
                std::uint8_t const,
                relying_party_hash_bytes> const expected_hash,
            std::uint8_t const required_flags) noexcept
        {
            return
                data.size() >= authenticator_data_minimum_bytes &&
                std::equal(
                    expected_hash.begin(),
                    expected_hash.end(),
                    data.begin()) &&
                (data[authenticator_flags_offset] & required_flags) ==
                    required_flags;
        }

        [[nodiscard]] bool valid_attested_credential(
            std::span<std::uint8_t const> const data,
            std::span<std::uint8_t const> const expected) noexcept
        {
            if (
                expected.empty() ||
                data.size() < attested_credential_offset)
            {
                return false;
            }
            std::size_t const length =
                (static_cast<std::size_t>(
                    data[attested_credential_length_offset]) << 8) |
                data[attested_credential_length_offset + 1];
            return
                length == expected.size() &&
                data.size() >= attested_credential_offset + length &&
                std::equal(
                    expected.begin(),
                    expected.end(),
                    data.begin() + attested_credential_offset);
        }

        [[nodiscard]] ValidationResult validated_prf(
            PrfView const& value) noexcept
        {
            if (
                value.first.size() != prf_bytes ||
                !value.second.empty())
            {
                return {};
            }
            std::span<std::uint8_t const, prf_bytes> const fixed{
                value.first.data(),
                prf_bytes,
            };
            return {
                .error = Error::None,
                .output = PrfOutput(fixed),
            };
        }
    }

    ValidationResult ValidateAttestation(
        AttestationView const& value,
        std::span<
            std::uint8_t const,
            relying_party_hash_bytes> const expected_relying_party_hash) noexcept
    {
        if (!value.prf_enabled)
        {
            return {.error = Error::Unsupported};
        }
        if (
            value.version < minimum_attestation_version ||
            value.used_transport != internal_transport ||
            !valid_authenticator_data(
                value.authenticator_data,
                expected_relying_party_hash,
                authenticator_user_present_flag |
                    authenticator_user_verified_flag |
                    authenticator_attested_data_flag) ||
            !valid_attested_credential(
                value.authenticator_data,
                value.credential_id))
        {
            return {};
        }
        return validated_prf(value.prf);
    }

    ValidationResult ValidateAssertion(
        AssertionView const& value,
        std::span<std::uint8_t const> const expected_credential_id,
        std::span<
            std::uint8_t const,
            relying_party_hash_bytes> const expected_relying_party_hash) noexcept
    {
        if (
            value.version < minimum_assertion_version ||
            value.credential_id.size() != expected_credential_id.size() ||
            !std::equal(
                value.credential_id.begin(),
                value.credential_id.end(),
                expected_credential_id.begin()) ||
            value.credential_type != public_key_type ||
            !valid_authenticator_data(
                value.authenticator_data,
                expected_relying_party_hash,
                authenticator_user_present_flag |
                    authenticator_user_verified_flag) ||
            (value.authenticator_data[authenticator_flags_offset] &
             authenticator_attested_data_flag) != 0)
        {
            return {};
        }
        return validated_prf(value.prf);
    }
}
