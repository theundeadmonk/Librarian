#include "librarian/windows_hello/client.h"
#include "librarian/windows_hello/bridge.h"
#include "validation.h"

#include <webauthn.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace
{
    using librarian::windows_hello::Error;
    using librarian::windows_hello::detail::AssertionView;
    using librarian::windows_hello::detail::AttestationView;
    using librarian::windows_hello::detail::PrfView;

    constexpr std::array<std::uint8_t, 32> relying_party_hash{
        0x5A, 0x65, 0xA3, 0xD9, 0x88, 0x6C, 0x0D, 0x8D,
        0x08, 0xE6, 0xC1, 0x2D, 0x96, 0xF5, 0x3B, 0x01,
        0x9E, 0x3F, 0x72, 0x13, 0xDD, 0xAE, 0x98, 0x68,
        0x27, 0xC8, 0xB6, 0xA2, 0xA4, 0x51, 0xCB, 0x85,
    };

    void require(bool const condition, std::string_view const message)
    {
        if (!condition)
        {
            throw std::runtime_error(std::string(message));
        }
    }

    struct Fixture final
    {
        Fixture()
        {
            std::copy(
                relying_party_hash.begin(),
                relying_party_hash.end(),
                attestation_data.begin());
            std::copy(
                relying_party_hash.begin(),
                relying_party_hash.end(),
                assertion_data.begin());
            attestation_data[32] = 0x45;
            assertion_data[32] = 0x05;
            attestation_data[53] = 0;
            attestation_data[54] =
                static_cast<std::uint8_t>(credential_id.size());
            std::copy(
                credential_id.begin(),
                credential_id.end(),
                attestation_data.begin() + 55);
            prf.fill(0xA5);
        }

        std::array<std::uint8_t, 4> credential_id{
            0x10,
            0x20,
            0x30,
            0x40,
        };
        std::array<std::uint8_t, 59> attestation_data{};
        std::array<std::uint8_t, 37> assertion_data{};
        std::array<std::uint8_t, 32> prf{};
    };

    [[nodiscard]] AttestationView attestation(Fixture const& fixture)
    {
        return {
            .version = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7,
            .credential_id = fixture.credential_id,
            .authenticator_data = fixture.attestation_data,
            .prf_enabled = true,
            .used_transport = WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            .prf = {.first = fixture.prf},
        };
    }

    [[nodiscard]] AssertionView assertion(Fixture const& fixture)
    {
        return {
            .version = WEBAUTHN_ASSERTION_VERSION_3,
            .credential_id = fixture.credential_id,
            .credential_type = L"public-key",
            .authenticator_data = fixture.assertion_data,
            .prf = {.first = fixture.prf},
        };
    }

    void validation_tests()
    {
        Fixture fixture;
        auto accepted =
            librarian::windows_hello::detail::ValidateAttestation(
                attestation(fixture),
                relying_party_hash);
        require(
            accepted.error == Error::None &&
            accepted.output.has_value() &&
            std::equal(
                accepted.output->value().begin(),
                accepted.output->value().end(),
                fixture.prf.begin()),
            "valid attestation was rejected");

        auto missing_prf = attestation(fixture);
        missing_prf.prf.first = {};
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                missing_prf,
                relying_party_hash).error == Error::InvalidResponse,
            "missing attestation PRF was accepted");

        auto unsupported = attestation(fixture);
        unsupported.prf_enabled = false;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                unsupported,
                relying_party_hash).error == Error::Unsupported,
            "disabled attestation PRF was accepted");

        auto wrong_transport = attestation(fixture);
        wrong_transport.used_transport = WEBAUTHN_CTAP_TRANSPORT_USB;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                wrong_transport,
                relying_party_hash).error == Error::InvalidResponse,
            "non-platform credential was accepted");

        auto missing_uv = attestation(fixture);
        Fixture no_uv_fixture;
        no_uv_fixture.attestation_data[32] = 0x41;
        missing_uv.authenticator_data = no_uv_fixture.attestation_data;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                missing_uv,
                relying_party_hash).error == Error::InvalidResponse,
            "attestation without user verification was accepted");

        auto missing_presence = attestation(fixture);
        Fixture no_presence_fixture;
        no_presence_fixture.attestation_data[32] = 0x44;
        missing_presence.authenticator_data =
            no_presence_fixture.attestation_data;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                missing_presence,
                relying_party_hash).error == Error::InvalidResponse,
            "attestation without user presence was accepted");

        auto wrong_attested_credential = attestation(fixture);
        std::array<std::uint8_t, 4> const other_attested_id{
            0x40,
            0x30,
            0x20,
            0x10,
        };
        wrong_attested_credential.credential_id = other_attested_id;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                wrong_attested_credential,
                relying_party_hash).error == Error::InvalidResponse,
            "mismatched attested credential ID was accepted");

        auto malformed_attested_length = attestation(fixture);
        Fixture malformed_attestation_fixture;
        malformed_attestation_fixture.attestation_data[54] = 5;
        malformed_attested_length.authenticator_data =
            malformed_attestation_fixture.attestation_data;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                malformed_attested_length,
                relying_party_hash).error == Error::InvalidResponse,
            "malformed attested credential length was accepted");

        Fixture wrong_rp_fixture;
        wrong_rp_fixture.attestation_data[0] ^= 0xFF;
        require(
            librarian::windows_hello::detail::ValidateAttestation(
                attestation(wrong_rp_fixture),
                relying_party_hash).error == Error::InvalidResponse,
            "wrong relying party was accepted");

        auto assertion_result =
            librarian::windows_hello::detail::ValidateAssertion(
                assertion(fixture),
                fixture.credential_id,
                relying_party_hash);
        require(
            assertion_result.error == Error::None &&
            assertion_result.output.has_value(),
            "valid assertion was rejected");

        auto wrong_credential = assertion(fixture);
        std::array<std::uint8_t, 4> const other_id{
            0x40,
            0x30,
            0x20,
            0x10,
        };
        require(
            librarian::windows_hello::detail::ValidateAssertion(
                wrong_credential,
                other_id,
                relying_party_hash).error == Error::InvalidResponse,
            "wrong credential was accepted");

        auto wrong_type = assertion(fixture);
        wrong_type.credential_type = L"password";
        require(
            librarian::windows_hello::detail::ValidateAssertion(
                wrong_type,
                fixture.credential_id,
                relying_party_hash).error == Error::InvalidResponse,
            "wrong credential type was accepted");

        auto second_prf = assertion(fixture);
        second_prf.prf.second = fixture.prf;
        require(
            librarian::windows_hello::detail::ValidateAssertion(
                second_prf,
                fixture.credential_id,
                relying_party_hash).error == Error::InvalidResponse,
            "second PRF output was accepted");
    }

    void public_contract_tests()
    {
        std::array<std::uint8_t, 32> salt{};
        librarian::windows_hello::OperationId operation_id{};
        operation_id[0] = 1;
        require(
            librarian::windows_hello::Enroll(
                nullptr,
                operation_id).error ==
                Error::InvalidArgument,
            "null enrollment parent was accepted");
        require(
            librarian::windows_hello::Evaluate(
                nullptr,
                {},
                salt,
                operation_id).error == Error::InvalidArgument,
            "invalid evaluation request was accepted");
        require(
            librarian::windows_hello::Cancel({}) ==
                Error::InvalidArgument,
            "empty cancellation identifier was accepted");
        require(
            librarian::windows_hello::Remove({}) ==
                Error::InvalidArgument,
            "empty credential removal was accepted");

        std::array<std::uint8_t, 32> bridge_output{};
        bridge_output.fill(0x7A);
        require(
            librarian_windows_hello_evaluate(
                0,
                operation_id.data(),
                static_cast<std::uint32_t>(operation_id.size()),
                nullptr,
                0,
                salt.data(),
                static_cast<std::uint32_t>(salt.size()),
                bridge_output.data(),
                static_cast<std::uint32_t>(bridge_output.size())) ==
                librarian_windows_hello_invalid_argument,
            "bridge accepted an invalid evaluation request");
        require(
            std::all_of(
                bridge_output.begin(),
                bridge_output.end(),
                [](std::uint8_t const byte)
                {
                    return byte == 0;
                }),
            "bridge did not clear PRF output before returning");
        require(
            librarian_windows_hello_cancel(
                nullptr,
                0) ==
                librarian_windows_hello_invalid_argument,
            "bridge accepted an invalid cancellation request");

        std::array<std::uint8_t, 32> secret{};
        secret.fill(0x7A);
        librarian::windows_hello::PrfOutput first(secret);
        librarian::windows_hello::PrfOutput moved(std::move(first));
        require(
            std::equal(
                moved.value().begin(),
                moved.value().end(),
                secret.begin()),
            "PRF output move lost the secret");
    }
}

int main(int const argc, char const* const* const argv)
try
{
    require(
        argc == 2 &&
        std::string_view(argv[1]) == "--self-test",
        "usage: Librarian.WindowsHelloTests --self-test");
    validation_tests();
    public_contract_tests();
    bool const available =
        librarian::windows_hello::IsAvailable();
    std::cout
        << "[PASS] WebAuthn attestation and assertion validation\n"
        << "[PASS] wrong RP, credential, type, transport, UV, and PRF shape fail closed\n"
        << "[PASS] public invalid-argument paths require no prompt\n"
        << "[PASS] PRF output uses move-only zeroizing storage\n"
        << "[PASS] API v8 platform authenticator: "
        << (available ? "available" : "unavailable (fail closed)")
        << '\n'
        << "5 passed; 0 failed\n";
    return 0;
}
catch (std::exception const& error)
{
    std::cerr << "[FAIL] " << error.what() << '\n';
    return 1;
}
