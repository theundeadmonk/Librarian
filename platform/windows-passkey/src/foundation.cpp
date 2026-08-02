#include "librarian/windows_passkey/foundation.h"

static_assert(
    librarian::windows_passkey::current_readiness() ==
    librarian::windows_passkey::readiness::scaffold_only);

namespace
{
    constexpr bool authorization_context_changes_the_binding() noexcept
    {
        std::array<std::uint8_t, 16> transaction{};
        std::array<std::uint8_t, 16> agent_challenge_a{};
        std::array<std::uint8_t, 16> agent_challenge_b{};
        std::array<std::uint8_t, 32> request_hash{};
        std::array<std::uint8_t, 32> credential_a{};
        std::array<std::uint8_t, 32> credential_b{};
        credential_a.fill(0xa1);
        credential_b.fill(0xb2);
        agent_challenge_a.fill(0xc3);
        agent_challenge_b.fill(0xd4);
        librarian::windows_passkey::user_verification_binding binding_a{};
        librarian::windows_passkey::user_verification_binding binding_b{};
        librarian::windows_passkey::user_verification_binding binding_c{};
        return librarian::windows_passkey::build_user_verification_binding(
                   31,
                   transaction,
                   agent_challenge_a,
                   request_hash,
                   credential_a,
                   binding_a) &&
               librarian::windows_passkey::build_user_verification_binding(
                   31,
                   transaction,
                   agent_challenge_a,
                   request_hash,
                   credential_b,
                   binding_b) &&
               librarian::windows_passkey::build_user_verification_binding(
                   31,
                   transaction,
                   agent_challenge_b,
                   request_hash,
                   credential_a,
                   binding_c) &&
               binding_a.size == binding_b.size && binding_a.size == binding_c.size &&
               binding_a.bytes != binding_b.bytes && binding_a.bytes != binding_c.bytes;
    }
}

static_assert(authorization_context_changes_the_binding());
