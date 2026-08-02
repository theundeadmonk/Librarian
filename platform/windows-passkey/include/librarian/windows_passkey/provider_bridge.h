#pragma once

#include <cstddef>
#include <cstdint>

extern "C"
{
    constexpr std::size_t librarian_passkey_credential_id_bytes = 32;
    constexpr std::size_t librarian_passkey_user_handle_capacity = 64;
    constexpr std::size_t librarian_passkey_user_name_capacity = 256;
    constexpr std::size_t librarian_passkey_public_key_bytes = 65;
    constexpr std::size_t librarian_passkey_authenticator_data_bytes = 37;
    constexpr std::size_t librarian_passkey_signature_capacity = 80;

    struct librarian_passkey_request
    {
        std::uintptr_t parent_window;
        std::uint8_t const* transaction_id;
        std::uint32_t request_type;
        std::uint8_t const* request_signature;
        std::uint32_t request_signature_bytes;
        std::uint8_t const* encoded_request;
        std::uint32_t encoded_request_bytes;
        std::uint8_t const* agent_challenge;
        std::uint32_t agent_challenge_bytes;
        std::uint8_t const* user_verification_signature;
        std::uint32_t user_verification_signature_bytes;
    };

    struct librarian_passkey_summary
    {
        std::uint8_t credential_id[librarian_passkey_credential_id_bytes];
        std::uint8_t user_handle[librarian_passkey_user_handle_capacity];
        std::uint32_t user_handle_bytes;
        std::uint8_t user_name[librarian_passkey_user_name_capacity];
        std::uint32_t user_name_bytes;
        std::uint8_t user_display_name[librarian_passkey_user_name_capacity];
        std::uint32_t user_display_name_bytes;
    };

    struct librarian_passkey_credential
    {
        std::uint8_t credential_id[librarian_passkey_credential_id_bytes];
        std::uint8_t user_handle[librarian_passkey_user_handle_capacity];
        std::uint32_t user_handle_bytes;
        std::uint8_t public_key[librarian_passkey_public_key_bytes];
    };

    struct librarian_passkey_assertion
    {
        std::uint8_t credential_id[librarian_passkey_credential_id_bytes];
        std::uint8_t user_handle[librarian_passkey_user_handle_capacity];
        std::uint32_t user_handle_bytes;
        std::uint8_t authenticator_data[librarian_passkey_authenticator_data_bytes];
        std::uint8_t signature[librarian_passkey_signature_capacity];
        std::uint32_t signature_bytes;
    };

    using librarian_provider_status_callback = std::uint32_t (*)(
        void* context,
        std::uint32_t* unlocked) noexcept;
    using librarian_provider_prepare_callback = std::uint32_t (*)(
        void* context,
        std::uint8_t const* transaction_id,
        std::uint32_t transaction_id_bytes,
        std::uint8_t* challenge,
        std::uint32_t challenge_bytes) noexcept;
    using librarian_provider_discard_callback = void (*)(
        void* context,
        std::uint8_t const* transaction_id,
        std::uint32_t transaction_id_bytes) noexcept;
    using librarian_provider_list_callback = std::uint32_t (*)(
        void* context,
        librarian_passkey_request const* request,
        librarian_passkey_summary* summaries,
        std::uint32_t summary_capacity,
        std::uint32_t* summary_count) noexcept;
    using librarian_provider_make_callback = std::uint32_t (*)(
        void* context,
        librarian_passkey_request const* request,
        librarian_passkey_credential* credential) noexcept;
    using librarian_provider_rollback_make_callback = std::uint32_t (*)(
        void* context,
        librarian_passkey_request const* request,
        std::uint8_t const* credential_id,
        std::uint32_t credential_id_bytes) noexcept;
    using librarian_provider_assert_callback = std::uint32_t (*)(
        void* context,
        librarian_passkey_request const* request,
        std::uint8_t const* credential_id,
        std::uint32_t credential_id_bytes,
        librarian_passkey_assertion* assertion) noexcept;
    struct librarian_passkey_provider_callbacks
    {
        void* context;
        librarian_provider_status_callback status;
        librarian_provider_prepare_callback prepare;
        librarian_provider_discard_callback discard;
        librarian_provider_list_callback list;
        librarian_provider_make_callback make;
        librarian_provider_rollback_make_callback rollback_make;
        librarian_provider_assert_callback get_assertion;
    };

    std::uint32_t librarian_windows_passkey_provider_run(
        librarian_passkey_provider_callbacks const* callbacks) noexcept;

    std::uint32_t librarian_windows_passkey_provider_register() noexcept;

    std::uint32_t librarian_windows_passkey_provider_unregister() noexcept;

    std::uint32_t librarian_windows_passkey_provider_registration_state(
        std::uint32_t* registered) noexcept;

    std::uint32_t librarian_windows_passkey_provider_request_cancelled(
        std::uint8_t const* transaction_id,
        std::uint32_t transaction_id_bytes) noexcept;
}
