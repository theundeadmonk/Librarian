#pragma once

#include <cstdint>

extern "C"
{
    struct librarian_windows_passkey_proof
    {
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

    std::uint32_t librarian_windows_passkey_verify_make(
        librarian_windows_passkey_proof const* proof,
        std::uint8_t* rp_id,
        std::uint32_t rp_id_capacity,
        std::uint32_t* rp_id_bytes,
        std::uint8_t* client_data_hash,
        std::uint8_t* user_handle,
        std::uint32_t user_handle_capacity,
        std::uint32_t* user_handle_bytes,
        std::uint8_t* user_name,
        std::uint32_t user_name_capacity,
        std::uint32_t* user_name_bytes,
        std::uint8_t* user_display_name,
        std::uint32_t user_display_name_capacity,
        std::uint32_t* user_display_name_bytes,
        std::uint8_t* excluded_credential_ids,
        std::uint32_t excluded_credential_ids_capacity,
        std::uint32_t* excluded_credential_ids_count) noexcept;

    std::uint32_t librarian_windows_passkey_verify_assertion(
        librarian_windows_passkey_proof const* proof,
        std::uint8_t const* selected_credential_id,
        std::uint32_t selected_credential_id_bytes,
        std::uint8_t* rp_id,
        std::uint32_t rp_id_capacity,
        std::uint32_t* rp_id_bytes,
        std::uint8_t* client_data_hash) noexcept;

    std::uint32_t librarian_windows_passkey_verify_assertion_lookup(
        librarian_windows_passkey_proof const* proof,
        std::uint8_t* rp_id,
        std::uint32_t rp_id_capacity,
        std::uint32_t* rp_id_bytes,
        std::uint8_t* allowed_credential_ids,
        std::uint32_t allowed_credential_ids_capacity,
        std::uint32_t* allowed_credential_ids_count,
        std::uint8_t* allow_list_present) noexcept;
}
