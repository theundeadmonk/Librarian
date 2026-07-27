#pragma once

#include <cstdint>

extern "C"
{
    enum librarian_windows_hello_status : std::uint32_t
    {
        librarian_windows_hello_success = 0,
        librarian_windows_hello_invalid_argument = 1,
        librarian_windows_hello_unavailable = 2,
        librarian_windows_hello_unsupported = 3,
        librarian_windows_hello_cancelled = 4,
        librarian_windows_hello_invalid_response = 5,
        librarian_windows_hello_platform_failure = 6,
        librarian_windows_hello_credential_removal_failed = 7,
    };

    [[nodiscard]] std::uint32_t
    librarian_windows_hello_is_available(
        std::uint32_t* available) noexcept;

    [[nodiscard]] std::uint32_t
    librarian_windows_hello_enroll(
        std::uintptr_t parent_window,
        std::uint8_t const* operation_id,
        std::uint32_t operation_id_bytes,
        std::uint8_t* credential_id,
        std::uint32_t credential_id_capacity,
        std::uint32_t* credential_id_bytes,
        std::uint8_t* salt,
        std::uint32_t salt_bytes,
        std::uint8_t* prf_output,
        std::uint32_t prf_output_bytes) noexcept;

    [[nodiscard]] std::uint32_t
    librarian_windows_hello_evaluate(
        std::uintptr_t parent_window,
        std::uint8_t const* operation_id,
        std::uint32_t operation_id_bytes,
        std::uint8_t const* credential_id,
        std::uint32_t credential_id_bytes,
        std::uint8_t const* salt,
        std::uint32_t salt_bytes,
        std::uint8_t* prf_output,
        std::uint32_t prf_output_bytes) noexcept;

    [[nodiscard]] std::uint32_t
    librarian_windows_hello_cancel(
        std::uint8_t const* operation_id,
        std::uint32_t operation_id_bytes) noexcept;

    [[nodiscard]] std::uint32_t
    librarian_windows_hello_remove(
        std::uint8_t const* credential_id,
        std::uint32_t credential_id_bytes) noexcept;
}
