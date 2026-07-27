#include "librarian/windows_hello/bridge.h"
#include "librarian/windows_hello/client.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace
{
    using librarian::windows_hello::Error;
    using librarian::windows_hello::OperationId;
    using librarian::windows_hello::operation_id_bytes;
    using librarian::windows_hello::prf_bytes;

    [[nodiscard]] std::uint32_t status(Error const error) noexcept
    {
        switch (error)
        {
        case Error::None:
            return librarian_windows_hello_success;
        case Error::InvalidArgument:
            return librarian_windows_hello_invalid_argument;
        case Error::Unavailable:
            return librarian_windows_hello_unavailable;
        case Error::Unsupported:
            return librarian_windows_hello_unsupported;
        case Error::Cancelled:
            return librarian_windows_hello_cancelled;
        case Error::InvalidResponse:
            return librarian_windows_hello_invalid_response;
        case Error::PlatformFailure:
            return librarian_windows_hello_platform_failure;
        case Error::CredentialRemovalFailed:
            return librarian_windows_hello_credential_removal_failed;
        }
        return librarian_windows_hello_invalid_response;
    }

    [[nodiscard]] bool valid_operation(
        std::uint8_t const* const value,
        std::uint32_t const bytes) noexcept
    {
        return
            value != nullptr &&
            bytes == operation_id_bytes &&
            std::any_of(value, value + bytes, [](std::uint8_t const byte)
            {
                return byte != 0;
            });
    }

    [[nodiscard]] OperationId operation(
        std::uint8_t const* const value) noexcept
    {
        OperationId result{};
        std::copy_n(value, result.size(), result.begin());
        return result;
    }

    void clear(
        std::uint8_t* const value,
        std::uint32_t const bytes) noexcept
    {
        if (value != nullptr && bytes != 0)
        {
            SecureZeroMemory(value, bytes);
        }
    }
}

std::uint32_t librarian_windows_hello_is_available(
    std::uint32_t* const available) noexcept
{
    if (available == nullptr)
    {
        return librarian_windows_hello_invalid_argument;
    }
    *available = 0;
    auto const result = librarian::windows_hello::IsAvailable();
    if (result.error != Error::None)
    {
        return status(result.error);
    }
    if (result.available)
    {
        *available = 1;
    }
    return librarian_windows_hello_success;
}

std::uint32_t librarian_windows_hello_enroll(
    std::uintptr_t const parent_window,
    std::uint8_t const* const operation_id,
    std::uint32_t const operation_id_length,
    std::uint8_t* const credential_id,
    std::uint32_t const credential_id_capacity,
    std::uint32_t* const credential_id_length,
    std::uint8_t* const salt,
    std::uint32_t const salt_length,
    std::uint8_t* const prf_output,
    std::uint32_t const prf_output_length) noexcept
{
    if (prf_output_length == prf_bytes)
    {
        clear(prf_output, prf_output_length);
    }
    if (credential_id_length != nullptr)
    {
        *credential_id_length = 0;
    }
    if (
        parent_window == 0 ||
        !valid_operation(operation_id, operation_id_length) ||
        credential_id == nullptr ||
        credential_id_capacity !=
            librarian::windows_hello::maximum_credential_id_bytes ||
        credential_id_length == nullptr ||
        salt == nullptr ||
        salt_length != prf_bytes ||
        prf_output == nullptr ||
        prf_output_length != prf_bytes)
    {
        return librarian_windows_hello_invalid_argument;
    }
    std::fill_n(
        credential_id,
        credential_id_capacity,
        std::uint8_t{0});
    std::fill_n(salt, salt_length, std::uint8_t{0});

    auto result = librarian::windows_hello::Enroll(
        reinterpret_cast<HWND>(parent_window),
        operation(operation_id));
    if (result.error != Error::None)
    {
        if (
            result.enrollment.has_value() &&
            !result.enrollment->credential_id.empty() &&
            librarian::windows_hello::Remove(
                result.enrollment->credential_id) != Error::None)
        {
            return librarian_windows_hello_credential_removal_failed;
        }
        return status(result.error);
    }
    if (!result.enrollment.has_value())
    {
        return librarian_windows_hello_invalid_response;
    }
    auto const& enrollment = *result.enrollment;
    if (enrollment.credential_id.empty())
    {
        return librarian_windows_hello_invalid_response;
    }
    if (enrollment.credential_id.size() > credential_id_capacity)
    {
        return
            librarian::windows_hello::Remove(
                enrollment.credential_id) == Error::None
                ? librarian_windows_hello_invalid_response
                : librarian_windows_hello_credential_removal_failed;
    }

    std::copy(
        enrollment.credential_id.begin(),
        enrollment.credential_id.end(),
        credential_id);
    *credential_id_length =
        static_cast<std::uint32_t>(enrollment.credential_id.size());
    std::copy(enrollment.salt.begin(), enrollment.salt.end(), salt);
    std::copy(
        enrollment.output.value().begin(),
        enrollment.output.value().end(),
        prf_output);
    return librarian_windows_hello_success;
}

std::uint32_t librarian_windows_hello_evaluate(
    std::uintptr_t const parent_window,
    std::uint8_t const* const operation_id,
    std::uint32_t const operation_id_length,
    std::uint8_t const* const credential_id,
    std::uint32_t const credential_id_length,
    std::uint8_t const* const salt,
    std::uint32_t const salt_length,
    std::uint8_t* const prf_output,
    std::uint32_t const prf_output_length) noexcept
{
    if (prf_output_length == prf_bytes)
    {
        clear(prf_output, prf_output_length);
    }
    if (
        parent_window == 0 ||
        !valid_operation(operation_id, operation_id_length) ||
        credential_id == nullptr ||
        credential_id_length == 0 ||
        credential_id_length >
            librarian::windows_hello::maximum_credential_id_bytes ||
        salt == nullptr ||
        salt_length != prf_bytes ||
        prf_output == nullptr ||
        prf_output_length != prf_bytes)
    {
        return librarian_windows_hello_invalid_argument;
    }

    std::array<std::uint8_t, prf_bytes> fixed_salt{};
    std::copy_n(salt, fixed_salt.size(), fixed_salt.begin());
    auto result = librarian::windows_hello::Evaluate(
        reinterpret_cast<HWND>(parent_window),
        {credential_id, credential_id_length},
        fixed_salt,
        operation(operation_id));
    if (result.error != Error::None || !result.output.has_value())
    {
        return status(
            result.error == Error::None
                ? Error::InvalidResponse
                : result.error);
    }
    std::copy(
        result.output->value().begin(),
        result.output->value().end(),
        prf_output);
    return librarian_windows_hello_success;
}

std::uint32_t librarian_windows_hello_cancel(
    std::uint8_t const* const operation_id,
    std::uint32_t const operation_id_length) noexcept
{
    if (!valid_operation(operation_id, operation_id_length))
    {
        return librarian_windows_hello_invalid_argument;
    }
    return status(
        librarian::windows_hello::Cancel(
            operation(operation_id)));
}

std::uint32_t librarian_windows_hello_remove(
    std::uint8_t const* const credential_id,
    std::uint32_t const credential_id_length) noexcept
{
    if (
        credential_id == nullptr ||
        credential_id_length == 0 ||
        credential_id_length >
            librarian::windows_hello::maximum_credential_id_bytes)
    {
        return librarian_windows_hello_invalid_argument;
    }
    return status(librarian::windows_hello::Remove(
        {credential_id, credential_id_length}));
}
