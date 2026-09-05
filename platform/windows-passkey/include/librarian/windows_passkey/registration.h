#pragma once

#include <cstdint>

namespace librarian::windows_passkey::registration_command
{
    // Process exit codes shared by the hidden desktop commands and launcher.
    inline constexpr std::uint32_t success = 0U;
    inline constexpr std::uint32_t not_registered = 4U;
    inline constexpr std::uint32_t operation_failed = 11U;
    inline constexpr std::uint32_t platform_unavailable = 12U;

    constexpr std::uint32_t exit_code(std::uint32_t result) noexcept
    {
        // Only missing API exports (HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND))
        // or an explicitly unimplemented API (E_NOTIMPL) establish unsupported
        // registration. Other failures must not use the platform fallback.
        constexpr std::uint32_t api_not_found = 0x8007007FU;
        constexpr std::uint32_t not_implemented = 0x80004001U;
        return result == 0U ? success :
            (result == api_not_found || result == not_implemented ?
                platform_unavailable : operation_failed);
    }

    constexpr bool can_continue(std::uint32_t code, bool registering) noexcept
    {
        return code == success || (registering && code == platform_unavailable);
    }
}

extern "C"
{
    std::uint32_t librarian_windows_passkey_provider_register() noexcept;
    std::uint32_t librarian_windows_passkey_provider_unregister() noexcept;
    std::uint32_t librarian_windows_passkey_provider_registration_state(
        std::uint32_t* registered) noexcept;
}
