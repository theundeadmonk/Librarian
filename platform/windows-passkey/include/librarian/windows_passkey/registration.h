#pragma once

#include <cstdint>

extern "C"
{
    std::uint32_t librarian_windows_passkey_provider_register() noexcept;
    std::uint32_t librarian_windows_passkey_provider_unregister() noexcept;
    std::uint32_t librarian_windows_passkey_provider_registration_state(
        std::uint32_t* registered) noexcept;
}
