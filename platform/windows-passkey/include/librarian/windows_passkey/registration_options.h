#pragma once

#include <windows.h>
#include <webauthn.h>
#include <webauthnplugin.h>

#include <cstddef>
#include <cstdint>

namespace librarian::windows_passkey::registration_metadata
{
    // A reserved, non-resolving identity for this plugin's own nested calls,
    // not an allowlist of websites whose credentials Librarian can service.
    // No nested WebAuthn call is currently made with this identifier.
    inline constexpr wchar_t plugin_rp_id[]{L"librarian.invalid"};

    template <std::size_t Size>
    [[nodiscard]] WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS make_add_options(
        CLSID const& provider_clsid,
        std::uint8_t const (&authenticator_info)[Size]) noexcept
    {
        static_assert(Size > 0U && Size <= UINT32_MAX);
        return {
            L"Librarian",
            provider_clsid,
            // webauthn.dll 10.0.26100.8117 rejects a null plugin RP ID with
            // NTE_INVALID_PARAMETER, despite the documentation's optional label.
            plugin_rp_id,
            nullptr,
            nullptr,
            static_cast<DWORD>(Size),
            authenticator_info,
            0U,
            nullptr};
    }
}
