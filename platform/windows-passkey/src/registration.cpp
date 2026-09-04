#include "librarian/windows_passkey/registration.h"

#include <windows.h>
#include <webauthn.h>
#include <webauthnplugin.h>

#include <cstddef>
#include <cstdint>
#include <iterator>

namespace
{
    constexpr CLSID provider_clsid{
        0x68fe5df7,
        0x9fe6,
        0x4145,
        {0xbb, 0xa0, 0x95, 0x01, 0x0f, 0x43, 0xbf, 0xbe}};
    constexpr std::uint8_t authenticator_info[]{
        0xa5,
        0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '1',
        0x03, 0x50,
        0xb7, 0x9a, 0x73, 0xf8, 0x4b, 0xd4, 0x45, 0xe7,
        0xa8, 0x17, 0xb6, 0x2f, 0x31, 0xac, 0xae, 0xc5,
        0x04, 0xa3,
        0x62, 'r', 'k', 0xf5,
        0x62, 'u', 'p', 0xf5,
        0x62, 'u', 'v', 0xf5,
        0x09, 0x81, 0x68, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l',
        0x0a, 0x81, 0xa2,
        0x63, 'a', 'l', 'g', 0x26,
        0x64, 't', 'y', 'p', 'e',
        0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'};

    using get_state_function = HRESULT(WINAPI*)(REFCLSID, AUTHENTICATOR_STATE*);
    using add_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE*);
    using free_response_function = void(WINAPI*)(
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
    using update_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS);
    using remove_function = HRESULT(WINAPI*)(REFCLSID);

    class registration_api final
    {
    public:
        registration_api() noexcept
            : module_(LoadLibraryExW(
                  L"webauthn.dll",
                  nullptr,
                  LOAD_LIBRARY_SEARCH_SYSTEM32))
        {
            if (module_ == nullptr)
            {
                return;
            }
            get_state = resolve<get_state_function>(
                "WebAuthNPluginGetAuthenticatorState");
            add = resolve<add_function>("WebAuthNPluginAddAuthenticator");
            free_response = resolve<free_response_function>(
                "WebAuthNPluginFreeAddAuthenticatorResponse");
            update = resolve<update_function>(
                "WebAuthNPluginUpdateAuthenticatorDetails");
            remove = resolve<remove_function>(
                "WebAuthNPluginRemoveAuthenticator");
        }

        registration_api(registration_api const&) = delete;
        registration_api& operator=(registration_api const&) = delete;

        ~registration_api()
        {
            if (module_ != nullptr)
            {
                FreeLibrary(module_);
            }
        }

        [[nodiscard]] bool complete() const noexcept
        {
            return module_ != nullptr && get_state != nullptr && add != nullptr &&
                   free_response != nullptr && update != nullptr && remove != nullptr;
        }

        get_state_function get_state{};
        add_function add{};
        free_response_function free_response{};
        update_function update{};
        remove_function remove{};

    private:
        template <typename Function>
        [[nodiscard]] Function resolve(char const* name) const noexcept
        {
            return reinterpret_cast<Function>(GetProcAddress(module_, name));
        }

        HMODULE module_{};
    };
}

extern "C" std::uint32_t librarian_windows_passkey_provider_register() noexcept
{
    registration_api const api;
    if (!api.complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }

    AUTHENTICATOR_STATE state{};
    HRESULT result = api.get_state(provider_clsid, &state);
    if (result == NTE_NOT_FOUND)
    {
        WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS const options{
            L"Librarian",
            provider_clsid,
            nullptr,
            nullptr,
            nullptr,
            static_cast<DWORD>(std::size(authenticator_info)),
            authenticator_info,
            0U,
            nullptr};
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE response{};
        result = api.add(&options, &response);
        if (FAILED(result))
        {
            return static_cast<std::uint32_t>(result);
        }
        bool const valid_response =
            response != nullptr && response->pbOpSignPubKey != nullptr &&
            response->cbOpSignPubKey != 0U;
        api.free_response(response);
        if (!valid_response)
        {
            static_cast<void>(api.remove(provider_clsid));
            return static_cast<std::uint32_t>(E_UNEXPECTED);
        }
        return 0U;
    }
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }

    WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS const details{
        L"Librarian",
        provider_clsid,
        provider_clsid,
        nullptr,
        nullptr,
        static_cast<DWORD>(std::size(authenticator_info)),
        authenticator_info,
        0U,
        nullptr};
    return static_cast<std::uint32_t>(api.update(&details));
}

extern "C" std::uint32_t librarian_windows_passkey_provider_unregister() noexcept
{
    registration_api const api;
    if (!api.complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }
    HRESULT const result = api.remove(provider_clsid);
    return result == NTE_NOT_FOUND ? 0U : static_cast<std::uint32_t>(result);
}

extern "C" std::uint32_t librarian_windows_passkey_provider_registration_state(
    std::uint32_t* registered) noexcept
{
    if (registered == nullptr)
    {
        return static_cast<std::uint32_t>(E_POINTER);
    }
    *registered = 0U;
    registration_api const api;
    if (!api.complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }
    AUTHENTICATOR_STATE state{};
    HRESULT const result = api.get_state(provider_clsid, &state);
    if (result == NTE_NOT_FOUND)
    {
        return 0U;
    }
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }
    *registered = 1U;
    return 0U;
}
