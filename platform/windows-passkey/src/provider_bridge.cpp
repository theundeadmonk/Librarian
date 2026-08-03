#include "librarian/windows_passkey/provider_bridge.h"
#include "librarian/windows_passkey/foundation.h"

#include <Windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <ncrypt.h>
#include <objbase.h>
#include <pluginauthenticator.h>
#include <webauthn.h>
#include <webauthnplugin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    constexpr std::uint32_t callback_success = 0;
    constexpr std::uint32_t callback_invalid = 1;
    constexpr std::uint32_t callback_locked = 3;
    constexpr std::uint32_t callback_not_found = 4;
    constexpr std::uint32_t callback_conflict = 5;
    constexpr std::uint32_t callback_busy = 6;
    constexpr std::uint32_t callback_cancelled = 7;
    constexpr std::uint32_t callback_deadline = 8;
    constexpr std::uint32_t callback_unavailable = 9;
    constexpr std::uint32_t callback_incompatible = 10;
    constexpr std::uint32_t make_operation = 30;
    constexpr std::uint32_t assertion_operation = 31;
    constexpr std::size_t transaction_id_bytes = 16;
    constexpr std::size_t maximum_request_signature_bytes = 2 * 1024;
    constexpr std::size_t maximum_encoded_request_bytes = 48 * 1024;
    constexpr std::size_t maximum_summaries = 64;
    constexpr std::array<std::uint8_t, 16> authenticator_aaguid{
        0xb7, 0x9a, 0x73, 0xf8, 0x4b, 0xd4, 0x45, 0xe7,
        0xa8, 0x17, 0xb6, 0x2f, 0x31, 0xac, 0xae, 0xc5};
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

    std::atomic<std::uint32_t> server_objects{};
    std::atomic<std::uint32_t> server_locks{};
    std::atomic<std::int64_t> last_activity_ticks{};
    std::mutex operation_gate;
    std::mutex active_gate;
    GUID active_transaction{};
    bool transaction_active{};
    std::atomic<bool> active_cancelled{};
    librarian_passkey_provider_callbacks callbacks{};

    [[nodiscard]] std::int64_t steady_ticks() noexcept
    {
        return std::chrono::steady_clock::now().time_since_epoch().count();
    }

    void note_activity() noexcept
    {
        last_activity_ticks.store(steady_ticks(), std::memory_order_release);
    }

    template <typename function_type>
    class scope_exit final
    {
    public:
        explicit scope_exit(function_type function) noexcept
            : function_(std::move(function))
        {
        }

        scope_exit(scope_exit const&) = delete;
        scope_exit& operator=(scope_exit const&) = delete;

        ~scope_exit()
        {
            function_();
        }

    private:
        function_type function_;
    };

    template <typename function_type>
    scope_exit(function_type) -> scope_exit<function_type>;

    class transaction_scope final
    {
    public:
        explicit transaction_scope(GUID const& transaction) noexcept
        {
            std::lock_guard lock(active_gate);
            active_transaction = transaction;
            active_cancelled.store(false, std::memory_order_release);
            transaction_active = true;
            note_activity();
        }

        transaction_scope(transaction_scope const&) = delete;
        transaction_scope& operator=(transaction_scope const&) = delete;

        ~transaction_scope()
        {
            if (completed_)
            {
                return;
            }
            std::lock_guard lock(active_gate);
            SecureZeroMemory(&active_transaction, sizeof(active_transaction));
            active_cancelled.store(false, std::memory_order_release);
            transaction_active = false;
            note_activity();
        }

        [[nodiscard]] bool complete() noexcept
        {
            std::lock_guard lock(active_gate);
            if (!transaction_active || active_cancelled.load(std::memory_order_acquire))
            {
                return false;
            }
            SecureZeroMemory(&active_transaction, sizeof(active_transaction));
            active_cancelled.store(false, std::memory_order_release);
            transaction_active = false;
            completed_ = true;
            note_activity();
            return true;
        }

    private:
        bool completed_{};
    };

    [[nodiscard]] HRESULT callback_hresult(std::uint32_t result) noexcept
    {
        switch (result)
        {
        case callback_success:
            return S_OK;
        case callback_invalid:
            return E_INVALIDARG;
        case callback_locked:
            return HRESULT_FROM_WIN32(ERROR_NOT_READY);
        case callback_not_found:
            return NTE_NOT_FOUND;
        case callback_conflict:
            return NTE_EXISTS;
        case callback_busy:
            return HRESULT_FROM_WIN32(ERROR_BUSY);
        case callback_cancelled:
            return NTE_USER_CANCELLED;
        case callback_deadline:
            return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        case callback_unavailable:
            return HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE);
        case callback_incompatible:
            return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
        default:
            return E_FAIL;
        }
    }

    [[nodiscard]] bool valid_operation_request(
        WEBAUTHN_PLUGIN_OPERATION_REQUEST const* request) noexcept
    {
        if (request == nullptr || request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR ||
            request->pbRequestSignature == nullptr || request->cbRequestSignature == 0 ||
            request->cbRequestSignature > maximum_request_signature_bytes ||
            request->pbEncodedRequest == nullptr || request->cbEncodedRequest == 0 ||
            request->cbEncodedRequest > maximum_encoded_request_bytes)
        {
            return false;
        }
        auto const* transaction = reinterpret_cast<std::uint8_t const*>(&request->transactionId);
        return std::any_of(
            transaction,
            transaction + transaction_id_bytes,
            [](std::uint8_t value) { return value != 0; });
    }

    [[nodiscard]] librarian_passkey_request callback_request(
        WEBAUTHN_PLUGIN_OPERATION_REQUEST const& request,
        std::span<std::uint8_t const> agent_challenge = {},
        std::span<std::uint8_t const> uv_signature = {}) noexcept
    {
        return librarian_passkey_request{
            .parent_window = reinterpret_cast<std::uintptr_t>(request.hWnd),
            .transaction_id = reinterpret_cast<std::uint8_t const*>(&request.transactionId),
            .request_type = static_cast<std::uint32_t>(request.requestType),
            .request_signature = request.pbRequestSignature,
            .request_signature_bytes = request.cbRequestSignature,
            .encoded_request = request.pbEncodedRequest,
            .encoded_request_bytes = request.cbEncodedRequest,
            .agent_challenge = agent_challenge.data(),
            .agent_challenge_bytes = static_cast<std::uint32_t>(agent_challenge.size()),
            .user_verification_signature = uv_signature.data(),
            .user_verification_signature_bytes = static_cast<std::uint32_t>(uv_signature.size())};
    }

    using perform_uv_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST_2,
        DWORD*,
        PBYTE*);
    using free_uv_function = void(WINAPI*)(PBYTE);
    using decode_make_function = HRESULT(WINAPI*)(
        DWORD,
        const BYTE*,
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST*);
    using free_make_function = void(WINAPI*)(PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST);
    using encode_make_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_CREDENTIAL_ATTESTATION,
        DWORD*,
        BYTE**);
    using encode_assertion_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE,
        DWORD*,
        BYTE**);
    using add_credentials_function = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD,
        PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    using remove_credentials_function = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD,
        PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    using get_all_credentials_function = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD*,
        PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS*);
    using free_credentials_function = void(WINAPI*)(
        DWORD,
        PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    using get_authenticator_state_function = HRESULT(WINAPI*)(
        REFCLSID,
        AUTHENTICATOR_STATE*);
    using add_authenticator_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE*);
    using free_add_authenticator_response_function = void(WINAPI*)(
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
    using update_authenticator_function = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS);
    using remove_authenticator_function = HRESULT(WINAPI*)(REFCLSID);

    class webauthn_api final
    {
    public:
        webauthn_api() noexcept
            : module_(LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32))
        {
            if (module_ == nullptr)
            {
                return;
            }
            perform_uv = resolve<perform_uv_function>("WebAuthNPluginPerformUserVerification2");
            free_uv = resolve<free_uv_function>("WebAuthNPluginFreeUserVerificationResponse");
            decode_make = resolve<decode_make_function>("WebAuthNDecodeMakeCredentialRequest");
            free_make = resolve<free_make_function>("WebAuthNFreeDecodedMakeCredentialRequest");
            encode_make = resolve<encode_make_function>("WebAuthNEncodeMakeCredentialResponse");
            encode_assertion =
                resolve<encode_assertion_function>("WebAuthNEncodeGetAssertionResponse");
            add_credentials = resolve<add_credentials_function>(
                "WebAuthNPluginAuthenticatorAddCredentials");
            remove_credentials = resolve<remove_credentials_function>(
                "WebAuthNPluginAuthenticatorRemoveCredentials");
            get_all_credentials = resolve<get_all_credentials_function>(
                "WebAuthNPluginAuthenticatorGetAllCredentials");
            free_credentials = resolve<free_credentials_function>(
                "WebAuthNPluginAuthenticatorFreeCredentialDetailsArray");
            get_authenticator_state = resolve<get_authenticator_state_function>(
                "WebAuthNPluginGetAuthenticatorState");
            add_authenticator = resolve<add_authenticator_function>(
                "WebAuthNPluginAddAuthenticator");
            free_add_authenticator_response =
                resolve<free_add_authenticator_response_function>(
                    "WebAuthNPluginFreeAddAuthenticatorResponse");
            update_authenticator = resolve<update_authenticator_function>(
                "WebAuthNPluginUpdateAuthenticatorDetails");
            remove_authenticator = resolve<remove_authenticator_function>(
                "WebAuthNPluginRemoveAuthenticator");
        }

        webauthn_api(webauthn_api const&) = delete;
        webauthn_api& operator=(webauthn_api const&) = delete;

        ~webauthn_api()
        {
            if (module_ != nullptr)
            {
                FreeLibrary(module_);
            }
        }

        [[nodiscard]] bool complete() const noexcept
        {
            return module_ != nullptr && perform_uv != nullptr && free_uv != nullptr &&
                   decode_make != nullptr && free_make != nullptr && encode_make != nullptr &&
                   encode_assertion != nullptr && add_credentials != nullptr;
        }

        [[nodiscard]] bool registration_complete() const noexcept
        {
            return module_ != nullptr && get_authenticator_state != nullptr &&
                   add_authenticator != nullptr &&
                   free_add_authenticator_response != nullptr &&
                   update_authenticator != nullptr && remove_authenticator != nullptr;
        }

        [[nodiscard]] bool credential_cache_complete() const noexcept
        {
            return module_ != nullptr && remove_credentials != nullptr &&
                   get_all_credentials != nullptr && free_credentials != nullptr;
        }

        perform_uv_function perform_uv{};
        free_uv_function free_uv{};
        decode_make_function decode_make{};
        free_make_function free_make{};
        encode_make_function encode_make{};
        encode_assertion_function encode_assertion{};
        add_credentials_function add_credentials{};
        remove_credentials_function remove_credentials{};
        get_all_credentials_function get_all_credentials{};
        free_credentials_function free_credentials{};
        get_authenticator_state_function get_authenticator_state{};
        add_authenticator_function add_authenticator{};
        free_add_authenticator_response_function free_add_authenticator_response{};
        update_authenticator_function update_authenticator{};
        remove_authenticator_function remove_authenticator{};

    private:
        template <typename function_type>
        [[nodiscard]] function_type resolve(char const* name) const noexcept
        {
            return reinterpret_cast<function_type>(GetProcAddress(module_, name));
        }

        HMODULE module_{};
    };

    class decoded_make final
    {
    public:
        explicit decoded_make(webauthn_api const& api) noexcept : api_(api) {}
        decoded_make(decoded_make const&) = delete;
        decoded_make& operator=(decoded_make const&) = delete;
        ~decoded_make()
        {
            if (value != nullptr)
            {
                api_.free_make(value);
            }
        }
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST value{};

    private:
        webauthn_api const& api_;
    };

    [[nodiscard]] bool sha256(
        std::span<std::uint8_t const> input,
        std::array<std::uint8_t, 32>& output) noexcept
    {
        BCRYPT_ALG_HANDLE algorithm{};
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        {
            return false;
        }
        auto cleanup = scope_exit([&] { BCryptCloseAlgorithmProvider(algorithm, 0); });
        return input.size() <= std::numeric_limits<ULONG>::max() &&
               BCryptHash(
                   algorithm,
                   nullptr,
                   0,
                   const_cast<PUCHAR>(input.data()),
                   static_cast<ULONG>(input.size()),
                   output.data(),
                   static_cast<ULONG>(output.size())) >= 0;
    }

    [[nodiscard]] HRESULT perform_user_verification(
        webauthn_api const& api,
        WEBAUTHN_PLUGIN_OPERATION_REQUEST const& request,
        std::uint8_t operation,
        std::span<std::uint8_t const> agent_challenge,
        std::span<std::uint8_t const> credential_id,
        wchar_t const* username,
        wchar_t const* hint,
        std::vector<std::uint8_t>& signature) noexcept
    {
        if (agent_challenge.size() != librarian::windows_passkey::agent_challenge_bytes ||
            (!credential_id.empty() &&
            credential_id.size() != librarian_passkey_credential_id_bytes)
            )
        {
            return E_INVALIDARG;
        }
        std::array<std::uint8_t, 32> request_hash{};
        if (!sha256(
                std::span<std::uint8_t const>{
                    request.pbEncodedRequest,
                    request.cbEncodedRequest},
                request_hash))
        {
            return E_FAIL;
        }
        auto const* transaction = reinterpret_cast<std::uint8_t const*>(&request.transactionId);
        librarian::windows_passkey::user_verification_binding binding{};
        if (!librarian::windows_passkey::build_user_verification_binding(
                operation,
                std::span<std::uint8_t const>{transaction, transaction_id_bytes},
                agent_challenge,
                request_hash,
                credential_id,
                binding))
        {
            return E_INVALIDARG;
        }
        std::array<std::uint8_t, 32> digest{};
        if (!sha256(
                std::span<std::uint8_t const>{binding.bytes.data(), binding.size},
                digest))
        {
            SecureZeroMemory(binding.bytes.data(), binding.bytes.size());
            return E_FAIL;
        }
        SecureZeroMemory(binding.bytes.data(), binding.bytes.size());

        WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST_2 uv_request{};
        uv_request.hwnd = request.hWnd;
        uv_request.pGuidTransactionId = &request.transactionId;
        uv_request.pwszUsername = username;
        uv_request.pwszDisplayHint = hint;
        uv_request.cbBufferToSign = static_cast<DWORD>(digest.size());
        uv_request.pbBufferToSign = digest.data();
        DWORD response_bytes{};
        PBYTE response{};
        auto const result = api.perform_uv(&uv_request, &response_bytes, &response);
        SecureZeroMemory(digest.data(), digest.size());
        if (FAILED(result))
        {
            return result;
        }
        auto cleanup = scope_exit([&] {
            if (response != nullptr)
            {
                SecureZeroMemory(response, response_bytes);
                api.free_uv(response);
            }
        });
        if (response == nullptr || response_bytes == 0 ||
            response_bytes > maximum_request_signature_bytes)
        {
            return E_FAIL;
        }
        signature.assign(response, response + response_bytes);
        return S_OK;
    }

    [[nodiscard]] HRESULT prepare_agent_challenge(
        WEBAUTHN_PLUGIN_OPERATION_REQUEST const& request,
        std::array<std::uint8_t, librarian::windows_passkey::agent_challenge_bytes>& challenge)
        noexcept
    {
        auto const result = callbacks.prepare(
            callbacks.context,
            reinterpret_cast<std::uint8_t const*>(&request.transactionId),
            transaction_id_bytes,
            challenge.data(),
            static_cast<std::uint32_t>(challenge.size()));
        return callback_hresult(result);
    }

    void discard_agent_challenge(WEBAUTHN_PLUGIN_OPERATION_REQUEST const& request) noexcept
    {
        callbacks.discard(
            callbacks.context,
            reinterpret_cast<std::uint8_t const*>(&request.transactionId),
            transaction_id_bytes);
    }

    [[nodiscard]] bool utf8_to_wide(
        std::uint8_t const* input,
        std::uint32_t input_bytes,
        std::wstring& output) noexcept
    {
        if (input == nullptr || input_bytes == 0 ||
            input_bytes > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
        {
            return false;
        }
        auto const required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<char const*>(input),
            static_cast<int>(input_bytes),
            nullptr,
            0);
        if (required <= 0)
        {
            return false;
        }
        output.resize(static_cast<std::size_t>(required));
        return MultiByteToWideChar(
                   CP_UTF8,
                   MB_ERR_INVALID_CHARS,
                   reinterpret_cast<char const*>(input),
                   static_cast<int>(input_bytes),
                   output.data(),
                   required) == required;
    }

    HRESULT CALLBACK selection_dialog_callback(
        HWND dialog,
        UINT notification,
        WPARAM,
        LPARAM,
        LONG_PTR) noexcept
    {
        if (notification == TDN_TIMER && active_cancelled.load(std::memory_order_acquire))
        {
            SendMessageW(dialog, TDM_CLICK_BUTTON, IDCANCEL, 0);
        }
        return S_OK;
    }

    [[nodiscard]] HRESULT select_summary(
        HWND parent,
        std::span<librarian_passkey_summary const> summaries,
        std::size_t& selected) noexcept
    {
        if (summaries.empty())
        {
            return NTE_NOT_FOUND;
        }
        if (summaries.size() == 1)
        {
            selected = 0;
            return S_OK;
        }
        try
        {
            std::vector<std::wstring> labels;
            std::vector<TASKDIALOG_BUTTON> buttons;
            labels.reserve(summaries.size());
            buttons.reserve(summaries.size());
            for (std::size_t index = 0; index < summaries.size(); ++index)
            {
                std::wstring name;
                std::wstring display;
                if (!utf8_to_wide(
                        summaries[index].user_name,
                        summaries[index].user_name_bytes,
                        name) ||
                    !utf8_to_wide(
                        summaries[index].user_display_name,
                        summaries[index].user_display_name_bytes,
                        display))
                {
                    return E_FAIL;
                }
                labels.push_back(display + L"\n" + name);
                buttons.push_back(TASKDIALOG_BUTTON{
                    .nButtonID = static_cast<int>(1000 + index),
                    .pszButtonText = labels.back().c_str()});
            }
            TASKDIALOGCONFIG config{};
            config.cbSize = sizeof(config);
            config.hwndParent = parent;
            config.dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION |
                             TDF_POSITION_RELATIVE_TO_WINDOW | TDF_CALLBACK_TIMER;
            config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
            config.pszWindowTitle = L"Librarian";
            config.pszMainInstruction = L"Choose a passkey";
            config.pszContent = L"Select the account to use for this sign-in.";
            config.cButtons = static_cast<UINT>(buttons.size());
            config.pButtons = buttons.data();
            config.pfCallback = selection_dialog_callback;
            int button{};
            auto const result = TaskDialogIndirect(&config, &button, nullptr, nullptr);
            if (FAILED(result))
            {
                return result;
            }
            if (button < 1000 ||
                static_cast<std::size_t>(button - 1000) >= summaries.size())
            {
                return NTE_USER_CANCELLED;
            }
            selected = static_cast<std::size_t>(button - 1000);
            return S_OK;
        }
        catch (...)
        {
            return E_FAIL;
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> cose_public_key(
        std::span<std::uint8_t const, librarian_passkey_public_key_bytes> public_key)
    {
        std::vector<std::uint8_t> cose;
        cose.reserve(77);
        std::array<std::uint8_t, 9> const prefix{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58};
        cose.insert(cose.end(), prefix.begin(), prefix.end());
        cose.push_back(0x20);
        cose.insert(cose.end(), public_key.begin() + 1, public_key.begin() + 33);
        cose.push_back(0x22);
        cose.push_back(0x58);
        cose.push_back(0x20);
        cose.insert(cose.end(), public_key.begin() + 33, public_key.end());
        return cose;
    }

    [[nodiscard]] HRESULT encode_make_response(
        webauthn_api const& api,
        WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST const& request,
        librarian_passkey_credential const& credential,
        WEBAUTHN_PLUGIN_OPERATION_RESPONSE* response) noexcept
    {
        if (response == nullptr || request.pbRpId == nullptr || request.cbRpId == 0 ||
            credential.user_handle_bytes == 0 ||
            credential.user_handle_bytes > librarian_passkey_user_handle_capacity ||
            credential.public_key[0] != 0x04)
        {
            return E_INVALIDARG;
        }
        std::array<std::uint8_t, 32> rp_hash{};
        if (!sha256(
                std::span<std::uint8_t const>{request.pbRpId, request.cbRpId},
                rp_hash))
        {
            return E_FAIL;
        }
        auto const cose = cose_public_key(credential.public_key);
        std::vector<std::uint8_t> authenticator_data;
        authenticator_data.reserve(
            rp_hash.size() + 1 + 4 + authenticator_aaguid.size() + 2 +
            librarian_passkey_credential_id_bytes + cose.size());
        authenticator_data.insert(authenticator_data.end(), rp_hash.begin(), rp_hash.end());
        authenticator_data.push_back(0x4d);
        authenticator_data.insert(authenticator_data.end(), 4, 0);
        authenticator_data.insert(
            authenticator_data.end(),
            authenticator_aaguid.begin(),
            authenticator_aaguid.end());
        authenticator_data.push_back(0);
        authenticator_data.push_back(
            static_cast<std::uint8_t>(librarian_passkey_credential_id_bytes));
        authenticator_data.insert(
            authenticator_data.end(),
            credential.credential_id,
            credential.credential_id + librarian_passkey_credential_id_bytes);
        authenticator_data.insert(authenticator_data.end(), cose.begin(), cose.end());

        WEBAUTHN_CREDENTIAL_ATTESTATION attestation{};
        attestation.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
        attestation.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
        attestation.cbAuthenticatorData = static_cast<DWORD>(authenticator_data.size());
        attestation.pbAuthenticatorData = authenticator_data.data();
        DWORD encoded_bytes{};
        BYTE* encoded{};
        auto const result = api.encode_make(&attestation, &encoded_bytes, &encoded);
        if (FAILED(result))
        {
            return result;
        }
        response->cbEncodedResponse = encoded_bytes;
        response->pbEncodedResponse = encoded;
        return S_OK;
    }

    [[nodiscard]] HRESULT encode_assertion_response(
        webauthn_api const& api,
        librarian_passkey_assertion const& result,
        WEBAUTHN_PLUGIN_OPERATION_RESPONSE* response) noexcept
    {
        if (response == nullptr || result.user_handle_bytes == 0 ||
            result.user_handle_bytes > librarian_passkey_user_handle_capacity ||
            result.signature_bytes == 0 ||
            result.signature_bytes > librarian_passkey_signature_capacity)
        {
            return E_INVALIDARG;
        }
        WEBAUTHN_ASSERTION assertion{};
        assertion.dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;
        assertion.Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
        assertion.Credential.cbId = librarian_passkey_credential_id_bytes;
        assertion.Credential.pbId = const_cast<PBYTE>(result.credential_id);
        assertion.Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
        assertion.cbAuthenticatorData = librarian_passkey_authenticator_data_bytes;
        assertion.pbAuthenticatorData = const_cast<PBYTE>(result.authenticator_data);
        assertion.cbSignature = result.signature_bytes;
        assertion.pbSignature = const_cast<PBYTE>(result.signature);
        assertion.cbUserId = result.user_handle_bytes;
        assertion.pbUserId = const_cast<PBYTE>(result.user_handle);

        WEBAUTHN_USER_ENTITY_INFORMATION user{};
        user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
        user.cbId = result.user_handle_bytes;
        user.pbId = const_cast<PBYTE>(result.user_handle);
        WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE ctap{};
        ctap.WebAuthNAssertion = assertion;
        ctap.pUserInformation = &user;
        ctap.dwNumberOfCredentials = 1;
        DWORD encoded_bytes{};
        BYTE* encoded{};
        auto const encode_result = api.encode_assertion(&ctap, &encoded_bytes, &encoded);
        if (FAILED(encode_result))
        {
            return encode_result;
        }
        response->cbEncodedResponse = encoded_bytes;
        response->pbEncodedResponse = encoded;
        return S_OK;
    }

    class authenticator final : public IPluginAuthenticator
    {
    public:
        authenticator() noexcept
        {
            server_objects.fetch_add(1, std::memory_order_acq_rel);
            note_activity();
        }

        authenticator(authenticator const&) = delete;
        authenticator& operator=(authenticator const&) = delete;

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) noexcept override
        {
            if (value == nullptr)
            {
                return E_POINTER;
            }
            *value = nullptr;
            if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, __uuidof(IPluginAuthenticator)))
            {
                *value = static_cast<IPluginAuthenticator*>(this);
                AddRef();
                return S_OK;
            }
            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() noexcept override
        {
            return references_.fetch_add(1, std::memory_order_relaxed) + 1;
        }

        ULONG STDMETHODCALLTYPE Release() noexcept override
        {
            auto const remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
            if (remaining == 0)
            {
                delete this;
            }
            return remaining;
        }

        HRESULT STDMETHODCALLTYPE MakeCredential(
            PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override
        {
            if (response == nullptr)
            {
                return E_POINTER;
            }
            *response = {};
            if (!valid_operation_request(request))
            {
                return E_INVALIDARG;
            }
            std::unique_lock operation(operation_gate, std::try_to_lock);
            if (!operation.owns_lock())
            {
                return HRESULT_FROM_WIN32(ERROR_BUSY);
            }
            transaction_scope transaction(request->transactionId);
            webauthn_api api;
            if (!api.complete())
            {
                return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
            }
            decoded_make decoded(api);
            auto result = api.decode_make(
                request->cbEncodedRequest,
                request->pbEncodedRequest,
                &decoded.value);
            if (FAILED(result) || decoded.value == nullptr ||
                decoded.value->pRpInformation == nullptr ||
                decoded.value->pUserInformation == nullptr ||
                decoded.value->pUserInformation->pwszName == nullptr)
            {
                return E_INVALIDARG;
            }
            std::vector<std::uint8_t> uv_signature;
            std::array<std::uint8_t, librarian::windows_passkey::agent_challenge_bytes>
                agent_challenge{};
            result = prepare_agent_challenge(*request, agent_challenge);
            if (FAILED(result))
            {
                return result;
            }
            auto discard_challenge = scope_exit([&] {
                discard_agent_challenge(*request);
                SecureZeroMemory(agent_challenge.data(), agent_challenge.size());
            });
            result = perform_user_verification(
                api,
                *request,
                static_cast<std::uint8_t>(make_operation),
                agent_challenge,
                {},
                decoded.value->pUserInformation->pwszName,
                L"Create a passkey with Librarian",
                uv_signature);
            if (FAILED(result))
            {
                return result;
            }
            auto scrub_uv = scope_exit([&] {
                SecureZeroMemory(uv_signature.data(), uv_signature.size());
            });
            if (active_cancelled.load(std::memory_order_acquire))
            {
                return NTE_USER_CANCELLED;
            }
            librarian_passkey_credential credential{};
            auto const proof = callback_request(*request, agent_challenge, uv_signature);
            result = callback_hresult(callbacks.make(callbacks.context, &proof, &credential));
            if (FAILED(result))
            {
                SecureZeroMemory(&credential, sizeof(credential));
                return result;
            }
            auto scrub_credential = scope_exit([&] {
                SecureZeroMemory(&credential, sizeof(credential));
            });
            auto const rollback_creation = [&]() noexcept {
                return callback_hresult(callbacks.rollback_make(
                    callbacks.context,
                    &proof,
                    credential.credential_id,
                    librarian_passkey_credential_id_bytes));
            };
            if (active_cancelled.load(std::memory_order_acquire))
            {
                result = rollback_creation();
                return FAILED(result) ? result : NTE_USER_CANCELLED;
            }
            result = encode_make_response(api, *decoded.value, credential, response);
            if (FAILED(result))
            {
                auto const rollback_result = rollback_creation();
                return FAILED(rollback_result) ? rollback_result : result;
            }
            WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS details{};
            details.cbCredentialId = librarian_passkey_credential_id_bytes;
            details.pbCredentialId = credential.credential_id;
            details.pwszRpId = decoded.value->pRpInformation->pwszId;
            details.pwszRpName = decoded.value->pRpInformation->pwszName;
            details.cbUserId = credential.user_handle_bytes;
            details.pbUserId = credential.user_handle;
            details.pwszUserName = decoded.value->pUserInformation->pwszName;
            details.pwszUserDisplayName = decoded.value->pUserInformation->pwszDisplayName;
            result = api.add_credentials(provider_clsid, 1, &details);
            if (FAILED(result))
            {
                CoTaskMemFree(response->pbEncodedResponse);
                *response = {};
                static_cast<void>(api.remove_credentials(provider_clsid, 1, &details));
                auto const rollback_result = rollback_creation();
                return FAILED(rollback_result) ? rollback_result : result;
            }
            result = callback_hresult(callbacks.confirm_make(
                callbacks.context,
                &proof,
                credential.credential_id,
                librarian_passkey_credential_id_bytes));
            if (FAILED(result))
            {
                CoTaskMemFree(response->pbEncodedResponse);
                *response = {};
                static_cast<void>(api.remove_credentials(provider_clsid, 1, &details));
                auto const rollback_result = rollback_creation();
                return FAILED(rollback_result) ? rollback_result : result;
            }
            if (!transaction.complete())
            {
                CoTaskMemFree(response->pbEncodedResponse);
                *response = {};
                static_cast<void>(api.remove_credentials(provider_clsid, 1, &details));
                result = rollback_creation();
                return FAILED(result) ? result : NTE_USER_CANCELLED;
            }
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetAssertion(
            PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override
        {
            if (response == nullptr)
            {
                return E_POINTER;
            }
            *response = {};
            if (!valid_operation_request(request))
            {
                return E_INVALIDARG;
            }
            std::unique_lock operation(operation_gate, std::try_to_lock);
            if (!operation.owns_lock())
            {
                return HRESULT_FROM_WIN32(ERROR_BUSY);
            }
            transaction_scope transaction(request->transactionId);
            webauthn_api api;
            if (!api.complete())
            {
                return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
            }
            std::vector<librarian_passkey_summary> summaries(maximum_summaries);
            auto scrub_summaries = scope_exit([&] {
                SecureZeroMemory(summaries.data(), summaries.size() * sizeof(summaries[0]));
            });
            std::uint32_t summary_count{};
            auto proof = callback_request(*request);
            auto result = callback_hresult(callbacks.list(
                callbacks.context,
                &proof,
                summaries.data(),
                static_cast<std::uint32_t>(summaries.size()),
                &summary_count));
            if (FAILED(result))
            {
                return result;
            }
            if (summary_count == 0 || summary_count > summaries.size())
            {
                return NTE_NOT_FOUND;
            }
            std::size_t selected{};
            result = select_summary(
                request->hWnd,
                std::span<librarian_passkey_summary const>{summaries.data(), summary_count},
                selected);
            if (FAILED(result) || active_cancelled.load(std::memory_order_acquire))
            {
                return FAILED(result) ? result : NTE_USER_CANCELLED;
            }
            std::wstring username;
            if (!utf8_to_wide(
                    summaries[selected].user_name,
                    summaries[selected].user_name_bytes,
                    username))
            {
                return E_FAIL;
            }
            std::vector<std::uint8_t> uv_signature;
            std::array<std::uint8_t, librarian::windows_passkey::agent_challenge_bytes>
                agent_challenge{};
            result = prepare_agent_challenge(*request, agent_challenge);
            if (FAILED(result))
            {
                SecureZeroMemory(username.data(), username.size() * sizeof(wchar_t));
                return result;
            }
            auto discard_challenge = scope_exit([&] {
                discard_agent_challenge(*request);
                SecureZeroMemory(agent_challenge.data(), agent_challenge.size());
            });
            result = perform_user_verification(
                api,
                *request,
                static_cast<std::uint8_t>(assertion_operation),
                agent_challenge,
                std::span<std::uint8_t const>{
                    summaries[selected].credential_id,
                    librarian_passkey_credential_id_bytes},
                username.c_str(),
                L"Sign in with Librarian",
                uv_signature);
            SecureZeroMemory(username.data(), username.size() * sizeof(wchar_t));
            if (FAILED(result))
            {
                return result;
            }
            auto scrub_uv = scope_exit([&] {
                SecureZeroMemory(uv_signature.data(), uv_signature.size());
            });
            if (active_cancelled.load(std::memory_order_acquire))
            {
                return NTE_USER_CANCELLED;
            }
            librarian_passkey_assertion assertion{};
            proof = callback_request(*request, agent_challenge, uv_signature);
            result = callback_hresult(callbacks.get_assertion(
                callbacks.context,
                &proof,
                summaries[selected].credential_id,
                librarian_passkey_credential_id_bytes,
                &assertion));
            if (FAILED(result))
            {
                SecureZeroMemory(&assertion, sizeof(assertion));
                return result;
            }
            auto scrub_assertion = scope_exit([&] {
                SecureZeroMemory(&assertion, sizeof(assertion));
            });
            if (active_cancelled.load(std::memory_order_acquire))
            {
                return NTE_USER_CANCELLED;
            }
            result = encode_assertion_response(api, assertion, response);
            if (FAILED(result))
            {
                return result;
            }
            if (!transaction.complete())
            {
                CoTaskMemFree(response->pbEncodedResponse);
                *response = {};
                return NTE_USER_CANCELLED;
            }
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE CancelOperation(
            PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) noexcept override
        {
            if (request == nullptr)
            {
                return E_INVALIDARG;
            }
            std::lock_guard lock(active_gate);
            if (!transaction_active || !IsEqualGUID(active_transaction, request->transactionId))
            {
                return NTE_NOT_FOUND;
            }
            active_cancelled.store(true, std::memory_order_release);
            note_activity();
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetLockStatus(PLUGIN_LOCK_STATUS* status) noexcept override
        {
            if (status == nullptr)
            {
                return E_POINTER;
            }
            std::uint32_t unlocked{};
            auto const result = callbacks.status(callbacks.context, &unlocked);
            *status = result == callback_success && unlocked != 0 ? PluginUnlocked : PluginLocked;
            note_activity();
            return S_OK;
        }

    private:
        ~authenticator()
        {
            server_objects.fetch_sub(1, std::memory_order_acq_rel);
            note_activity();
        }

        std::atomic<ULONG> references_{1};
    };

    class authenticator_factory final : public IClassFactory
    {
    public:
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) noexcept override
        {
            if (value == nullptr)
            {
                return E_POINTER;
            }
            *value = nullptr;
            if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IClassFactory))
            {
                *value = static_cast<IClassFactory*>(this);
                AddRef();
                return S_OK;
            }
            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() noexcept override
        {
            return references_.fetch_add(1, std::memory_order_relaxed) + 1;
        }

        ULONG STDMETHODCALLTYPE Release() noexcept override
        {
            auto const remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
            if (remaining == 0)
            {
                delete this;
            }
            return remaining;
        }

        HRESULT STDMETHODCALLTYPE CreateInstance(
            IUnknown* outer,
            REFIID iid,
            void** value) noexcept override
        {
            if (value == nullptr)
            {
                return E_POINTER;
            }
            *value = nullptr;
            if (outer != nullptr)
            {
                return CLASS_E_NOAGGREGATION;
            }
            auto* instance = new (std::nothrow) authenticator();
            if (instance == nullptr)
            {
                return E_OUTOFMEMORY;
            }
            auto const result = instance->QueryInterface(iid, value);
            instance->Release();
            return result;
        }

        HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) noexcept override
        {
            if (lock != FALSE)
            {
                server_locks.fetch_add(1, std::memory_order_acq_rel);
            }
            else
            {
                auto current = server_locks.load(std::memory_order_acquire);
                while (current != 0 &&
                       !server_locks.compare_exchange_weak(
                           current,
                           current - 1,
                           std::memory_order_acq_rel,
                           std::memory_order_acquire))
                {
                }
            }
            note_activity();
            return S_OK;
        }

    private:
        ~authenticator_factory() = default;
        std::atomic<ULONG> references_{1};
    };
}

extern "C" std::uint32_t librarian_windows_passkey_provider_request_cancelled(
    std::uint8_t const* transaction_id,
    std::uint32_t transaction_bytes) noexcept
{
    if (transaction_id == nullptr || transaction_bytes != transaction_id_bytes)
    {
        return 1;
    }
    std::lock_guard lock(active_gate);
    return transaction_active &&
                   std::memcmp(&active_transaction, transaction_id, transaction_id_bytes) == 0 &&
                   active_cancelled.load(std::memory_order_acquire)
               ? 1
               : 0;
}

extern "C" std::uint32_t librarian_windows_passkey_provider_register() noexcept
{
    webauthn_api const api;
    if (!api.registration_complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }

    AUTHENTICATOR_STATE state{};
    HRESULT result = api.get_authenticator_state(provider_clsid, &state);
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
        result = api.add_authenticator(&options, &response);
        if (FAILED(result))
        {
            return static_cast<std::uint32_t>(result);
        }
        bool const valid_response =
            response != nullptr && response->pbOpSignPubKey != nullptr &&
            response->cbOpSignPubKey != 0U;
        api.free_add_authenticator_response(response);
        if (!valid_response)
        {
            static_cast<void>(api.remove_authenticator(provider_clsid));
            return static_cast<std::uint32_t>(E_UNEXPECTED);
        }
        return 0;
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
    return static_cast<std::uint32_t>(api.update_authenticator(&details));
}

extern "C" std::uint32_t librarian_windows_passkey_provider_unregister() noexcept
{
    webauthn_api const api;
    if (!api.registration_complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }
    HRESULT const result = api.remove_authenticator(provider_clsid);
    return result == NTE_NOT_FOUND ? 0U : static_cast<std::uint32_t>(result);
}

extern "C" std::uint32_t librarian_windows_passkey_provider_registration_state(
    std::uint32_t* registered) noexcept
{
    if (registered == nullptr)
    {
        return static_cast<std::uint32_t>(E_POINTER);
    }
    *registered = 0;
    webauthn_api const api;
    if (!api.registration_complete())
    {
        return static_cast<std::uint32_t>(HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND));
    }
    AUTHENTICATOR_STATE state{};
    HRESULT const result = api.get_authenticator_state(provider_clsid, &state);
    if (result == NTE_NOT_FOUND)
    {
        return 0;
    }
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }
    *registered = 1;
    return 0;
}

extern "C" std::uint32_t librarian_windows_passkey_provider_run(
    librarian_passkey_provider_callbacks const* supplied_callbacks) noexcept
{
    if (supplied_callbacks == nullptr || supplied_callbacks->context == nullptr ||
        supplied_callbacks->status == nullptr || supplied_callbacks->prepare == nullptr ||
        supplied_callbacks->discard == nullptr || supplied_callbacks->list == nullptr ||
        supplied_callbacks->make == nullptr || supplied_callbacks->confirm_make == nullptr ||
        supplied_callbacks->rollback_make == nullptr ||
        supplied_callbacks->get_assertion == nullptr)
    {
        return static_cast<std::uint32_t>(E_INVALIDARG);
    }
    callbacks = *supplied_callbacks;
    note_activity();
    auto result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }
    auto uninitialize = scope_exit([] { CoUninitialize(); });
    result = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr);
    if (FAILED(result) && result != RPC_E_TOO_LATE)
    {
        return static_cast<std::uint32_t>(result);
    }
    auto* factory = new (std::nothrow) authenticator_factory();
    if (factory == nullptr)
    {
        return static_cast<std::uint32_t>(E_OUTOFMEMORY);
    }
    DWORD registration{};
    result = CoRegisterClassObject(
        provider_clsid,
        factory,
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
        &registration);
    factory->Release();
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }
    auto revoke = scope_exit([&] { CoRevokeClassObject(registration); });
    result = CoResumeClassObjects();
    if (FAILED(result))
    {
        return static_cast<std::uint32_t>(result);
    }
    constexpr auto idle_timeout = std::chrono::seconds(30);
    for (;;)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (server_objects.load(std::memory_order_acquire) != 0 ||
            server_locks.load(std::memory_order_acquire) != 0)
        {
            continue;
        }
        auto const last = std::chrono::steady_clock::duration(last_activity_ticks.load(
            std::memory_order_acquire));
        if (std::chrono::steady_clock::now().time_since_epoch() - last >= idle_timeout)
        {
            result = CoSuspendClassObjects();
            if (FAILED(result))
            {
                return static_cast<std::uint32_t>(result);
            }
            auto const suspended_last = std::chrono::steady_clock::duration(
                last_activity_ticks.load(std::memory_order_acquire));
            if (server_objects.load(std::memory_order_acquire) == 0 &&
                server_locks.load(std::memory_order_acquire) == 0 &&
                std::chrono::steady_clock::now().time_since_epoch() - suspended_last >=
                    idle_timeout)
            {
                return 0;
            }
            result = CoResumeClassObjects();
            if (FAILED(result))
            {
                return static_cast<std::uint32_t>(result);
            }
        }
    }
}
