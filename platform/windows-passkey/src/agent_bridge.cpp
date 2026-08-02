#include "librarian/windows_passkey/agent_bridge.h"
#include "librarian/windows_passkey/foundation.h"

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <webauthn.h>
#include <webauthnplugin.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    constexpr std::uint32_t success = 0;
    constexpr std::uint32_t invalid = 1;
    constexpr std::uint32_t unavailable = 2;
    constexpr std::uint32_t failed = 3;
    constexpr std::uint32_t ctap2_cbor_request_type = 1;
    constexpr std::size_t transaction_id_bytes = 16;
    constexpr std::size_t client_data_hash_bytes = 32;
    constexpr std::size_t credential_id_bytes = 32;
    constexpr std::size_t max_signature_bytes = 2 * 1024;
    constexpr std::size_t max_encoded_request_bytes = 48 * 1024;
    constexpr std::size_t max_rp_id_bytes = 253;
    constexpr std::size_t max_user_handle_bytes = 64;
    constexpr std::size_t max_user_name_bytes = 256;
    constexpr std::size_t max_excluded_credentials = 64;
    constexpr std::uint8_t make_operation = 30;
    constexpr std::uint8_t assertion_operation = 31;

    // This identity is intentionally fixed: Windows binds both public keys to
    // the registered provider identity, not to the caller-supplied request.
    constexpr CLSID provider_clsid{
        0x68fe5df7,
        0x9fe6,
        0x4145,
        {0xbb, 0xa0, 0x95, 0x01, 0x0f, 0x43, 0xbf, 0xbe}};

    using get_public_key_function = HRESULT(WINAPI*)(REFCLSID, DWORD*, PBYTE*);
    using free_public_key_function = void(WINAPI*)(PBYTE);
    using decode_make_function = HRESULT(WINAPI*)(
        DWORD,
        const BYTE*,
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST*);
    using free_make_function = void(WINAPI*)(PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST);
    using decode_assertion_function = HRESULT(WINAPI*)(
        DWORD,
        const BYTE*,
        PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST*);
    using free_assertion_function = void(WINAPI*)(PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST);

    class webauthn_api final
    {
    public:
        webauthn_api() noexcept
            : module_(LoadLibraryExW(
                  L"webauthn.dll",
                  nullptr,
                  LOAD_LIBRARY_SEARCH_SYSTEM32))
        {
            if (module_ == nullptr)
            {
                return;
            }
            get_operation_key = resolve<get_public_key_function>(
                "WebAuthNPluginGetOperationSigningPublicKey");
            get_uv_key = resolve<get_public_key_function>(
                "WebAuthNPluginGetUserVerificationPublicKey");
            free_public_key = resolve<free_public_key_function>(
                "WebAuthNPluginFreePublicKeyResponse");
            decode_make = resolve<decode_make_function>(
                "WebAuthNDecodeMakeCredentialRequest");
            free_make = resolve<free_make_function>(
                "WebAuthNFreeDecodedMakeCredentialRequest");
            decode_assertion = resolve<decode_assertion_function>(
                "WebAuthNDecodeGetAssertionRequest");
            free_assertion = resolve<free_assertion_function>(
                "WebAuthNFreeDecodedGetAssertionRequest");
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
            return module_ != nullptr && get_operation_key != nullptr && get_uv_key != nullptr &&
                   free_public_key != nullptr && decode_make != nullptr && free_make != nullptr &&
                   decode_assertion != nullptr && free_assertion != nullptr;
        }

        get_public_key_function get_operation_key{};
        get_public_key_function get_uv_key{};
        free_public_key_function free_public_key{};
        decode_make_function decode_make{};
        free_make_function free_make{};
        decode_assertion_function decode_assertion{};
        free_assertion_function free_assertion{};

    private:
        template <typename function_type>
        [[nodiscard]] function_type resolve(char const* name) const noexcept
        {
            return reinterpret_cast<function_type>(GetProcAddress(module_, name));
        }

        HMODULE module_{};
    };

    class public_key_response final
    {
    public:
        public_key_response(webauthn_api const& api, PBYTE value) noexcept
            : api_(api), value_(value)
        {
        }

        public_key_response(public_key_response const&) = delete;
        public_key_response& operator=(public_key_response const&) = delete;

        ~public_key_response()
        {
            if (value_ != nullptr)
            {
                api_.free_public_key(value_);
            }
        }

    private:
        webauthn_api const& api_;
        PBYTE value_{};
    };

    class ncrypt_provider final
    {
    public:
        ncrypt_provider() noexcept
        {
            status_ = NCryptOpenStorageProvider(
                &handle_,
                MS_KEY_STORAGE_PROVIDER,
                0);
        }

        ncrypt_provider(ncrypt_provider const&) = delete;
        ncrypt_provider& operator=(ncrypt_provider const&) = delete;

        ~ncrypt_provider()
        {
            if (handle_ != 0)
            {
                NCryptFreeObject(handle_);
            }
        }

        [[nodiscard]] bool valid() const noexcept
        {
            return status_ == ERROR_SUCCESS && handle_ != 0;
        }

        [[nodiscard]] NCRYPT_PROV_HANDLE get() const noexcept
        {
            return handle_;
        }

    private:
        NCRYPT_PROV_HANDLE handle_{};
        SECURITY_STATUS status_{NTE_FAIL};
    };

    class ncrypt_key final
    {
    public:
        explicit ncrypt_key(NCRYPT_KEY_HANDLE handle) noexcept : handle_(handle)
        {
        }

        ncrypt_key(ncrypt_key const&) = delete;
        ncrypt_key& operator=(ncrypt_key const&) = delete;

        ~ncrypt_key()
        {
            if (handle_ != 0)
            {
                NCryptFreeObject(handle_);
            }
        }

        [[nodiscard]] NCRYPT_KEY_HANDLE get() const noexcept
        {
            return handle_;
        }

    private:
        NCRYPT_KEY_HANDLE handle_{};
    };

    class bcrypt_algorithm final
    {
    public:
        bcrypt_algorithm() noexcept
        {
            status_ = BCryptOpenAlgorithmProvider(
                &handle_,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0);
        }

        bcrypt_algorithm(bcrypt_algorithm const&) = delete;
        bcrypt_algorithm& operator=(bcrypt_algorithm const&) = delete;

        ~bcrypt_algorithm()
        {
            if (handle_ != nullptr)
            {
                BCryptCloseAlgorithmProvider(handle_, 0);
            }
        }

        [[nodiscard]] bool hash(
            std::span<std::uint8_t const> input,
            std::array<std::uint8_t, client_data_hash_bytes>& output) const noexcept
        {
            if (status_ < 0 || handle_ == nullptr ||
                input.size() > std::numeric_limits<ULONG>::max())
            {
                return false;
            }
            return BCryptHash(
                       handle_,
                       nullptr,
                       0,
                       const_cast<PUCHAR>(input.data()),
                       static_cast<ULONG>(input.size()),
                       output.data(),
                       static_cast<ULONG>(output.size())) >= 0;
        }

    private:
        BCRYPT_ALG_HANDLE handle_{};
        NTSTATUS status_{static_cast<NTSTATUS>(-1)};
    };

    struct decoded_make final
    {
        webauthn_api const& api;
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST value{};

        ~decoded_make()
        {
            if (value != nullptr)
            {
                api.free_make(value);
            }
        }
    };

    struct decoded_assertion final
    {
        webauthn_api const& api;
        PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST value{};

        ~decoded_assertion()
        {
            if (value != nullptr)
            {
                api.free_assertion(value);
            }
        }
    };

    [[nodiscard]] bool valid_request_proof(
        librarian_windows_passkey_proof const& proof) noexcept
    {
        if (proof.transaction_id == nullptr || proof.request_type != ctap2_cbor_request_type ||
            proof.request_signature == nullptr || proof.request_signature_bytes == 0 ||
            proof.request_signature_bytes > max_signature_bytes || proof.encoded_request == nullptr ||
            proof.encoded_request_bytes == 0 ||
            proof.encoded_request_bytes > max_encoded_request_bytes)
        {
            return false;
        }
        return std::any_of(
            proof.transaction_id,
            proof.transaction_id + transaction_id_bytes,
            [](std::uint8_t value) { return value != 0; });
    }

    [[nodiscard]] bool valid_proof(librarian_windows_passkey_proof const& proof) noexcept
    {
        return valid_request_proof(proof) && proof.agent_challenge != nullptr &&
               proof.agent_challenge_bytes ==
                   librarian::windows_passkey::agent_challenge_bytes &&
               proof.user_verification_signature != nullptr &&
               proof.user_verification_signature_bytes != 0 &&
               proof.user_verification_signature_bytes <= max_signature_bytes;
    }

    [[nodiscard]] bool valid_utf8(std::span<std::uint8_t const> value) noexcept
    {
        if (value.empty() || value.size() > std::numeric_limits<int>::max() ||
            std::find(value.begin(), value.end(), 0) != value.end())
        {
            return false;
        }
        auto const length = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            reinterpret_cast<char const*>(value.data()),
            static_cast<int>(value.size()),
            nullptr,
            0);
        return length > 0;
    }

    [[nodiscard]] bool wide_to_utf8(
        wchar_t const* value,
        std::size_t maximum_bytes,
        std::vector<std::uint8_t>& output) noexcept
    {
        if (value == nullptr)
        {
            return false;
        }
        auto const required = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value,
            -1,
            nullptr,
            0,
            nullptr,
            nullptr);
        if (required <= 1 || static_cast<std::size_t>(required - 1) > maximum_bytes)
        {
            return false;
        }
        std::vector<char> converted(static_cast<std::size_t>(required));
        if (WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                value,
                -1,
                converted.data(),
                required,
                nullptr,
                nullptr) != required)
        {
            return false;
        }
        output.assign(converted.begin(), converted.end() - 1);
        SecureZeroMemory(converted.data(), converted.size());
        return true;
    }

    [[nodiscard]] bool hash_sha256(
        std::span<std::uint8_t const> input,
        std::array<std::uint8_t, client_data_hash_bytes>& output) noexcept
    {
        bcrypt_algorithm algorithm;
        return algorithm.hash(input, output);
    }

    [[nodiscard]] bool verify_with_public_key(
        std::span<std::uint8_t const> public_key,
        std::span<std::uint8_t const> digest,
        std::span<std::uint8_t const> signature) noexcept
    {
        if (public_key.size() < sizeof(BCRYPT_KEY_BLOB) ||
            public_key.size() > std::numeric_limits<DWORD>::max() ||
            digest.size() > std::numeric_limits<DWORD>::max() ||
            signature.size() > std::numeric_limits<DWORD>::max())
        {
            return false;
        }

        ULONG magic{};
        std::memcpy(&magic, public_key.data(), sizeof(magic));
        bool const is_rsa = magic == BCRYPT_RSAPUBLIC_MAGIC;
        bool const is_ecc = magic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC ||
                            magic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC ||
                            magic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
        if (!is_rsa && !is_ecc)
        {
            return false;
        }

        ncrypt_provider provider;
        if (!provider.valid())
        {
            return false;
        }
        NCRYPT_KEY_HANDLE raw_key{};
        auto const import_status = NCryptImportKey(
            provider.get(),
            0,
            BCRYPT_PUBLIC_KEY_BLOB,
            nullptr,
            &raw_key,
            const_cast<PBYTE>(public_key.data()),
            static_cast<DWORD>(public_key.size()),
            0);
        if (import_status != ERROR_SUCCESS || raw_key == 0)
        {
            return false;
        }
        ncrypt_key key(raw_key);

        BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
        return NCryptVerifySignature(
                   key.get(),
                   is_rsa ? static_cast<void*>(&padding) : nullptr,
                   const_cast<PBYTE>(digest.data()),
                   static_cast<DWORD>(digest.size()),
                   const_cast<PBYTE>(signature.data()),
                   static_cast<DWORD>(signature.size()),
                   is_rsa ? NCRYPT_PAD_PKCS1_FLAG : 0) == ERROR_SUCCESS;
    }

    [[nodiscard]] bool verify_windows_signature(
        webauthn_api const& api,
        get_public_key_function get_key,
        std::span<std::uint8_t const> message,
        std::span<std::uint8_t const> signature) noexcept
    {
        DWORD public_key_bytes{};
        PBYTE public_key{};
        auto const key_status = get_key(provider_clsid, &public_key_bytes, &public_key);
        public_key_response response(api, public_key);
        if (FAILED(key_status) || public_key == nullptr || public_key_bytes == 0)
        {
            return false;
        }
        std::array<std::uint8_t, client_data_hash_bytes> digest{};
        return hash_sha256(message, digest) && verify_with_public_key(
            std::span<std::uint8_t const>{public_key, public_key_bytes},
            digest,
            signature);
    }

    [[nodiscard]] bool verify_request_proof(
        webauthn_api const& api,
        librarian_windows_passkey_proof const& proof) noexcept
    {
        if (!valid_request_proof(proof))
        {
            return false;
        }
        auto const request = std::span<std::uint8_t const>{
            proof.encoded_request,
            proof.encoded_request_bytes};
        auto const operation_signature = std::span<std::uint8_t const>{
            proof.request_signature,
            proof.request_signature_bytes};
        return verify_windows_signature(api, api.get_operation_key, request, operation_signature);
    }

    [[nodiscard]] bool verify_proof(
        webauthn_api const& api,
        librarian_windows_passkey_proof const& proof,
        std::uint8_t operation,
        std::span<std::uint8_t const> credential_id = {}) noexcept
    {
        if ((!credential_id.empty() && credential_id.size() != credential_id_bytes) ||
            !valid_proof(proof) || !verify_request_proof(api, proof))
        {
            return false;
        }

        auto const request = std::span<std::uint8_t const>{
            proof.encoded_request,
            proof.encoded_request_bytes};
        std::array<std::uint8_t, client_data_hash_bytes> request_hash{};
        if (!hash_sha256(request, request_hash))
        {
            return false;
        }
        librarian::windows_passkey::user_verification_binding binding{};
        if (!librarian::windows_passkey::build_user_verification_binding(
                operation,
                std::span<std::uint8_t const>{proof.transaction_id, transaction_id_bytes},
                std::span<std::uint8_t const>{
                    proof.agent_challenge,
                    proof.agent_challenge_bytes},
                request_hash,
                credential_id,
                binding))
        {
            return false;
        }
        auto const uv_signature = std::span<std::uint8_t const>{
            proof.user_verification_signature,
            proof.user_verification_signature_bytes};
        auto const verified = verify_windows_signature(
            api,
            api.get_uv_key,
            std::span<std::uint8_t const>{binding.bytes.data(), binding.size},
            uv_signature);
        SecureZeroMemory(binding.bytes.data(), binding.bytes.size());
        return verified;
    }

    [[nodiscard]] bool public_key_credential_type(wchar_t const* value) noexcept
    {
        return value != nullptr && std::wcscmp(value, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY) == 0;
    }

    [[nodiscard]] bool validate_credential_list(
        WEBAUTHN_CREDENTIAL_LIST const& list) noexcept
    {
        if (list.cCredentials > max_excluded_credentials ||
            (list.cCredentials != 0 && list.ppCredentials == nullptr))
        {
            return false;
        }
        for (DWORD index = 0; index < list.cCredentials; ++index)
        {
            auto const* credential = list.ppCredentials[index];
            if (credential == nullptr || !public_key_credential_type(credential->pwszCredentialType) ||
                credential->cbId == 0 || credential->pbId == nullptr)
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool supports_es256(
        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS const& parameters) noexcept
    {
        if (parameters.cCredentialParameters == 0 ||
            parameters.cCredentialParameters > 64 ||
            parameters.pCredentialParameters == nullptr)
        {
            return false;
        }
        for (DWORD index = 0; index < parameters.cCredentialParameters; ++index)
        {
            auto const& parameter = parameters.pCredentialParameters[index];
            if (parameter.dwVersion != WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION ||
                !public_key_credential_type(parameter.pwszCredentialType))
            {
                continue;
            }
            if (parameter.lAlg == WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256)
            {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool valid_options(
        WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS const* options) noexcept
    {
        auto const valid_tristate = [](LONG const value) {
            return value >= -1 && value <= 1;
        };
        return options == nullptr ||
               (options->dwVersion == WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_CURRENT_VERSION &&
                   valid_tristate(options->lUp) && valid_tristate(options->lUv) &&
                   valid_tristate(options->lRequireResidentKey));
    }

    [[nodiscard]] bool equal_rp_id(
        std::span<std::uint8_t const> raw,
        wchar_t const* wide) noexcept
    {
        std::vector<std::uint8_t> converted;
        return wide_to_utf8(wide, max_rp_id_bytes, converted) &&
               std::ranges::equal(raw, converted);
    }

    [[nodiscard]] bool no_unsupported_extensions(
        WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST const& request) noexcept
    {
        return request.cbCborExtensionsMap == 0 && request.pbCborExtensionsMap == nullptr &&
               valid_options(request.pAuthenticatorOptions) && !request.fEmptyPinAuth &&
               request.cbPinAuth == 0 && request.pbPinAuth == nullptr &&
               request.lHmacSecretExt == 0 && request.pHmacSecretMcExtension == nullptr &&
               request.lPrfExt == 0 && request.cbHmacSecretSaltValues == 0 &&
               request.pbHmacSecretSaltValues == nullptr && request.dwCredProtect == 0 &&
               request.dwPinProtocol == 0 && request.dwEnterpriseAttestation == 0 &&
               request.cbCredBlobExt == 0 && request.pbCredBlobExt == nullptr &&
               request.lLargeBlobKeyExt == 0 && request.dwLargeBlobSupport == 0 &&
               request.lMinPinLengthExt == 0 && request.cbJsonExt == 0 &&
               request.pbJsonExt == nullptr;
    }

    [[nodiscard]] bool no_unsupported_extensions(
        WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST const& request) noexcept
    {
        return request.cbCborExtensionsMap == 0 && request.pbCborExtensionsMap == nullptr &&
               valid_options(request.pAuthenticatorOptions) && !request.fEmptyPinAuth &&
               request.cbPinAuth == 0 && request.pbPinAuth == nullptr &&
               request.pHmacSaltExtension == nullptr && request.cbHmacSecretSaltValues == 0 &&
               request.pbHmacSecretSaltValues == nullptr && request.dwPinProtocol == 0 &&
               request.lCredBlobExt == 0 && request.lLargeBlobKeyExt == 0 &&
               request.dwCredLargeBlobOperation == 0 &&
               request.cbCredLargeBlobCompressed == 0 &&
               request.pbCredLargeBlobCompressed == nullptr &&
               request.dwCredLargeBlobOriginalSize == 0 && request.cbJsonExt == 0 &&
               request.pbJsonExt == nullptr;
    }

    [[nodiscard]] bool copy_outputs(
        std::span<std::uint8_t const> rp,
        std::span<std::uint8_t const> client_hash,
        std::uint8_t* rp_output,
        std::uint32_t rp_capacity,
        std::uint32_t* rp_bytes,
        std::uint8_t* client_hash_output) noexcept
    {
        if (rp_output == nullptr || rp_bytes == nullptr || client_hash_output == nullptr ||
            rp.size() > rp_capacity || client_hash.size() != client_data_hash_bytes)
        {
            return false;
        }
        std::memcpy(rp_output, rp.data(), rp.size());
        std::memcpy(client_hash_output, client_hash.data(), client_hash.size());
        *rp_bytes = static_cast<std::uint32_t>(rp.size());
        return true;
    }
}

extern "C" std::uint32_t librarian_windows_passkey_verify_make(
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
    std::uint32_t* excluded_credential_ids_count) noexcept
{
    try
    {
        if (proof == nullptr || rp_id_bytes == nullptr || user_handle_bytes == nullptr ||
            user_name_bytes == nullptr || user_display_name_bytes == nullptr ||
            excluded_credential_ids_count == nullptr || user_handle == nullptr ||
            user_name == nullptr || user_display_name == nullptr || excluded_credential_ids == nullptr)
        {
            return invalid;
        }
        webauthn_api api;
        if (!api.complete())
        {
            return unavailable;
        }
        if (!verify_proof(api, *proof, make_operation))
        {
            return invalid;
        }
        decoded_make decoded{api};
        if (FAILED(api.decode_make(
                proof->encoded_request_bytes,
                proof->encoded_request,
                &decoded.value)) ||
            decoded.value == nullptr)
        {
            return invalid;
        }
        auto const& request = *decoded.value;
        if (request.dwVersion != WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_CURRENT_VERSION ||
            request.pbRpId == nullptr || request.cbRpId == 0 || request.cbRpId > max_rp_id_bytes ||
            request.pbClientDataHash == nullptr ||
            request.cbClientDataHash != client_data_hash_bytes ||
            std::ranges::all_of(
                request.pbClientDataHash,
                request.pbClientDataHash + request.cbClientDataHash,
                [](std::uint8_t const value) { return value == 0; }) ||
            request.pRpInformation == nullptr ||
            request.pRpInformation->dwVersion != WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION ||
            request.pRpInformation->pwszName == nullptr || request.pUserInformation == nullptr ||
            request.pUserInformation->dwVersion != WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION ||
            request.pUserInformation->pbId == nullptr || request.pUserInformation->cbId == 0 ||
            request.pUserInformation->cbId > max_user_handle_bytes ||
            !supports_es256(request.WebAuthNCredentialParameters) ||
            !validate_credential_list(request.CredentialList) ||
            !no_unsupported_extensions(request))
        {
            return invalid;
        }
        auto const rp = std::span<std::uint8_t const>{request.pbRpId, request.cbRpId};
        if (!valid_utf8(rp) || !equal_rp_id(rp, request.pRpInformation->pwszId))
        {
            return invalid;
        }
        std::vector<std::uint8_t> name;
        std::vector<std::uint8_t> display_name;
        if (!wide_to_utf8(request.pUserInformation->pwszName, max_user_name_bytes, name) ||
            !wide_to_utf8(
                request.pUserInformation->pwszDisplayName,
                max_user_name_bytes,
                display_name))
        {
            return invalid;
        }
        std::vector<std::uint8_t> exclusions;
        for (DWORD index = 0; index < request.CredentialList.cCredentials; ++index)
        {
            auto const& credential = *request.CredentialList.ppCredentials[index];
            if (credential.cbId == credential_id_bytes)
            {
                exclusions.insert(
                    exclusions.end(),
                    credential.pbId,
                    credential.pbId + credential.cbId);
            }
        }
        auto const exclusion_count = exclusions.size() / credential_id_bytes;
        if (request.pUserInformation->cbId > user_handle_capacity || name.size() > user_name_capacity ||
            display_name.size() > user_display_name_capacity ||
            exclusions.size() > excluded_credential_ids_capacity ||
            exclusion_count > std::numeric_limits<std::uint32_t>::max() ||
            !copy_outputs(
                rp,
                std::span<std::uint8_t const>{
                    request.pbClientDataHash,
                    request.cbClientDataHash},
                rp_id,
                rp_id_capacity,
                rp_id_bytes,
                client_data_hash))
        {
            return invalid;
        }
        std::memcpy(user_handle, request.pUserInformation->pbId, request.pUserInformation->cbId);
        std::memcpy(user_name, name.data(), name.size());
        std::memcpy(user_display_name, display_name.data(), display_name.size());
        if (!exclusions.empty())
        {
            std::memcpy(excluded_credential_ids, exclusions.data(), exclusions.size());
        }
        *user_handle_bytes = request.pUserInformation->cbId;
        *user_name_bytes = static_cast<std::uint32_t>(name.size());
        *user_display_name_bytes = static_cast<std::uint32_t>(display_name.size());
        *excluded_credential_ids_count = static_cast<std::uint32_t>(exclusion_count);
        return success;
    }
    catch (...)
    {
        return failed;
    }
}

extern "C" std::uint32_t librarian_windows_passkey_verify_assertion(
    librarian_windows_passkey_proof const* proof,
    std::uint8_t const* selected_credential_id,
    std::uint32_t selected_credential_id_bytes,
    std::uint8_t* rp_id,
    std::uint32_t rp_id_capacity,
    std::uint32_t* rp_id_bytes,
    std::uint8_t* client_data_hash) noexcept
{
    try
    {
        if (proof == nullptr || selected_credential_id == nullptr ||
            selected_credential_id_bytes != credential_id_bytes)
        {
            return invalid;
        }
        webauthn_api api;
        if (!api.complete())
        {
            return unavailable;
        }
        if (!verify_proof(
                api,
                *proof,
                assertion_operation,
                std::span<std::uint8_t const>{
                    selected_credential_id,
                    selected_credential_id_bytes}))
        {
            return invalid;
        }
        decoded_assertion decoded{api};
        if (FAILED(api.decode_assertion(
                proof->encoded_request_bytes,
                proof->encoded_request,
                &decoded.value)) ||
            decoded.value == nullptr)
        {
            return invalid;
        }
        auto const& request = *decoded.value;
        if (request.dwVersion != WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_CURRENT_VERSION ||
            request.pbRpId == nullptr || request.cbRpId == 0 || request.cbRpId > max_rp_id_bytes ||
            request.pbClientDataHash == nullptr || request.cbClientDataHash != client_data_hash_bytes ||
            std::ranges::all_of(
                request.pbClientDataHash,
                request.pbClientDataHash + request.cbClientDataHash,
                [](std::uint8_t const value) { return value == 0; }) ||
            !validate_credential_list(request.CredentialList) ||
            !no_unsupported_extensions(request))
        {
            return invalid;
        }
        auto const rp = std::span<std::uint8_t const>{request.pbRpId, request.cbRpId};
        if (!valid_utf8(rp) || !equal_rp_id(rp, request.pwszRpId))
        {
            return invalid;
        }
        if (request.CredentialList.cCredentials != 0)
        {
            bool selected_is_allowed = false;
            for (DWORD index = 0; index < request.CredentialList.cCredentials; ++index)
            {
                auto const& credential = *request.CredentialList.ppCredentials[index];
                if (credential.cbId == credential_id_bytes &&
                    std::memcmp(
                        credential.pbId,
                        selected_credential_id,
                        credential_id_bytes) == 0)
                {
                    selected_is_allowed = true;
                    break;
                }
            }
            if (!selected_is_allowed)
            {
                return invalid;
            }
        }
        return copy_outputs(
                   rp,
                   std::span<std::uint8_t const>{
                       request.pbClientDataHash,
                       request.cbClientDataHash},
                   rp_id,
                   rp_id_capacity,
                   rp_id_bytes,
                   client_data_hash)
                   ? success
                   : invalid;
    }
    catch (...)
    {
        return failed;
    }
}

extern "C" std::uint32_t librarian_windows_passkey_verify_assertion_lookup(
    librarian_windows_passkey_proof const* proof,
    std::uint8_t* rp_id,
    std::uint32_t rp_id_capacity,
    std::uint32_t* rp_id_bytes,
    std::uint8_t* allowed_credential_ids,
    std::uint32_t allowed_credential_ids_capacity,
    std::uint32_t* allowed_credential_ids_count,
    std::uint8_t* allow_list_present) noexcept
{
    try
    {
        if (proof == nullptr || rp_id == nullptr || rp_id_bytes == nullptr ||
            allowed_credential_ids == nullptr || allowed_credential_ids_count == nullptr ||
            allow_list_present == nullptr)
        {
            return invalid;
        }
        webauthn_api api;
        if (!api.complete())
        {
            return unavailable;
        }
        if (!verify_request_proof(api, *proof))
        {
            return invalid;
        }
        decoded_assertion decoded{api};
        if (FAILED(api.decode_assertion(
                proof->encoded_request_bytes,
                proof->encoded_request,
                &decoded.value)) ||
            decoded.value == nullptr)
        {
            return invalid;
        }
        auto const& request = *decoded.value;
        if (request.dwVersion != WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_CURRENT_VERSION ||
            request.pbRpId == nullptr || request.cbRpId == 0 || request.cbRpId > max_rp_id_bytes ||
            request.pbClientDataHash == nullptr || request.cbClientDataHash != client_data_hash_bytes ||
            std::ranges::all_of(
                request.pbClientDataHash,
                request.pbClientDataHash + request.cbClientDataHash,
                [](std::uint8_t const value) { return value == 0; }) ||
            !validate_credential_list(request.CredentialList) ||
            !no_unsupported_extensions(request))
        {
            return invalid;
        }
        auto const rp = std::span<std::uint8_t const>{request.pbRpId, request.cbRpId};
        if (!valid_utf8(rp) || !equal_rp_id(rp, request.pwszRpId) ||
            rp.size() > rp_id_capacity)
        {
            return invalid;
        }
        std::vector<std::uint8_t> allowed;
        for (DWORD index = 0; index < request.CredentialList.cCredentials; ++index)
        {
            auto const& credential = *request.CredentialList.ppCredentials[index];
            if (credential.cbId == credential_id_bytes)
            {
                allowed.insert(
                    allowed.end(),
                    credential.pbId,
                    credential.pbId + credential.cbId);
            }
        }
        auto const allowed_count = allowed.size() / credential_id_bytes;
        if (allowed.size() > allowed_credential_ids_capacity ||
            allowed_count > std::numeric_limits<std::uint32_t>::max())
        {
            return invalid;
        }
        std::memcpy(rp_id, rp.data(), rp.size());
        if (!allowed.empty())
        {
            std::memcpy(allowed_credential_ids, allowed.data(), allowed.size());
        }
        *rp_id_bytes = static_cast<std::uint32_t>(rp.size());
        *allowed_credential_ids_count = static_cast<std::uint32_t>(allowed_count);
        *allow_list_present = request.CredentialList.cCredentials == 0 ? 0 : 1;
        return success;
    }
    catch (...)
    {
        return failed;
    }
}
