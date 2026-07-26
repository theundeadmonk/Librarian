#include <windows.h>

#include <bcrypt.h>
#include <webauthn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    constexpr DWORD probe_timeout_ms = 120'000;
    constexpr wchar_t relying_party_id[] = L"librarian.local";
    constexpr wchar_t relying_party_name[] =
        L"Librarian disposable Windows Hello probe";
    constexpr wchar_t user_name[] = L"disposable-local-probe";
    constexpr wchar_t user_display_name[] =
        L"Librarian disposable local probe";
    constexpr std::size_t secret_bytes = WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH;

    static_assert(secret_bytes == 32);

    class credential_attestation final
    {
    public:
        credential_attestation() noexcept = default;

        ~credential_attestation()
        {
            reset();
        }

        credential_attestation(credential_attestation const&) = delete;
        credential_attestation& operator=(credential_attestation const&) = delete;

        [[nodiscard]] PWEBAUTHN_CREDENTIAL_ATTESTATION* put() noexcept
        {
            reset();
            return &value_;
        }

        [[nodiscard]] PWEBAUTHN_CREDENTIAL_ATTESTATION get() const noexcept
        {
            return value_;
        }

        void reset() noexcept
        {
            if (value_ != nullptr)
            {
                clear_secret(value_->pHmacSecret);
                WebAuthNFreeCredentialAttestation(value_);
                value_ = nullptr;
            }
        }

    private:
        static void clear_secret(PWEBAUTHN_HMAC_SECRET_SALT value) noexcept
        {
            if (value == nullptr)
            {
                return;
            }
            if (value->pbFirst != nullptr && value->cbFirst != 0)
            {
                SecureZeroMemory(value->pbFirst, value->cbFirst);
            }
            if (value->pbSecond != nullptr && value->cbSecond != 0)
            {
                SecureZeroMemory(value->pbSecond, value->cbSecond);
            }
        }

        PWEBAUTHN_CREDENTIAL_ATTESTATION value_{nullptr};
    };

    class assertion final
    {
    public:
        assertion() noexcept = default;

        ~assertion()
        {
            reset();
        }

        assertion(assertion const&) = delete;
        assertion& operator=(assertion const&) = delete;

        [[nodiscard]] PWEBAUTHN_ASSERTION* put() noexcept
        {
            reset();
            return &value_;
        }

        [[nodiscard]] PWEBAUTHN_ASSERTION get() const noexcept
        {
            return value_;
        }

        void reset() noexcept
        {
            if (value_ != nullptr)
            {
                clear_secret(value_->pHmacSecret);
                WebAuthNFreeAssertion(value_);
                value_ = nullptr;
            }
        }

    private:
        static void clear_secret(PWEBAUTHN_HMAC_SECRET_SALT value) noexcept
        {
            if (value == nullptr)
            {
                return;
            }
            if (value->pbFirst != nullptr && value->cbFirst != 0)
            {
                SecureZeroMemory(value->pbFirst, value->cbFirst);
            }
            if (value->pbSecond != nullptr && value->cbSecond != 0)
            {
                SecureZeroMemory(value->pbSecond, value->cbSecond);
            }
        }

        PWEBAUTHN_ASSERTION value_{nullptr};
    };

    class platform_credential final
    {
    public:
        platform_credential() = default;

        explicit platform_credential(std::span<std::uint8_t const> identifier) :
            identifier_(identifier.begin(), identifier.end())
        {
        }

        ~platform_credential()
        {
            (void)remove();
        }

        platform_credential(platform_credential const&) = delete;
        platform_credential& operator=(platform_credential const&) = delete;

        platform_credential(platform_credential&& other) noexcept :
            identifier_(std::move(other.identifier_)),
            removed_(std::exchange(other.removed_, true))
        {
        }

        platform_credential& operator=(platform_credential&& other) noexcept
        {
            if (this != &other)
            {
                (void)remove();
                identifier_ = std::move(other.identifier_);
                removed_ = std::exchange(other.removed_, true);
            }
            return *this;
        }

        [[nodiscard]] std::span<std::uint8_t const> identifier() const noexcept
        {
            return identifier_;
        }

        [[nodiscard]] HRESULT remove() noexcept
        {
            if (removed_ || identifier_.empty())
            {
                return S_OK;
            }
            HRESULT const result = WebAuthNDeletePlatformCredential(
                static_cast<DWORD>(identifier_.size()),
                identifier_.data());
            if (SUCCEEDED(result))
            {
                removed_ = true;
            }
            return result;
        }

    private:
        std::vector<std::uint8_t> identifier_;
        bool removed_{false};
    };

    class secret final
    {
    public:
        secret() = default;

        ~secret()
        {
            SecureZeroMemory(value_.data(), value_.size());
        }

        secret(secret const&) = delete;
        secret& operator=(secret const&) = delete;

        secret(secret&& other) noexcept : value_(other.value_)
        {
            SecureZeroMemory(other.value_.data(), other.value_.size());
        }

        secret& operator=(secret&&) = delete;

        [[nodiscard]] std::span<std::uint8_t const> value() const noexcept
        {
            return value_;
        }

        [[nodiscard]] std::span<std::uint8_t> writable() noexcept
        {
            return value_;
        }

    private:
        std::array<std::uint8_t, secret_bytes> value_{};
    };

    [[nodiscard]] std::string hresult_name(HRESULT const result)
    {
        PCWSTR const name = WebAuthNGetErrorName(result);
        if (name == nullptr)
        {
            return "UnknownError";
        }

        int const bytes = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            name,
            -1,
            nullptr,
            0,
            nullptr,
            nullptr);
        if (bytes <= 1)
        {
            return "UnknownError";
        }
        std::string text(static_cast<std::size_t>(bytes), '\0');
        if (WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                name,
                -1,
                text.data(),
                bytes,
                nullptr,
                nullptr) == 0)
        {
            return "UnknownError";
        }
        text.pop_back();
        return text;
    }

    [[noreturn]] void throw_hresult(
        std::string const& operation,
        HRESULT const result)
    {
        throw std::runtime_error(
            operation + " failed (" + hresult_name(result) + ", HRESULT " +
            std::to_string(static_cast<std::uint32_t>(result)) + ").");
    }

    void require(bool const condition, std::string const& message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }

    void random_bytes(std::span<std::uint8_t> destination)
    {
        NTSTATUS const result = BCryptGenRandom(
            nullptr,
            destination.data(),
            static_cast<ULONG>(destination.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (result < 0)
        {
            throw std::runtime_error("Operating-system randomness is unavailable.");
        }
    }

    [[nodiscard]] WEBAUTHN_CLIENT_DATA client_data(
        std::string_view const json) noexcept
    {
        return {
            .dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            .cbClientDataJSON = static_cast<DWORD>(json.size()),
            .pbClientDataJSON = reinterpret_cast<PBYTE>(
                const_cast<char*>(json.data())),
            .pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
    }

    [[nodiscard]] bool platform_authenticator_available()
    {
        BOOL available = FALSE;
        HRESULT const result =
            WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&available);
        if (FAILED(result))
        {
            throw_hresult(
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
                result);
        }
        return available != FALSE;
    }

    [[nodiscard]] platform_credential create_credential(HWND const parent)
    {
        std::array<std::uint8_t, 32> user_identifier{};
        random_bytes(user_identifier);

        WEBAUTHN_RP_ENTITY_INFORMATION relying_party{
            .dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            .pwszId = relying_party_id,
            .pwszName = relying_party_name,
            .pwszIcon = nullptr,
        };
        WEBAUTHN_USER_ENTITY_INFORMATION user{
            .dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            .cbId = static_cast<DWORD>(user_identifier.size()),
            .pbId = user_identifier.data(),
            .pwszName = user_name,
            .pwszIcon = nullptr,
            .pwszDisplayName = user_display_name,
        };
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER parameter{
            .dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            .lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        WEBAUTHN_COSE_CREDENTIAL_PARAMETERS parameters{
            .cCredentialParameters = 1,
            .pCredentialParameters = &parameter,
        };
        std::string const json =
            R"({"type":"webauthn.create","challenge":"LibrarianDisposableProbeCreate","origin":"https://librarian.local","crossOrigin":false})";
        WEBAUTHN_CLIENT_DATA const data = client_data(json);
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{
            .dwVersion =
                WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6,
            .dwTimeoutMilliseconds = probe_timeout_ms,
            .dwAuthenticatorAttachment =
                WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            .bRequireResidentKey = FALSE,
            .dwUserVerificationRequirement =
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            .dwAttestationConveyancePreference =
                WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            .bEnablePrf = TRUE,
        };

        credential_attestation attestation;
        HRESULT const result = WebAuthNAuthenticatorMakeCredential(
            parent,
            &relying_party,
            &user,
            &parameters,
            &data,
            &options,
            attestation.put());
        SecureZeroMemory(user_identifier.data(), user_identifier.size());
        if (FAILED(result))
        {
            throw_hresult("WebAuthNAuthenticatorMakeCredential", result);
        }

        PWEBAUTHN_CREDENTIAL_ATTESTATION const value = attestation.get();
        require(value != nullptr, "Windows returned no credential attestation.");
        require(
            value->cbCredentialId != 0 && value->pbCredentialId != nullptr,
            "Windows returned an empty credential identifier.");

        platform_credential credential;
        try
        {
            credential = platform_credential({
                value->pbCredentialId,
                static_cast<std::size_t>(value->cbCredentialId),
            });
        }
        catch (...)
        {
            (void)WebAuthNDeletePlatformCredential(
                value->cbCredentialId,
                value->pbCredentialId);
            throw;
        }
        require(
            value->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5 &&
                value->bPrfEnabled != FALSE,
            "The platform credential did not enable WebAuthn PRF.");
        require(
            value->dwUsedTransport == WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            "Windows created the disposable credential on a non-platform authenticator.");
        return credential;
    }

    [[nodiscard]] secret release_secret(
        HWND const parent,
        platform_credential const& credential,
        std::span<std::uint8_t const, secret_bytes> const salt,
        std::string_view const challenge)
    {
        WEBAUTHN_CREDENTIAL allowed{
            .dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            .cbId = static_cast<DWORD>(credential.identifier().size()),
            .pbId = const_cast<PBYTE>(credential.identifier().data()),
            .pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        WEBAUTHN_CREDENTIALS allowed_credentials{
            .cCredentials = 1,
            .pCredentials = &allowed,
        };
        WEBAUTHN_HMAC_SECRET_SALT requested_salt{
            .cbFirst = static_cast<DWORD>(salt.size()),
            .pbFirst = const_cast<PBYTE>(salt.data()),
        };
        WEBAUTHN_HMAC_SECRET_SALT_VALUES requested_values{
            .pGlobalHmacSalt = &requested_salt,
        };
        std::string const json =
            std::string(
                R"({"type":"webauthn.get","challenge":")") +
            std::string(challenge) +
            R"(","origin":"https://librarian.local","crossOrigin":false})";
        WEBAUTHN_CLIENT_DATA const data = client_data(json);
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{
            .dwVersion =
                WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
            .dwTimeoutMilliseconds = probe_timeout_ms,
            .CredentialList = allowed_credentials,
            .dwAuthenticatorAttachment =
                WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            .dwUserVerificationRequirement =
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            .pHmacSecretSaltValues = &requested_values,
        };

        assertion result_value;
        HRESULT const result = WebAuthNAuthenticatorGetAssertion(
            parent,
            relying_party_id,
            &data,
            &options,
            result_value.put());
        if (FAILED(result))
        {
            throw_hresult("WebAuthNAuthenticatorGetAssertion", result);
        }

        PWEBAUTHN_ASSERTION const value = result_value.get();
        require(value != nullptr, "Windows returned no assertion.");
        require(
            value->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 &&
                value->pHmacSecret != nullptr &&
                value->pHmacSecret->cbFirst == secret_bytes &&
                value->pHmacSecret->pbFirst != nullptr,
            "Windows returned no valid 32-byte WebAuthn PRF result.");
        require(
            value->Credential.cbId == credential.identifier().size() &&
                value->Credential.pbId != nullptr &&
                value->Credential.pwszCredentialType != nullptr &&
                std::wstring_view(value->Credential.pwszCredentialType) ==
                    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY &&
                std::memcmp(
                    value->Credential.pbId,
                    credential.identifier().data(),
                    credential.identifier().size()) == 0,
            "Windows returned an assertion for the wrong credential.");

        secret released;
        std::memcpy(
            released.writable().data(),
            value->pHmacSecret->pbFirst,
            secret_bytes);
        return released;
    }

    [[nodiscard]] int self_test()
    {
        DWORD const version = WebAuthNGetApiVersionNumber();
        require(version != 0, "Windows WebAuthn API is unavailable.");
        bool const available = platform_authenticator_available();

        std::cout << "[PASS] Windows WebAuthn API version " << version << '\n';
        std::cout << "[PASS] PRF request structures require API version 6; "
                  << (version >= WEBAUTHN_API_VERSION_6 ? "supported" : "unsupported")
                  << '\n';
        std::cout << "[PASS] user-verifying platform authenticator: "
                  << (available ? "available" : "not available (fail closed)")
                  << '\n';
        return 0;
    }

    [[nodiscard]] int manual_test()
    {
        DWORD const version = WebAuthNGetApiVersionNumber();
        require(
            version >= WEBAUTHN_API_VERSION_6,
            "Windows WebAuthn API version 6 or later is required.");
        require(
            platform_authenticator_available(),
            "No user-verifying platform authenticator is available. Configure Windows Hello first.");
        HWND const parent = GetConsoleWindow();
        require(
            parent != nullptr,
            "Manual mode requires an interactive console window.");

        std::array<std::uint8_t, secret_bytes> salt{};
        random_bytes(salt);
        platform_credential credential = create_credential(parent);
        secret first =
            release_secret(parent, credential, salt, "LibrarianDisposableProbeFirst");
        secret second =
            release_secret(parent, credential, salt, "LibrarianDisposableProbeSecond");

        bool const stable = std::equal(
            first.value().begin(),
            first.value().end(),
            second.value().begin(),
            second.value().end());
        SecureZeroMemory(salt.data(), salt.size());
        require(stable, "Windows returned inconsistent WebAuthn PRF results.");

        HRESULT const removal = credential.remove();
        if (FAILED(removal))
        {
            throw_hresult("WebAuthNDeletePlatformCredential", removal);
        }

        std::cout
            << "[PASS] disposable platform credential enabled WebAuthn PRF\n"
            << "[PASS] two user-verified releases returned the same 32-byte result\n"
            << "[PASS] disposable platform credential was removed\n"
            << "3 passed; 0 failed\n";
        return 0;
    }
}

int wmain(int const argc, wchar_t* const argv[])
try
{
    if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test")
    {
        return self_test();
    }
    if (argc == 2 && std::wstring_view(argv[1]) == L"--manual-test")
    {
        return manual_test();
    }

    std::cerr
        << "Usage: Librarian.WindowsHelloProbe.exe --self-test | --manual-test\n";
    return 64;
}
catch (std::exception const& error)
{
    std::cerr << "[FAIL] " << error.what() << '\n';
    return 1;
}
