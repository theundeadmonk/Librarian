#include <windows.h>

#include <bcrypt.h>
#include <webauthn.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
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
    constexpr std::size_t authenticator_data_minimum_bytes = 37;
    constexpr std::size_t relying_party_id_hash_bytes = 32;
    constexpr std::size_t authenticator_flags_offset = 32;
    constexpr std::uint8_t authenticator_user_verified_flag = 0x04;

    static_assert(secret_bytes == 32);
    static_assert(relying_party_id_hash_bytes == authenticator_flags_offset);

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
                if (value_->dwVersion >=
                    WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7)
                {
                    clear_secret(value_->pHmacSecret);
                }
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
                if (value_->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3)
                {
                    clear_secret(value_->pHmacSecret);
                }
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
        using deleter = decltype(&WebAuthNDeletePlatformCredential);

        platform_credential() = default;

        explicit platform_credential(
            std::span<std::uint8_t const> identifier,
            deleter const delete_credential = &WebAuthNDeletePlatformCredential) :
            identifier_(identifier.begin(), identifier.end()),
            delete_credential_(delete_credential)
        {
            if (delete_credential_ == nullptr)
            {
                throw std::runtime_error(
                    "Platform credential deletion is unavailable.");
            }
        }

        ~platform_credential()
        {
            (void)remove();
        }

        platform_credential(platform_credential const&) = delete;
        platform_credential& operator=(platform_credential const&) = delete;

        platform_credential(platform_credential&& other) noexcept :
            identifier_(std::move(other.identifier_)),
            removed_(std::exchange(other.removed_, true)),
            delete_credential_(other.delete_credential_)
        {
        }

        platform_credential& operator=(platform_credential&&) = delete;

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
            HRESULT const result = delete_credential_(
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
        deleter delete_credential_{&WebAuthNDeletePlatformCredential};
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

        [[nodiscard]] std::span<std::uint8_t const, secret_bytes>
        value() const noexcept
        {
            return value_;
        }

        [[nodiscard]] std::span<std::uint8_t, secret_bytes>
        writable() noexcept
        {
            return value_;
        }

        void clear() noexcept
        {
            SecureZeroMemory(value_.data(), value_.size());
        }

    private:
        std::array<std::uint8_t, secret_bytes> value_{};
    };

    struct credential_enrollment final
    {
        platform_credential credential;
        secret creation_prf;
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

    [[nodiscard]] std::string hresult_failure(
        std::string const& operation,
        HRESULT const result)
    {
        return
            operation + " failed (" + hresult_name(result) + ", HRESULT " +
            std::to_string(static_cast<std::uint32_t>(result)) + ").";
    }

    [[noreturn]] void throw_hresult(
        std::string const& operation,
        HRESULT const result)
    {
        throw std::runtime_error(hresult_failure(operation, result));
    }

    void require(bool const condition, std::string const& message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }

    void require_hresult_success(
        std::string const& operation,
        HRESULT const result)
    {
        if (FAILED(result))
        {
            throw_hresult(operation, result);
        }
    }

    [[noreturn]] void rethrow_after_cleanup(
        std::exception_ptr const original_error,
        HRESULT const cleanup_result)
    {
        require(
            original_error != nullptr,
            "Credential cleanup requires an active failure.");
        if (SUCCEEDED(cleanup_result))
        {
            std::rethrow_exception(original_error);
        }

        std::string const cleanup_error = hresult_failure(
            "WebAuthNDeletePlatformCredential cleanup",
            cleanup_result);
        try
        {
            std::rethrow_exception(original_error);
        }
        catch (std::exception const& error)
        {
            throw std::runtime_error(
                std::string(error.what()) + " " + cleanup_error);
        }
        catch (...)
        {
            throw std::runtime_error(
                "The WebAuthn operation failed. " + cleanup_error);
        }
    }

    [[noreturn]] void rethrow_after_credential_cleanup(
        platform_credential& credential,
        std::exception_ptr const original_error)
    {
        rethrow_after_cleanup(original_error, credential.remove());
    }

    [[noreturn]] void rethrow_after_raw_credential_cleanup(
        DWORD const identifier_size,
        PBYTE const identifier,
        std::exception_ptr const original_error)
    {
        rethrow_after_cleanup(
            original_error,
            WebAuthNDeletePlatformCredential(identifier_size, identifier));
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

    [[nodiscard]] std::array<std::uint8_t, relying_party_id_hash_bytes> const&
    relying_party_id_hash()
    {
        static std::array<std::uint8_t, relying_party_id_hash_bytes> const hash =
            []()
            {
                constexpr int relying_party_id_characters = static_cast<int>(
                    (sizeof(relying_party_id) /
                     sizeof(relying_party_id[0])) -
                    1);
                int const utf8_bytes = WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    relying_party_id,
                    relying_party_id_characters,
                    nullptr,
                    0,
                    nullptr,
                    nullptr);
                if (utf8_bytes <= 0)
                {
                    throw std::runtime_error(
                        "The relying-party identifier is invalid.");
                }
                std::vector<std::uint8_t> utf8(
                    static_cast<std::size_t>(utf8_bytes));
                if (WideCharToMultiByte(
                        CP_UTF8,
                        WC_ERR_INVALID_CHARS,
                        relying_party_id,
                        relying_party_id_characters,
                        reinterpret_cast<char*>(utf8.data()),
                        utf8_bytes,
                        nullptr,
                        nullptr) != utf8_bytes)
                {
                    throw std::runtime_error(
                        "The relying-party identifier is invalid.");
                }

                BCRYPT_ALG_HANDLE algorithm = nullptr;
                NTSTATUS const open_result = BCryptOpenAlgorithmProvider(
                    &algorithm,
                    BCRYPT_SHA256_ALGORITHM,
                    nullptr,
                    0);
                if (open_result < 0)
                {
                    throw std::runtime_error(
                        "Operating-system SHA-256 is unavailable.");
                }

                std::array<std::uint8_t, relying_party_id_hash_bytes> value{};
                NTSTATUS const hash_result = BCryptHash(
                    algorithm,
                    nullptr,
                    0,
                    utf8.data(),
                    static_cast<ULONG>(utf8.size()),
                    value.data(),
                    static_cast<ULONG>(value.size()));
                NTSTATUS const close_result =
                    BCryptCloseAlgorithmProvider(algorithm, 0);
                if (hash_result < 0 || close_result < 0)
                {
                    throw std::runtime_error(
                        "Operating-system SHA-256 is unavailable.");
                }
                return value;
            }();
        return hash;
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
        require_hresult_success(
            "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
            result);
        return available != FALSE;
    }

    [[nodiscard]] secret validated_secret_from_attestation(
        PWEBAUTHN_CREDENTIAL_ATTESTATION const value)
    {
        require(value != nullptr, "Windows returned no credential attestation.");
        require(
            value->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7,
            "Windows returned a credential attestation without creation-time WebAuthn PRF fields.");
        require(
            value->pbAuthenticatorData != nullptr &&
                value->cbAuthenticatorData >= authenticator_data_minimum_bytes,
            "Windows returned malformed WebAuthn credential authenticator data.");
        require(
            std::equal(
                relying_party_id_hash().begin(),
                relying_party_id_hash().end(),
                value->pbAuthenticatorData),
            "Windows created a WebAuthn credential for the wrong relying party.");
        require(
            (value->pbAuthenticatorData[authenticator_flags_offset] &
             authenticator_user_verified_flag) != 0,
            "Windows created a WebAuthn credential without user verification.");
        require(
            value->bPrfEnabled != FALSE,
            "The platform credential did not enable WebAuthn PRF.");
        require(
            value->pHmacSecret != nullptr &&
                value->pHmacSecret->cbFirst == secret_bytes &&
                value->pHmacSecret->pbFirst != nullptr &&
                value->pHmacSecret->cbSecond == 0 &&
                value->pHmacSecret->pbSecond == nullptr,
            "Windows returned no valid 32-byte creation-time WebAuthn PRF result.");
        require(
            value->dwUsedTransport == WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            "Windows created the disposable credential on a non-platform authenticator.");

        secret released;
        std::memcpy(
            released.writable().data(),
            value->pHmacSecret->pbFirst,
            secret_bytes);
        return released;
    }

    [[nodiscard]] credential_enrollment create_credential(
        HWND const parent,
        std::span<std::uint8_t const, secret_bytes> const creation_salt)
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
        WEBAUTHN_HMAC_SECRET_SALT requested_prf{
            .cbFirst = static_cast<DWORD>(creation_salt.size()),
            .pbFirst = const_cast<PBYTE>(creation_salt.data()),
        };
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{
            .dwVersion =
                WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8,
            .dwTimeoutMilliseconds = probe_timeout_ms,
            .dwAuthenticatorAttachment =
                WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
            .bRequireResidentKey = FALSE,
            .dwUserVerificationRequirement =
                WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            .dwAttestationConveyancePreference =
                WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            .bEnablePrf = TRUE,
            .pPRFGlobalEval = &requested_prf,
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
        require_hresult_success("WebAuthNAuthenticatorMakeCredential", result);

        PWEBAUTHN_CREDENTIAL_ATTESTATION const value = attestation.get();
        require(value != nullptr, "Windows returned no credential attestation.");
        require(
            value->cbCredentialId != 0 && value->pbCredentialId != nullptr,
            "Windows returned an empty credential identifier.");

        platform_credential credential = [&value]()
        {
            try
            {
                return platform_credential({
                    value->pbCredentialId,
                    static_cast<std::size_t>(value->cbCredentialId),
                });
            }
            catch (...)
            {
                rethrow_after_raw_credential_cleanup(
                    value->cbCredentialId,
                    value->pbCredentialId,
                    std::current_exception());
            }
        }();

        try
        {
            secret creation_prf = validated_secret_from_attestation(value);
            return {
                .credential = std::move(credential),
                .creation_prf = std::move(creation_prf),
            };
        }
        catch (...)
        {
            rethrow_after_credential_cleanup(
                credential,
                std::current_exception());
        }
    }

    [[nodiscard]] secret validated_secret_from_assertion(
        PWEBAUTHN_ASSERTION const value,
        std::span<std::uint8_t const> const expected_credential)
    {
        require(value != nullptr, "Windows returned no assertion.");
        require(
            value->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3,
            "Windows returned an assertion without WebAuthn PRF fields.");
        require(
            value->Credential.cbId == expected_credential.size() &&
                value->Credential.pbId != nullptr &&
                value->Credential.pwszCredentialType != nullptr &&
                std::wstring_view(value->Credential.pwszCredentialType) ==
                    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY &&
                std::memcmp(
                    value->Credential.pbId,
                    expected_credential.data(),
                    expected_credential.size()) == 0,
            "Windows returned an assertion for the wrong credential.");
        require(
            value->pbAuthenticatorData != nullptr &&
                value->cbAuthenticatorData >=
                    authenticator_data_minimum_bytes,
            "Windows returned malformed WebAuthn authenticator data.");
        require(
            std::equal(
                relying_party_id_hash().begin(),
                relying_party_id_hash().end(),
                value->pbAuthenticatorData),
            "Windows returned a WebAuthn assertion for the wrong relying party.");
        require(
            (value->pbAuthenticatorData[authenticator_flags_offset] &
             authenticator_user_verified_flag) != 0,
            "Windows returned a WebAuthn assertion without user verification.");
        require(
            value->pHmacSecret != nullptr &&
                value->pHmacSecret->cbFirst == secret_bytes &&
                value->pHmacSecret->pbFirst != nullptr &&
                value->pHmacSecret->cbSecond == 0 &&
                value->pHmacSecret->pbSecond == nullptr,
            "Windows returned no valid 32-byte WebAuthn PRF result.");

        secret released;
        std::memcpy(
            released.writable().data(),
            value->pHmacSecret->pbFirst,
            secret_bytes);
        return released;
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
        require_hresult_success("WebAuthNAuthenticatorGetAssertion", result);
        return validated_secret_from_assertion(
            result_value.get(),
            credential.identifier());
    }

    struct prf_comparison final
    {
        bool stable_for_same_salt;
        bool changes_for_different_salt;
    };

    [[nodiscard]] prf_comparison compare_prf_results(
        std::span<std::uint8_t const, secret_bytes> const creation,
        std::span<std::uint8_t const, secret_bytes> const first_assertion,
        std::span<std::uint8_t const, secret_bytes> const repeated,
        std::span<std::uint8_t const, secret_bytes> const independent) noexcept
    {
        return {
            .stable_for_same_salt =
                std::equal(
                    creation.begin(),
                    creation.end(),
                    first_assertion.begin(),
                    first_assertion.end()) &&
                std::equal(
                    first_assertion.begin(),
                    first_assertion.end(),
                    repeated.begin(),
                    repeated.end()),
            .changes_for_different_salt =
                !std::equal(
                    creation.begin(),
                    creation.end(),
                    independent.begin(),
                    independent.end()),
        };
    }

    template<typename Action>
    void require_failure(
        Action&& action,
        std::string_view const expected_message)
    {
        try
        {
            std::forward<Action>(action)();
        }
        catch (std::exception const& error)
        {
            require(
                std::string_view(error.what()).find(expected_message) !=
                    std::string_view::npos,
                "A synthetic failure did not report the expected reason.");
            return;
        }
        throw std::runtime_error(
            "A synthetic security-negative path was accepted.");
    }

    struct synthetic_assertion_fixture final
    {
        synthetic_assertion_fixture()
        {
            std::copy(
                relying_party_id_hash().begin(),
                relying_party_id_hash().end(),
                authenticator_data.begin());
            authenticator_data[authenticator_flags_offset] =
                authenticator_user_verified_flag;
            prf_bytes.fill(0xA5);
            prf.cbFirst = static_cast<DWORD>(prf_bytes.size());
            prf.pbFirst = prf_bytes.data();

            value.dwVersion = WEBAUTHN_ASSERTION_VERSION_3;
            value.cbAuthenticatorData =
                static_cast<DWORD>(authenticator_data.size());
            value.pbAuthenticatorData = authenticator_data.data();
            value.Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            value.Credential.cbId =
                static_cast<DWORD>(credential_identifier.size());
            value.Credential.pbId = credential_identifier.data();
            value.Credential.pwszCredentialType =
                WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            value.pHmacSecret = &prf;
        }

        std::array<std::uint8_t, 4> credential_identifier{
            0x10,
            0x20,
            0x30,
            0x40,
        };
        std::array<std::uint8_t, authenticator_data_minimum_bytes>
            authenticator_data{};
        std::array<std::uint8_t, secret_bytes> prf_bytes{};
        WEBAUTHN_HMAC_SECRET_SALT prf{};
        WEBAUTHN_ASSERTION value{};
    };

    struct synthetic_attestation_fixture final
    {
        synthetic_attestation_fixture()
        {
            std::copy(
                relying_party_id_hash().begin(),
                relying_party_id_hash().end(),
                authenticator_data.begin());
            authenticator_data[authenticator_flags_offset] =
                authenticator_user_verified_flag;
            prf_bytes.fill(0x5A);
            prf.cbFirst = static_cast<DWORD>(prf_bytes.size());
            prf.pbFirst = prf_bytes.data();

            value.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7;
            value.cbAuthenticatorData =
                static_cast<DWORD>(authenticator_data.size());
            value.pbAuthenticatorData = authenticator_data.data();
            value.dwUsedTransport = WEBAUTHN_CTAP_TRANSPORT_INTERNAL;
            value.bPrfEnabled = TRUE;
            value.pHmacSecret = &prf;
        }

        std::array<std::uint8_t, authenticator_data_minimum_bytes>
            authenticator_data{};
        std::array<std::uint8_t, secret_bytes> prf_bytes{};
        WEBAUTHN_HMAC_SECRET_SALT prf{};
        WEBAUTHN_CREDENTIAL_ATTESTATION value{};
    };

    void attestation_validation_self_test()
    {
        {
            synthetic_attestation_fixture fixture;
            secret const accepted =
                validated_secret_from_attestation(&fixture.value);
            require(
                std::equal(
                    accepted.value().begin(),
                    accepted.value().end(),
                    fixture.prf_bytes.begin(),
                    fixture.prf_bytes.end()),
                "A valid synthetic credential attestation returned the wrong PRF result.");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.value.dwVersion =
                WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_6;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "without creation-time WebAuthn PRF fields");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.authenticator_data.front() ^= 0xFF;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "wrong relying party");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.authenticator_data[authenticator_flags_offset] = 0;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "without user verification");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.value.bPrfEnabled = FALSE;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "did not enable WebAuthn PRF");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.value.pHmacSecret = nullptr;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "no valid 32-byte creation-time WebAuthn PRF result");
        }
        {
            synthetic_attestation_fixture fixture;
            --fixture.prf.cbFirst;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "no valid 32-byte creation-time WebAuthn PRF result");
        }
        {
            synthetic_attestation_fixture fixture;
            fixture.value.dwUsedTransport = WEBAUTHN_CTAP_TRANSPORT_USB;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_attestation(&fixture.value);
                },
                "non-platform authenticator");
        }
    }

    void assertion_validation_self_test()
    {
        {
            synthetic_assertion_fixture fixture;
            secret const accepted = validated_secret_from_assertion(
                &fixture.value,
                fixture.credential_identifier);
            require(
                std::equal(
                    accepted.value().begin(),
                    accepted.value().end(),
                    fixture.prf_bytes.begin(),
                    fixture.prf_bytes.end()),
                "A valid synthetic assertion returned the wrong PRF result.");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.value.pbAuthenticatorData = nullptr;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "malformed WebAuthn authenticator data");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.value.cbAuthenticatorData =
                static_cast<DWORD>(authenticator_flags_offset);
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "malformed WebAuthn authenticator data");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.authenticator_data.front() ^= 0xFF;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "wrong relying party");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.authenticator_data[authenticator_flags_offset] = 0;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "without user verification");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.value.pHmacSecret = nullptr;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "no valid 32-byte WebAuthn PRF result");
        }
        {
            synthetic_assertion_fixture fixture;
            --fixture.prf.cbFirst;
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "no valid 32-byte WebAuthn PRF result");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.prf.cbSecond =
                static_cast<DWORD>(fixture.prf_bytes.size());
            fixture.prf.pbSecond = fixture.prf_bytes.data();
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "no valid 32-byte WebAuthn PRF result");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.credential_identifier.front() ^= 0xFF;
            std::array<std::uint8_t, 4> const expected{
                0x10,
                0x20,
                0x30,
                0x40,
            };
            require_failure(
                [&fixture, &expected]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        expected);
                },
                "wrong credential");
        }
        {
            synthetic_assertion_fixture fixture;
            fixture.value.Credential.pwszCredentialType = L"password";
            require_failure(
                [&fixture]()
                {
                    (void)validated_secret_from_assertion(
                        &fixture.value,
                        fixture.credential_identifier);
                },
                "wrong credential");
        }
    }

    HRESULT WINAPI synthetic_delete_success(DWORD, BYTE const*)
    {
        return S_OK;
    }

    HRESULT WINAPI synthetic_delete_failure(DWORD, BYTE const*)
    {
        return E_ACCESSDENIED;
    }

    void failure_propagation_self_test()
    {
        require_failure(
            []()
            {
                require_hresult_success(
                    "Synthetic WebAuthn cancellation",
                    NTE_USER_CANCELLED);
            },
            "Synthetic WebAuthn cancellation failed");

        std::array<std::uint8_t, 4> const identifier{
            0x10,
            0x20,
            0x30,
            0x40,
        };
        platform_credential removed(
            identifier,
            &synthetic_delete_success);
        require(
            SUCCEEDED(removed.remove()),
            "Synthetic credential deletion should succeed.");
        require(
            SUCCEEDED(removed.remove()),
            "Successful credential deletion should be idempotent.");

        platform_credential cleanup_failure(
            identifier,
            &synthetic_delete_failure);
        require_failure(
            [&cleanup_failure]()
            {
                try
                {
                    throw std::runtime_error(
                        "Synthetic manual WebAuthn operation failed.");
                }
                catch (...)
                {
                    rethrow_after_credential_cleanup(
                        cleanup_failure,
                        std::current_exception());
                }
            },
            "WebAuthNDeletePlatformCredential cleanup failed");
    }

    void prf_comparison_self_test()
    {
        std::array<std::uint8_t, secret_bytes> creation{};
        std::array<std::uint8_t, secret_bytes> first{};
        std::array<std::uint8_t, secret_bytes> repeated{};
        std::array<std::uint8_t, secret_bytes> independent{};
        creation.fill(0x11);
        first.fill(0x11);
        repeated.fill(0x11);
        independent.fill(0x22);

        prf_comparison const valid =
            compare_prf_results(creation, first, repeated, independent);
        require(
            valid.stable_for_same_salt &&
                valid.changes_for_different_salt,
            "Valid synthetic PRF behavior was rejected.");

        first.fill(0x33);
        prf_comparison const ceremony_inconsistent =
            compare_prf_results(creation, first, repeated, independent);
        require(
            !ceremony_inconsistent.stable_for_same_salt,
            "Creation and assertion PRF disagreement was accepted.");

        first.fill(0x11);
        independent.fill(0x11);
        prf_comparison const salt_independent =
            compare_prf_results(creation, first, repeated, independent);
        require(
            !salt_independent.changes_for_different_salt,
            "Salt-independent synthetic PRF output was accepted.");
    }

    [[nodiscard]] int self_test()
    {
        DWORD const version = WebAuthNGetApiVersionNumber();
        require(version != 0, "Windows WebAuthn API is unavailable.");
        bool const available = platform_authenticator_available();
        attestation_validation_self_test();
        assertion_validation_self_test();
        failure_propagation_self_test();
        prf_comparison_self_test();

        std::cout << "[PASS] Windows WebAuthn API version " << version << '\n';
        std::cout << "[PASS] creation-time PRF evaluation requires API version 8; "
                  << (version >= WEBAUTHN_API_VERSION_8 ? "supported" : "unsupported")
                  << '\n';
        std::cout << "[PASS] user-verifying platform authenticator: "
                  << (available ? "available" : "not available (fail closed)")
                  << '\n'
                  << "[PASS] malformed, wrong-RP, missing-UV, missing-PRF, and wrong-transport attestations rejected\n"
                  << "[PASS] malformed, wrong-RP, wrong-credential, missing-UV, and missing-PRF assertions rejected\n"
                  << "[PASS] cancellation and credential-cleanup failures surfaced\n"
                  << "[PASS] creation/assertion stability and different-salt independence enforced\n"
                  << "7 passed; 0 failed\n";
        return 0;
    }

    [[nodiscard]] int manual_test()
    {
        DWORD const version = WebAuthNGetApiVersionNumber();
        require(
            version >= WEBAUTHN_API_VERSION_8,
            "Windows WebAuthn API version 8 or later is required.");
        require(
            platform_authenticator_available(),
            "No user-verifying platform authenticator is available. Configure Windows Hello first.");
        HWND const parent = GetConsoleWindow();
        require(
            parent != nullptr,
            "Manual mode requires an interactive console window.");

        std::array<std::uint8_t, secret_bytes> first_salt{};
        std::array<std::uint8_t, secret_bytes> second_salt{};
        random_bytes(first_salt);
        do
        {
            random_bytes(second_salt);
        } while (std::equal(
            first_salt.begin(),
            first_salt.end(),
            second_salt.begin(),
            second_salt.end()));

        credential_enrollment enrollment =
            create_credential(parent, first_salt);
        prf_comparison comparison{};
        try
        {
            {
                secret const first = release_secret(
                    parent,
                    enrollment.credential,
                    first_salt,
                    "LibrarianDisposableProbeFirst");
                secret const repeated = release_secret(
                    parent,
                    enrollment.credential,
                    first_salt,
                    "LibrarianDisposableProbeRepeated");
                secret const independent = release_secret(
                    parent,
                    enrollment.credential,
                    second_salt,
                    "LibrarianDisposableProbeIndependent");
                comparison = compare_prf_results(
                    enrollment.creation_prf.value(),
                    first.value(),
                    repeated.value(),
                    independent.value());
                enrollment.creation_prf.clear();
            }

            require(
                comparison.stable_for_same_salt,
                "Windows returned inconsistent WebAuthn PRF results for the same salt.");
            require(
                comparison.changes_for_different_salt,
                "Windows returned salt-independent WebAuthn PRF output.");
        }
        catch (...)
        {
            SecureZeroMemory(first_salt.data(), first_salt.size());
            SecureZeroMemory(second_salt.data(), second_salt.size());
            rethrow_after_credential_cleanup(
                enrollment.credential,
                std::current_exception());
        }
        SecureZeroMemory(first_salt.data(), first_salt.size());
        SecureZeroMemory(second_salt.data(), second_salt.size());

        HRESULT const removal = enrollment.credential.remove();
        if (FAILED(removal))
        {
            throw_hresult("WebAuthNDeletePlatformCredential", removal);
        }

        std::cout
            << "[PASS] disposable platform credential returned a creation-time WebAuthn PRF result\n"
            << "[PASS] creation and two same-salt assertions returned the same 32-byte result\n"
            << "[PASS] a different salt returned a different 32-byte result\n"
            << "[PASS] copied PRF results were zeroed immediately after comparison\n"
            << "[PASS] disposable platform credential was removed\n"
            << "5 passed; 0 failed\n";
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
