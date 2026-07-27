#include "librarian/windows_hello/client.h"
#include "validation.h"

#include <bcrypt.h>
#include <webauthn.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace librarian::windows_hello
{
    PrfOutput::PrfOutput(
        std::span<std::uint8_t const, prf_bytes> const value) noexcept
    {
        std::copy(value.begin(), value.end(), value_.begin());
    }

    PrfOutput::~PrfOutput() noexcept
    {
        Clear();
    }

    PrfOutput::PrfOutput(PrfOutput&& other) noexcept :
        value_(other.value_)
    {
        other.Clear();
    }

    PrfOutput& PrfOutput::operator=(PrfOutput&& other) noexcept
    {
        if (this != &other)
        {
            Clear();
            value_ = other.value_;
            other.Clear();
        }
        return *this;
    }

    std::span<std::uint8_t const, prf_bytes>
    PrfOutput::value() const noexcept
    {
        return value_;
    }

    void PrfOutput::Clear() noexcept
    {
        SecureZeroMemory(value_.data(), value_.size());
    }

    Enrollment::Enrollment(
        std::vector<std::uint8_t> credential_id_value,
        std::array<std::uint8_t, prf_bytes> salt_value,
        PrfOutput output_value) noexcept :
        credential_id(std::move(credential_id_value)),
        salt(salt_value),
        output(std::move(output_value))
    {
    }

    namespace
    {
        constexpr DWORD ceremony_timeout_ms = 120'000;
        constexpr wchar_t relying_party_id[] = L"librarian.local";
        constexpr wchar_t relying_party_name[] = L"Librarian";
        constexpr wchar_t user_name[] = L"local-vault";
        constexpr wchar_t user_display_name[] = L"Librarian local vault";
        constexpr std::size_t relying_party_id_hash_bytes =
            detail::relying_party_hash_bytes;

        static_assert(
            WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH ==
            librarian::windows_hello::prf_bytes);
        static_assert(sizeof(GUID) == operation_id_bytes);

        [[nodiscard]] bool valid_operation(
            OperationId const& operation_id) noexcept
        {
            return std::any_of(
                operation_id.begin(),
                operation_id.end(),
                [](std::uint8_t const byte)
                {
                    return byte != 0;
                });
        }

        [[nodiscard]] GUID operation_guid(
            OperationId const& operation_id) noexcept
        {
            GUID result{};
            std::memcpy(
                &result,
                operation_id.data(),
                operation_id.size());
            return result;
        }

        class failure final : public std::exception
        {
        public:
            explicit failure(Error const error) noexcept : error_(error)
            {
            }

            [[nodiscard]] Error error() const noexcept
            {
                return error_;
            }

        private:
            Error error_;
        };

        [[noreturn]] void fail(Error const error)
        {
            throw failure(error);
        }

        void require(
            bool const condition,
            Error const error = Error::InvalidResponse)
        {
            if (!condition)
            {
                fail(error);
            }
        }

        [[nodiscard]] bool is_cancellation(HRESULT const result) noexcept
        {
            return
                result == NTE_USER_CANCELLED ||
                result == HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }

        void require_hresult(HRESULT const result)
        {
            if (FAILED(result))
            {
                fail(
                    is_cancellation(result)
                        ? Error::Cancelled
                        : Error::PlatformFailure);
            }
        }

        void clear_hmac_secret(
            PWEBAUTHN_HMAC_SECRET_SALT const value) noexcept
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

        class attestation_owner final
        {
        public:
            ~attestation_owner()
            {
                if (value_ != nullptr)
                {
                    if (value_->dwVersion >=
                        WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_7)
                    {
                        clear_hmac_secret(value_->pHmacSecret);
                    }
                    WebAuthNFreeCredentialAttestation(value_);
                }
            }

            attestation_owner(attestation_owner const&) = delete;
            attestation_owner& operator=(attestation_owner const&) = delete;

            attestation_owner() noexcept = default;

            [[nodiscard]] PWEBAUTHN_CREDENTIAL_ATTESTATION* put() noexcept
            {
                return &value_;
            }

            [[nodiscard]] PWEBAUTHN_CREDENTIAL_ATTESTATION get() const noexcept
            {
                return value_;
            }

        private:
            PWEBAUTHN_CREDENTIAL_ATTESTATION value_{nullptr};
        };

        class assertion_owner final
        {
        public:
            ~assertion_owner()
            {
                if (value_ != nullptr)
                {
                    if (value_->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3)
                    {
                        clear_hmac_secret(value_->pHmacSecret);
                    }
                    WebAuthNFreeAssertion(value_);
                }
            }

            assertion_owner(assertion_owner const&) = delete;
            assertion_owner& operator=(assertion_owner const&) = delete;

            assertion_owner() noexcept = default;

            [[nodiscard]] PWEBAUTHN_ASSERTION* put() noexcept
            {
                return &value_;
            }

            [[nodiscard]] PWEBAUTHN_ASSERTION get() const noexcept
            {
                return value_;
            }

        private:
            PWEBAUTHN_ASSERTION value_{nullptr};
        };

        class created_credential final
        {
        public:
            explicit created_credential(
                PBYTE const identifier,
                DWORD const size) noexcept :
                identifier_(identifier),
                size_(size)
            {
            }

            ~created_credential()
            {
                if (owned_ && identifier_ != nullptr && size_ != 0)
                {
                    (void)WebAuthNDeletePlatformCredential(
                        size_,
                        identifier_);
                }
            }

            created_credential(created_credential const&) = delete;
            created_credential& operator=(created_credential const&) = delete;
            created_credential(created_credential&&) = delete;
            created_credential& operator=(created_credential&&) = delete;

            [[nodiscard]] std::vector<std::uint8_t> release()
            {
                std::vector<std::uint8_t> result(
                    identifier_,
                    identifier_ + size_);
                owned_ = false;
                return result;
            }

            [[nodiscard]] HRESULT remove() noexcept
            {
                if (!owned_ || identifier_ == nullptr || size_ == 0)
                {
                    return S_OK;
                }
                HRESULT const result = WebAuthNDeletePlatformCredential(
                    size_,
                    identifier_);
                if (SUCCEEDED(result))
                {
                    owned_ = false;
                }
                return result;
            }

        private:
            PBYTE identifier_{nullptr};
            DWORD size_{0};
            bool owned_{true};
        };

        void random_bytes(std::span<std::uint8_t> const destination)
        {
            NTSTATUS const result = BCryptGenRandom(
                nullptr,
                destination.data(),
                static_cast<ULONG>(destination.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (result < 0)
            {
                fail(Error::PlatformFailure);
            }
        }

        [[nodiscard]] std::string random_challenge()
        {
            constexpr char digits[] = "0123456789abcdef";
            std::array<std::uint8_t, 32> bytes{};
            random_bytes(bytes);
            std::string result;
            result.reserve(bytes.size() * 2);
            for (std::uint8_t const value : bytes)
            {
                result.push_back(digits[value >> 4]);
                result.push_back(digits[value & 0x0F]);
            }
            SecureZeroMemory(bytes.data(), bytes.size());
            return result;
        }

        [[nodiscard]] std::array<
            std::uint8_t,
            relying_party_id_hash_bytes> const&
        relying_party_hash()
        {
            static std::array<
                std::uint8_t,
                relying_party_id_hash_bytes> const hash = []()
            {
                constexpr int characters =
                    static_cast<int>(
                        sizeof(relying_party_id) /
                        sizeof(relying_party_id[0])) -
                    1;
                int const utf8_size = WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    relying_party_id,
                    characters,
                    nullptr,
                    0,
                    nullptr,
                    nullptr);
                require(utf8_size > 0, Error::PlatformFailure);
                std::vector<std::uint8_t> utf8(
                    static_cast<std::size_t>(utf8_size));
                require(
                    WideCharToMultiByte(
                        CP_UTF8,
                        WC_ERR_INVALID_CHARS,
                        relying_party_id,
                        characters,
                        reinterpret_cast<char*>(utf8.data()),
                        utf8_size,
                        nullptr,
                        nullptr) == utf8_size,
                    Error::PlatformFailure);

                BCRYPT_ALG_HANDLE algorithm = nullptr;
                require(
                    BCryptOpenAlgorithmProvider(
                        &algorithm,
                        BCRYPT_SHA256_ALGORITHM,
                        nullptr,
                        0) >= 0,
                    Error::PlatformFailure);
                std::array<
                    std::uint8_t,
                    relying_party_id_hash_bytes> value{};
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
                require(
                    hash_result >= 0 && close_result >= 0,
                    Error::PlatformFailure);
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

        [[nodiscard]] std::span<std::uint8_t const> bytes(
            PBYTE const value,
            DWORD const size) noexcept
        {
            if (value == nullptr)
            {
                return {};
            }
            return {value, static_cast<std::size_t>(size)};
        }

        [[nodiscard]] detail::PrfView prf_view(
            PWEBAUTHN_HMAC_SECRET_SALT const value) noexcept
        {
            if (value == nullptr)
            {
                return {};
            }
            return {
                .first = bytes(value->pbFirst, value->cbFirst),
                .second = bytes(value->pbSecond, value->cbSecond),
            };
        }

        [[nodiscard]] PrfOutput validated_output(
            detail::ValidationResult result)
        {
            if (
                result.error != Error::None ||
                !result.output.has_value())
            {
                fail(
                    result.error == Error::None
                        ? Error::InvalidResponse
                        : result.error);
            }
            return std::move(*result.output);
        }

        [[nodiscard]] Enrollment enroll(
            HWND const parent,
            OperationId const& operation_id)
        {
            require(
                parent != nullptr && valid_operation(operation_id),
                Error::InvalidArgument);
            require(
                WebAuthNGetApiVersionNumber() >= WEBAUTHN_API_VERSION_8,
                Error::Unsupported);
            BOOL available = FALSE;
            require_hresult(
                WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
                    &available));
            require(available != FALSE, Error::Unavailable);

            std::array<std::uint8_t, 32> user_identifier{};
            std::array<std::uint8_t, prf_bytes> salt{};
            random_bytes(user_identifier);
            random_bytes(salt);

            WEBAUTHN_RP_ENTITY_INFORMATION relying_party{
                .dwVersion =
                    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
                .pwszId = relying_party_id,
                .pwszName = relying_party_name,
            };
            WEBAUTHN_USER_ENTITY_INFORMATION user{
                .dwVersion =
                    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                .cbId = static_cast<DWORD>(user_identifier.size()),
                .pbId = user_identifier.data(),
                .pwszName = user_name,
                .pwszDisplayName = user_display_name,
            };
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER parameter{
                .dwVersion =
                    WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                .pwszCredentialType =
                    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                .lAlg =
                    WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            };
            WEBAUTHN_COSE_CREDENTIAL_PARAMETERS parameters{
                .cCredentialParameters = 1,
                .pCredentialParameters = &parameter,
            };
            std::string const json =
                std::string(
                    R"({"type":"webauthn.create","challenge":")") +
                random_challenge() +
                R"(","origin":"https://librarian.local","crossOrigin":false})";
            WEBAUTHN_CLIENT_DATA const data = client_data(json);
            WEBAUTHN_HMAC_SECRET_SALT requested_prf{
                .cbFirst = static_cast<DWORD>(salt.size()),
                .pbFirst = salt.data(),
            };
            GUID cancellation_id = operation_guid(operation_id);
            WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{
                .dwVersion =
                    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_8,
                .dwTimeoutMilliseconds = ceremony_timeout_ms,
                .dwAuthenticatorAttachment =
                    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                .bRequireResidentKey = TRUE,
                .dwUserVerificationRequirement =
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                .dwAttestationConveyancePreference =
                    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                .pCancellationId = &cancellation_id,
                .bEnablePrf = TRUE,
                .pPRFGlobalEval = &requested_prf,
            };

            attestation_owner attestation;
            HRESULT const result = WebAuthNAuthenticatorMakeCredential(
                parent,
                &relying_party,
                &user,
                &parameters,
                &data,
                &options,
                attestation.put());
            SecureZeroMemory(
                user_identifier.data(),
                user_identifier.size());
            require_hresult(result);

            PWEBAUTHN_CREDENTIAL_ATTESTATION const value =
                attestation.get();
            require(
                value != nullptr &&
                value->cbCredentialId != 0 &&
                value->pbCredentialId != nullptr);

            created_credential credential(
                value->pbCredentialId,
                value->cbCredentialId);
            try
            {
                require(
                    value->cbCredentialId <=
                    maximum_credential_id_bytes);
                PrfOutput output = validated_output(
                    detail::ValidateAttestation(
                        {
                            .version = value->dwVersion,
                            .credential_id = bytes(
                                value->pbCredentialId,
                                value->cbCredentialId),
                            .authenticator_data = bytes(
                                value->pbAuthenticatorData,
                                value->cbAuthenticatorData),
                            .prf_enabled = value->bPrfEnabled != FALSE,
                            .used_transport = value->dwUsedTransport,
                            .prf = prf_view(value->pHmacSecret),
                        },
                        relying_party_hash()));
                return Enrollment(
                    credential.release(),
                    salt,
                    std::move(output));
            }
            catch (...)
            {
                std::exception_ptr const original =
                    std::current_exception();
                if (FAILED(credential.remove()))
                {
                    fail(Error::CredentialRemovalFailed);
                }
                std::rethrow_exception(original);
            }
        }

        [[nodiscard]] PrfOutput evaluate(
            HWND const parent,
            std::span<std::uint8_t const> const credential_id,
            std::span<std::uint8_t const, prf_bytes> const salt,
            OperationId const& operation_id)
        {
            require(
                parent != nullptr &&
                !credential_id.empty() &&
                credential_id.size() <= maximum_credential_id_bytes &&
                valid_operation(operation_id),
                Error::InvalidArgument);
            require(
                WebAuthNGetApiVersionNumber() >= WEBAUTHN_API_VERSION_8,
                Error::Unsupported);

            WEBAUTHN_CREDENTIAL credential{
                .dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                .cbId = static_cast<DWORD>(credential_id.size()),
                .pbId = const_cast<PBYTE>(credential_id.data()),
                .pwszCredentialType =
                    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            };
            WEBAUTHN_CREDENTIALS allowed{
                .cCredentials = 1,
                .pCredentials = &credential,
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
                random_challenge() +
                R"(","origin":"https://librarian.local","crossOrigin":false})";
            WEBAUTHN_CLIENT_DATA const data = client_data(json);
            GUID cancellation_id = operation_guid(operation_id);
            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{
                .dwVersion =
                    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
                .dwTimeoutMilliseconds = ceremony_timeout_ms,
                .CredentialList = allowed,
                .dwAuthenticatorAttachment =
                    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                .dwUserVerificationRequirement =
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                .pCancellationId = &cancellation_id,
                .pHmacSecretSaltValues = &requested_values,
            };

            assertion_owner assertion;
            require_hresult(WebAuthNAuthenticatorGetAssertion(
                parent,
                relying_party_id,
                &data,
                &options,
                assertion.put()));
            PWEBAUTHN_ASSERTION const value = assertion.get();
            require(value != nullptr);
            return validated_output(detail::ValidateAssertion(
                {
                    .version = value->dwVersion,
                    .credential_id = bytes(
                        value->Credential.pbId,
                        value->Credential.cbId),
                    .credential_type =
                        value->Credential.pwszCredentialType == nullptr
                            ? std::wstring_view{}
                            : std::wstring_view(
                                value->Credential.pwszCredentialType),
                    .authenticator_data = bytes(
                        value->pbAuthenticatorData,
                        value->cbAuthenticatorData),
                    .prf = prf_view(value->pHmacSecret),
                },
                credential_id,
                relying_party_hash()));
        }
    }

    AvailabilityResult IsAvailable() noexcept
    {
        if (WebAuthNGetApiVersionNumber() < WEBAUTHN_API_VERSION_8)
        {
            return {
                .error = Error::None,
                .available = false,
            };
        }
        BOOL available = FALSE;
        if (FAILED(
            WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
                &available)))
        {
            return {
                .error = Error::PlatformFailure,
                .available = false,
            };
        }
        return {
            .error = Error::None,
            .available = available != FALSE,
        };
    }

    EnrollmentResult Enroll(
        HWND const parent,
        OperationId const& operation_id) noexcept
    {
        try
        {
            return {
                .error = Error::None,
                .enrollment = enroll(parent, operation_id),
            };
        }
        catch (failure const& error)
        {
            return {.error = error.error()};
        }
        catch (...)
        {
            return {.error = Error::PlatformFailure};
        }
    }

    EvaluationResult Evaluate(
        HWND const parent,
        std::span<std::uint8_t const> const credential_id,
        std::span<std::uint8_t const, prf_bytes> const salt,
        OperationId const& operation_id) noexcept
    {
        try
        {
            return {
                .error = Error::None,
                .output = evaluate(
                    parent,
                    credential_id,
                    salt,
                    operation_id),
            };
        }
        catch (failure const& error)
        {
            return {.error = error.error()};
        }
        catch (...)
        {
            return {.error = Error::PlatformFailure};
        }
    }

    Error Cancel(OperationId const& operation_id) noexcept
    {
        if (!valid_operation(operation_id))
        {
            return Error::InvalidArgument;
        }
        GUID const cancellation_id = operation_guid(operation_id);
        HRESULT const result =
            WebAuthNCancelCurrentOperation(&cancellation_id);
        if (SUCCEEDED(result))
        {
            return Error::None;
        }
        return
            is_cancellation(result)
                ? Error::Cancelled
                : Error::PlatformFailure;
    }

    Error Remove(
        std::span<std::uint8_t const> const credential_id) noexcept
    {
        if (
            credential_id.empty() ||
            credential_id.size() > maximum_credential_id_bytes)
        {
            return Error::InvalidArgument;
        }
        HRESULT const result = WebAuthNDeletePlatformCredential(
            static_cast<DWORD>(credential_id.size()),
            credential_id.data());
        if (SUCCEEDED(result) || result == NTE_NOT_FOUND)
        {
            return Error::None;
        }
        return
            is_cancellation(result)
                ? Error::Cancelled
                : Error::CredentialRemovalFailed;
    }
}
