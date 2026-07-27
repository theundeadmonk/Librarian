#pragma once

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace librarian::windows_hello
{
    inline constexpr std::size_t prf_bytes = 32;
    inline constexpr std::size_t operation_id_bytes = 16;
    inline constexpr std::size_t maximum_credential_id_bytes = 1'024;
    using OperationId = std::array<std::uint8_t, operation_id_bytes>;

    enum class Error
    {
        None,
        InvalidArgument,
        Unavailable,
        Unsupported,
        Cancelled,
        InvalidResponse,
        PlatformFailure,
        CredentialRemovalFailed,
    };

    // A transient WebAuthn PRF result. This component belongs inside the
    // trusted vault-agent boundary: the PRF result must never cross
    // desktop-controlled IPC, be logged, or be persisted. The allocation is
    // move-only and cleared on destruction.
    class PrfOutput final
    {
    public:
        explicit PrfOutput(std::span<std::uint8_t const, prf_bytes> value) noexcept;
        ~PrfOutput() noexcept;

        PrfOutput(PrfOutput const&) = delete;
        PrfOutput& operator=(PrfOutput const&) = delete;

        PrfOutput(PrfOutput&& other) noexcept;
        PrfOutput& operator=(PrfOutput&& other) noexcept;

        [[nodiscard]] std::span<std::uint8_t const, prf_bytes>
        value() const noexcept;

    private:
        void Clear() noexcept;

        std::array<std::uint8_t, prf_bytes> value_{};
    };

    struct Enrollment final
    {
        Enrollment(
            std::vector<std::uint8_t> credential_id,
            std::array<std::uint8_t, prf_bytes> salt,
            PrfOutput output) noexcept;

        Enrollment(Enrollment const&) = delete;
        Enrollment& operator=(Enrollment const&) = delete;
        Enrollment(Enrollment&&) noexcept = default;
        Enrollment& operator=(Enrollment&&) noexcept = default;

        std::vector<std::uint8_t> credential_id;
        std::array<std::uint8_t, prf_bytes> salt;
        PrfOutput output;
    };

    struct EnrollmentResult final
    {
        Error error{Error::PlatformFailure};
        std::optional<Enrollment> enrollment;
    };

    struct EvaluationResult final
    {
        Error error{Error::PlatformFailure};
        std::optional<PrfOutput> output;
    };

    struct AvailabilityResult final
    {
        Error error{Error::PlatformFailure};
        bool available{false};
    };

    // This is a capability check only. Enrollment still validates the API
    // version and the credential's returned PRF capability before success.
    [[nodiscard]] AvailabilityResult IsAvailable() noexcept;

    // Displays a Windows-owned user-verification prompt and creates one
    // platform credential for Librarian. On every failure after credential
    // creation, the credential is removed before the error is returned.
    [[nodiscard]] EnrollmentResult Enroll(
        HWND parent,
        OperationId const& operation_id) noexcept;

    // Displays a Windows-owned user-verification prompt and evaluates PRF for
    // the exact enrolled credential and salt.
    [[nodiscard]] EvaluationResult Evaluate(
        HWND parent,
        std::span<std::uint8_t const> credential_id,
        std::span<std::uint8_t const, prf_bytes> salt,
        OperationId const& operation_id) noexcept;

    // Cancels only the ceremony carrying the supplied agent-generated ID.
    [[nodiscard]] Error Cancel(OperationId const& operation_id) noexcept;

    // Removes only the supplied Librarian platform credential.
    [[nodiscard]] Error Remove(
        std::span<std::uint8_t const> credential_id) noexcept;
}
