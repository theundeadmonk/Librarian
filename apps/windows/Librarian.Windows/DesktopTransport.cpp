#include "DesktopTransport.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <aclapi.h>
#include <appmodel.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <shobjidl_core.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace librarian::windows
{
    namespace
    {
        constexpr std::size_t frame_header_bytes = 40U;
        constexpr std::size_t maximum_payload_bytes = 65'536U;
        constexpr std::size_t maximum_descriptor_bytes = 4'096U;
        constexpr std::uint32_t frame_write_allowance_ms = 2'000U;
        constexpr std::uint16_t protocol_major = 1U;
        constexpr std::uint16_t protocol_minor = 1U;
        constexpr std::uint16_t windows_hello_feature = 1U;
        constexpr std::uint32_t medium_integrity_rid = 0x2000U;
        constexpr std::wstring_view desktop_executable{L"Librarian.Windows.exe"};
        constexpr std::wstring_view agent_executable{L"Librarian.VaultAgent.exe"};
        constexpr std::wstring_view endpoint_relative_path{
            L"Librarian\\agent-endpoint-v1.cbor"};
        constexpr std::wstring_view pipe_prefix{
            L"\\\\.\\pipe\\LOCAL\\Librarian.Agent.v1."};

        enum class transport_error
        {
            unavailable,
            cancelled,
            invalid,
        };

        class transport_exception final : public std::exception
        {
        public:
            explicit transport_exception(transport_error const error) noexcept :
                error_(error)
            {
            }

            [[nodiscard]] transport_error error() const noexcept
            {
                return error_;
            }

        private:
            transport_error error_;
        };

        [[noreturn]] void fail(transport_error const error)
        {
            throw transport_exception{error};
        }

        class unique_handle final
        {
        public:
            unique_handle() noexcept = default;
            explicit unique_handle(HANDLE const value) noexcept : value_(value)
            {
            }

            ~unique_handle() noexcept
            {
                reset();
            }

            unique_handle(unique_handle const&) = delete;
            unique_handle& operator=(unique_handle const&) = delete;

            unique_handle(unique_handle&& other) noexcept :
                value_(std::exchange(other.value_, INVALID_HANDLE_VALUE))
            {
            }

            unique_handle& operator=(unique_handle&& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
                }
                return *this;
            }

            [[nodiscard]] HANDLE get() const noexcept
            {
                return value_;
            }

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
            }

            void reset(HANDLE const value = INVALID_HANDLE_VALUE) noexcept
            {
                if (*this)
                {
                    CloseHandle(value_);
                }
                value_ = value;
            }

        private:
            HANDLE value_{INVALID_HANDLE_VALUE};
        };

        class local_memory final
        {
        public:
            local_memory() noexcept = default;
            explicit local_memory(void* const value) noexcept : value_(value)
            {
            }
            ~local_memory() noexcept
            {
                if (value_ != nullptr)
                {
                    LocalFree(value_);
                }
            }
            local_memory(local_memory const&) = delete;
            local_memory& operator=(local_memory const&) = delete;
            [[nodiscard]] void* get() const noexcept
            {
                return value_;
            }

        private:
            void* value_{nullptr};
        };

        class secret_bytes final
        {
        public:
            secret_bytes() = default;
            explicit secret_bytes(std::size_t const size) : value_(size)
            {
            }
            explicit secret_bytes(std::vector<std::uint8_t> value) :
                value_(std::move(value))
            {
            }
            ~secret_bytes() noexcept
            {
                clear();
            }
            secret_bytes(secret_bytes const&) = delete;
            secret_bytes& operator=(secret_bytes const&) = delete;
            secret_bytes(secret_bytes&& other) noexcept : value_(std::move(other.value_))
            {
                other.clear();
            }
            secret_bytes& operator=(secret_bytes&& other) noexcept
            {
                if (this != &other)
                {
                    clear();
                    value_ = std::move(other.value_);
                    other.clear();
                }
                return *this;
            }
            [[nodiscard]] std::vector<std::uint8_t>& value() noexcept
            {
                return value_;
            }
            [[nodiscard]] std::vector<std::uint8_t> const& value() const noexcept
            {
                return value_;
            }
            [[nodiscard]] std::uint8_t* data() noexcept
            {
                return value_.data();
            }
            [[nodiscard]] std::uint8_t const* data() const noexcept
            {
                return value_.data();
            }
            [[nodiscard]] std::size_t size() const noexcept
            {
                return value_.size();
            }
            [[nodiscard]] bool empty() const noexcept
            {
                return value_.empty();
            }

        private:
            void clear() noexcept
            {
                if (!value_.empty())
                {
                    SecureZeroMemory(value_.data(), value_.size());
                    value_.clear();
                }
            }

            std::vector<std::uint8_t> value_;
        };

        bool equal_path(std::filesystem::path const& left, std::filesystem::path const& right)
        {
            return CompareStringOrdinal(
                       left.c_str(),
                       -1,
                       right.c_str(),
                       -1,
                       TRUE) == CSTR_EQUAL;
        }

        std::wstring sid_string(PSID const sid)
        {
            if (sid == nullptr || !IsValidSid(sid))
            {
                fail(transport_error::invalid);
            }
            LPWSTR raw = nullptr;
            if (!ConvertSidToStringSidW(sid, &raw))
            {
                fail(transport_error::invalid);
            }
            local_memory const memory{raw};
            return raw;
        }

        class token_buffer final
        {
        public:
            explicit token_buffer(std::size_t const byte_length) :
                words_((byte_length + sizeof(std::uintptr_t) - 1U) /
                    sizeof(std::uintptr_t)),
                byte_length_(byte_length)
            {
            }

            [[nodiscard]] void* data() noexcept
            {
                return words_.data();
            }

            [[nodiscard]] void const* data() const noexcept
            {
                return words_.data();
            }

            [[nodiscard]] std::size_t size() const noexcept
            {
                return byte_length_;
            }

        private:
            std::vector<std::uintptr_t> words_;
            std::size_t byte_length_;
        };

        token_buffer token_information(
            HANDLE const token,
            TOKEN_INFORMATION_CLASS const information_class)
        {
            DWORD length = 0U;
            BOOL const size_result = GetTokenInformation(
                token,
                information_class,
                nullptr,
                0U,
                &length);
            DWORD const size_error = GetLastError();
            // Windows may report ERROR_BAD_LENGTH for the zero-buffer size
            // query of fixed-size token classes such as TokenElevation.
            if (size_result ||
                (size_error != ERROR_INSUFFICIENT_BUFFER &&
                    size_error != ERROR_BAD_LENGTH) ||
                length == 0U ||
                length > 1'048'576U)
            {
                fail(transport_error::invalid);
            }
            token_buffer bytes{length};
            DWORD written = length;
            if (!GetTokenInformation(
                    token,
                    information_class,
                    bytes.data(),
                    length,
                    &written) ||
                written == 0U ||
                written > bytes.size())
            {
                fail(transport_error::invalid);
            }
            return bytes;
        }

        template<typename Value>
        Value const& token_value(token_buffer const& bytes)
        {
            if (bytes.size() < sizeof(Value))
            {
                fail(transport_error::invalid);
            }
            return *static_cast<Value const*>(bytes.data());
        }

        using appmodel_query = LONG(WINAPI*)(HANDLE, UINT32*, PWSTR);

        std::wstring process_appmodel_string(HANDLE const process, appmodel_query const query)
        {
            UINT32 length = 0U;
            LONG const first = query(process, &length, nullptr);
            if (first != ERROR_INSUFFICIENT_BUFFER || length <= 1U || length > 32'768U)
            {
                fail(transport_error::invalid);
            }
            std::wstring value(length, L'\0');
            if (query(process, &length, value.data()) != ERROR_SUCCESS ||
                length == 0U || value[length - 1U] != L'\0')
            {
                fail(transport_error::invalid);
            }
            value.resize(length - 1U);
            return value;
        }

        struct process_observation
        {
            DWORD process_id{};
            std::uint64_t creation_time{};
            DWORD session_id{};
            std::wstring user_sid;
            std::wstring logon_sid;
            DWORD integrity_rid{};
            bool elevated{};
            bool app_container{};
            std::filesystem::path image_path;
            std::wstring package_full_name;
            std::wstring package_family_name;
            std::wstring application_user_model_id;
        };

        process_observation observe_process(HANDLE const process, DWORD const process_id)
        {
            unique_handle token;
            HANDLE raw_token = nullptr;
            if (!OpenProcessToken(process, TOKEN_QUERY, &raw_token))
            {
                fail(transport_error::invalid);
            }
            token.reset(raw_token);

            auto const user = token_information(token.get(), TokenUser);
            auto const& token_user = token_value<TOKEN_USER>(user);
            auto const groups = token_information(token.get(), TokenGroups);
            auto const& token_groups = token_value<TOKEN_GROUPS>(groups);
            std::size_t const groups_offset = offsetof(TOKEN_GROUPS, Groups);
            if (groups.size() < groups_offset ||
                token_groups.GroupCount >
                    (groups.size() - groups_offset) / sizeof(SID_AND_ATTRIBUTES))
            {
                fail(transport_error::invalid);
            }
            std::wstring logon_sid;
            for (DWORD index = 0U; index < token_groups.GroupCount; ++index)
            {
                if ((token_groups.Groups[index].Attributes & SE_GROUP_LOGON_ID) ==
                    SE_GROUP_LOGON_ID)
                {
                    if (!logon_sid.empty())
                    {
                        fail(transport_error::invalid);
                    }
                    logon_sid = sid_string(token_groups.Groups[index].Sid);
                }
            }
            if (logon_sid.empty())
            {
                fail(transport_error::invalid);
            }

            auto const integrity = token_information(token.get(), TokenIntegrityLevel);
            auto const& label = token_value<TOKEN_MANDATORY_LABEL>(integrity);
            if (label.Label.Sid == nullptr || !IsValidSid(label.Label.Sid))
            {
                fail(transport_error::invalid);
            }
            auto const* subauthority_count_pointer = GetSidSubAuthorityCount(label.Label.Sid);
            if (subauthority_count_pointer == nullptr || *subauthority_count_pointer == 0U)
            {
                fail(transport_error::invalid);
            }
            DWORD const subauthority_count = *subauthority_count_pointer;
            DWORD const integrity_rid = *GetSidSubAuthority(
                label.Label.Sid,
                subauthority_count - 1U);
            auto const elevation = token_information(token.get(), TokenElevation);
            auto const& token_elevation = token_value<TOKEN_ELEVATION>(elevation);
            auto const container = token_information(token.get(), TokenIsAppContainer);
            DWORD const is_container = token_value<DWORD>(container);
            auto const session = token_information(token.get(), TokenSessionId);
            DWORD const session_id = token_value<DWORD>(session);

            std::wstring image(32'768U, L'\0');
            DWORD image_length = static_cast<DWORD>(image.size());
            if (!QueryFullProcessImageNameW(
                    process,
                    0U,
                    image.data(),
                    &image_length) || image_length == 0U)
            {
                fail(transport_error::invalid);
            }
            image.resize(image_length);

            FILETIME created{};
            FILETIME exited{};
            FILETIME kernel{};
            FILETIME user_time{};
            if (!GetProcessTimes(process, &created, &exited, &kernel, &user_time))
            {
                fail(transport_error::invalid);
            }
            ULARGE_INTEGER created_value{};
            created_value.LowPart = created.dwLowDateTime;
            created_value.HighPart = created.dwHighDateTime;

            auto const package_full_name = process_appmodel_string(process, GetPackageFullName);
            auto const package_family_name = process_appmodel_string(process, GetPackageFamilyName);
            auto const application_user_model_id = process_appmodel_string(
                process,
                GetApplicationUserModelId);

            return {
                process_id,
                created_value.QuadPart,
                session_id,
                sid_string(token_user.User.Sid),
                std::move(logon_sid),
                integrity_rid,
                token_elevation.TokenIsElevated != 0U,
                is_container != 0U,
                std::filesystem::path{image},
                package_full_name,
                package_family_name,
                application_user_model_id,
            };
        }

        std::pair<unique_handle, process_observation> observe_process(DWORD const process_id)
        {
            unique_handle process{OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                FALSE,
                process_id)};
            if (!process)
            {
                fail(transport_error::unavailable);
            }
            auto observation = observe_process(process.get(), process_id);
            if (WaitForSingleObject(process.get(), 0U) != WAIT_TIMEOUT)
            {
                fail(transport_error::unavailable);
            }
            return {std::move(process), std::move(observation)};
        }

        std::array<std::uint8_t, 32U> sha256_file(std::filesystem::path const& path)
        {
            unique_handle file{CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr)};
            if (!file)
            {
                fail(transport_error::invalid);
            }
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            auto close_algorithm = [&]() noexcept {
                if (hash != nullptr)
                {
                    BCryptDestroyHash(hash);
                }
                if (algorithm != nullptr)
                {
                    BCryptCloseAlgorithmProvider(algorithm, 0U);
                }
            };
            if (BCryptOpenAlgorithmProvider(
                    &algorithm,
                    BCRYPT_SHA256_ALGORITHM,
                    nullptr,
                    0U) < 0)
            {
                fail(transport_error::invalid);
            }
            DWORD object_length = 0U;
            DWORD returned = 0U;
            if (BCryptGetProperty(
                    algorithm,
                    BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&object_length),
                    sizeof(object_length),
                    &returned,
                    0U) < 0 || object_length == 0U)
            {
                close_algorithm();
                fail(transport_error::invalid);
            }
            secret_bytes hash_object{object_length};
            if (BCryptCreateHash(
                    algorithm,
                    &hash,
                    hash_object.data(),
                    static_cast<ULONG>(hash_object.size()),
                    nullptr,
                    0U,
                    0U) < 0)
            {
                close_algorithm();
                fail(transport_error::invalid);
            }
            std::array<std::uint8_t, 16U * 1024U> buffer{};
            for (;;)
            {
                DWORD read = 0U;
                if (!ReadFile(
                        file.get(),
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        &read,
                        nullptr))
                {
                    SecureZeroMemory(buffer.data(), buffer.size());
                    close_algorithm();
                    fail(transport_error::invalid);
                }
                if (read == 0U)
                {
                    break;
                }
                if (BCryptHashData(hash, buffer.data(), read, 0U) < 0)
                {
                    SecureZeroMemory(buffer.data(), buffer.size());
                    close_algorithm();
                    fail(transport_error::invalid);
                }
            }
            SecureZeroMemory(buffer.data(), buffer.size());
            std::array<std::uint8_t, 32U> digest{};
            if (BCryptFinishHash(
                    hash,
                    digest.data(),
                    static_cast<ULONG>(digest.size()),
                    0U) < 0)
            {
                close_algorithm();
                fail(transport_error::invalid);
            }
            close_algorithm();
            return digest;
        }

        void random_bytes(std::span<std::uint8_t> const destination)
        {
            if (destination.empty() ||
                destination.size() > std::numeric_limits<ULONG>::max() ||
                BCryptGenRandom(
                    nullptr,
                    destination.data(),
                    static_cast<ULONG>(destination.size()),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
                std::ranges::all_of(destination, [](std::uint8_t const value) {
                    return value == 0U;
                }))
            {
                fail(transport_error::invalid);
            }
        }

        class cbor_writer final
        {
        public:
            void unsigned_value(std::uint64_t const value)
            {
                type_value(0U, value);
            }

            void array(std::uint64_t const length)
            {
                type_value(4U, length);
            }

            void bytes(std::span<std::uint8_t const> const value)
            {
                type_value(2U, value.size());
                append(value);
            }

            void text(std::span<std::uint8_t const> const value)
            {
                type_value(3U, value.size());
                append(value);
            }

            void null_value()
            {
                buffer_.value().push_back(0xf6U);
            }

            [[nodiscard]] secret_bytes take()
            {
                if (buffer_.size() > maximum_payload_bytes)
                {
                    fail(transport_error::invalid);
                }
                return std::move(buffer_);
            }

        private:
            void append(std::span<std::uint8_t const> const value)
            {
                buffer_.value().insert(
                    buffer_.value().end(),
                    value.begin(),
                    value.end());
            }

            void type_value(std::uint8_t const major, std::uint64_t const value)
            {
                auto& output = buffer_.value();
                std::uint8_t const prefix = static_cast<std::uint8_t>(major << 5U);
                if (value < 24U)
                {
                    output.push_back(static_cast<std::uint8_t>(prefix | value));
                }
                else if (value <= std::numeric_limits<std::uint8_t>::max())
                {
                    output.push_back(static_cast<std::uint8_t>(prefix | 24U));
                    output.push_back(static_cast<std::uint8_t>(value));
                }
                else if (value <= std::numeric_limits<std::uint16_t>::max())
                {
                    output.push_back(static_cast<std::uint8_t>(prefix | 25U));
                    output.push_back(static_cast<std::uint8_t>(value >> 8U));
                    output.push_back(static_cast<std::uint8_t>(value));
                }
                else if (value <= std::numeric_limits<std::uint32_t>::max())
                {
                    output.push_back(static_cast<std::uint8_t>(prefix | 26U));
                    for (int shift = 24; shift >= 0; shift -= 8)
                    {
                        output.push_back(static_cast<std::uint8_t>(value >> shift));
                    }
                }
                else
                {
                    output.push_back(static_cast<std::uint8_t>(prefix | 27U));
                    for (int shift = 56; shift >= 0; shift -= 8)
                    {
                        output.push_back(static_cast<std::uint8_t>(value >> shift));
                    }
                }
            }

            secret_bytes buffer_;
        };

        class cbor_reader final
        {
        public:
            explicit cbor_reader(std::span<std::uint8_t const> const bytes) : bytes_(bytes)
            {
            }

            [[nodiscard]] std::uint64_t unsigned_value()
            {
                return type_value(0U);
            }

            [[nodiscard]] std::uint64_t array()
            {
                return type_value(4U);
            }

            [[nodiscard]] std::span<std::uint8_t const> bytes(std::size_t const maximum)
            {
                std::uint64_t const length = type_value(2U);
                if (length > maximum || length > bytes_.size() - offset_)
                {
                    fail(transport_error::invalid);
                }
                auto const value = bytes_.subspan(
                    offset_,
                    static_cast<std::size_t>(length));
                offset_ += static_cast<std::size_t>(length);
                return value;
            }

            [[nodiscard]] std::span<std::uint8_t const> text(std::size_t const maximum)
            {
                std::uint64_t const length = type_value(3U);
                if (length > maximum || length > bytes_.size() - offset_)
                {
                    fail(transport_error::invalid);
                }
                auto const value = bytes_.subspan(
                    offset_,
                    static_cast<std::size_t>(length));
                offset_ += static_cast<std::size_t>(length);
                return value;
            }

            [[nodiscard]] bool next_is_null() const noexcept
            {
                return offset_ < bytes_.size() && bytes_[offset_] == 0xf6U;
            }

            void null_value()
            {
                if (!next_is_null())
                {
                    fail(transport_error::invalid);
                }
                ++offset_;
            }

            void finish() const
            {
                if (offset_ != bytes_.size())
                {
                    fail(transport_error::invalid);
                }
            }

        private:
            [[nodiscard]] std::uint8_t read_byte()
            {
                if (offset_ >= bytes_.size())
                {
                    fail(transport_error::invalid);
                }
                return bytes_[offset_++];
            }

            [[nodiscard]] std::uint64_t read_integer(std::uint8_t const bytes)
            {
                if (bytes > 8U || bytes > bytes_.size() - offset_)
                {
                    fail(transport_error::invalid);
                }
                std::uint64_t value = 0U;
                for (std::uint8_t index = 0U; index < bytes; ++index)
                {
                    value = (value << 8U) | read_byte();
                }
                return value;
            }

            [[nodiscard]] std::uint64_t type_value(std::uint8_t const expected_major)
            {
                std::uint8_t const initial = read_byte();
                if ((initial >> 5U) != expected_major)
                {
                    fail(transport_error::invalid);
                }
                std::uint8_t const additional = initial & 0x1fU;
                if (additional < 24U)
                {
                    return additional;
                }
                std::uint8_t const length = additional == 24U ? 1U :
                    additional == 25U ? 2U :
                    additional == 26U ? 4U :
                    additional == 27U ? 8U : 0U;
                if (length == 0U)
                {
                    fail(transport_error::invalid);
                }
                std::uint64_t const value = read_integer(length);
                std::uint64_t const minimum = length == 1U ? 24U :
                    length == 2U ? 256U :
                    length == 4U ? 65'536U : 4'294'967'296ULL;
                if (value < minimum)
                {
                    fail(transport_error::invalid);
                }
                return value;
            }

            std::span<std::uint8_t const> bytes_;
            std::size_t offset_{0U};
        };

        secret_bytes utf8(std::wstring_view const value)
        {
            if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                fail(transport_error::invalid);
            }
            int const length = WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (length < 0 || (!value.empty() && length == 0))
            {
                fail(transport_error::invalid);
            }
            secret_bytes bytes{static_cast<std::size_t>(length)};
            if (length != 0 && WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    value.data(),
                    static_cast<int>(value.size()),
                    reinterpret_cast<char*>(bytes.data()),
                    length,
                    nullptr,
                    nullptr) != length)
            {
                fail(transport_error::invalid);
            }
            return bytes;
        }

        std::wstring wide(std::span<std::uint8_t const> const value)
        {
            if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
            {
                fail(transport_error::invalid);
            }
            int const length = MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                reinterpret_cast<char const*>(value.data()),
                static_cast<int>(value.size()),
                nullptr,
                0);
            if (length < 0 || (!value.empty() && length == 0))
            {
                fail(transport_error::invalid);
            }
            std::wstring result(static_cast<std::size_t>(length), L'\0');
            if (length != 0 && MultiByteToWideChar(
                    CP_UTF8,
                    MB_ERR_INVALID_CHARS,
                    reinterpret_cast<char const*>(value.data()),
                    static_cast<int>(value.size()),
                    result.data(),
                    length) != length)
            {
                fail(transport_error::invalid);
            }
            return result;
        }

        struct endpoint_descriptor
        {
            std::wstring pipe_name;
            DWORD process_id{};
            std::uint64_t creation_time{};
            std::wstring package_full_name;
        };

        bool nonzero(std::span<std::uint8_t const> const value)
        {
            return std::ranges::any_of(value, [](std::uint8_t const byte) {
                return byte != 0U;
            });
        }

        endpoint_descriptor decode_descriptor(
            std::span<std::uint8_t const> const bytes,
            std::wstring const& expected_package)
        {
            cbor_reader reader{bytes};
            if (reader.array() != 8U || reader.unsigned_value() != 1U)
            {
                fail(transport_error::invalid);
            }
            auto const pipe_name = wide(reader.text(512U));
            std::uint64_t const process_id = reader.unsigned_value();
            std::uint64_t const creation_time = reader.unsigned_value();
            auto const package_full_name = wide(reader.text(256U));
            std::uint64_t const minimum_major = reader.unsigned_value();
            std::uint64_t const maximum_major = reader.unsigned_value();
            auto const startup_nonce = reader.bytes(32U);
            reader.finish();
            if (process_id == 0U || process_id > MAXDWORD || creation_time == 0U ||
                package_full_name != expected_package || minimum_major == 0U ||
                minimum_major > protocol_major || maximum_major < protocol_major ||
                startup_nonce.size() != 32U || !nonzero(startup_nonce) ||
                !pipe_name.starts_with(pipe_prefix))
            {
                fail(transport_error::invalid);
            }
            std::wstring_view const suffix =
                std::wstring_view{pipe_name}.substr(pipe_prefix.size());
            if (suffix.size() != 32U ||
                !std::ranges::all_of(suffix, [](wchar_t const value) {
                    return (value >= L'0' && value <= L'9') ||
                           (value >= L'a' && value <= L'f');
                }) || std::ranges::all_of(suffix, [](wchar_t const value) {
                    return value == L'0';
                }))
            {
                fail(transport_error::invalid);
            }
            return {
                pipe_name,
                static_cast<DWORD>(process_id),
                creation_time,
                package_full_name,
            };
        }

        void verify_not_redirected_directory(std::filesystem::path const& path)
        {
            unique_handle directory{CreateFileW(
                path.c_str(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr)};
            if (!directory)
            {
                fail(transport_error::unavailable);
            }
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (!GetFileInformationByHandleEx(
                    directory.get(),
                    FileAttributeTagInfo,
                    &attributes,
                    sizeof(attributes)) ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U)
            {
                fail(transport_error::invalid);
            }
        }

        void verify_ancestor_chain(std::filesystem::path const& path)
        {
            std::vector<std::filesystem::path> ancestors;
            auto current = path;
            while (!current.empty())
            {
                ancestors.push_back(current);
                auto const parent = current.parent_path();
                if (parent == current)
                {
                    break;
                }
                current = parent;
            }
            for (auto iterator = ancestors.rbegin(); iterator != ancestors.rend(); ++iterator)
            {
                verify_not_redirected_directory(*iterator);
            }
        }

        bool same_file(HANDLE const left, HANDLE const right)
        {
            BY_HANDLE_FILE_INFORMATION first{};
            BY_HANDLE_FILE_INFORMATION second{};
            return GetFileInformationByHandle(left, &first) &&
                   GetFileInformationByHandle(right, &second) &&
                   first.dwVolumeSerialNumber == second.dwVolumeSerialNumber &&
                   first.nFileIndexHigh == second.nFileIndexHigh &&
                   first.nFileIndexLow == second.nFileIndexLow;
        }

        void verify_file_owner(HANDLE const file, std::wstring const& expected_user_sid)
        {
            PSID owner = nullptr;
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            DWORD const result = GetSecurityInfo(
                file,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &owner,
                nullptr,
                nullptr,
                nullptr,
                &descriptor);
            local_memory const memory{descriptor};
            if (result != ERROR_SUCCESS || sid_string(owner) != expected_user_sid)
            {
                fail(transport_error::invalid);
            }
        }

        endpoint_descriptor load_descriptor(
            std::filesystem::path const& path,
            std::wstring const& expected_package,
            std::wstring const& expected_user_sid)
        {
            verify_ancestor_chain(path.parent_path());
            unique_handle file{CreateFileW(
                path.c_str(),
                GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr)};
            if (!file)
            {
                fail(transport_error::unavailable);
            }
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (!GetFileInformationByHandleEx(
                    file.get(),
                    FileAttributeTagInfo,
                    &attributes,
                    sizeof(attributes)) ||
                (attributes.FileAttributes &
                    (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U)
            {
                fail(transport_error::invalid);
            }
            verify_file_owner(file.get(), expected_user_sid);
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 ||
                size.QuadPart > static_cast<LONGLONG>(maximum_descriptor_bytes))
            {
                fail(transport_error::invalid);
            }
            secret_bytes bytes{static_cast<std::size_t>(size.QuadPart)};
            DWORD read = 0U;
            if (!ReadFile(
                    file.get(),
                    bytes.data(),
                    static_cast<DWORD>(bytes.size()),
                    &read,
                    nullptr) || read != bytes.size())
            {
                fail(transport_error::invalid);
            }
            unique_handle current{CreateFileW(
                path.c_str(),
                GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr)};
            if (!current || !same_file(file.get(), current.get()))
            {
                fail(transport_error::invalid);
            }
            verify_ancestor_chain(path.parent_path());
            return decode_descriptor(bytes.value(), expected_package);
        }

        std::filesystem::path local_app_data_path()
        {
            PWSTR raw = nullptr;
            if (FAILED(SHGetKnownFolderPath(
                    FOLDERID_LocalAppData,
                    KF_FLAG_DEFAULT,
                    nullptr,
                    &raw)))
            {
                fail(transport_error::invalid);
            }
            struct task_memory final
            {
                PWSTR value;
                ~task_memory() noexcept
                {
                    CoTaskMemFree(value);
                }
            } const memory{raw};
            return std::filesystem::path{raw};
        }

        struct packaged_context
        {
            process_observation current;
            std::filesystem::path agent_path;
            std::filesystem::path endpoint_path;
            std::array<std::uint8_t, 32U> desktop_build_id{};
        };

        packaged_context make_packaged_context()
        {
            auto [process, current] = observe_process(GetCurrentProcessId());
            std::wstring const expected_application =
                current.package_family_name + L"!Desktop";
            if (current.elevated || current.app_container ||
                current.integrity_rid != medium_integrity_rid ||
                current.application_user_model_id != expected_application ||
                !equal_path(
                    current.image_path.filename(),
                    std::filesystem::path{desktop_executable}))
            {
                fail(transport_error::invalid);
            }
            auto const install_root = current.image_path.parent_path();
            auto const agent_path = install_root / agent_executable;
            auto const local_state = local_app_data_path() /
                L"Packages" /
                current.package_family_name /
                L"LocalState";
            auto const build_id = sha256_file(install_root / desktop_executable);
            return {
                std::move(current),
                agent_path,
                local_state / endpoint_relative_path,
                build_id,
            };
        }

        void authorize_agent(
            process_observation const& current,
            process_observation const& agent,
            std::filesystem::path const& expected_agent_path,
            endpoint_descriptor const& endpoint)
        {
            std::wstring const expected_application =
                current.package_family_name + L"!VaultAgent";
            if (agent.process_id != endpoint.process_id ||
                agent.creation_time != endpoint.creation_time ||
                agent.user_sid != current.user_sid ||
                agent.logon_sid != current.logon_sid ||
                agent.session_id != current.session_id ||
                agent.elevated || agent.app_container ||
                agent.integrity_rid > medium_integrity_rid ||
                agent.package_full_name != current.package_full_name ||
                agent.package_full_name != endpoint.package_full_name ||
                agent.package_family_name != current.package_family_name ||
                agent.application_user_model_id != expected_application ||
                !equal_path(agent.image_path, expected_agent_path))
            {
                fail(transport_error::invalid);
            }
        }

        struct pipe_connection
        {
            unique_handle pipe;
            unique_handle server_process;
            std::array<std::uint8_t, 16U> connection_id{};
            std::uint64_t unlock_epoch{};
            std::uint8_t agent_state{};
        };

        pipe_connection connect_pipe(
            packaged_context const& context,
            endpoint_descriptor const& endpoint)
        {
            unique_handle pipe;
            for (unsigned int attempt = 0U; attempt < 2U; ++attempt)
            {
                pipe.reset(CreateFileW(
                    endpoint.pipe_name.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0U,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED |
                        SECURITY_SQOS_PRESENT |
                        SECURITY_IDENTIFICATION |
                        SECURITY_EFFECTIVE_ONLY,
                    nullptr));
                if (pipe)
                {
                    break;
                }
                if (attempt != 0U || GetLastError() != ERROR_PIPE_BUSY ||
                    !WaitNamedPipeW(endpoint.pipe_name.c_str(), 2'000U))
                {
                    fail(transport_error::unavailable);
                }
            }
            ULONG server_process_id = 0U;
            if (!GetNamedPipeServerProcessId(pipe.get(), &server_process_id) ||
                server_process_id == 0U)
            {
                fail(transport_error::invalid);
            }
            auto [server_process, observation] = observe_process(server_process_id);
            authorize_agent(context.current, observation, context.agent_path, endpoint);
            return {std::move(pipe), std::move(server_process), {}, 0U, 0U};
        }

        DWORD remaining_milliseconds(std::uint64_t const deadline)
        {
            std::uint64_t const now = GetTickCount64();
            if (now >= deadline)
            {
                fail(transport_error::unavailable);
            }
            std::uint64_t const remaining = deadline - now;
            return remaining > MAXDWORD ? MAXDWORD : static_cast<DWORD>(remaining);
        }

        void wait_overlapped(
            HANDLE const pipe,
            HANDLE const peer,
            OVERLAPPED& overlapped,
            std::uint64_t const deadline)
        {
            std::array<HANDLE, 2U> const handles{overlapped.hEvent, peer};
            DWORD const result = WaitForMultipleObjects(
                static_cast<DWORD>(handles.size()),
                handles.data(),
                FALSE,
                remaining_milliseconds(deadline));
            if (result == WAIT_OBJECT_0)
            {
                return;
            }
            CancelIoEx(pipe, &overlapped);
            DWORD ignored = 0U;
            GetOverlappedResult(pipe, &overlapped, &ignored, TRUE);
            fail(transport_error::unavailable);
        }

        void read_exact(
            HANDLE const pipe,
            HANDLE const peer,
            std::span<std::uint8_t> destination,
            std::uint64_t const deadline)
        {
            while (!destination.empty())
            {
                unique_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
                if (!event)
                {
                    fail(transport_error::invalid);
                }
                OVERLAPPED overlapped{};
                overlapped.hEvent = event.get();
                DWORD transferred = 0U;
                DWORD const request = static_cast<DWORD>(std::min<std::size_t>(
                    destination.size(),
                    MAXDWORD));
                if (!ReadFile(
                        pipe,
                        destination.data(),
                        request,
                        &transferred,
                        &overlapped))
                {
                    if (GetLastError() != ERROR_IO_PENDING)
                    {
                        fail(transport_error::unavailable);
                    }
                    wait_overlapped(pipe, peer, overlapped, deadline);
                    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
                    {
                        fail(GetLastError() == ERROR_OPERATION_ABORTED ?
                            transport_error::cancelled : transport_error::unavailable);
                    }
                }
                if (transferred == 0U || transferred > destination.size())
                {
                    fail(transport_error::unavailable);
                }
                destination = destination.subspan(transferred);
            }
            if (WaitForSingleObject(peer, 0U) != WAIT_TIMEOUT)
            {
                fail(transport_error::unavailable);
            }
        }

        void write_all(
            HANDLE const pipe,
            HANDLE const peer,
            std::span<std::uint8_t const> source,
            std::uint64_t const deadline)
        {
            if (WaitForSingleObject(peer, 0U) != WAIT_TIMEOUT)
            {
                fail(transport_error::unavailable);
            }
            while (!source.empty())
            {
                unique_handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
                if (!event)
                {
                    fail(transport_error::invalid);
                }
                OVERLAPPED overlapped{};
                overlapped.hEvent = event.get();
                DWORD transferred = 0U;
                DWORD const request = static_cast<DWORD>(std::min<std::size_t>(
                    source.size(),
                    MAXDWORD));
                if (!WriteFile(
                        pipe,
                        source.data(),
                        request,
                        &transferred,
                        &overlapped))
                {
                    if (GetLastError() != ERROR_IO_PENDING)
                    {
                        fail(transport_error::unavailable);
                    }
                    wait_overlapped(pipe, peer, overlapped, deadline);
                    if (!GetOverlappedResult(pipe, &overlapped, &transferred, FALSE))
                    {
                        fail(GetLastError() == ERROR_OPERATION_ABORTED ?
                            transport_error::cancelled : transport_error::unavailable);
                    }
                }
                if (transferred == 0U || transferred > source.size())
                {
                    fail(transport_error::unavailable);
                }
                source = source.subspan(transferred);
            }
            if (WaitForSingleObject(peer, 0U) != WAIT_TIMEOUT)
            {
                fail(transport_error::unavailable);
            }
        }

        void write_u16(
            std::span<std::uint8_t> const bytes,
            std::size_t const offset,
            std::uint16_t const value)
        {
            bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
            bytes[offset + 1U] = static_cast<std::uint8_t>(value);
        }

        void write_u32(
            std::span<std::uint8_t> const bytes,
            std::size_t const offset,
            std::uint32_t const value)
        {
            for (int shift = 24; shift >= 0; shift -= 8)
            {
                bytes[offset + static_cast<std::size_t>((24 - shift) / 8)] =
                    static_cast<std::uint8_t>(value >> shift);
            }
        }

        void write_u64(
            std::span<std::uint8_t> const bytes,
            std::size_t const offset,
            std::uint64_t const value)
        {
            for (int shift = 56; shift >= 0; shift -= 8)
            {
                bytes[offset + static_cast<std::size_t>((56 - shift) / 8)] =
                    static_cast<std::uint8_t>(value >> shift);
            }
        }

        std::uint16_t read_u16(std::span<std::uint8_t const> const bytes, std::size_t const offset)
        {
            return static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                bytes[offset + 1U]);
        }

        std::uint32_t read_u32(std::span<std::uint8_t const> const bytes, std::size_t const offset)
        {
            std::uint32_t value = 0U;
            for (std::size_t index = 0U; index < 4U; ++index)
            {
                value = (value << 8U) | bytes[offset + index];
            }
            return value;
        }

        std::uint64_t read_u64(std::span<std::uint8_t const> const bytes, std::size_t const offset)
        {
            std::uint64_t value = 0U;
            for (std::size_t index = 0U; index < 8U; ++index)
            {
                value = (value << 8U) | bytes[offset + index];
            }
            return value;
        }

        enum class message_kind : std::uint8_t
        {
            client_hello = 1U,
            server_hello = 2U,
            request = 3U,
            response = 4U,
            cancel = 5U,
            event = 6U,
        };

        struct frame
        {
            message_kind kind{};
            std::uint16_t major{};
            std::uint16_t minor{};
            std::array<std::uint8_t, 16U> connection_id{};
            std::uint64_t request_id{};
            secret_bytes payload;
        };

        void write_frame(
            pipe_connection const& connection,
            message_kind const kind,
            std::uint16_t const major,
            std::uint16_t const minor,
            std::span<std::uint8_t const> const connection_id,
            std::uint64_t const request_id,
            std::span<std::uint8_t const> const payload,
            std::uint32_t const timeout_ms)
        {
            if (payload.size() > maximum_payload_bytes || connection_id.size() != 16U)
            {
                fail(transport_error::invalid);
            }
            std::array<std::uint8_t, frame_header_bytes> header{};
            header[0] = L'L';
            header[1] = L'B';
            header[2] = L'I';
            header[3] = L'P';
            header[4] = 1U;
            header[5] = static_cast<std::uint8_t>(kind);
            write_u16(header, 8U, major);
            write_u16(header, 10U, minor);
            write_u32(header, 12U, static_cast<std::uint32_t>(payload.size()));
            std::ranges::copy(connection_id, header.begin() + 16);
            write_u64(header, 32U, request_id);
            std::uint64_t const deadline = GetTickCount64() + timeout_ms;
            write_all(
                connection.pipe.get(),
                connection.server_process.get(),
                header,
                deadline);
            write_all(
                connection.pipe.get(),
                connection.server_process.get(),
                payload,
                deadline);
        }

        frame read_frame(pipe_connection const& connection, std::uint32_t const timeout_ms)
        {
            std::array<std::uint8_t, frame_header_bytes> header{};
            std::uint64_t const deadline = GetTickCount64() + timeout_ms;
            read_exact(
                connection.pipe.get(),
                connection.server_process.get(),
                header,
                deadline);
            if (header[0] != L'L' || header[1] != L'B' ||
                header[2] != L'I' || header[3] != L'P' ||
                header[4] != 1U || header[6] != 0U || header[7] != 0U ||
                header[5] < 1U || header[5] > 6U)
            {
                fail(transport_error::invalid);
            }
            std::uint32_t const payload_length = read_u32(header, 12U);
            if (payload_length > maximum_payload_bytes)
            {
                fail(transport_error::invalid);
            }
            frame result{
                static_cast<message_kind>(header[5]),
                read_u16(header, 8U),
                read_u16(header, 10U),
                {},
                read_u64(header, 32U),
                secret_bytes{payload_length},
            };
            std::ranges::copy(header.begin() + 16, header.begin() + 32,
                result.connection_id.begin());
            read_exact(
                connection.pipe.get(),
                connection.server_process.get(),
                result.payload.value(),
                deadline);
            return result;
        }

        secret_bytes client_hello_payload(packaged_context const& context)
        {
            std::array<std::uint8_t, 32U> nonce{};
            random_bytes(nonce);
            cbor_writer writer;
            writer.array(8U);
            writer.bytes(nonce);
            writer.unsigned_value(protocol_major);
            writer.unsigned_value(protocol_major);
            writer.unsigned_value(protocol_minor);
            writer.unsigned_value(protocol_minor);
            writer.unsigned_value(1U);
            writer.bytes(context.desktop_build_id);
            writer.array(1U);
            writer.unsigned_value(windows_hello_feature);
            return writer.take();
        }

        void decode_server_hello(pipe_connection& connection, frame const& response)
        {
            if (response.kind != message_kind::server_hello ||
                response.major != protocol_major || response.minor != protocol_minor ||
                response.request_id != 0U || !nonzero(response.connection_id))
            {
                fail(transport_error::invalid);
            }
            cbor_reader reader{response.payload.value()};
            if (reader.array() != 9U)
            {
                fail(transport_error::invalid);
            }
            auto const server_nonce = reader.bytes(32U);
            std::uint64_t const major = reader.unsigned_value();
            std::uint64_t const minor = reader.unsigned_value();
            std::uint64_t const role = reader.unsigned_value();
            if (reader.array() != 1U ||
                reader.unsigned_value() != windows_hello_feature)
            {
                fail(transport_error::invalid);
            }
            std::uint64_t const maximum_payload = reader.unsigned_value();
            std::uint64_t const maximum_in_flight = reader.unsigned_value();
            std::uint64_t const state = reader.unsigned_value();
            std::uint64_t const epoch = reader.unsigned_value();
            reader.finish();
            if (server_nonce.size() != 32U || !nonzero(server_nonce) ||
                major != protocol_major || minor != protocol_minor || role != 1U ||
                maximum_payload < 21U || maximum_payload > maximum_payload_bytes ||
                maximum_in_flight == 0U || maximum_in_flight > 4U ||
                state < 1U || state > 7U)
            {
                fail(transport_error::invalid);
            }
            connection.connection_id = response.connection_id;
            connection.agent_state = static_cast<std::uint8_t>(state);
            connection.unlock_epoch = epoch;
        }

        void negotiate(packaged_context const& context, pipe_connection& connection)
        {
            auto hello = client_hello_payload(context);
            std::array<std::uint8_t, 16U> const empty_connection{};
            write_frame(
                connection,
                message_kind::client_hello,
                0U,
                0U,
                empty_connection,
                0U,
                hello.value(),
                2'000U);
            auto const response = read_frame(connection, 2'000U);
            decode_server_hello(connection, response);
        }

        void activate_agent(std::wstring const& package_family_name)
        {
            HRESULT const initialization = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            bool const uninitialize = SUCCEEDED(initialization);
            if (FAILED(initialization) && initialization != RPC_E_CHANGED_MODE)
            {
                fail(transport_error::unavailable);
            }
            IApplicationActivationManager* manager = nullptr;
            HRESULT const creation = CoCreateInstance(
                CLSID_ApplicationActivationManager,
                nullptr,
                CLSCTX_LOCAL_SERVER,
                IID_PPV_ARGS(&manager));
            if (FAILED(creation) || manager == nullptr)
            {
                if (uninitialize)
                {
                    CoUninitialize();
                }
                fail(transport_error::unavailable);
            }
            DWORD process_id = 0U;
            std::wstring const application = package_family_name + L"!VaultAgent";
            HRESULT const activation = manager->ActivateApplication(
                application.c_str(),
                nullptr,
                AO_NONE,
                &process_id);
            manager->Release();
            if (uninitialize)
            {
                CoUninitialize();
            }
            if (FAILED(activation) || process_id == 0U)
            {
                fail(transport_error::unavailable);
            }
        }

        template<typename RegisterPipe, typename ClearPipe>
        pipe_connection connect_agent(
            packaged_context const& context,
            std::atomic_bool const& closed,
            RegisterPipe&& register_pipe,
            ClearPipe&& clear_pipe)
        {
            bool activated = false;
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            for (;;)
            {
                if (closed.load(std::memory_order_acquire))
                {
                    fail(transport_error::cancelled);
                }
                try
                {
                    auto endpoint = load_descriptor(
                        context.endpoint_path,
                        context.current.package_full_name,
                        context.current.user_sid);
                    auto connection = connect_pipe(context, endpoint);
                    register_pipe(connection.pipe.get());
                    try
                    {
                        negotiate(context, connection);
                    }
                    catch (...)
                    {
                        clear_pipe(connection.pipe.get());
                        throw;
                    }
                    return connection;
                }
                catch (transport_exception const& error)
                {
                    if (error.error() == transport_error::cancelled ||
                        error.error() == transport_error::invalid)
                    {
                        throw;
                    }
                }
                if (!activated)
                {
                    activate_agent(context.current.package_family_name);
                    activated = true;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    fail(transport_error::unavailable);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{50});
            }
        }

        enum class operation : std::uint16_t
        {
            status = 1U,
            create_vault = 2U,
            unlock_master_password = 3U,
            lock = 4U,
            list_account_summaries = 5U,
            add_account = 7U,
            enroll_windows_hello = 10U,
            remove_windows_hello = 11U,
            unlock_windows_hello = 12U,
        };

        bool requires_idempotency(operation const value)
        {
            return value == operation::create_vault ||
                   value == operation::add_account ||
                   value == operation::enroll_windows_hello ||
                   value == operation::remove_windows_hello;
        }

        struct decoded_response
        {
            std::uint8_t error{};
            std::uint8_t retry{};
            secret_bytes body;
        };

        decoded_response decode_response(frame const& response)
        {
            cbor_reader reader{response.payload.value()};
            if (reader.array() != 4U)
            {
                fail(transport_error::invalid);
            }
            std::uint64_t const error = reader.unsigned_value();
            std::uint64_t const retry = reader.unsigned_value();
            auto const correlation = reader.bytes(16U);
            auto const body = reader.bytes(maximum_payload_bytes - 96U);
            reader.finish();
            if (error > 11U || retry == 0U || retry > 4U ||
                correlation.size() != 16U || !nonzero(correlation) ||
                (error != 0U && !body.empty()) ||
                (error == 0U && retry != 1U))
            {
                fail(transport_error::invalid);
            }
            return {
                static_cast<std::uint8_t>(error),
                static_cast<std::uint8_t>(retry),
                secret_bytes{std::vector<std::uint8_t>{body.begin(), body.end()}},
            };
        }

        secret_bytes request_envelope(
            operation const requested_operation,
            std::uint64_t const unlock_epoch,
            std::uint32_t const timeout_ms,
            std::span<std::uint8_t const> const body)
        {
            cbor_writer writer;
            writer.array(5U);
            writer.unsigned_value(static_cast<std::uint16_t>(requested_operation));
            writer.unsigned_value(unlock_epoch);
            writer.unsigned_value(timeout_ms);
            if (requires_idempotency(requested_operation))
            {
                std::array<std::uint8_t, 16U> key{};
                random_bytes(key);
                writer.bytes(key);
            }
            else
            {
                writer.null_value();
            }
            writer.bytes(body);
            return writer.take();
        }

        ClientResult decode_status_body(std::span<std::uint8_t const> const body)
        {
            cbor_reader reader{body};
            if (reader.array() != 2U)
            {
                fail(transport_error::invalid);
            }
            std::uint64_t const state = reader.unsigned_value();
            static_cast<void>(reader.unsigned_value());
            reader.finish();
            switch (state)
            {
            case 2U:
                return {ClientError::None, VaultStatus::FirstRun};
            case 3U:
                return {ClientError::None, VaultStatus::Locked};
            case 4U:
            case 6U:
                return {ClientError::Busy, VaultStatus::Locked};
            case 5U:
                return {ClientError::None, VaultStatus::Unlocked};
            default:
                fail(transport_error::unavailable);
            }
        }

        ClientError map_public_error(
            std::uint8_t const error,
            operation const requested_operation)
        {
            switch (error)
            {
            case 0U:
                return ClientError::None;
            case 3U:
                return ClientError::Locked;
            case 6U:
                return ClientError::Busy;
            case 7U:
            case 8U:
                return ClientError::Cancelled;
            case 9U:
            case 10U:
                return ClientError::AgentUnavailable;
            case 11U:
                if (requested_operation == operation::unlock_master_password)
                {
                    return ClientError::InvalidCredentials;
                }
                if (requested_operation == operation::unlock_windows_hello ||
                    requested_operation == operation::enroll_windows_hello ||
                    requested_operation == operation::remove_windows_hello)
                {
                    return ClientError::WindowsHelloUnavailable;
                }
                return ClientError::Unexpected;
            default:
                return ClientError::Unexpected;
            }
        }

        secret_bytes empty_body()
        {
            cbor_writer writer;
            writer.array(0U);
            return writer.take();
        }

        secret_bytes password_body(SecretText const& password)
        {
            auto password_bytes = utf8(password.value());
            cbor_writer writer;
            writer.array(1U);
            writer.text(password_bytes.value());
            return writer.take();
        }

        secret_bytes parent_window_body(std::uintptr_t const parent_window)
        {
            if (parent_window == 0U)
            {
                fail(transport_error::invalid);
            }
            cbor_writer writer;
            writer.array(1U);
            writer.unsigned_value(parent_window);
            return writer.take();
        }

        secret_bytes account_body(AccountDraft const& account)
        {
            auto service = utf8(account.service_name);
            auto origin = utf8(account.origin);
            auto username = utf8(account.username);
            auto password = utf8(account.password.value());
            cbor_writer writer;
            writer.array(4U);
            writer.text(service.value());
            writer.text(origin.value());
            writer.text(username.value());
            writer.text(password.value());
            return writer.take();
        }

        secret_bytes list_body(std::uint32_t const offset)
        {
            cbor_writer writer;
            writer.array(2U);
            writer.unsigned_value(offset);
            writer.unsigned_value(100U);
            return writer.take();
        }

        struct account_page
        {
            std::optional<std::uint32_t> next_offset;
            std::vector<AccountSummary> accounts;
        };

        std::wstring record_identifier(std::span<std::uint8_t const> const bytes)
        {
            constexpr wchar_t digits[] = L"0123456789abcdef";
            if (bytes.size() != 16U)
            {
                fail(transport_error::invalid);
            }
            std::wstring result;
            result.reserve(32U);
            for (std::uint8_t const byte : bytes)
            {
                result.push_back(digits[byte >> 4U]);
                result.push_back(digits[byte & 0x0fU]);
            }
            return result;
        }

        account_page decode_account_page(std::span<std::uint8_t const> const body)
        {
            cbor_reader reader{body};
            if (reader.array() != 2U)
            {
                fail(transport_error::invalid);
            }
            std::optional<std::uint32_t> next_offset;
            if (reader.next_is_null())
            {
                reader.null_value();
            }
            else
            {
                std::uint64_t const value = reader.unsigned_value();
                if (value > MAXDWORD)
                {
                    fail(transport_error::invalid);
                }
                next_offset = static_cast<std::uint32_t>(value);
            }
            std::uint64_t const count = reader.array();
            if (count > 100U)
            {
                fail(transport_error::invalid);
            }
            std::vector<AccountSummary> accounts;
            accounts.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t index = 0U; index < count; ++index)
            {
                if (reader.array() != 7U)
                {
                    fail(transport_error::invalid);
                }
                auto const id = reader.bytes(16U);
                static_cast<void>(reader.unsigned_value());
                static_cast<void>(reader.unsigned_value());
                static_cast<void>(reader.unsigned_value());
                auto const service = wide(reader.text(256U));
                auto const origin = wide(reader.text(2'048U));
                auto const username = wide(reader.text(1'024U));
                accounts.push_back({
                    record_identifier(id),
                    service,
                    origin,
                    username,
                });
            }
            reader.finish();
            return {next_offset, std::move(accounts)};
        }

        class packaged_desktop_client final : public IDesktopClient
        {
        public:
            explicit packaged_desktop_client(packaged_context context) :
                context_(std::move(context))
            {
            }

            [[nodiscard]] ClientResult GetStatus() override
            {
                return execute_status(operation::status, empty_body(), 5'000U);
            }

            [[nodiscard]] ClientResult CreateVault(
                SecretText const& master_password) override
            {
                try
                {
                    return execute_status(
                        operation::create_vault,
                        password_body_after_latch(master_password),
                        30'000U);
                }
                catch (transport_exception const& error)
                {
                    return {
                        map_transport_error(error.error()),
                        VaultStatus::Locked,
                    };
                }
            }

            [[nodiscard]] ClientResult Unlock(
                SecretText const& master_password) override
            {
                try
                {
                    return execute_status(
                        operation::unlock_master_password,
                        password_body_after_latch(master_password),
                        30'000U);
                }
                catch (transport_exception const& error)
                {
                    return {
                        map_transport_error(error.error()),
                        VaultStatus::Locked,
                    };
                }
            }

            [[nodiscard]] ClientResult UnlockWindowsHello(
                std::uintptr_t const parent_window) override
            {
                if (parent_window == 0U)
                {
                    return {
                        ClientError::WindowsHelloUnavailable,
                        VaultStatus::Locked,
                    };
                }
                return execute_status(
                    operation::unlock_windows_hello,
                    parent_window_body(parent_window),
                    120'000U);
            }

            [[nodiscard]] ClientResult EnrollWindowsHello(
                std::uintptr_t const parent_window) override
            {
                if (parent_window == 0U)
                {
                    return {
                        ClientError::WindowsHelloUnavailable,
                        VaultStatus::Unlocked,
                    };
                }
                return execute_empty(
                    operation::enroll_windows_hello,
                    parent_window_body(parent_window),
                    120'000U,
                    VaultStatus::Unlocked);
            }

            [[nodiscard]] ClientResult RemoveWindowsHello() override
            {
                return execute_empty(
                    operation::remove_windows_hello,
                    empty_body(),
                    120'000U,
                    VaultStatus::Unlocked);
            }

            [[nodiscard]] ClientResult Lock() override
            {
                return execute_empty(
                    operation::lock,
                    empty_body(),
                    30'000U,
                    VaultStatus::Locked);
            }

            [[nodiscard]] AccountListResult ListAccounts(
                std::uint32_t const offset) override
            {
                std::scoped_lock request_lock{request_gate_};
                if (closed_.load(std::memory_order_acquire))
                {
                    return {ClientError::Cancelled, {}};
                }
                try
                {
                    auto body = list_body(offset);
                    auto response = send_locked(
                        operation::list_account_summaries,
                        body.value(),
                        5'000U);
                    ClientError const error = map_public_error(
                        response.error,
                        operation::list_account_summaries);
                    if (error != ClientError::None)
                    {
                        return {error, {}};
                    }
                    auto page = decode_account_page(response.body.value());
                    if (page.next_offset.has_value())
                    {
                        if (
                            page.accounts.empty() ||
                            page.accounts.size() > MAXDWORD - offset ||
                            *page.next_offset != offset + page.accounts.size())
                        {
                            fail(transport_error::invalid);
                        }
                    }
                    return {
                        ClientError::None,
                        std::move(page.accounts),
                        page.next_offset,
                    };
                }
                catch (transport_exception const& error)
                {
                    return {map_transport_error(error.error()), {}};
                }
            }

            [[nodiscard]] ClientResult SaveAccount(AccountDraft const& account) override
            {
                std::scoped_lock request_lock{request_gate_};
                if (closed_.load(std::memory_order_acquire))
                {
                    return {ClientError::Cancelled, VaultStatus::Locked};
                }
                try
                {
                    auto body = account_body(account);
                    auto response = send_locked(operation::add_account, body.value(), 5'000U);
                    ClientError const error = map_public_error(
                        response.error,
                        operation::add_account);
                    if (error != ClientError::None)
                    {
                        return {error, VaultStatus::Unlocked};
                    }
                    cbor_reader reader{response.body.value()};
                    if (reader.array() != 1U || reader.bytes(16U).size() != 16U)
                    {
                        fail(transport_error::invalid);
                    }
                    reader.finish();
                    return {ClientError::None, VaultStatus::Unlocked};
                }
                catch (transport_exception const& error)
                {
                    return {
                        map_transport_error(error.error()),
                        VaultStatus::Locked,
                    };
                }
            }

            void Close() noexcept override
            {
                closed_.store(true, std::memory_order_release);
                std::scoped_lock active_lock{active_gate_};
                if (active_pipe_ != INVALID_HANDLE_VALUE)
                {
                    CancelIoEx(active_pipe_, nullptr);
                }
            }

        private:
            class active_request final
            {
            public:
                active_request(packaged_desktop_client& owner, HANDLE const pipe) :
                    owner_(owner), pipe_(pipe)
                {
                    std::scoped_lock active_lock{owner_.active_gate_};
                    if (owner_.closed_.load(std::memory_order_acquire))
                    {
                        if (owner_.active_pipe_ == pipe_)
                        {
                            owner_.active_pipe_ = INVALID_HANDLE_VALUE;
                        }
                        fail(transport_error::cancelled);
                    }
                    if (owner_.active_pipe_ != pipe_)
                    {
                        fail(transport_error::invalid);
                    }
                }

                ~active_request() noexcept
                {
                    std::scoped_lock active_lock{owner_.active_gate_};
                    if (owner_.active_pipe_ == pipe_)
                    {
                        owner_.active_pipe_ = INVALID_HANDLE_VALUE;
                    }
                }

                active_request(active_request const&) = delete;
                active_request& operator=(active_request const&) = delete;

            private:
                packaged_desktop_client& owner_;
                HANDLE pipe_;
            };

            [[nodiscard]] secret_bytes password_body_after_latch(
                SecretText const& password)
            {
                if (closed_.load(std::memory_order_acquire))
                {
                    fail(transport_error::cancelled);
                }
                return password_body(password);
            }

            void register_active_pipe(HANDLE const pipe)
            {
                std::scoped_lock active_lock{active_gate_};
                if (closed_.load(std::memory_order_acquire))
                {
                    fail(transport_error::cancelled);
                }
                if (active_pipe_ != INVALID_HANDLE_VALUE)
                {
                    fail(transport_error::invalid);
                }
                active_pipe_ = pipe;
            }

            void clear_active_pipe(HANDLE const pipe) noexcept
            {
                std::scoped_lock active_lock{active_gate_};
                if (active_pipe_ == pipe)
                {
                    active_pipe_ = INVALID_HANDLE_VALUE;
                }
            }

            [[nodiscard]] ClientResult execute_status(
                operation const requested_operation,
                secret_bytes body,
                std::uint32_t const timeout_ms)
            {
                std::scoped_lock request_lock{request_gate_};
                if (closed_.load(std::memory_order_acquire))
                {
                    return {ClientError::Cancelled, VaultStatus::Locked};
                }
                try
                {
                    auto response = send_locked(
                        requested_operation,
                        body.value(),
                        timeout_ms);
                    ClientError const error = map_public_error(
                        response.error,
                        requested_operation);
                    if (error != ClientError::None)
                    {
                        return {error, VaultStatus::Locked};
                    }
                    return decode_status_body(response.body.value());
                }
                catch (transport_exception const& error)
                {
                    return {
                        map_transport_error(error.error()),
                        VaultStatus::Locked,
                    };
                }
            }

            [[nodiscard]] ClientResult execute_empty(
                operation const requested_operation,
                secret_bytes body,
                std::uint32_t const timeout_ms,
                VaultStatus const success_status)
            {
                std::scoped_lock request_lock{request_gate_};
                if (closed_.load(std::memory_order_acquire))
                {
                    return {ClientError::Cancelled, VaultStatus::Locked};
                }
                try
                {
                    auto response = send_locked(
                        requested_operation,
                        body.value(),
                        timeout_ms);
                    ClientError const error = map_public_error(
                        response.error,
                        requested_operation);
                    if (error != ClientError::None)
                    {
                        return {error, VaultStatus::Locked};
                    }
                    cbor_reader reader{response.body.value()};
                    if (reader.array() != 0U)
                    {
                        fail(transport_error::invalid);
                    }
                    reader.finish();
                    return {ClientError::None, success_status};
                }
                catch (transport_exception const& error)
                {
                    return {
                        map_transport_error(error.error()),
                        VaultStatus::Locked,
                    };
                }
            }

            [[nodiscard]] decoded_response send_locked(
                operation const requested_operation,
                std::span<std::uint8_t const> const body,
                std::uint32_t const timeout_ms)
            {
                auto connection = connect_agent(
                    context_,
                    closed_,
                    [this](HANDLE const pipe)
                    {
                        register_active_pipe(pipe);
                    },
                    [this](HANDLE const pipe) noexcept
                    {
                        clear_active_pipe(pipe);
                    });
                active_request const active{*this, connection.pipe.get()};
                auto request = request_envelope(
                    requested_operation,
                    connection.unlock_epoch,
                    timeout_ms,
                    body);
                write_frame(
                    connection,
                    message_kind::request,
                    protocol_major,
                    protocol_minor,
                    connection.connection_id,
                    1U,
                    request.value(),
                    timeout_ms);
                auto const response = read_frame(
                    connection,
                    timeout_ms + frame_write_allowance_ms);
                if (response.kind != message_kind::response ||
                    response.major != protocol_major ||
                    response.minor != protocol_minor ||
                    response.connection_id != connection.connection_id ||
                    response.request_id != 1U)
                {
                    fail(transport_error::invalid);
                }
                return decode_response(response);
            }

            static ClientError map_transport_error(transport_error const error) noexcept
            {
                return error == transport_error::cancelled ?
                    ClientError::Cancelled : ClientError::AgentUnavailable;
            }

            packaged_context context_;
            std::atomic_bool closed_{false};
            std::mutex request_gate_;
            std::mutex active_gate_;
            HANDLE active_pipe_{INVALID_HANDLE_VALUE};
        };
    }

    std::shared_ptr<IDesktopClient> TryMakePackagedDesktopClient() noexcept
    {
        try
        {
            return std::make_shared<packaged_desktop_client>(make_packaged_context());
        }
        catch (...)
        {
            return {};
        }
    }
}
