#include <windows.h>

#include <aclapi.h>
#include <appmodel.h>
#include <bcrypt.h>
#include <sddl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    constexpr std::byte server_authorized{0xAC};
    constexpr std::byte client_payload{0xC1};
    constexpr DWORD child_timeout_ms = 10'000;
    constexpr DWORD pipe_buffer_bytes = 65'536;

    class unique_handle final
    {
    public:
        unique_handle() noexcept = default;

        explicit unique_handle(HANDLE value) noexcept : value_(value)
        {
        }

        ~unique_handle()
        {
            reset();
        }

        unique_handle(unique_handle const&) = delete;
        unique_handle& operator=(unique_handle const&) = delete;

        unique_handle(unique_handle&& other) noexcept : value_(other.release())
        {
        }

        unique_handle& operator=(unique_handle&& other) noexcept
        {
            if (this != &other)
            {
                reset(other.release());
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

        [[nodiscard]] HANDLE release() noexcept
        {
            HANDLE const released = value_;
            value_ = nullptr;
            return released;
        }

        void reset(HANDLE value = nullptr) noexcept
        {
            if (*this)
            {
                CloseHandle(value_);
            }
            value_ = value;
        }

    private:
        HANDLE value_{nullptr};
    };

    class local_memory final
    {
    public:
        local_memory() noexcept = default;

        explicit local_memory(HLOCAL value) noexcept : value_(value)
        {
        }

        ~local_memory()
        {
            if (value_ != nullptr)
            {
                LocalFree(value_);
            }
        }

        local_memory(local_memory const&) = delete;
        local_memory& operator=(local_memory const&) = delete;

        local_memory(local_memory&& other) noexcept : value_(other.release())
        {
        }

        local_memory& operator=(local_memory&& other) noexcept
        {
            if (this != &other)
            {
                if (value_ != nullptr)
                {
                    LocalFree(value_);
                }
                value_ = other.release();
            }
            return *this;
        }

        [[nodiscard]] HLOCAL get() const noexcept
        {
            return value_;
        }

        [[nodiscard]] HLOCAL release() noexcept
        {
            HLOCAL const released = value_;
            value_ = nullptr;
            return released;
        }

    private:
        HLOCAL value_{nullptr};
    };

    [[noreturn]] void throw_last_error(std::string const& operation)
    {
        DWORD const error = GetLastError();
        throw std::runtime_error(
            operation + " failed with Windows error " + std::to_string(error));
    }

    void require(bool condition, std::string const& message)
    {
        if (!condition)
        {
            throw std::runtime_error(message);
        }
    }

    [[nodiscard]] std::wstring sid_to_string(PSID sid)
    {
        LPWSTR raw = nullptr;
        if (!ConvertSidToStringSidW(sid, &raw))
        {
            throw_last_error("ConvertSidToStringSidW");
        }
        local_memory const storage(raw);
        return static_cast<wchar_t const*>(storage.get());
    }

    [[nodiscard]] std::vector<std::byte> token_information(
        HANDLE token,
        TOKEN_INFORMATION_CLASS information_class)
    {
        DWORD bytes = 0;
        if (GetTokenInformation(token, information_class, nullptr, 0, &bytes) != FALSE ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            throw_last_error("GetTokenInformation(size)");
        }

        std::vector<std::byte> result(bytes);
        if (!GetTokenInformation(
                token,
                information_class,
                result.data(),
                bytes,
                &bytes))
        {
            throw_last_error("GetTokenInformation(value)");
        }
        return result;
    }

    struct token_identity
    {
        std::wstring user_sid;
        std::wstring logon_sid;
    };

    [[nodiscard]] token_identity query_token_identity(HANDLE process)
    {
        HANDLE raw_token = nullptr;
        if (!OpenProcessToken(process, TOKEN_QUERY, &raw_token))
        {
            throw_last_error("OpenProcessToken");
        }
        unique_handle const token(raw_token);

        std::vector<std::byte> const user_bytes =
            token_information(token.get(), TokenUser);
        auto const* const user =
            reinterpret_cast<TOKEN_USER const*>(user_bytes.data());

        std::vector<std::byte> const group_bytes =
            token_information(token.get(), TokenGroups);
        auto const* const groups =
            reinterpret_cast<TOKEN_GROUPS const*>(group_bytes.data());

        std::optional<std::wstring> logon_sid;
        for (DWORD index = 0; index < groups->GroupCount; ++index)
        {
            SID_AND_ATTRIBUTES const& group = groups->Groups[index];
            if ((group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            {
                logon_sid = sid_to_string(group.Sid);
                break;
            }
        }

        require(logon_sid.has_value(), "Process token has no logon SID.");
        return {
            .user_sid = sid_to_string(user->User.Sid),
            .logon_sid = std::move(*logon_sid),
        };
    }

    [[nodiscard]] std::optional<std::wstring> query_appmodel_string(
        HANDLE process,
        LONG(WINAPI* query)(HANDLE, UINT32*, PWSTR))
    {
        UINT32 characters = 0;
        LONG const size_status = query(process, &characters, nullptr);
        if (size_status == APPMODEL_ERROR_NO_PACKAGE ||
            size_status == APPMODEL_ERROR_NO_APPLICATION)
        {
            return std::nullopt;
        }
        if (size_status != ERROR_INSUFFICIENT_BUFFER)
        {
            throw std::runtime_error(
                "App-model identity size query failed with Windows error " +
                std::to_string(size_status));
        }

        std::vector<wchar_t> buffer(characters);
        LONG const value_status = query(process, &characters, buffer.data());
        if (value_status != ERROR_SUCCESS)
        {
            throw std::runtime_error(
                "App-model identity query failed with Windows error " +
                std::to_string(value_status));
        }
        return std::wstring(buffer.data());
    }

    [[nodiscard]] std::wstring query_process_image(HANDLE process)
    {
        std::vector<wchar_t> buffer(32'768);
        DWORD characters = static_cast<DWORD>(buffer.size());
        if (!QueryFullProcessImageNameW(
                process,
                0,
                buffer.data(),
                &characters))
        {
            throw_last_error("QueryFullProcessImageNameW");
        }
        return std::wstring(buffer.data(), characters);
    }

    [[nodiscard]] bool equal_ordinal_ignore_case(
        std::wstring_view left,
        std::wstring_view right)
    {
        int const result = CompareStringOrdinal(
            left.data(),
            static_cast<int>(left.size()),
            right.data(),
            static_cast<int>(right.size()),
            TRUE);
        if (result == 0)
        {
            throw_last_error("CompareStringOrdinal");
        }
        return result == CSTR_EQUAL;
    }

    struct peer_observation
    {
        DWORD process_id{};
        DWORD session_id{};
        std::wstring user_sid;
        std::wstring logon_sid;
        std::wstring image_path;
        std::optional<std::wstring> package_full_name;
        std::optional<std::wstring> package_family_name;
        std::optional<std::wstring> application_user_model_id;
    };

    struct observed_process
    {
        unique_handle process;
        peer_observation identity;
    };

    [[nodiscard]] observed_process observe_process(DWORD process_id)
    {
        unique_handle process(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE,
            process_id));
        if (!process)
        {
            throw_last_error("OpenProcess");
        }

        DWORD session_id = 0;
        if (!ProcessIdToSessionId(process_id, &session_id))
        {
            throw_last_error("ProcessIdToSessionId");
        }

        token_identity identity = query_token_identity(process.get());
        peer_observation observation{
            .process_id = process_id,
            .session_id = session_id,
            .user_sid = std::move(identity.user_sid),
            .logon_sid = std::move(identity.logon_sid),
            .image_path = query_process_image(process.get()),
            .package_full_name =
                query_appmodel_string(process.get(), GetPackageFullName),
            .package_family_name =
                query_appmodel_string(process.get(), GetPackageFamilyName),
            .application_user_model_id =
                query_appmodel_string(process.get(), GetApplicationUserModelId),
        };
        return {
            .process = std::move(process),
            .identity = std::move(observation),
        };
    }

    [[nodiscard]] peer_observation observe_peer(DWORD process_id)
    {
        observed_process process = observe_process(process_id);
        return std::move(process.identity);
    }

    void require_process_running(
        observed_process const& process,
        std::string const& message)
    {
        require(
            WaitForSingleObject(process.process.get(), 0) == WAIT_TIMEOUT,
            message);
    }

    struct peer_policy
    {
        DWORD session_id{};
        std::wstring user_sid;
        std::wstring logon_sid;
        std::wstring image_path;
        bool require_package_identity{true};
        std::optional<std::wstring> package_full_name;
        std::optional<std::wstring> package_family_name;
        std::optional<std::wstring> application_user_model_id;
    };

    [[nodiscard]] bool authorize_peer(
        peer_observation const& peer,
        peer_policy const& policy)
    {
        if (peer.session_id != policy.session_id ||
            peer.user_sid != policy.user_sid ||
            peer.logon_sid != policy.logon_sid ||
            !equal_ordinal_ignore_case(peer.image_path, policy.image_path))
        {
            return false;
        }

        if (policy.require_package_identity)
        {
            if (!peer.package_full_name ||
                !peer.package_family_name ||
                !policy.package_full_name ||
                !policy.package_family_name ||
                *peer.package_full_name != *policy.package_full_name ||
                *peer.package_family_name != *policy.package_family_name)
            {
                return false;
            }
        }

        if (policy.application_user_model_id &&
            peer.application_user_model_id != policy.application_user_model_id)
        {
            return false;
        }
        return true;
    }

    [[nodiscard]] peer_policy development_policy_for(
        peer_observation const& expected,
        std::wstring expected_image)
    {
        return {
            .session_id = expected.session_id,
            .user_sid = expected.user_sid,
            .logon_sid = expected.logon_sid,
            .image_path = std::move(expected_image),
            .require_package_identity = false,
            .package_full_name = std::nullopt,
            .package_family_name = std::nullopt,
            .application_user_model_id = std::nullopt,
        };
    }

    [[nodiscard]] std::wstring current_image_path()
    {
        return query_process_image(GetCurrentProcess());
    }

    struct pipe_security
    {
        local_memory descriptor;
        std::wstring logon_sid;
        SECURITY_ATTRIBUTES attributes{};
    };

    [[nodiscard]] pipe_security make_pipe_security()
    {
        token_identity const identity = query_token_identity(GetCurrentProcess());
        std::wstring const sddl =
            L"D:P(A;;GA;;;SY)(A;;GA;;;" + identity.logon_sid + L")";

        PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.c_str(),
                SDDL_REVISION_1,
                &raw_descriptor,
                nullptr))
        {
            throw_last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW");
        }

        pipe_security result{
            .descriptor = local_memory(raw_descriptor),
            .logon_sid = identity.logon_sid,
            .attributes = {},
        };
        result.attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        result.attributes.lpSecurityDescriptor = result.descriptor.get();
        result.attributes.bInheritHandle = FALSE;
        return result;
    }

    void verify_pipe_dacl(pipe_security const& security)
    {
        BOOL present = FALSE;
        BOOL defaulted = FALSE;
        PACL dacl = nullptr;
        if (!GetSecurityDescriptorDacl(
                security.descriptor.get(),
                &present,
                &dacl,
                &defaulted))
        {
            throw_last_error("GetSecurityDescriptorDacl");
        }
        require(present != FALSE, "Pipe DACL must be present.");
        require(defaulted == FALSE, "Pipe DACL must not be defaulted.");
        require(dacl != nullptr, "Pipe DACL must not be null.");

        ACL_SIZE_INFORMATION size{};
        if (!GetAclInformation(
                dacl,
                &size,
                sizeof(size),
                AclSizeInformation))
        {
            throw_last_error("GetAclInformation");
        }
        require(
            size.AceCount == 2,
            "Pipe DACL must contain only LocalSystem and the current logon SID.");

        PSID system_sid = nullptr;
        if (!ConvertStringSidToSidW(L"S-1-5-18", &system_sid))
        {
            throw_last_error("ConvertStringSidToSidW(System)");
        }
        local_memory const system_sid_storage(system_sid);

        PSID logon_sid = nullptr;
        if (!ConvertStringSidToSidW(security.logon_sid.c_str(), &logon_sid))
        {
            throw_last_error("ConvertStringSidToSidW(logon)");
        }
        local_memory const logon_sid_storage(logon_sid);

        bool saw_system = false;
        bool saw_logon = false;
        for (DWORD index = 0; index < size.AceCount; ++index)
        {
            void* raw_ace = nullptr;
            if (!GetAce(dacl, index, &raw_ace))
            {
                throw_last_error("GetAce");
            }
            auto const* const header =
                static_cast<ACE_HEADER const*>(raw_ace);
            require(
                header->AceType == ACCESS_ALLOWED_ACE_TYPE,
                "Pipe DACL may contain only allow entries.");
            auto const* const ace =
                static_cast<ACCESS_ALLOWED_ACE const*>(raw_ace);
            PSID const sid = const_cast<DWORD*>(&ace->SidStart);
            saw_system =
                saw_system || EqualSid(sid, system_sid_storage.get()) != FALSE;
            saw_logon =
                saw_logon || EqualSid(sid, logon_sid_storage.get()) != FALSE;
        }
        require(saw_system, "Pipe DACL must allow LocalSystem.");
        require(saw_logon, "Pipe DACL must allow the current logon SID.");
    }

    [[nodiscard]] std::wstring random_hex()
    {
        std::array<UCHAR, 16> bytes{};
        NTSTATUS const status = BCryptGenRandom(
            nullptr,
            bytes.data(),
            static_cast<ULONG>(bytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
        {
            throw std::runtime_error(
                "BCryptGenRandom failed with NTSTATUS " +
                std::to_string(status));
        }

        constexpr wchar_t alphabet[] = L"0123456789abcdef";
        std::wstring result;
        result.reserve(bytes.size() * 2);
        for (UCHAR const value : bytes)
        {
            result.push_back(alphabet[value >> 4]);
            result.push_back(alphabet[value & 0x0F]);
        }
        return result;
    }

    [[nodiscard]] std::wstring random_pipe_name()
    {
        return L"\\\\.\\pipe\\LOCAL\\Librarian.IpcProbe." + random_hex();
    }

    [[nodiscard]] unique_handle create_pipe(
        std::wstring const& name,
        SECURITY_ATTRIBUTES* security,
        bool first_instance)
    {
        DWORD open_mode = PIPE_ACCESS_DUPLEX;
        open_mode |= FILE_FLAG_OVERLAPPED;
        if (first_instance)
        {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        return unique_handle(CreateNamedPipeW(
            name.c_str(),
            open_mode,
            PIPE_TYPE_BYTE |
                PIPE_READMODE_BYTE |
                PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
            8,
            pipe_buffer_bytes,
            pipe_buffer_bytes,
            0,
            security));
    }

    [[noreturn]] void cancel_pending_io(
        HANDLE handle,
        OVERLAPPED& overlapped,
        std::string const& reason)
    {
        if (!CancelIoEx(handle, &overlapped) &&
            GetLastError() != ERROR_NOT_FOUND)
        {
            ExitProcess(3);
        }
        if (WaitForSingleObject(overlapped.hEvent, child_timeout_ms) !=
            WAIT_OBJECT_0)
        {
            ExitProcess(3);
        }

        DWORD ignored = 0;
        GetOverlappedResult(handle, &overlapped, &ignored, FALSE);
        throw std::runtime_error(reason);
    }

    [[nodiscard]] DWORD wait_for_pipe_io(
        HANDLE handle,
        OVERLAPPED& overlapped,
        HANDLE peer_process,
        std::string const& operation)
    {
        std::array<HANDLE, 2> const waits{
            overlapped.hEvent,
            peer_process,
        };
        DWORD const wait = WaitForMultipleObjects(
            peer_process == nullptr ? 1 : 2,
            waits.data(),
            FALSE,
            child_timeout_ms);
        if (wait == WAIT_OBJECT_0)
        {
            DWORD transferred = 0;
            if (!GetOverlappedResult(
                    handle,
                    &overlapped,
                    &transferred,
                    FALSE))
            {
                throw_last_error(operation);
            }
            return transferred;
        }
        if (peer_process != nullptr && wait == WAIT_OBJECT_0 + 1)
        {
            cancel_pending_io(
                handle,
                overlapped,
                operation + " stopped because the peer process exited.");
        }
        if (wait == WAIT_TIMEOUT)
        {
            cancel_pending_io(
                handle,
                overlapped,
                operation + " timed out.");
        }
        if (wait == WAIT_FAILED)
        {
            DWORD const error = GetLastError();
            cancel_pending_io(
                handle,
                overlapped,
                operation + " wait failed with Windows error " +
                    std::to_string(error));
        }
        cancel_pending_io(
            handle,
            overlapped,
            operation + " produced an unexpected wait result.");
    }

    void accept_pipe(HANDLE pipe, HANDLE peer_process = nullptr)
    {
        unique_handle const event(CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr));
        if (!event)
        {
            throw_last_error("CreateEventW(ConnectNamedPipe)");
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();

        if (ConnectNamedPipe(pipe, &overlapped))
        {
            return;
        }

        DWORD const error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED)
        {
            return;
        }
        if (error != ERROR_IO_PENDING)
        {
            SetLastError(error);
            throw_last_error("ConnectNamedPipe");
        }
        if (wait_for_pipe_io(
                pipe,
                overlapped,
                peer_process,
                "ConnectNamedPipe") != 0)
        {
            throw std::runtime_error(
                "ConnectNamedPipe transferred unexpected bytes.");
        }
    }

    [[nodiscard]] unique_handle connect_pipe(std::wstring const& name)
    {
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            unique_handle pipe(CreateFileW(
                name.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED |
                SECURITY_SQOS_PRESENT |
                    SECURITY_ANONYMOUS |
                    SECURITY_EFFECTIVE_ONLY,
                nullptr));
            if (pipe)
            {
                return pipe;
            }
            if (GetLastError() != ERROR_PIPE_BUSY ||
                !WaitNamedPipeW(name.c_str(), 5'000))
            {
                break;
            }
        }
        throw_last_error("CreateFileW(named pipe)");
    }

    [[nodiscard]] std::byte read_byte(
        HANDLE handle,
        HANDLE peer_process = nullptr)
    {
        unique_handle const event(CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr));
        if (!event)
        {
            throw_last_error("CreateEventW(ReadFile)");
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();

        std::byte value{};
        DWORD read = 0;
        if (!ReadFile(handle, &value, 1, &read, &overlapped))
        {
            DWORD const error = GetLastError();
            if (error != ERROR_IO_PENDING)
            {
                SetLastError(error);
                throw_last_error("ReadFile");
            }
            read = wait_for_pipe_io(
                handle,
                overlapped,
                peer_process,
                "ReadFile");
        }
        require(read == 1, "ReadFile did not return exactly one byte.");
        return value;
    }

    void write_byte(
        HANDLE handle,
        std::byte value,
        HANDLE peer_process = nullptr)
    {
        unique_handle const event(CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr));
        if (!event)
        {
            throw_last_error("CreateEventW(WriteFile)");
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();

        DWORD written = 0;
        if (!WriteFile(handle, &value, 1, &written, &overlapped))
        {
            DWORD const error = GetLastError();
            if (error != ERROR_IO_PENDING)
            {
                SetLastError(error);
                throw_last_error("WriteFile");
            }
            written = wait_for_pipe_io(
                handle,
                overlapped,
                peer_process,
                "WriteFile");
        }
        require(written == 1, "WriteFile did not write exactly one byte.");
    }

    [[nodiscard]] std::wstring quote_argument(std::wstring const& value)
    {
        require(
            value.find(L'"') == std::wstring::npos,
            "Probe arguments may not contain quotes.");
        return L"\"" + value + L"\"";
    }

    struct child_process
    {
        unique_handle process;
        unique_handle thread;
        DWORD process_id{};
    };

    [[nodiscard]] child_process launch_child(
        std::wstring const& image,
        std::vector<std::wstring> const& arguments,
        bool inherit_handles)
    {
        std::wstring command_line = quote_argument(image);
        for (std::wstring const& argument : arguments)
        {
            command_line += L" ";
            command_line += quote_argument(argument);
        }

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION information{};
        if (!CreateProcessW(
                image.c_str(),
                command_line.data(),
                nullptr,
                nullptr,
                inherit_handles ? TRUE : FALSE,
                CREATE_NO_WINDOW,
                nullptr,
                nullptr,
                &startup,
                &information))
        {
            throw_last_error("CreateProcessW");
        }

        return {
            .process = unique_handle(information.hProcess),
            .thread = unique_handle(information.hThread),
            .process_id = information.dwProcessId,
        };
    }

    [[nodiscard]] DWORD wait_for_child(child_process const& child)
    {
        DWORD const wait = WaitForSingleObject(child.process.get(), child_timeout_ms);
        require(wait == WAIT_OBJECT_0, "Child process did not finish in time.");
        DWORD exit_code = 0;
        if (!GetExitCodeProcess(child.process.get(), &exit_code))
        {
            throw_last_error("GetExitCodeProcess");
        }
        return exit_code;
    }

    class hostile_copy final
    {
    public:
        explicit hostile_copy(std::wstring const& source)
        {
            wchar_t temp_path[MAX_PATH + 1]{};
            DWORD const length =
                GetTempPathW(static_cast<DWORD>(std::size(temp_path)), temp_path);
            if (length == 0 || length >= std::size(temp_path))
            {
                throw_last_error("GetTempPathW");
            }

            directory_ =
                std::filesystem::path(temp_path) /
                (L"LibrarianIpcProbe-" + random_hex());
            if (!CreateDirectoryW(directory_.c_str(), nullptr))
            {
                throw_last_error("CreateDirectoryW");
            }

            image_ = directory_ / L"Untrusted.Copy.exe";
            if (!CopyFileW(source.c_str(), image_.c_str(), TRUE))
            {
                throw_last_error("CopyFileW");
            }
        }

        ~hostile_copy()
        {
            DeleteFileW(image_.c_str());
            RemoveDirectoryW(directory_.c_str());
        }

        hostile_copy(hostile_copy const&) = delete;
        hostile_copy& operator=(hostile_copy const&) = delete;

        [[nodiscard]] std::wstring image() const
        {
            return image_.wstring();
        }

    private:
        std::filesystem::path directory_;
        std::filesystem::path image_;
    };

    [[nodiscard]] DWORD client_mode(
        std::wstring const& pipe_name,
        DWORD expected_server_pid,
        std::wstring const& expected_server_image)
    {
        unique_handle const pipe = connect_pipe(pipe_name);
        ULONG server_pid = 0;
        if (!GetNamedPipeServerProcessId(pipe.get(), &server_pid))
        {
            throw_last_error("GetNamedPipeServerProcessId");
        }
        require(
            server_pid == expected_server_pid,
            "Client connected to an unexpected server PID.");

        observed_process const server = observe_process(server_pid);
        peer_observation const current = observe_peer(GetCurrentProcessId());
        peer_policy const policy =
            development_policy_for(current, expected_server_image);
        require(
            authorize_peer(server.identity, policy),
            "Client rejected the server process before sending payload.");
        require_process_running(
            server,
            "Authenticated server process exited before payload exchange.");

        try
        {
            require(
                read_byte(pipe.get(), server.process.get()) ==
                    server_authorized,
                "Server returned an invalid authorization marker.");
        }
        catch (std::runtime_error const&)
        {
            return 20;
        }
        write_byte(pipe.get(), client_payload, server.process.get());
        return 0;
    }

    [[nodiscard]] DWORD squatter_mode(
        std::wstring const& pipe_name,
        HANDLE ready_event)
    {
        unique_handle const pipe = create_pipe(pipe_name, nullptr, true);
        if (!pipe)
        {
            throw_last_error("CreateNamedPipeW(squatter)");
        }
        if (!SetEvent(ready_event))
        {
            throw_last_error("SetEvent");
        }
        accept_pipe(pipe.get());
        try
        {
            static_cast<void>(read_byte(pipe.get()));
        }
        catch (std::runtime_error const&)
        {
        }
        return 0;
    }

    void test_identity_policy()
    {
        peer_observation const current = observe_peer(GetCurrentProcessId());
        peer_policy const allowed =
            development_policy_for(current, current.image_path);
        require(
            authorize_peer(current, allowed),
            "Expected development peer was rejected.");

        peer_observation changed = current;
        changed.user_sid += L"-1";
        require(
            !authorize_peer(changed, allowed),
            "Mismatched user SID was accepted.");

        changed = current;
        changed.logon_sid += L"-1";
        require(
            !authorize_peer(changed, allowed),
            "Mismatched logon SID was accepted.");

        changed = current;
        ++changed.session_id;
        require(
            !authorize_peer(changed, allowed),
            "Mismatched Windows session was accepted.");

        changed = current;
        changed.image_path += L".copy";
        require(
            !authorize_peer(changed, allowed),
            "Mismatched image path was accepted.");

        peer_policy production = allowed;
        production.require_package_identity = true;
        production.package_full_name =
            current.package_full_name.value_or(L"Librarian_missing");
        production.package_family_name =
            current.package_family_name.value_or(L"Librarian_missing");
        bool const expected_production_result =
            current.package_full_name.has_value() &&
            current.package_family_name.has_value();
        require(
            authorize_peer(current, production) == expected_production_result,
            "Production package-identity requirement did not fail closed.");

        if (current.package_full_name)
        {
            production.package_full_name = *current.package_full_name + L".stale";
            require(
                !authorize_peer(current, production),
                "Mismatched package version was accepted.");
        }

        peer_policy application = allowed;
        application.application_user_model_id = L"Librarian.UnexpectedRole";
        require(
            !authorize_peer(current, application),
            "Mismatched application identity was accepted.");
    }

    void test_pipe_security_descriptor()
    {
        pipe_security const security = make_pipe_security();
        verify_pipe_dacl(security);
    }

    void test_first_instance_blocks_duplicate()
    {
        pipe_security security = make_pipe_security();
        std::wstring const name = random_pipe_name();
        unique_handle const first =
            create_pipe(name, &security.attributes, true);
        if (!first)
        {
            throw_last_error("CreateNamedPipeW(first)");
        }

        unique_handle const duplicate =
            create_pipe(name, &security.attributes, true);
        require(
            !duplicate,
            "FILE_FLAG_FIRST_PIPE_INSTANCE allowed a duplicate server.");
    }

    void test_peer_exit_cancels_pending_accept()
    {
        pipe_security security = make_pipe_security();
        std::wstring const name = random_pipe_name();
        unique_handle const pipe =
            create_pipe(name, &security.attributes, true);
        if (!pipe)
        {
            throw_last_error("CreateNamedPipeW(peer exit)");
        }

        child_process const child = launch_child(
            current_image_path(),
            {L"--exit"},
            false);
        require(
            wait_for_child(child) == 0,
            "Peer-exit fixture did not exit cleanly.");

        bool cancelled = false;
        try
        {
            accept_pipe(pipe.get(), child.process.get());
        }
        catch (std::runtime_error const& error)
        {
            cancelled =
                std::string_view(error.what()).find("peer process exited") !=
                std::string_view::npos;
        }
        require(
            cancelled,
            "Pending pipe accept did not stop when the peer process exited.");
    }

    void test_mutual_peer_attestation()
    {
        pipe_security security = make_pipe_security();
        std::wstring const name = random_pipe_name();
        unique_handle const pipe =
            create_pipe(name, &security.attributes, true);
        if (!pipe)
        {
            throw_last_error("CreateNamedPipeW(mutual)");
        }

        std::wstring const image = current_image_path();
        child_process const child = launch_child(
            image,
            {
                L"--client",
                name,
                std::to_wstring(GetCurrentProcessId()),
                image,
            },
            false);
        accept_pipe(pipe.get(), child.process.get());

        ULONG client_pid = 0;
        if (!GetNamedPipeClientProcessId(pipe.get(), &client_pid))
        {
            throw_last_error("GetNamedPipeClientProcessId");
        }
        require(
            client_pid == child.process_id,
            "Server observed an unexpected client PID.");

        peer_observation const expected = observe_peer(GetCurrentProcessId());
        observed_process const client = observe_process(client_pid);
        peer_policy const policy = development_policy_for(expected, image);
        require(
            authorize_peer(client.identity, policy),
            "Server rejected the expected client process.");
        require_process_running(
            client,
            "Authenticated client process exited before payload exchange.");

        write_byte(
            pipe.get(),
            server_authorized,
            child.process.get());
        require(
            read_byte(pipe.get(), child.process.get()) == client_payload,
            "Client payload was not bound to the authenticated connection.");
        require(wait_for_child(child) == 0, "Expected client failed.");
    }

    void test_server_rejects_copied_client()
    {
        pipe_security security = make_pipe_security();
        std::wstring const name = random_pipe_name();
        unique_handle pipe =
            create_pipe(name, &security.attributes, true);
        if (!pipe)
        {
            throw_last_error("CreateNamedPipeW(hostile client)");
        }

        std::wstring const image = current_image_path();
        hostile_copy const copy(image);
        child_process const child = launch_child(
            copy.image(),
            {
                L"--client",
                name,
                std::to_wstring(GetCurrentProcessId()),
                image,
            },
            false);
        accept_pipe(pipe.get(), child.process.get());

        ULONG client_pid = 0;
        if (!GetNamedPipeClientProcessId(pipe.get(), &client_pid))
        {
            throw_last_error("GetNamedPipeClientProcessId(hostile)");
        }
        peer_observation const expected = observe_peer(GetCurrentProcessId());
        observed_process const client = observe_process(client_pid);
        peer_policy const policy = development_policy_for(expected, image);
        require(
            !authorize_peer(client.identity, policy),
            "Copied client binary was authorized.");

        pipe.reset();
        require(
            wait_for_child(child) == 20,
            "Copied client did not observe fail-closed rejection.");
    }

    void test_client_rejects_copied_server()
    {
        std::wstring const image = current_image_path();
        hostile_copy const copy(image);
        std::wstring const name = random_pipe_name();

        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        unique_handle const ready(CreateEventW(
            &inheritable,
            TRUE,
            FALSE,
            nullptr));
        if (!ready)
        {
            throw_last_error("CreateEventW");
        }

        child_process const squatter = launch_child(
            copy.image(),
            {
                L"--squatter",
                name,
                std::to_wstring(
                    reinterpret_cast<std::uintptr_t>(ready.get())),
            },
            true);
        require(
            WaitForSingleObject(ready.get(), child_timeout_ms) == WAIT_OBJECT_0,
            "Copied server did not become ready.");

        unique_handle pipe = connect_pipe(name);
        ULONG server_pid = 0;
        if (!GetNamedPipeServerProcessId(pipe.get(), &server_pid))
        {
            throw_last_error("GetNamedPipeServerProcessId(squatter)");
        }
        require(
            server_pid == squatter.process_id,
            "Client did not connect to the copied server fixture.");

        peer_observation const current = observe_peer(GetCurrentProcessId());
        observed_process const server = observe_process(server_pid);
        peer_policy const policy = development_policy_for(current, image);
        require(
            !authorize_peer(server.identity, policy),
            "Client authorized a copied server binary.");

        pipe.reset();
        require(
            wait_for_child(squatter) == 0,
            "Copied server fixture did not exit cleanly.");
    }

    [[nodiscard]] int self_test()
    {
        struct test_case
        {
            std::wstring_view name;
            std::function<void()> run;
        };

        std::array<test_case, 7> const tests{{
            {L"identity policy fails closed", test_identity_policy},
            {L"pipe DACL is logon-session scoped", test_pipe_security_descriptor},
            {L"first pipe instance blocks duplicates", test_first_instance_blocks_duplicate},
            {L"peer exit cancels pending accept", test_peer_exit_cancels_pending_accept},
            {L"client and server attest each other", test_mutual_peer_attestation},
            {L"server rejects a copied client", test_server_rejects_copied_client},
            {L"client rejects a copied server", test_client_rejects_copied_server},
        }};

        std::size_t failures = 0;
        for (test_case const& test : tests)
        {
            try
            {
                test.run();
                std::wcout << L"[PASS] " << test.name << L"\n";
            }
            catch (std::exception const& error)
            {
                ++failures;
                std::wcerr
                    << L"[FAIL] "
                    << test.name
                    << L": "
                    << error.what()
                    << L"\n";
            }
        }

        std::wcout
            << (tests.size() - failures)
            << L" passed; "
            << failures
            << L" failed\n";
        return failures == 0 ? 0 : 1;
    }

    [[nodiscard]] DWORD parse_dword(std::wstring const& value)
    {
        std::size_t consumed = 0;
        unsigned long const parsed = std::stoul(value, &consumed, 10);
        require(consumed == value.size(), "Invalid numeric argument.");
        return static_cast<DWORD>(parsed);
    }

    [[nodiscard]] HANDLE parse_handle(std::wstring const& value)
    {
        std::size_t consumed = 0;
        unsigned long long const parsed = std::stoull(value, &consumed, 10);
        require(consumed == value.size(), "Invalid handle argument.");
        return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(parsed));
    }
}

int wmain(int argc, wchar_t* argv[])
{
    try
    {
        if (argc == 2 && std::wstring_view(argv[1]) == L"--self-test")
        {
            return self_test();
        }
        if (argc == 2 && std::wstring_view(argv[1]) == L"--exit")
        {
            return 0;
        }
        if (argc == 5 && std::wstring_view(argv[1]) == L"--client")
        {
            return static_cast<int>(client_mode(
                argv[2],
                parse_dword(argv[3]),
                argv[4]));
        }
        if (argc == 4 && std::wstring_view(argv[1]) == L"--squatter")
        {
            return static_cast<int>(squatter_mode(
                argv[2],
                parse_handle(argv[3])));
        }

        std::wcerr << L"Usage: Librarian.WindowsIpcProbe --self-test\n";
        return 2;
    }
    catch (std::exception const& error)
    {
        std::cerr << "Windows IPC probe failed: " << error.what() << "\n";
        return 1;
    }
}
