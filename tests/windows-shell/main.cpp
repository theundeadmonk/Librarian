#include "../../apps/windows/Librarian.Windows/ShellViewModel.h"
#include "../../apps/windows/Librarian.Windows/DesktopLaunchArguments.h"
#include "../../packaging/windows/identity-launcher/src/NativeHostStartup.h"
#include "../../packaging/windows/identity-launcher/src/LaunchOperation.h"
#include "../../platform/windows-passkey/include/librarian/windows_passkey/registration.h"

#include <atomic>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    using librarian::windows::AccountDraft;
    using librarian::windows::AccountListResult;
    using librarian::windows::AccountSummary;
    using librarian::windows::ClientError;
    using librarian::windows::ClientResult;
    using librarian::windows::IDesktopClient;
    using librarian::windows::PasskeyListResult;
    using librarian::windows::PasskeySummary;
    using librarian::windows::SecretText;
    using librarian::windows::ShellState;
    using librarian::windows::ShellViewModel;
    using librarian::windows::VaultStatus;

    class TestContext final
    {
    public:
        void Check(bool const condition, std::string_view const name)
        {
            if (condition)
            {
                std::cout << "[PASS] " << name << '\n';
                return;
            }

            std::cerr << "[FAIL] " << name << '\n';
            ++failures_;
        }

        [[nodiscard]] int Failures() const noexcept
        {
            return failures_;
        }

    private:
        int failures_{ 0 };
    };

    void TestRegistrationResults(TestContext& test)
    {
        namespace registration = librarian::windows_passkey::registration_command;
        test.Check(registration::exit_code(S_OK) == registration::success &&
            registration::can_continue(registration::success, true) &&
            registration::can_continue(registration::success, false),
            "successful provider operations continue");
        for (HRESULT const result : {HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND), E_NOTIMPL})
        {
            auto const unavailable = registration::exit_code(static_cast<std::uint32_t>(result));
            test.Check(unavailable == registration::platform_unavailable &&
                registration::can_continue(unavailable, true) &&
                !registration::can_continue(unavailable, false),
                "only registration with missing or unimplemented APIs permits password fallback");
        }
        for (HRESULT const result : {E_ACCESSDENIED, E_UNEXPECTED, E_FAIL, E_INVALIDARG,
            HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND), HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT)})
        {
            auto const code = registration::exit_code(static_cast<std::uint32_t>(result));
            test.Check(code == registration::operation_failed &&
                !registration::can_continue(code, true) &&
                !registration::can_continue(code, false),
                "unexpected registration, update, response, and loader failures remain fatal");
        }
        for (std::uint32_t const code : {1U, registration::not_registered, 42U, 0xC0000135U})
        {
            test.Check(!registration::can_continue(code, true) &&
                !registration::can_continue(code, false),
                "not-registered, rejected activation, and crash exits are not platform fallback");
        }
    }

    void TestLaunchOperations(TestContext& test)
    {
        using librarian::identity_launcher::dispatch_operation;
        using librarian::identity_launcher::operation;
        // Keep injected failures runtime-controlled under MSVC whole-program
        // optimization so both successful and throwing callback paths exist.
        volatile bool inject_failure = true;
        for (auto const& [requested, expected] : std::vector<std::pair<operation, std::string>>{
            {operation::native_host, "identity host "},
            {operation::launch, "identity provider desktop "},
            {operation::register_only, "identity provider "},
            {operation::unregister, "remove "}})
        {
            std::string calls;
            int const result = dispatch_operation(requested,
                [&] { calls += "identity "; }, [&] { calls += "remove "; },
                [&] { calls += "provider "; }, [&] { calls += "desktop "; },
                [&] { calls += "host "; return 37; });
            test.Check(calls == expected, "launcher follows the identity-first operation-specific sequence");
            test.Check(result == (requested == operation::native_host ? 37 : 0),
                "launcher preserves the native host exit code");
        }
        for (operation const requested : {operation::native_host, operation::launch, operation::register_only})
        {
            bool child_started = false;
            bool failed = false;
            try
            {
                dispatch_operation(requested, [&] { if (inject_failure) throw 1; }, [] {},
                    [&] { child_started = true; }, [&] { child_started = true; },
                    [&] { child_started = true; return 0; });
            }
            catch (int) { failed = true; }
            test.Check(failed && !child_started, "identity failure prevents all child activation");
        }
        bool desktop_started = false;
        bool failed = false;
        try
        {
            dispatch_operation(operation::launch, [] {}, [] {}, [&] { if (inject_failure) throw 1; },
                [&] { desktop_started = true; }, [] { return 0; });
        }
        catch (int) { failed = true; }
        test.Check(failed && !desktop_started, "fatal provider failure still prevents desktop launch");
    }

    struct TestHandle
    {
        HANDLE value{};
        ~TestHandle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        void Close() { if (value) CloseHandle(value); value = nullptr; }
    };

    int EchoNativeHostStreams()
    {
        std::array<unsigned char, 5> message{};
        DWORD read{};
        DWORD written{};
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), message.data(),
                static_cast<DWORD>(message.size()), &read, nullptr) || read != message.size()) return 91;
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message.data(), read, &written, nullptr) || written != read) return 92;
        constexpr char diagnostic[] = "fixture-diagnostic";
        if (!WriteFile(GetStdHandle(STD_ERROR_HANDLE), diagnostic, sizeof(diagnostic), &written, nullptr) ||
            written != sizeof(diagnostic)) return 93;
        return 0;
    }

    void TestNativeHostStreams(TestContext& test)
    {
        using librarian::identity_launcher::configure_native_host_startup;
        STARTUPINFOW startup{};
        test.Check(!configure_native_host_startup(startup, {nullptr, nullptr, nullptr}),
            "native-host startup rejects missing standard handles");
        test.Check(!configure_native_host_startup(startup, {INVALID_HANDLE_VALUE, nullptr, nullptr}),
            "native-host startup rejects invalid standard handles");
        TestHandle inputRead, inputWrite, outputRead, outputWrite, errorRead, errorWrite;
        bool const pipes = CreatePipe(&inputRead.value, &inputWrite.value, nullptr, 0) &&
            CreatePipe(&outputRead.value, &outputWrite.value, nullptr, 0) &&
            CreatePipe(&errorRead.value, &errorWrite.value, nullptr, 0);
        test.Check(pipes, "native-host regression creates isolated anonymous pipes");
        if (!pipes) return;
        bool const configured = configure_native_host_startup(startup,
            {inputRead.value, outputWrite.value, errorWrite.value});
        test.Check(configured && startup.dwFlags == STARTF_USESTDHANDLES &&
            startup.hStdInput == inputRead.value && startup.hStdOutput == outputWrite.value &&
            startup.hStdError == errorWrite.value,
            "native-host startup explicitly binds three separate standard streams");
        if (!configured) return;
        std::array<wchar_t, 32768> path{};
        DWORD const length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        test.Check(length > 0 && length < path.size(), "native-host regression resolves its own test executable");
        if (length == 0 || length >= path.size()) return;
        std::wstring command = L"\"" + std::wstring{path.data(), length} + L"\" --echo-native-host-streams";
        PROCESS_INFORMATION child{};
        bool const launched = CreateProcessW(path.data(), command.data(), nullptr, nullptr,
            TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child) != FALSE;
        test.Check(launched, "native-host regression launches a windowless console child");
        if (!launched) return;
        TestHandle process{child.hProcess}, thread{child.hThread};
        inputRead.Close(); outputWrite.Close(); errorWrite.Close();
        std::array<unsigned char, 5> const expected{0x00, 0x0A, 0x1A, 0x80, 0xFF};
        DWORD written{};
        test.Check(WriteFile(inputWrite.value, expected.data(), static_cast<DWORD>(expected.size()), &written, nullptr) &&
            written == expected.size(), "native-host regression sends an exact binary payload");
        inputWrite.Close();
        DWORD const wait = WaitForSingleObject(process.value, 5000);
        test.Check(wait == WAIT_OBJECT_0, "native-host child completes without losing its browser pipes");
        if (wait != WAIT_OBJECT_0)
        {
            TerminateProcess(process.value, 94);
            WaitForSingleObject(process.value, 5000);
            return;
        }
        DWORD code{};
        test.Check(GetExitCodeProcess(process.value, &code) && code == 0,
            "native-host child can read stdin and write stdout and stderr");
        std::array<unsigned char, 64> bytes{};
        DWORD count{};
        bool const readOutput = ReadFile(outputRead.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) != FALSE;
        test.Check(readOutput && count == expected.size() && std::equal(expected.begin(), expected.end(), bytes.begin()),
            "native-host binary stdout is byte-exact and contains no diagnostics");
        bool const readError = ReadFile(errorRead.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) != FALSE;
        test.Check(readError && count == sizeof("fixture-diagnostic") &&
            std::string_view{reinterpret_cast<char const*>(bytes.data()), count} == std::string_view{"fixture-diagnostic", sizeof("fixture-diagnostic")},
            "native-host diagnostics remain on their separate stderr channel");
    }

    void TestDesktopLaunchArguments(TestContext& test)
    {
        using librarian::windows::ParseDesktopLaunchArguments;
        std::wstring const executable = L"\"C:\\Program Files\\Librarian\\Librarian.Windows.exe\"";
        auto const normal = ParseDesktopLaunchArguments(std::nullopt, executable);
        test.Check(normal.valid && normal.command.empty(),
            "direct desktop launch does not mistake the executable path for a command");
        for (std::wstring_view const command : {
            L"--register-passkey-provider", L"--unregister-passkey-provider",
            L"--passkey-provider-registration-state"})
        {
            auto const activated = ParseDesktopLaunchArguments(command, executable);
            auto const direct = ParseDesktopLaunchArguments(
                std::nullopt, executable + L" \"" + std::wstring{command} + L"\"");
            test.Check(activated.valid && activated.command == command,
                "platform hidden command is accepted without raw process arguments");
            test.Check(direct.valid && direct.command == command,
                "quoted direct hidden command is parsed exactly once");
        }
        auto const empty = ParseDesktopLaunchArguments(std::wstring_view{}, executable + L" -Embedding");
        test.Check(empty.valid && empty.command.empty(),
            "empty platform launch is authoritative over broker command-line data");
        test.Check(!ParseDesktopLaunchArguments(L"--unknown", executable + L" --register-passkey-provider").valid,
            "invalid platform payload cannot fall back to a valid process command");
        test.Check(!ParseDesktopLaunchArguments(executable, executable).valid,
            "an executable path is not a valid platform command payload");
        for (std::wstring_view const suffix : {
            L" --unknown", L" --register-passkey-provider extra", L" \"\"",
            L" --REGISTER-PASSKEY-PROVIDER"})
        {
            test.Check(!ParseDesktopLaunchArguments(std::nullopt, executable + std::wstring{suffix}).valid,
                "unexpected direct command arguments fail closed");
        }
        test.Check(!ParseDesktopLaunchArguments(std::nullopt, L"").valid,
            "an empty process command line fails closed");
        test.Check(!ParseDesktopLaunchArguments(std::nullopt, std::wstring(32768U, L'a')).valid,
            "an oversized process command line fails closed");
        test.Check(!ParseDesktopLaunchArguments(std::nullopt, executable + std::wstring(1, L'\0')).valid,
            "an embedded null in process arguments fails closed");
        test.Check(!ParseDesktopLaunchArguments(L"--register-passkey-provider extra", executable).valid,
            "multiple platform command arguments fail closed");
    }

    class FakeDesktopClient final : public IDesktopClient
    {
    public:
        ClientResult status_result{ ClientError::None, VaultStatus::Locked };
        ClientResult create_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult unlock_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult windows_hello_unlock_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult windows_hello_enroll_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult windows_hello_remove_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult lock_result{ ClientError::None, VaultStatus::Locked };
        ClientResult save_result{ ClientError::None, VaultStatus::Unlocked };
        AccountListResult list_result{};
        PasskeyListResult passkey_list_result{};
        ClientResult delete_passkey_result{ ClientError::None, VaultStatus::Unlocked };
        std::wstring expected_password;
        bool password_matched{ false };
        int status_calls{ 0 };
        int unlock_calls{ 0 };
        int windows_hello_unlock_calls{ 0 };
        int windows_hello_enroll_calls{ 0 };
        int windows_hello_remove_calls{ 0 };
        std::uintptr_t windows_hello_parent_window{ 0U };
        int lock_calls{ 0 };
        std::vector<std::uint32_t> list_offsets;
        int save_calls{ 0 };
        int list_passkey_calls{ 0 };
        int delete_passkey_calls{ 0 };
        std::wstring deleted_passkey_id;
        int close_calls{ 0 };
        std::atomic_bool closed{ false };

        [[nodiscard]] ClientResult GetStatus() override
        {
            ++status_calls;
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            return status_result;
        }

        [[nodiscard]] ClientResult CreateVault(SecretText const& master_password) override
        {
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            password_matched = master_password.value() == expected_password;
            return create_result;
        }

        [[nodiscard]] ClientResult Unlock(SecretText const& master_password) override
        {
            ++unlock_calls;
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            password_matched = master_password.value() == expected_password;
            return unlock_result;
        }

        [[nodiscard]] ClientResult UnlockWindowsHello(
            std::uintptr_t const parent_window) override
        {
            ++windows_hello_unlock_calls;
            windows_hello_parent_window = parent_window;
            return closed.load(std::memory_order_acquire) ?
                Closed() : windows_hello_unlock_result;
        }

        [[nodiscard]] ClientResult EnrollWindowsHello(
            std::uintptr_t const parent_window) override
        {
            ++windows_hello_enroll_calls;
            windows_hello_parent_window = parent_window;
            return closed.load(std::memory_order_acquire) ?
                Closed() : windows_hello_enroll_result;
        }

        [[nodiscard]] ClientResult RemoveWindowsHello() override
        {
            ++windows_hello_remove_calls;
            return closed.load(std::memory_order_acquire) ?
                Closed() : windows_hello_remove_result;
        }

        [[nodiscard]] ClientResult Lock() override
        {
            ++lock_calls;
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            return lock_result;
        }

        [[nodiscard]] AccountListResult ListAccounts(
            std::uint32_t const offset) override
        {
            list_offsets.push_back(offset);
            if (closed.load(std::memory_order_acquire))
            {
                return { ClientError::Cancelled, {} };
            }
            return list_result;
        }

        [[nodiscard]] ClientResult SaveAccount(AccountDraft const& account) override
        {
            ++save_calls;
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            password_matched = account.password.value() == expected_password;
            if (save_result.error == ClientError::None)
            {
                list_result.accounts.push_back({
                    L"test-record",
                    account.service_name,
                    account.origin,
                    account.username,
                });
            }
            return save_result;
        }

        [[nodiscard]] PasskeyListResult ListPasskeys() override
        {
            ++list_passkey_calls;
            if (closed.load(std::memory_order_acquire))
            {
                return { ClientError::Cancelled, {} };
            }
            return passkey_list_result;
        }

        [[nodiscard]] ClientResult DeletePasskey(
            std::wstring_view const credential_id) override
        {
            ++delete_passkey_calls;
            deleted_passkey_id = credential_id;
            if (closed.load(std::memory_order_acquire))
            {
                return Closed();
            }
            if (delete_passkey_result.error == ClientError::None)
            {
                passkey_list_result.passkeys.clear();
            }
            return delete_passkey_result;
        }

        void Close() noexcept override
        {
            ++close_calls;
            closed.store(true, std::memory_order_release);
        }

    private:
        [[nodiscard]] static ClientResult Closed() noexcept
        {
            return { ClientError::Cancelled, VaultStatus::Locked };
        }
    };

    std::shared_ptr<FakeDesktopClient> ClientWithStatus(VaultStatus const status)
    {
        auto client = std::make_shared<FakeDesktopClient>();
        client->status_result = { ClientError::None, status };
        return client;
    }

    void InitializeModel(ShellViewModel& model)
    {
        if (model.BeginInitialize())
        {
            model.CompleteInitialize(model.ExecuteStatusRequest());
        }
    }

    void TestInitialStates(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::FirstRun);
            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.State() == ShellState::FirstRun, "first-run status maps to setup");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.State() == ShellState::Locked, "locked status maps to unlock");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.State() == ShellState::Unlocked, "unlocked status maps to accounts");
            test.Check(model.Accounts().size() == 1, "unlocked status loads account summaries");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->status_result.error = ClientError::AgentUnavailable;
            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(
                model.State() == ShellState::AgentUnavailable,
                "unavailable agent fails closed");
        }
    }

    void TestUnlockLifecycle(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Locked);
        client->expected_password = L"disposable unlock";
        client->list_result.accounts.push_back(
            { L"record", L"Example", L"https://example.com", L"person" });

        ShellViewModel model{ client };
        InitializeModel(model);

        test.Check(model.BeginUnlock(), "locked vault begins unlock");
        test.Check(model.State() == ShellState::Unlocking, "unlocking is a distinct state");

        SecretText password{ L"disposable unlock" };
        auto unlock_outcome = model.ExecuteUnlockRequest(password);
        test.Check(
            model.State() == ShellState::Unlocking,
            "worker-side unlock I/O does not mutate the UI model");
        model.CompleteUnlock(std::move(unlock_outcome));

        test.Check(client->password_matched, "unlock forwards the typed secret without storing it");
        test.Check(client->unlock_calls == 1, "unlock is submitted exactly once");
        test.Check(model.State() == ShellState::Unlocked, "successful unlock opens accounts");
        test.Check(model.Accounts().size() == 1, "successful unlock refreshes account summaries");

        test.Check(model.BeginLock(), "unlocked vault begins locking");
        test.Check(
            model.IsLockRequestPending(),
            "accepted lock remains identifiable until its client result");
        test.Check(
            model.State() == ShellState::Unlocking,
            "lock uses the busy security state");
        test.Check(
            model.Accounts().empty(),
            "lock intent hides account summaries before the client call");
        auto lock_outcome = model.ExecuteLockRequest();
        test.Check(
            model.IsLockRequestPending(),
            "worker-side lock I/O leaves completion on the UI model");
        model.CompleteLock(std::move(lock_outcome));
        test.Check(
            !model.IsLockRequestPending(),
            "completed lock no longer reports an in-flight request");
        test.Check(model.State() == ShellState::Locked, "lock returns to the native unlock surface");
        test.Check(model.Accounts().empty(), "lock clears account summaries from the view model");
    }

    void TestPostUnlockPasskeyRefreshCancellation(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Locked);
        client->expected_password = L"disposable refresh cancellation";
        client->list_result.accounts.push_back(
            { L"record", L"Example", L"https://example.com", L"person" });
        client->passkey_list_result = { ClientError::Cancelled, {} };
        ShellViewModel model{ client };
        InitializeModel(model);

        test.Check(model.BeginUnlock(), "unlock begins before a canceled passkey refresh");
        SecretText password{ L"disposable refresh cancellation" };
        model.CompleteUnlock(model.ExecuteUnlockRequest(password));

        test.Check(
            model.State() == ShellState::Unlocked,
            "a canceled post-unlock passkey refresh preserves the confirmed unlocked state");
        test.Check(
            model.Accounts().size() == 1U,
            "a canceled passkey refresh preserves loaded account summaries");
        test.Check(
            model.Passkeys().empty(),
            "a canceled passkey refresh exposes no stale passkey summaries");
    }

    void TestPasskeyDeletionLifecycle(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Unlocked);
        std::wstring const credential_id(64U, L'a');
        client->passkey_list_result.passkeys.push_back({
            credential_id,
            L"example.com",
            L"person@example.com",
            L"Disposable Person",
        });
        ShellViewModel model{ client };
        InitializeModel(model);
        test.Check(model.Passkeys().size() == 1U, "unlocked status loads passkey summaries");
        test.Check(model.BeginDeletePasskey(), "unlocked vault begins passkey deletion");
        auto outcome = model.ExecuteDeletePasskeyRequest(credential_id);
        model.CompleteDeletePasskey(std::move(outcome));
        test.Check(client->delete_passkey_calls == 1, "passkey deletion is submitted once");
        test.Check(
            client->deleted_passkey_id == credential_id,
            "passkey deletion uses the selected public credential ID");
        test.Check(model.State() == ShellState::Unlocked, "passkey deletion keeps vault unlocked");
        test.Check(model.Passkeys().empty(), "passkey deletion refreshes the management list");
    }

    void TestActivationRefreshFailsClosed(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Unlocked);
        client->list_result.accounts.push_back(
            { L"record", L"Example", L"https://example.com", L"person" });
        ShellViewModel model{ client };
        InitializeModel(model);

        client->status_result = { ClientError::AgentUnavailable, VaultStatus::Locked };
        test.Check(model.BeginRefresh(), "window reactivation begins a status refresh");
        test.Check(
            model.Accounts().empty(),
            "window reactivation clears cached account summaries before transport I/O");
        model.CompleteRefresh(model.ExecuteStatusRequest());
        test.Check(
            model.State() == ShellState::AgentUnavailable,
            "lifecycle agent shutdown remains fail closed after reactivation");
    }

    void TestAccountPagingIsBounded(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Unlocked);
        client->list_result.accounts.push_back(
            { L"first", L"First", L"https://first.example", L"person" });
        client->list_result.next_offset = 100U;
        ShellViewModel model{ client };
        InitializeModel(model);

        test.Check(
            client->list_offsets == std::vector<std::uint32_t>{ 0U },
            "initial account loading requests only the first bounded page");
        test.Check(model.HasNextAccountPage(), "first account page exposes next navigation");
        test.Check(
            !model.HasPreviousAccountPage(),
            "first account page has no previous navigation");

        client->list_result.accounts = {
            { L"second", L"Second", L"https://second.example", L"person" },
        };
        client->list_result.next_offset.reset();
        auto const next_offset = model.BeginNextAccountPage();
        test.Check(next_offset == 100U, "next navigation uses the server continuation offset");
        model.CompleteNextAccountPage(
            model.ExecuteAccountPageRequest(next_offset.value_or(0U)));
        test.Check(
            model.Accounts().size() == 1 && model.Accounts().front().id == L"second",
            "next navigation replaces rather than accumulates account controls");
        test.Check(
            model.HasPreviousAccountPage() && !model.HasNextAccountPage(),
            "last account page exposes only previous navigation");

        client->list_result.accounts = {
            { L"first", L"First", L"https://first.example", L"person" },
        };
        client->list_result.next_offset = 100U;
        auto const previous_offset = model.BeginPreviousAccountPage();
        test.Check(previous_offset == 0U, "previous navigation restores the prior page offset");
        model.CompletePreviousAccountPage(
            model.ExecuteAccountPageRequest(previous_offset.value_or(0U)));
        test.Check(
            model.Accounts().size() == 1 && model.Accounts().front().id == L"first",
            "previous navigation restores the prior bounded page");
        test.Check(
            !model.HasPreviousAccountPage() && model.HasNextAccountPage(),
            "returning to the first page restores its navigation state");
    }

    void TestUnlockFailuresAreSafe(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->unlock_result = { ClientError::InvalidCredentials, VaultStatus::Locked };

            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.BeginUnlock(), "failed unlock starts from locked state");

            SecretText password{ L"do-not-render-this-value" };
            model.CompleteUnlock(model.ExecuteUnlockRequest(password));

            test.Check(
                model.State() == ShellState::Locked,
                "invalid credentials return directly to the locked surface");
            test.Check(
                model.Message().find(L"do-not-render-this-value") == std::wstring::npos,
                "failed unlock never renders the submitted secret");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->unlock_result = { ClientError::Unexpected, VaultStatus::Locked };

            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.BeginUnlock(), "unexpected unlock begins from locked state");

            SecretText password{ L"disposable unexpected failure" };
            model.CompleteUnlock(model.ExecuteUnlockRequest(password));

            test.Check(
                model.State() == ShellState::Error,
                "unexpected unlock uses the distinct error state");
        }
    }

    void TestWindowsHelloLifecycle(TestContext& test)
    {
        constexpr std::uintptr_t parent_window = 0x1234U;
        auto client = ClientWithStatus(VaultStatus::Locked);
        client->list_result.accounts.push_back(
            { L"record", L"Example", L"https://example.com", L"person" });
        ShellViewModel model{ client };
        InitializeModel(model);

        test.Check(
            !model.BeginWindowsHelloEnrollment(),
            "Windows Hello enrollment is unavailable while locked");
        test.Check(
            !model.BeginWindowsHelloRemoval(),
            "Windows Hello removal is unavailable while locked");
        test.Check(model.BeginWindowsHelloUnlock(), "locked vault begins Windows Hello unlock");
        test.Check(
            model.State() == ShellState::Unlocking,
            "Windows Hello unlock uses the busy security state");
        model.CompleteWindowsHelloUnlock(
            model.ExecuteWindowsHelloUnlockRequest(parent_window));

        test.Check(
            client->windows_hello_unlock_calls == 1,
            "Windows Hello unlock is submitted exactly once");
        test.Check(
            client->windows_hello_parent_window == parent_window,
            "Windows Hello unlock forwards the native parent window");
        test.Check(
            model.State() == ShellState::Unlocked,
            "successful Windows Hello unlock opens accounts");
        test.Check(
            model.Accounts().size() == 1,
            "successful Windows Hello unlock refreshes account summaries");

        test.Check(
            model.BeginWindowsHelloEnrollment(),
            "unlocked vault begins Windows Hello enrollment");
        model.CompleteWindowsHelloEnrollment(
            model.ExecuteWindowsHelloEnrollmentRequest(parent_window));
        test.Check(
            client->windows_hello_enroll_calls == 1,
            "Windows Hello enrollment is submitted exactly once");
        test.Check(
            model.State() == ShellState::Unlocked && model.Accounts().size() == 1,
            "successful enrollment preserves the unlocked account surface");
        test.Check(
            model.Message().find(L"enabled") != std::wstring::npos &&
                model.Message().find(L"master password") != std::wstring::npos,
            "successful enrollment confirms the master-password fallback");

        test.Check(
            model.BeginWindowsHelloRemoval(),
            "unlocked vault begins Windows Hello removal");
        model.CompleteWindowsHelloRemoval(model.ExecuteWindowsHelloRemovalRequest());
        test.Check(
            client->windows_hello_remove_calls == 1,
            "Windows Hello removal is submitted exactly once");
        test.Check(
            model.State() == ShellState::Unlocked && model.Accounts().size() == 1,
            "successful removal preserves the unlocked account surface");
        test.Check(
            model.Message().find(L"removed") != std::wstring::npos &&
                model.Message().find(L"vault") != std::wstring::npos,
            "successful removal confirms the vault is unchanged");
    }

    void TestWindowsHelloFailuresPreserveFallback(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->windows_hello_unlock_result = {
                ClientError::WindowsHelloUnavailable,
                VaultStatus::Locked,
            };
            ShellViewModel model{ client };
            InitializeModel(model);

            test.Check(model.BeginWindowsHelloUnlock(), "unavailable Hello unlock begins");
            model.CompleteWindowsHelloUnlock(
                model.ExecuteWindowsHelloUnlockRequest(0x1234U));

            test.Check(
                model.State() == ShellState::Locked,
                "unavailable Windows Hello remains locked");
            test.Check(
                model.Message().find(L"master password") != std::wstring::npos,
                "unavailable Windows Hello explains the master-password fallback");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->windows_hello_unlock_result = {
                ClientError::Cancelled,
                VaultStatus::Locked,
            };
            ShellViewModel model{ client };
            InitializeModel(model);

            test.Check(model.BeginWindowsHelloUnlock(), "cancelled Hello unlock begins");
            model.CompleteWindowsHelloUnlock(
                model.ExecuteWindowsHelloUnlockRequest(0x1234U));

            test.Check(
                model.State() == ShellState::Locked,
                "cancelled Windows Hello remains locked");
            test.Check(
                model.Message().find(L"master password") != std::wstring::npos,
                "cancelled Windows Hello explains the master-password fallback");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            client->windows_hello_enroll_result = {
                ClientError::WindowsHelloUnavailable,
                VaultStatus::Unlocked,
            };
            ShellViewModel model{ client };
            InitializeModel(model);

            test.Check(
                model.BeginWindowsHelloEnrollment(),
                "unavailable Hello enrollment begins while unlocked");
            model.CompleteWindowsHelloEnrollment(
                model.ExecuteWindowsHelloEnrollmentRequest(0x1234U));

            test.Check(
                model.State() == ShellState::Unlocked,
                "failed Windows Hello enrollment preserves unlocked state");
            test.Check(
                model.Accounts().size() == 1,
                "failed Windows Hello enrollment preserves account summaries");
        }
    }

    void TestCreateAndAccountEditor(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::FirstRun);
        client->expected_password = L"disposable setup";

        ShellViewModel model{ client };
        InitializeModel(model);
        test.Check(model.BeginCreate(), "first run begins vault creation");
        test.Check(model.State() == ShellState::Unlocking, "vault creation uses the busy security state");

        SecretText setup_password{ L"disposable setup" };
        model.CompleteCreate(model.ExecuteCreateRequest(setup_password));
        test.Check(client->password_matched, "vault creation forwards the typed secret");
        test.Check(model.State() == ShellState::Unlocked, "created vault opens account management");

        model.ShowAccountEditor();
        test.Check(model.IsAccountEditorVisible(), "account editor opens only while unlocked");

        client->expected_password = L"disposable account";
        AccountDraft draft{
            L"Example",
            L"https://example.com",
            L"person",
            SecretText{ L"disposable account" },
        };
        test.Check(model.BeginSaveAccount(), "account editor begins saving");
        test.Check(model.State() == ShellState::Saving, "account save uses a busy state");
        model.CompleteSaveAccount(model.ExecuteSaveAccountRequest(draft));

        test.Check(client->password_matched, "account editor forwards its password as secret text");
        test.Check(client->save_calls == 1, "account editor submits exactly once");
        test.Check(!model.IsAccountEditorVisible(), "successful save closes the account editor");
        test.Check(model.Accounts().size() == 1, "successful save refreshes account summaries");
    }

    void TestProductionClientFailsClosed(TestContext& test)
    {
        ShellViewModel model{ librarian::windows::MakeDesktopClient() };
        InitializeModel(model);
        test.Check(
            model.State() == ShellState::AgentUnavailable,
            "the unpackaged production client never simulates an unlocked vault");
    }

    void TestCancelledActionsResumeSafely(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->unlock_result = { ClientError::Cancelled, VaultStatus::Locked };
            ShellViewModel model{ client };
            InitializeModel(model);
            test.Check(model.BeginUnlock(), "cancelled unlock begins from locked state");

            SecretText password{ L"disposable cancelled unlock" };
            model.CompleteUnlock(model.ExecuteUnlockRequest(password));

            test.Check(
                model.State() == ShellState::Locked,
                "cancelled unlock returns to the locked state");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            client->lock_result = { ClientError::Cancelled, VaultStatus::Unlocked };
            ShellViewModel model{ client };
            InitializeModel(model);

            test.Check(model.BeginLock(), "cancelled lock begins from the unlocked state");
            model.CompleteLock(model.ExecuteLockRequest());

            test.Check(
                model.State() == ShellState::Error,
                "cancelled lock hides access until lock is retried");
            test.Check(
                model.Accounts().empty(),
                "cancelled lock clears cached account summaries");

            client->lock_result = { ClientError::None, VaultStatus::Locked };
            test.Check(model.BeginRetry(), "retry preserves the pending lock intent");
            test.Check(
                model.IsLockRequestPending(),
                "lock retry remains identifiable for close-time completion");
            test.Check(
                model.State() == ShellState::Unlocking,
                "lock retry remains in the busy fail-closed state");
            model.CompleteRetry(model.ExecuteLockRequest());

            test.Check(
                !model.IsLockRequestPending(),
                "completed lock retry clears its in-flight request marker");
            test.Check(
                client->lock_calls == 2,
                "lock retry sends a second lock instead of refreshing status");
            test.Check(
                client->status_calls == 1,
                "lock retry does not reopen from an unlocked status response");
            test.Check(
                model.State() == ShellState::Locked,
                "lock retry requires an authoritative locked result");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            client->save_result = { ClientError::Cancelled, VaultStatus::Unlocked };
            ShellViewModel model{ client };
            InitializeModel(model);
            model.ShowAccountEditor();

            AccountDraft draft{
                L"Example",
                L"https://example.com",
                L"person",
                SecretText{ L"disposable cancelled save" },
            };
            test.Check(model.BeginSaveAccount(), "cancelled save begins from the editor");
            model.CompleteSaveAccount(model.ExecuteSaveAccountRequest(draft));

            test.Check(
                model.State() == ShellState::Unlocked,
                "cancelled save keeps the unlocked state");
            test.Check(
                model.IsAccountEditorVisible(),
                "cancelled save keeps the account editor open");
            test.Check(
                model.Accounts().size() == 1,
                "cancelled save keeps the current account summaries");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.error = ClientError::Cancelled;
            ShellViewModel model{ client };

            InitializeModel(model);

            test.Check(
                model.State() == ShellState::Error,
                "cancelled account loading requires an authoritative retry");
            test.Check(
                model.Accounts().empty(),
                "cancelled account loading returns no partial summaries");
            test.Check(
                model.Message().find(L"account list") != std::wstring::npos,
                "cancelled account loading is not presented as an empty vault");
        }
    }

    void TestWindowCloseLatchesDesktopClient(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Locked);
        client->expected_password = L"must not be observed after close";
        ShellViewModel model{ client };
        InitializeModel(model);
        test.Check(model.BeginUnlock(), "unlock can be queued before window close");

        model.Close();
        SecretText password{ L"must not be observed after close" };
        model.CompleteUnlock(model.ExecuteUnlockRequest(password));

        test.Check(
            client->close_calls == 1,
            "window close permanently closes the desktop client");
        test.Check(
            client->unlock_calls == 1,
            "request startup after close reaches the client latch");
        test.Check(
            !client->password_matched,
            "the closed client rejects later requests before observing their secret");
        test.Check(
            model.State() == ShellState::Locked,
            "a request rejected by the close latch remains fail closed");
    }

    std::string ReadFile(std::string const& path)
    {
        std::ifstream input{ path, std::ios::binary };
        std::ostringstream contents;
        contents << input.rdbuf();
        return contents.str();
    }

    void TestXamlContract(TestContext& test, std::string const& path)
    {
        auto const xaml = ReadFile(path);
        test.Check(!xaml.empty(), "WinUI shell XAML can be read");

        std::vector<std::string_view> const required{
            "x:Name=\"FirstRunPanel\"",
            "x:Name=\"LockedPanel\"",
            "x:Name=\"UnlockingPanel\"",
            "x:Name=\"UnlockedPanel\"",
            "x:Name=\"ErrorPanel\"",
            "x:Name=\"AgentUnavailablePanel\"",
            "x:Name=\"UnlockingProgressRing\"",
            "Activated=\"OnActivated\"",
            "Closed=\"OnClosed\"",
            "AutomationProperties.LiveSetting=\"Polite\"",
            "x:Name=\"StateDescriptionTextBlock\"",
            "AutomationProperties.Name=\"Master password\"",
            "PasswordRevealMode=\"Hidden\"",
            "IsTabStop=\"True\"",
            "Click=\"OnUnlockClicked\"",
            "x:Name=\"WindowsHelloUnlockButton\"",
            "Click=\"OnWindowsHelloUnlockClicked\"",
            "x:Name=\"WindowsHelloEnrollButton\"",
            "Click=\"OnWindowsHelloEnrollClicked\"",
            "x:Name=\"WindowsHelloRemoveButton\"",
            "Click=\"OnWindowsHelloRemoveClicked\"",
            "Or use your master password.",
            "Click=\"OnRetryClicked\"",
            "x:Name=\"AccountPaginationPanel\"",
            "Click=\"OnPreviousAccountPageClicked\"",
            "Click=\"OnNextAccountPageClicked\"",
            "x:Name=\"PasskeysListView\"",
            "Click=\"OnDeletePasskeyClicked\"",
        };

        for (auto const fragment : required)
        {
            test.Check(
                xaml.find(fragment) != std::string::npos,
                std::string{ "XAML contains " } + std::string{ fragment });
        }

        test.Check(
            xaml.find("<WebView") == std::string::npos &&
                xaml.find("<WebView2") == std::string::npos,
            "native unlock shell contains no web view");
        test.Check(
            xaml.find(" Password=\"") == std::string::npos,
            "XAML never embeds or binds a password value");
    }

    void TestWindowSourceContract(TestContext& test, std::string const& path)
    {
        auto const source = ReadFile(path);
        test.Check(!source.empty(), "WinUI shell source can be read");

        std::vector<std::string_view> const required{
            "view_model_.Close();",
            "MasterPasswordBox().Password(L\"\");",
            "AccountPasswordBox().Password(L\"\");",
            "L\"Service name: \"",
            "L\"Website origin: \"",
            "L\"Username: \"",
            "void MainWindow::OnActivated",
            "lock_request_in_flight_.store(true",
            "lifetime->CloseDesktopClient();",
            "FocusManager::",
            "GetFocusedElement(lifetime->RootLayout().XamlRoot())",
            "dispatcher.TryEnqueue([lifetime, outcome]",
            "CompleteInitialize(std::move(*outcome))",
            "CompleteRefresh(std::move(*outcome))",
            "CompleteCreate(std::move(*outcome))",
            "CompleteUnlock(std::move(*outcome))",
            "CompleteWindowsHelloUnlock(std::move(*outcome))",
            "CompleteWindowsHelloEnrollment(std::move(*outcome))",
            "CompleteWindowsHelloRemoval(std::move(*outcome))",
            "CompleteLock(std::move(*outcome))",
            "CompleteRetry(std::move(*outcome))",
            "CompleteSaveAccount(std::move(*outcome))",
            "CompleteDeletePasskey(std::move(*outcome))",
            "fire_and_forget MainWindow::OnLoaded",
            "void MainWindow::OnSecurityTimerTick",
            "GetLastInputInfo(&information)",
            "ContentDialog()",
            "Enable Windows Hello unlock?",
            "Remove Windows Hello unlock?",
            "try_as<::IWindowNative>()",
            "fire_and_forget MainWindow::OnLockClicked",
            "fire_and_forget MainWindow::OnRetryClicked",
            "fire_and_forget MainWindow::OnSaveAccountClicked",
            "fire_and_forget MainWindow::NavigateAccountPage",
        };

        for (auto const fragment : required)
        {
            test.Check(
                source.find(fragment) != std::string::npos,
                std::string{ "window source contains " } + std::string{ fragment });
        }
    }
}

int main(int const argc, char const* const* const argv)
{
    if (argc == 2 && std::string_view{argv[1]} == "--echo-native-host-streams") return EchoNativeHostStreams();
    TestContext test;
    TestNativeHostStreams(test);
    TestDesktopLaunchArguments(test);
    TestRegistrationResults(test);
    TestLaunchOperations(test);
    TestInitialStates(test);
    TestUnlockLifecycle(test);
    TestPostUnlockPasskeyRefreshCancellation(test);
    TestPasskeyDeletionLifecycle(test);
    TestActivationRefreshFailsClosed(test);
    TestAccountPagingIsBounded(test);
    TestUnlockFailuresAreSafe(test);
    TestWindowsHelloLifecycle(test);
    TestWindowsHelloFailuresPreserveFallback(test);
    TestCreateAndAccountEditor(test);
    TestProductionClientFailsClosed(test);
    TestCancelledActionsResumeSafely(test);
    TestWindowCloseLatchesDesktopClient(test);

    if (
        argc == 5 &&
        std::string_view{ argv[1] } == "--xaml" &&
        std::string_view{ argv[3] } == "--source")
    {
        TestXamlContract(test, argv[2]);
        TestWindowSourceContract(test, argv[4]);
    }
    else
    {
        test.Check(false, "XAML and window source path arguments are required");
    }

    if (test.Failures() != 0)
    {
        std::cerr << test.Failures() << " Windows shell test(s) failed\n";
        return 1;
    }

    std::cout << "Windows shell tests passed\n";
    return 0;
}
