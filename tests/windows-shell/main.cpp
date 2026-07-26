#include "../../apps/windows/Librarian.Windows/ShellViewModel.h"

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

    class FakeDesktopClient final : public IDesktopClient
    {
    public:
        ClientResult status_result{ ClientError::None, VaultStatus::Locked };
        ClientResult create_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult unlock_result{ ClientError::None, VaultStatus::Unlocked };
        ClientResult lock_result{ ClientError::None, VaultStatus::Locked };
        ClientResult save_result{ ClientError::None, VaultStatus::Unlocked };
        AccountListResult list_result{};
        std::wstring expected_password;
        bool password_matched{ false };
        int unlock_calls{ 0 };
        int save_calls{ 0 };
        int cancel_calls{ 0 };

        [[nodiscard]] ClientResult GetStatus() override
        {
            return status_result;
        }

        [[nodiscard]] ClientResult CreateVault(SecretText const& master_password) override
        {
            password_matched = master_password.value() == expected_password;
            return create_result;
        }

        [[nodiscard]] ClientResult Unlock(SecretText const& master_password) override
        {
            ++unlock_calls;
            password_matched = master_password.value() == expected_password;
            return unlock_result;
        }

        [[nodiscard]] ClientResult Lock() override
        {
            return lock_result;
        }

        [[nodiscard]] AccountListResult ListAccounts() override
        {
            return list_result;
        }

        [[nodiscard]] ClientResult SaveAccount(AccountDraft const& account) override
        {
            ++save_calls;
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

        void CancelPendingOperations() noexcept override
        {
            ++cancel_calls;
        }
    };

    std::shared_ptr<FakeDesktopClient> ClientWithStatus(VaultStatus const status)
    {
        auto client = std::make_shared<FakeDesktopClient>();
        client->status_result = { ClientError::None, status };
        return client;
    }

    void TestInitialStates(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::FirstRun);
            ShellViewModel model{ client };
            model.Initialize();
            test.Check(model.State() == ShellState::FirstRun, "first-run status maps to setup");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            ShellViewModel model{ client };
            model.Initialize();
            test.Check(model.State() == ShellState::Locked, "locked status maps to unlock");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            ShellViewModel model{ client };
            model.Initialize();
            test.Check(model.State() == ShellState::Unlocked, "unlocked status maps to accounts");
            test.Check(model.Accounts().size() == 1, "unlocked status loads account summaries");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->status_result.error = ClientError::AgentUnavailable;
            ShellViewModel model{ client };
            model.Initialize();
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
        model.Initialize();

        test.Check(model.BeginUnlock(), "locked vault begins unlock");
        test.Check(model.State() == ShellState::Unlocking, "unlocking is a distinct state");

        SecretText password{ L"disposable unlock" };
        model.CompleteUnlock(password);

        test.Check(client->password_matched, "unlock forwards the typed secret without storing it");
        test.Check(client->unlock_calls == 1, "unlock is submitted exactly once");
        test.Check(model.State() == ShellState::Unlocked, "successful unlock opens accounts");
        test.Check(model.Accounts().size() == 1, "successful unlock refreshes account summaries");

        model.Lock();
        test.Check(model.State() == ShellState::Locked, "lock returns to the native unlock surface");
        test.Check(model.Accounts().empty(), "lock clears account summaries from the view model");
    }

    void TestUnlockFailuresAreSafe(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->unlock_result = { ClientError::InvalidCredentials, VaultStatus::Locked };

            ShellViewModel model{ client };
            model.Initialize();
            test.Check(model.BeginUnlock(), "failed unlock starts from locked state");

            SecretText password{ L"do-not-render-this-value" };
            model.CompleteUnlock(password);

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
            model.Initialize();
            test.Check(model.BeginUnlock(), "unexpected unlock begins from locked state");

            SecretText password{ L"disposable unexpected failure" };
            model.CompleteUnlock(password);

            test.Check(
                model.State() == ShellState::Error,
                "unexpected unlock uses the distinct error state");
        }
    }

    void TestCreateAndAccountEditor(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::FirstRun);
        client->expected_password = L"disposable setup";

        ShellViewModel model{ client };
        model.Initialize();
        test.Check(model.BeginCreate(), "first run begins vault creation");
        test.Check(model.State() == ShellState::Unlocking, "vault creation uses the busy security state");

        SecretText setup_password{ L"disposable setup" };
        model.CompleteCreate(setup_password);
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
        model.CompleteSaveAccount(draft);

        test.Check(client->password_matched, "account editor forwards its password as secret text");
        test.Check(client->save_calls == 1, "account editor submits exactly once");
        test.Check(!model.IsAccountEditorVisible(), "successful save closes the account editor");
        test.Check(model.Accounts().size() == 1, "successful save refreshes account summaries");
    }

    void TestProductionClientFailsClosed(TestContext& test)
    {
        ShellViewModel model{ librarian::windows::MakeDesktopClient() };
        model.Initialize();
        test.Check(
            model.State() == ShellState::AgentUnavailable,
            "production placeholder never simulates an unlocked vault");
    }

    void TestCancelledActionsResumeSafely(TestContext& test)
    {
        {
            auto client = ClientWithStatus(VaultStatus::Locked);
            client->unlock_result = { ClientError::Cancelled, VaultStatus::Locked };
            ShellViewModel model{ client };
            model.Initialize();
            test.Check(model.BeginUnlock(), "cancelled unlock begins from locked state");

            SecretText password{ L"disposable cancelled unlock" };
            model.CompleteUnlock(password);

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
            model.Initialize();

            model.Lock();

            test.Check(
                model.State() == ShellState::Error,
                "cancelled lock hides access until status is rechecked");
            test.Check(
                model.Accounts().empty(),
                "cancelled lock clears cached account summaries");
        }

        {
            auto client = ClientWithStatus(VaultStatus::Unlocked);
            client->list_result.accounts.push_back(
                { L"record", L"Example", L"https://example.com", L"person" });
            client->save_result = { ClientError::Cancelled, VaultStatus::Unlocked };
            ShellViewModel model{ client };
            model.Initialize();
            model.ShowAccountEditor();

            AccountDraft draft{
                L"Example",
                L"https://example.com",
                L"person",
                SecretText{ L"disposable cancelled save" },
            };
            test.Check(model.BeginSaveAccount(), "cancelled save begins from the editor");
            model.CompleteSaveAccount(draft);

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

            model.Initialize();

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

    void TestCancellationReachesDesktopClient(TestContext& test)
    {
        auto client = ClientWithStatus(VaultStatus::Locked);
        ShellViewModel model{ client };
        model.Initialize();

        model.CancelPendingOperations();

        test.Check(
            client->cancel_calls == 1,
            "window lifecycle cancellation reaches the desktop client");
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
            "Closed=\"OnClosed\"",
            "AutomationProperties.LiveSetting=\"Polite\"",
            "x:Name=\"StateDescriptionTextBlock\"",
            "AutomationProperties.Name=\"Master password\"",
            "PasswordRevealMode=\"Hidden\"",
            "Click=\"OnUnlockClicked\"",
            "Click=\"OnRetryClicked\"",
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
            "view_model_.CancelPendingOperations();",
            "MasterPasswordBox().Password(L\"\");",
            "AccountPasswordBox().Password(L\"\");",
            "L\"Service name: \"",
            "L\"Website origin: \"",
            "L\"Username: \"",
            "fire_and_forget MainWindow::OnSaveAccountClicked",
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
    TestContext test;
    TestInitialStates(test);
    TestUnlockLifecycle(test);
    TestUnlockFailuresAreSafe(test);
    TestCreateAndAccountEditor(test);
    TestProductionClientFailsClosed(test);
    TestCancelledActionsResumeSafely(test);
    TestCancellationReachesDesktopClient(test);

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
