#include "pch.h"
#include "MainWindow.xaml.h"

#include <microsoft.ui.xaml.window.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>

#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

#include <chrono>
#include <memory>
#include <cstdint>
#include <string>
#include <utility>

using namespace winrt;
using namespace Microsoft::UI::Xaml;
using namespace Microsoft::UI::Xaml::Automation;
using namespace Microsoft::UI::Xaml::Controls;

namespace winrt::Librarian::Windows::implementation
{
    namespace
    {
        constexpr DWORD InactivityLockMilliseconds = 15U * 60U * 1'000U;

        Visibility VisibleWhen(bool const value)
        {
            return value ? Visibility::Visible : Visibility::Collapsed;
        }

        hstring TitleFor(librarian::windows::ShellState const state)
        {
            using librarian::windows::ShellState;

            switch (state)
            {
            case ShellState::FirstRun:
                return L"First-run setup";
            case ShellState::Locked:
                return L"Vault locked";
            case ShellState::Unlocking:
                return L"Working securely";
            case ShellState::Saving:
                return L"Saving account";
            case ShellState::Unlocked:
                return L"Accounts";
            case ShellState::Error:
                return L"Librarian needs attention";
            case ShellState::AgentUnavailable:
                return L"Vault agent unavailable";
            }

            return L"Librarian";
        }
    }

    MainWindow::MainWindow() :
        view_model_(librarian::windows::MakeDesktopClient())
    {
        InitializeComponent();
        security_timer_ = DispatcherQueue().CreateTimer();
        security_timer_.Interval(std::chrono::seconds(1));
        security_timer_.IsRepeating(true);
        auto const weak = get_weak();
        security_timer_.Tick([weak](auto const&, auto const&)
        {
            if (auto const lifetime = weak.get())
            {
                lifetime->OnSecurityTimerTick();
            }
        });
        (void)view_model_.BeginInitialize();
        Render();
    }

    fire_and_forget MainWindow::OnLoaded(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        is_loaded_ = true;
        security_timer_.Start();
        QueueFocusCurrentState();

        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteStatusRequest());
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteInitialize(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    void MainWindow::OnActivated(
        [[maybe_unused]] IInspectable const& sender,
        WindowActivatedEventArgs const& event)
    {
        auto const was_active = is_active_;
        is_active_ = event.WindowActivationState() != WindowActivationState::Deactivated;
        if (is_active_)
        {
            QueueFocusForActivation();
            if (is_loaded_ && !was_active)
            {
                RefreshAfterActivation();
            }
        }
    }

    void MainWindow::OnClosed(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] WindowEventArgs const& event)
    {
        is_closed_.store(true, std::memory_order_release);
        is_active_ = false;
        security_timer_.Stop();
        if (!lock_request_in_flight_.load(std::memory_order_acquire))
        {
            CloseDesktopClient();
        }
        ClearSetupPasswords();
        MasterPasswordBox().Password(L"");
        AccountPasswordBox().Password(L"");
    }

    fire_and_forget MainWindow::OnCreateVaultClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        librarian::windows::SecretText password{ SetupPasswordBox().Password() };
        {
            librarian::windows::SecretText confirmation{ ConfirmPasswordBox().Password() };
            ClearSetupPasswords();

            if (password.empty())
            {
                StateDescriptionTextBlock().Text(
                    L"Enter a master password to create the vault.");
                SetupPasswordBox().Focus(FocusState::Programmatic);
                co_return;
            }

            if (password.value() != confirmation.value())
            {
                StateDescriptionTextBlock().Text(L"The master passwords do not match.");
                SetupPasswordBox().Focus(FocusState::Programmatic);
                co_return;
            }
        }

        if (!view_model_.BeginCreate())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteCreateRequest(password));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteCreate(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnUnlockClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        librarian::windows::SecretText password{ MasterPasswordBox().Password() };
        MasterPasswordBox().Password(L"");

        if (password.empty())
        {
            StateDescriptionTextBlock().Text(L"Enter your master password to unlock the vault.");
            MasterPasswordBox().Focus(FocusState::Programmatic);
            co_return;
        }

        if (!view_model_.BeginUnlock())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteUnlockRequest(password));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteUnlock(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnWindowsHelloUnlockClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        auto const parent_window = ParentWindowHandle();

        if (!view_model_.BeginWindowsHelloUnlock())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteWindowsHelloUnlockRequest(parent_window));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteWindowsHelloUnlock(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnWindowsHelloEnrollClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto confirmation = ContentDialog();
        confirmation.XamlRoot(RootLayout().XamlRoot());
        confirmation.Title(box_value(L"Enable Windows Hello unlock?"));
        confirmation.Content(box_value(
            L"Windows will ask you to create or verify a passkey for this vault. "
            L"Your master password remains the recovery and fallback unlock method."));
        confirmation.PrimaryButtonText(L"Enable");
        confirmation.CloseButtonText(L"Cancel");
        confirmation.DefaultButton(ContentDialogButton::Close);

        if (co_await confirmation.ShowAsync() != ContentDialogResult::Primary)
        {
            co_return;
        }
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }

        auto const dispatcher = DispatcherQueue();
        auto const parent_window = ParentWindowHandle();
        if (!view_model_.BeginWindowsHelloEnrollment())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteWindowsHelloEnrollmentRequest(parent_window));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteWindowsHelloEnrollment(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnWindowsHelloRemoveClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto confirmation = ContentDialog();
        confirmation.XamlRoot(RootLayout().XamlRoot());
        confirmation.Title(box_value(L"Remove Windows Hello unlock?"));
        confirmation.Content(box_value(
            L"This removes the Windows Hello convenience unlock. "
            L"Your vault and master-password unlock remain unchanged."));
        confirmation.PrimaryButtonText(L"Remove");
        confirmation.CloseButtonText(L"Cancel");
        confirmation.DefaultButton(ContentDialogButton::Close);

        if (co_await confirmation.ShowAsync() != ContentDialogResult::Primary)
        {
            co_return;
        }
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }

        auto const dispatcher = DispatcherQueue();
        if (!view_model_.BeginWindowsHelloRemoval())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteWindowsHelloRemovalRequest());
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteWindowsHelloRemoval(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnLockClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        return LockVault();
    }

    fire_and_forget MainWindow::OnRetryClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();

        if (!view_model_.BeginRetry())
        {
            co_return;
        }

        auto const retries_lock = view_model_.IsLockRequestPending();
        lock_request_in_flight_.store(retries_lock, std::memory_order_release);
        Render();
        co_await resume_background();
        if (
            lifetime->is_closed_.load(std::memory_order_acquire) &&
            !retries_lock)
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            retries_lock ?
                lifetime->view_model_.ExecuteLockRequest() :
                lifetime->view_model_.ExecuteStatusRequest());
        lifetime->lock_request_in_flight_.store(false, std::memory_order_release);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            lifetime->CloseDesktopClient();
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteRetry(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    void MainWindow::OnNewAccountClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        view_model_.ShowAccountEditor();
        Render();
        ServiceNameTextBox().Focus(FocusState::Programmatic);
    }

    void MainWindow::OnCancelAccountClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        view_model_.CancelAccountEditor();
        ClearAccountEditor();
        Render();
    }

    fire_and_forget MainWindow::OnSaveAccountClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        librarian::windows::SecretText password{ AccountPasswordBox().Password() };
        AccountPasswordBox().Password(L"");

        librarian::windows::AccountDraft account{
            std::wstring{ ServiceNameTextBox().Text() },
            std::wstring{ OriginTextBox().Text() },
            std::wstring{ UsernameTextBox().Text() },
            std::move(password),
        };

        if (!view_model_.BeginSaveAccount())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteSaveAccountRequest(account));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteSaveAccount(std::move(*outcome));
            lifetime->RenderAccountSaveIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::OnPreviousAccountPageClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        return NavigateAccountPage(false);
    }

    fire_and_forget MainWindow::OnNextAccountPageClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        return NavigateAccountPage(true);
    }

    fire_and_forget MainWindow::OnDeletePasskeyClicked(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] RoutedEventArgs const& event)
    {
        auto lifetime = get_strong();
        auto const index = PasskeysListView().SelectedIndex();
        auto const& passkeys = view_model_.Passkeys();
        if (index < 0 || static_cast<std::size_t>(index) >= passkeys.size())
        {
            co_return;
        }
        auto const passkey = passkeys[static_cast<std::size_t>(index)];
        auto confirmation = ContentDialog();
        confirmation.XamlRoot(RootLayout().XamlRoot());
        confirmation.Title(box_value(L"Delete this passkey?"));
        confirmation.Content(box_value(
            std::wstring{L"Delete the passkey for "} + passkey.rp_id +
            L" (" + passkey.user_name + L") from Windows and this vault?"));
        confirmation.PrimaryButtonText(L"Delete");
        confirmation.CloseButtonText(L"Cancel");
        confirmation.DefaultButton(ContentDialogButton::Close);
        if (co_await confirmation.ShowAsync() != ContentDialogResult::Primary ||
            lifetime->is_closed_.load(std::memory_order_acquire) ||
            !lifetime->view_model_.BeginDeletePasskey())
        {
            co_return;
        }

        auto const dispatcher = DispatcherQueue();
        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteDeletePasskeyRequest(passkey.credential_id));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteDeletePasskey(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    void MainWindow::Render()
    {
        using librarian::windows::ShellState;

        auto const state = view_model_.State();
        StateTitleTextBlock().Text(TitleFor(state));
        StateDescriptionTextBlock().Text(view_model_.Message());
        StateDescriptionTextBlock().Visibility(
            VisibleWhen(!view_model_.Message().empty()));

        FirstRunPanel().Visibility(VisibleWhen(state == ShellState::FirstRun));
        LockedPanel().Visibility(VisibleWhen(state == ShellState::Locked));
        auto const is_working =
            state == ShellState::Unlocking || state == ShellState::Saving;
        UnlockingPanel().Visibility(VisibleWhen(is_working));
        UnlockedPanel().Visibility(VisibleWhen(state == ShellState::Unlocked));
        ErrorPanel().Visibility(VisibleWhen(state == ShellState::Error));
        AgentUnavailablePanel().Visibility(
            VisibleWhen(state == ShellState::AgentUnavailable));

        UnlockingProgressRing().IsActive(is_working);
        AccountEditorPanel().Visibility(
            VisibleWhen(view_model_.IsAccountEditorVisible()));

        if (state == ShellState::Error)
        {
            ErrorInfoBar().Message(view_model_.Message());
        }

        if (state == ShellState::Unlocked)
        {
            RenderAccounts();
            RenderPasskeys();
        }
        else if (state != ShellState::Saving)
        {
            AccountsListView().Items().Clear();
            PasskeysListView().Items().Clear();
            ClearAccountEditor();
        }

        QueueFocusCurrentState();
    }

    void MainWindow::RenderPasskeys()
    {
        auto const& passkeys = view_model_.Passkeys();
        PasskeysListView().Items().Clear();
        EmptyPasskeysTextBlock().Visibility(VisibleWhen(passkeys.empty()));
        PasskeysListView().Visibility(VisibleWhen(!passkeys.empty()));
        DeletePasskeyButton().Visibility(VisibleWhen(!passkeys.empty()));
        for (auto const& passkey : passkeys)
        {
            auto details = StackPanel();
            details.Spacing(2);

            auto rp_id = TextBlock();
            rp_id.Text(passkey.rp_id);
            AutomationProperties::SetName(
                rp_id,
                hstring{std::wstring{L"Relying party: "} + passkey.rp_id});
            rp_id.Style(
                Application::Current().Resources().Lookup(
                    box_value(L"BodyStrongTextBlockStyle")).as<Style>());
            details.Children().Append(rp_id);

            auto user_name = TextBlock();
            user_name.Text(passkey.user_name);
            AutomationProperties::SetName(
                user_name,
                hstring{std::wstring{L"Passkey username: "} + passkey.user_name});
            user_name.TextWrapping(TextWrapping::Wrap);
            details.Children().Append(user_name);

            auto item = ListViewItem();
            item.Content(details);
            PasskeysListView().Items().Append(item);
        }
    }

    void MainWindow::RenderAccounts()
    {
        auto const& accounts = view_model_.Accounts();
        AccountsListView().Items().Clear();
        EmptyAccountsTextBlock().Visibility(VisibleWhen(accounts.empty()));
        AccountsListView().Visibility(VisibleWhen(!accounts.empty()));
        auto const has_previous = view_model_.HasPreviousAccountPage();
        auto const has_next = view_model_.HasNextAccountPage();
        AccountPaginationPanel().Visibility(VisibleWhen(has_previous || has_next));
        PreviousAccountPageButton().Visibility(VisibleWhen(has_previous));
        NextAccountPageButton().Visibility(VisibleWhen(has_next));

        for (auto const& account : accounts)
        {
            auto details = StackPanel();
            details.Spacing(2);

            auto service_name = TextBlock();
            service_name.Text(account.service_name);
            AutomationProperties::SetName(
                service_name,
                hstring{ std::wstring{ L"Service name: " } + account.service_name });
            service_name.Style(
                Application::Current().Resources().Lookup(
                    box_value(L"BodyStrongTextBlockStyle")).as<Style>());
            details.Children().Append(service_name);

            auto origin = TextBlock();
            origin.Text(account.origin);
            AutomationProperties::SetName(
                origin,
                hstring{ std::wstring{ L"Website origin: " } + account.origin });
            origin.TextWrapping(TextWrapping::Wrap);
            details.Children().Append(origin);

            auto username = TextBlock();
            username.Text(account.username);
            AutomationProperties::SetName(
                username,
                hstring{ std::wstring{ L"Username: " } + account.username });
            username.TextWrapping(TextWrapping::Wrap);
            details.Children().Append(username);

            auto item = ListViewItem();
            item.Content(details);
            item.IsTabStop(false);
            AccountsListView().Items().Append(item);
        }
    }

    bool MainWindow::FocusCurrentState()
    {
        using librarian::windows::ShellState;

        switch (view_model_.State())
        {
        case ShellState::FirstRun:
            return SetupPasswordBox().Focus(FocusState::Programmatic);
        case ShellState::Locked:
            return WindowsHelloUnlockButton().Focus(FocusState::Programmatic);
        case ShellState::Unlocking:
        case ShellState::Saving:
            return UnlockingProgressRing().Focus(FocusState::Programmatic);
        case ShellState::Unlocked:
            if (view_model_.IsAccountEditorVisible())
            {
                return ServiceNameTextBox().Focus(FocusState::Programmatic);
            }
            return AddAccountButton().Focus(FocusState::Programmatic);
        case ShellState::Error:
            return ErrorRetryButton().Focus(FocusState::Programmatic);
        case ShellState::AgentUnavailable:
            return AgentUnavailableRetryButton().Focus(FocusState::Programmatic);
        }

        return false;
    }

    void MainWindow::QueueFocusCurrentState()
    {
        if (
            !is_loaded_ ||
            !is_active_ ||
            is_closed_.load(std::memory_order_acquire))
        {
            return;
        }

        auto lifetime = get_strong();
        (void)DispatcherQueue().TryEnqueue(
            Microsoft::UI::Dispatching::DispatcherQueuePriority::Low,
            [lifetime]
            {
                if (
                    lifetime->is_active_ &&
                    !lifetime->is_closed_.load(std::memory_order_acquire))
                {
                    (void)lifetime->FocusCurrentState();
                }
            });
    }

    void MainWindow::QueueFocusForActivation()
    {
        if (
            !is_loaded_ ||
            !is_active_ ||
            is_closed_.load(std::memory_order_acquire))
        {
            return;
        }

        auto lifetime = get_strong();
        (void)DispatcherQueue().TryEnqueue(
            Microsoft::UI::Dispatching::DispatcherQueuePriority::Low,
            [lifetime]
            {
                if (
                    !lifetime->is_active_ ||
                    lifetime->is_closed_.load(std::memory_order_acquire))
                {
                    return;
                }

                auto const focused = Microsoft::UI::Xaml::Input::FocusManager::
                    GetFocusedElement(lifetime->RootLayout().XamlRoot());
                if (auto const control = focused.try_as<Controls::Control>())
                {
                    if (control.Focus(FocusState::Programmatic))
                    {
                        return;
                    }
                }

                (void)lifetime->FocusCurrentState();
            });
    }

    void MainWindow::RenderSecurityTransitionIfOpen()
    {
        if (is_closed_.load(std::memory_order_acquire))
        {
            return;
        }

        Render();
    }

    void MainWindow::RenderAccountSaveIfOpen()
    {
        if (is_closed_.load(std::memory_order_acquire))
        {
            return;
        }

        if (!view_model_.IsAccountEditorVisible())
        {
            ClearAccountEditor();
        }
        Render();
    }

    void MainWindow::CloseDesktopClient() noexcept
    {
        if (!client_closed_.exchange(true, std::memory_order_acq_rel))
        {
            view_model_.Close();
        }
    }

    void MainWindow::ClearSetupPasswords()
    {
        SetupPasswordBox().Password(L"");
        ConfirmPasswordBox().Password(L"");
    }

    void MainWindow::ClearAccountEditor()
    {
        ServiceNameTextBox().Text(L"");
        OriginTextBox().Text(L"");
        UsernameTextBox().Text(L"");
        AccountPasswordBox().Password(L"");
    }

    void MainWindow::OnSecurityTimerTick()
    {
        if (
            is_closed_.load(std::memory_order_acquire) ||
            view_model_.State() != librarian::windows::ShellState::Unlocked)
        {
            return;
        }

        LASTINPUTINFO information{ sizeof(LASTINPUTINFO), 0U };
        auto const input_observed = GetLastInputInfo(&information) != FALSE;
        auto const idle_milliseconds = GetTickCount() - information.dwTime;
        if (!input_observed || idle_milliseconds >= InactivityLockMilliseconds)
        {
            LockVault();
        }
    }

    fire_and_forget MainWindow::RefreshAfterActivation()
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        if (!view_model_.BeginRefresh())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteStatusRequest());
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteRefresh(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::LockVault()
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        if (!view_model_.BeginLock())
        {
            co_return;
        }

        lock_request_in_flight_.store(true, std::memory_order_release);
        Render();
        co_await resume_background();
        auto outcome = std::make_shared<librarian::windows::ShellRequestOutcome>(
            lifetime->view_model_.ExecuteLockRequest());
        lifetime->lock_request_in_flight_.store(false, std::memory_order_release);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            lifetime->CloseDesktopClient();
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, outcome]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            lifetime->view_model_.CompleteLock(std::move(*outcome));
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    fire_and_forget MainWindow::NavigateAccountPage(bool const next)
    {
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();
        auto const offset = next ?
            view_model_.BeginNextAccountPage() :
            view_model_.BeginPreviousAccountPage();
        if (!offset.has_value())
        {
            co_return;
        }

        Render();
        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        auto result = std::make_shared<librarian::windows::AccountListResult>(
            lifetime->view_model_.ExecuteAccountPageRequest(*offset));
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime, result, next]
        {
            if (lifetime->is_closed_.load(std::memory_order_acquire))
            {
                return;
            }
            if (next)
            {
                lifetime->view_model_.CompleteNextAccountPage(std::move(*result));
            }
            else
            {
                lifetime->view_model_.CompletePreviousAccountPage(std::move(*result));
            }
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
    }

    std::uintptr_t MainWindow::ParentWindowHandle() noexcept
    {
        try
        {
            auto const window_native = this->try_as<::IWindowNative>();
            if (!window_native)
            {
                return 0U;
            }

            HWND window_handle{};
            if (FAILED(window_native->get_WindowHandle(&window_handle)))
            {
                return 0U;
            }
            return reinterpret_cast<std::uintptr_t>(window_handle);
        }
        catch (...)
        {
            return 0U;
        }
    }
}
