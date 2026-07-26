#include "pch.h"
#include "MainWindow.xaml.h"

#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>

#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

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
        QueueFocusCurrentState();

        co_await resume_background();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        lifetime->view_model_.CompleteInitialize();
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
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
        is_active_ = event.WindowActivationState() != WindowActivationState::Deactivated;
        if (is_active_)
        {
            QueueFocusForActivation();
        }
    }

    void MainWindow::OnClosed(
        [[maybe_unused]] IInspectable const& sender,
        [[maybe_unused]] WindowEventArgs const& event)
    {
        is_closed_.store(true, std::memory_order_release);
        is_active_ = false;
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
        lifetime->view_model_.CompleteCreate(password);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
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
        lifetime->view_model_.CompleteUnlock(password);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
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
        auto lifetime = get_strong();
        auto const dispatcher = DispatcherQueue();

        if (!view_model_.BeginLock())
        {
            co_return;
        }

        lock_request_in_flight_.store(true, std::memory_order_release);
        Render();
        co_await resume_background();
        lifetime->view_model_.CompleteLock();
        lifetime->lock_request_in_flight_.store(false, std::memory_order_release);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            lifetime->CloseDesktopClient();
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
            lifetime->RenderSecurityTransitionIfOpen();
        }))
        {
            co_return;
        }
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
        lifetime->view_model_.CompleteRetry();
        lifetime->lock_request_in_flight_.store(false, std::memory_order_release);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            lifetime->CloseDesktopClient();
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
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
        lifetime->view_model_.CompleteSaveAccount(account);
        if (lifetime->is_closed_.load(std::memory_order_acquire))
        {
            co_return;
        }
        if (!dispatcher.TryEnqueue([lifetime]
        {
            lifetime->RenderAccountSaveIfOpen();
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
        }
        else if (state != ShellState::Saving)
        {
            AccountsListView().Items().Clear();
            ClearAccountEditor();
        }

        QueueFocusCurrentState();
    }

    void MainWindow::RenderAccounts()
    {
        auto const& accounts = view_model_.Accounts();
        AccountsListView().Items().Clear();
        EmptyAccountsTextBlock().Visibility(VisibleWhen(accounts.empty()));
        AccountsListView().Visibility(VisibleWhen(!accounts.empty()));

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
            return MasterPasswordBox().Focus(FocusState::Programmatic);
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
}
