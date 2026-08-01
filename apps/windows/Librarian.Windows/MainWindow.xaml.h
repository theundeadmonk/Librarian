#pragma once

#include "MainWindow.g.h"
#include "ShellViewModel.h"

#include <atomic>

namespace winrt::Librarian::Windows::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        winrt::fire_and_forget OnLoaded(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnActivated(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::WindowActivatedEventArgs const&);
        void OnClosed(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::WindowEventArgs const&);
        winrt::fire_and_forget OnCreateVaultClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnUnlockClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnWindowsHelloUnlockClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnWindowsHelloEnrollClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnWindowsHelloRemoveClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnLockClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnRetryClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnNewAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnCancelAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnSaveAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnPreviousAccountPageClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnNextAccountPageClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);

    private:
        void Render();
        void RenderAccounts();
        void OnSecurityTimerTick();
        winrt::fire_and_forget RefreshAfterActivation();
        winrt::fire_and_forget LockVault();
        winrt::fire_and_forget NavigateAccountPage(bool next);
        [[nodiscard]] bool FocusCurrentState();
        void QueueFocusCurrentState();
        void QueueFocusForActivation();
        void RenderSecurityTransitionIfOpen();
        void RenderAccountSaveIfOpen();
        void CloseDesktopClient() noexcept;
        void ClearSetupPasswords();
        void ClearAccountEditor();
        [[nodiscard]] std::uintptr_t ParentWindowHandle() noexcept;

        librarian::windows::ShellViewModel view_model_;
        std::atomic_bool is_closed_{ false };
        std::atomic_bool client_closed_{ false };
        std::atomic_bool lock_request_in_flight_{ false };
        Microsoft::UI::Dispatching::DispatcherQueueTimer security_timer_{ nullptr };
        bool is_loaded_{ false };
        bool is_active_{ false };
    };
}

namespace winrt::Librarian::Windows::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
