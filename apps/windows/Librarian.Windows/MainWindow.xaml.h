#pragma once

#include "MainWindow.g.h"
#include "ShellViewModel.h"

#include <atomic>

namespace winrt::Librarian::Windows::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        void OnLoaded(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnClosed(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::WindowEventArgs const&);
        winrt::fire_and_forget OnCreateVaultClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        winrt::fire_and_forget OnUnlockClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnLockClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnRetryClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnNewAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnCancelAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);
        void OnSaveAccountClicked(
            winrt::Windows::Foundation::IInspectable const&,
            Microsoft::UI::Xaml::RoutedEventArgs const&);

    private:
        void Render();
        void RenderAccounts();
        void FocusCurrentState();
        void RenderSecurityTransitionIfOpen();
        void ClearSetupPasswords();
        void ClearAccountEditor();

        librarian::windows::ShellViewModel view_model_;
        std::atomic_bool is_closed_{ false };
        bool is_loaded_{ false };
    };
}

namespace winrt::Librarian::Windows::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
