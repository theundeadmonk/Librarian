#include "pch.h"
#include "App.xaml.h"
#include "MainWindow.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

namespace winrt::Librarian::Windows::implementation
{
    App::App()
    {
#if defined _DEBUG && !defined DISABLE_XAML_GENERATED_BREAK_ON_UNHANDLED_EXCEPTION
        UnhandledException([](IInspectable const&, UnhandledExceptionEventArgs const& event)
        {
            if (IsDebuggerPresent())
            {
                [[maybe_unused]] auto const message = event.Message();
                __debugbreak();
            }
        });
#endif
    }

    void App::OnLaunched([[maybe_unused]] LaunchActivatedEventArgs const& event)
    {
        if (!window)
        {
            window = make<MainWindow>();
            window.Closed([this](
                [[maybe_unused]] IInspectable const& sender,
                [[maybe_unused]] WindowEventArgs const& event)
            {
                window = nullptr;
            });
        }
        window.Activate();
    }
}
