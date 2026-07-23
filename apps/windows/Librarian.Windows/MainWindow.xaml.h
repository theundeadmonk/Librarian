#pragma once

#include "MainWindow.g.h"

namespace winrt::Librarian::Windows::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow() = default;
    };
}

namespace winrt::Librarian::Windows::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
