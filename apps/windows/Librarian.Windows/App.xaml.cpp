#include "pch.h"
#include "App.xaml.h"
#include "MainWindow.xaml.h"

#include <shlobj.h>

#include <winrt/Windows.ApplicationModel.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

namespace
{
    using winrt::Windows::ApplicationModel::PackageVersion;

    std::filesystem::path module_path()
    {
        std::vector<wchar_t> buffer(512U);
        while (true)
        {
            DWORD const length = GetModuleFileNameW(
                nullptr,
                buffer.data(),
                static_cast<DWORD>(buffer.size()));
            if (length == 0U)
            {
                return {};
            }
            if (static_cast<std::size_t>(length) <
                buffer.size() - 1U)
            {
                return std::filesystem::path{
                    std::wstring{buffer.data(), length}}.lexically_normal();
            }
            if (buffer.size() >= 32768U)
            {
                return {};
            }
            buffer.resize(buffer.size() * 2U);
        }
    }

    bool paths_equal(
        std::filesystem::path const& left,
        std::filesystem::path const& right)
    {
        std::wstring const normalized_left =
            left.lexically_normal().native();
        std::wstring const normalized_right =
            right.lexically_normal().native();
        return _wcsicmp(
                   normalized_left.c_str(),
                   normalized_right.c_str()) == 0;
    }

    std::filesystem::path required_install_folder()
    {
        PWSTR raw_path = nullptr;
        if (FAILED(SHGetKnownFolderPath(
                FOLDERID_ProgramFilesX64,
                KF_FLAG_DEFAULT,
                nullptr,
                &raw_path)))
        {
            return {};
        }
        std::filesystem::path const program_files{raw_path};
        CoTaskMemFree(raw_path);
        return (program_files / L"Librarian").lexically_normal();
    }

    bool parse_version(
        std::string_view text,
        PackageVersion& version)
    {
        std::array<std::uint16_t, 4> parts{};
        std::size_t start = 0U;
        for (std::size_t index = 0U; index < parts.size(); ++index)
        {
            std::size_t const separator = text.find('.', start);
            std::size_t const end =
                separator == std::string_view::npos ?
                    text.size() :
                    separator;
            if (end == start ||
                (index < parts.size() - 1U &&
                 separator == std::string_view::npos) ||
                (index == parts.size() - 1U &&
                 separator != std::string_view::npos))
            {
                return false;
            }

            unsigned long value = 0U;
            for (char const character : text.substr(start, end - start))
            {
                if (character < '0' || character > '9')
                {
                    return false;
                }
                value = value * 10U +
                        static_cast<unsigned long>(character - '0');
                if (value > UINT16_MAX)
                {
                    return false;
                }
            }
            parts[index] = static_cast<std::uint16_t>(value);
            start = end + 1U;
        }
        version = PackageVersion{
            .Major = parts[0],
            .Minor = parts[1],
            .Build = parts[2],
            .Revision = parts[3],
        };
        return true;
    }

    bool read_installed_version(
        std::filesystem::path const& install_folder,
        PackageVersion& version)
    {
        std::ifstream stream{
            install_folder / L"Librarian.PayloadHashes",
            std::ios::binary | std::ios::in};
        std::string const contents{
            std::istreambuf_iterator<char>{stream},
            std::istreambuf_iterator<char>{}};
        if (stream.bad() || contents.empty() ||
            contents.size() > 256U * 1024U ||
            !contents.starts_with("v4|"))
        {
            return false;
        }
        std::size_t const version_end = contents.find('|', 3U);
        if (version_end == std::string::npos)
        {
            return false;
        }
        return parse_version(
            std::string_view{contents}.substr(
                3U,
                version_end - 3U),
            version);
    }

    bool package_versions_equal(
        PackageVersion const& left,
        PackageVersion const& right)
    {
        return left.Major == right.Major &&
               left.Minor == right.Minor &&
               left.Build == right.Build &&
               left.Revision == right.Revision;
    }

    bool has_current_product_identity()
    {
        try
        {
            auto const package =
                winrt::Windows::ApplicationModel::Package::Current();
            if (!package.Status().VerifyIsOK())
            {
                return false;
            }
            std::filesystem::path const executable = module_path();
            if (executable.empty())
            {
                return false;
            }
            std::filesystem::path const install_folder =
                executable.parent_path();
            std::filesystem::path const required =
                required_install_folder();
            if (!required.empty() &&
                paths_equal(install_folder, required))
            {
                PackageVersion installed{};
                return read_installed_version(
                           install_folder,
                           installed) &&
                       package_versions_equal(
                           package.Id().Version(),
                           installed);
            }
            return package.IsDevelopmentMode();
        }
        catch (winrt::hresult_error const&)
        {
            return false;
        }
    }
}

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
        if (!has_current_product_identity())
        {
            MessageBoxW(
                nullptr,
                L"Librarian could not verify its current Windows package "
                L"identity. Start Librarian from its installed shortcut or "
                L"repair the installation.",
                L"Librarian",
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            Application::Current().Exit();
            return;
        }
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
