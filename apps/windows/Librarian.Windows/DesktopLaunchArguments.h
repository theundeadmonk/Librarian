#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

#include <optional>
#include <string>
#include <string_view>

namespace librarian::windows
{
    struct DesktopLaunchRequest
    {
        bool valid{false};
        std::wstring command;
    };

    inline DesktopLaunchRequest ParseDesktopCommand(std::wstring_view command)
    {
        if (command.empty() ||
            command == L"--register-passkey-provider" ||
            command == L"--unregister-passkey-provider" ||
            command == L"--passkey-provider-registration-state")
        {
            return {.valid = true, .command = std::wstring{command}};
        }
        return {};
    }

    inline DesktopLaunchRequest ParseDesktopLaunchArguments(
        std::optional<std::wstring_view> platform_arguments,
        std::wstring_view process_command_line)
    {
        // Genuine platform activation payloads are authoritative, even empty
        // ones. Never fall back from a rejected payload to a different command.
        if (platform_arguments)
        {
            return ParseDesktopCommand(*platform_arguments);
        }
        if (process_command_line.empty() || process_command_line.size() > 32767U ||
            process_command_line.find(L'\0') != std::wstring_view::npos)
        {
            return {};
        }
        std::wstring const terminated{process_command_line};
        int count = 0;
        LPWSTR* arguments = CommandLineToArgvW(terminated.c_str(), &count);
        if (arguments == nullptr)
        {
            return {};
        }
        struct argument_guard
        {
            LPWSTR* value;
            ~argument_guard() { LocalFree(value); }
        } const guard{arguments};
        if (count == 1)
        {
            return {.valid = true};
        }
        if (count == 2 && arguments[1][0] != L'\0')
        {
            return ParseDesktopCommand(arguments[1]);
        }
        return {};
    }
}
