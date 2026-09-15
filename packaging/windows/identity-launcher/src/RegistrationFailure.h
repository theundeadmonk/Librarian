#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace librarian::identity_launcher
{
    inline std::wstring registration_failure_message(std::uint32_t code)
    {
        constexpr wchar_t digits[]{L"0123456789ABCDEF"};
        std::array<wchar_t, 8> hexadecimal{};
        for (std::size_t position = hexadecimal.size(); position > 0U; --position)
        {
            hexadecimal[position - 1U] = digits[code & 0xFU];
            code >>= 4U;
        }
        std::wstring message{
            L"Librarian could not update passkey provider registration "
            L"(exit code 0x"};
        message.append(hexadecimal.data(), hexadecimal.size());
        message.append(L").");
        return message;
    }
}
