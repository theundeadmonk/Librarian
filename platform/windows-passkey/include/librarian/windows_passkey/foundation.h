#pragma once

#include <cstdint>

namespace librarian::windows_passkey
{
    enum class readiness : std::uint8_t
    {
        scaffold_only = 0,
    };

    [[nodiscard]] constexpr readiness current_readiness() noexcept
    {
        return readiness::scaffold_only;
    }
}
