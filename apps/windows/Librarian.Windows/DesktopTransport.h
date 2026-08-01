#pragma once

#include "DesktopClient.h"

#include <memory>

namespace librarian::windows
{
    [[nodiscard]] std::shared_ptr<IDesktopClient> TryMakePackagedDesktopClient() noexcept;
}
