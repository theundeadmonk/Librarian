#pragma once

#include <windows.h>
#include <array>

namespace librarian::identity_launcher
{
    inline bool configure_native_host_startup(
        STARTUPINFOW& startup,
        std::array<HANDLE, 3> const& handles)
    {
        for (HANDLE const handle : handles)
        {
            if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
                !SetHandleInformation(
                    handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            {
                return false;
            }
        }
        // Handle inheritance alone does not assign the standard streams of a
        // CREATE_NO_WINDOW console child launched by the GUI identity launcher.
        startup = {};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = handles[0];
        startup.hStdOutput = handles[1];
        startup.hStdError = handles[2];
        return true;
    }
}
