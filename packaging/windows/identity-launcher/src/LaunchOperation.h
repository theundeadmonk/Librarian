#pragma once

namespace librarian::identity_launcher
{
    enum class operation
    {
        launch,
        register_only,
        unregister,
        native_host,
    };

    // Called only after installation and signed-payload validation. Callbacks
    // propagate failures; no child may start before identity convergence.
    template <typename EnsureIdentity, typename RemoveIdentity,
        typename RegisterProvider, typename LaunchDesktop, typename LaunchHost>
    int dispatch_operation(operation requested, EnsureIdentity ensure_identity,
        RemoveIdentity remove_identity, RegisterProvider register_provider,
        LaunchDesktop launch_desktop, LaunchHost launch_host)
    {
        switch (requested)
        {
        case operation::unregister:
            remove_identity();
            return 0;
        case operation::native_host:
            ensure_identity();
            // Browser status does not depend on passkey-provider registration.
            // Its 30-second activation wait would exhaust the browser deadline.
            return launch_host();
        case operation::launch:
        case operation::register_only:
            ensure_identity();
            register_provider();
            if (requested == operation::launch)
            {
                launch_desktop();
            }
            return 0;
        default:
            return 1;
        }
    }
}
