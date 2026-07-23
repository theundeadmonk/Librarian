# MSIX packaging boundary

Issue [#19](https://github.com/theundeadmonk/Librarian/issues/19) owns the production MSIX layout, registration manifests, signing, installation, upgrade, repair, and removal behavior.

The foundation build compiles the package-enabled WinUI app with signing disabled. It does not yet produce a release MSIX or register the vault agent, Chromium native host, or Windows passkey provider.
