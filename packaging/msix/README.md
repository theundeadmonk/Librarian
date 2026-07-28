# Windows packaging boundary

Issue [#19](https://github.com/theundeadmonk/Librarian/issues/19) and
[[../../ADRs/0007 Windows Setup and Package Identity]] own the production
package layout, registration manifests, signing, installation, upgrade, repair,
and removal behavior.

The production design has one user-facing `LibrarianSetup.exe`. Its bundled MSI
owns the native binaries, identity-package registration, servicing, uninstall,
and selected Chrome/Edge native-host registrations.

The MSIX in this directory is identity-only and uses an external location. It
does not own the native binaries and must not appear as a second user-facing
installed product. Each external executable embeds matching package/application
identity metadata in Release builds. Unsigned, unregistered debug test
harnesses intentionally omit that metadata so Windows Application Control can
execute repository tests.

Browser integrations are optional. Setup may register the native host for an
installed browser only after user selection; browser extensions remain
user-confirmed installations from the official Chrome Web Store or Microsoft
Edge Add-ons store.

The package-enabled WinUI development target may continue to build a full,
unsigned MSIX for isolated UI smoke tests. That development package is not the
production setup lifecycle.

The identity fixture and validation scripts added here are development-only
until release signing, installer authoring, transaction, upgrade, repair, and
uninstall tests are complete. They must not install a package, trust a
certificate, or enable secret-bearing product paths automatically. MakeAppx
uses `/nv` because the future passkey-provider executable does not exist yet;
production setup must reject that incomplete payload rather than register it.
