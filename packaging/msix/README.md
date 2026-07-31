# Windows packaging boundary

Issue [#19](https://github.com/theundeadmonk/Librarian/issues/19) and
[[../../ADRs/0007 Windows Setup and Package Identity]] own the production
package layout, registration manifests, signing, installation, upgrade, repair,
and removal behavior.

The production design has one user-facing `LibrarianSetup.exe`. Its bundled MSI
owns the native binaries and identity-package file, servicing, uninstall, and
selected Chrome/Edge native-host registrations. The unpackaged identity
launcher owns supported per-user registration at first launch.

The MSIX in this directory is identity-only and uses an external location. It
does not own the native binaries and must not appear as a second user-facing
installed product. Each external executable embeds matching package/application
identity metadata in Release builds. Unsigned, unregistered debug test
harnesses intentionally omit that metadata so Windows Application Control can
execute repository tests.

The identity manifest intentionally follows Microsoft's external-location
template: it uses a neutral package architecture and keeps referenced visual
assets outside the identity package. The MSI-owned external installation
location must provide any image paths that Windows needs to resolve.

Browser integrations are optional. Setup may register the native host for an
installed browser only after user selection; browser extensions remain
user-confirmed installations from the official Chrome Web Store or Microsoft
Edge Add-ons store.

The package-enabled WinUI development target may continue to build a full,
unsigned MSIX for isolated UI smoke tests. That development package is not the
production setup lifecycle.

The identity fixture is embedded in the issue #19 MSI and inspected by the
installer structural suite. Build validation must not install a package, trust
a certificate, or enable secret-bearing product paths automatically. MakeAppx
uses `/nv` because external executable and visual-resource paths intentionally
do not resolve inside the identity package, as required by Microsoft's manual
external-location packaging procedure. The passkey-provider executable does
not exist yet; the current setup rejects that incomplete role rather than
registering a placeholder. Issue #18 will extend the same lifecycle when the
real provider exists.
