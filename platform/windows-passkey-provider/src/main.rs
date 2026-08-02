//! Packaged local-server adapter for Windows' third-party passkey contract.
//!
//! COM, Windows Hello, response encoding, and browser-facing metadata cache
//! updates are isolated in the native bridge. This process holds no private
//! passkey material; every vault operation uses the mutually authenticated
//! local agent protocol.

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() {
    use std::ffi::OsStr;

    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let operation = match arguments.as_slice() {
        [] => windows::run(),
        [argument] if argument == OsStr::new("-PluginActivated") => windows::run(),
        [argument] if argument == OsStr::new("--register") => windows::register(),
        [argument] if argument == OsStr::new("--unregister") => windows::unregister(),
        [argument] if argument == OsStr::new("--registration-state") => {
            windows::require_registered()
        }
        _ => Err(windows::ProviderError::Native),
    };
    if let Err(error) = operation {
        std::process::exit(error.process_exit_code());
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Librarian's passkey provider is available only on Windows.");
    std::process::exit(1);
}
