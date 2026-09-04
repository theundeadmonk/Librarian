//! Bounded Chromium native-messaging bridge for Librarian.

#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
mod protocol;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
fn main() {
    if windows::run().is_err() {
        eprintln!("Librarian browser bridge could not start securely.");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Librarian browser bridge is available only on Windows.");
    std::process::exit(1);
}
