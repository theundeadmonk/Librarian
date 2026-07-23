//! Process boundary for the future trusted local vault agent.

#![forbid(unsafe_code)]

use librarian_vault_core::credential_storage_is_approved;

fn main() {
    let status = if credential_storage_is_approved() {
        "credential storage approved"
    } else {
        "foundation only; credential storage disabled"
    };

    println!("Librarian vault agent: {status}");
}
