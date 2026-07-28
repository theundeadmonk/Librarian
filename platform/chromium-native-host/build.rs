use std::{env, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=app.manifest");
    println!("cargo::rerun-if-env-changed=PROFILE");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("PROFILE").as_deref() != Ok("release")
    {
        return;
    }

    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must set CARGO_MANIFEST_DIR"),
    )
    .join("app.manifest");

    println!("cargo::rustc-link-arg-bin=librarian-chromium-native-host=/MANIFEST:EMBED");
    println!(
        "cargo::rustc-link-arg-bin=librarian-chromium-native-host=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
