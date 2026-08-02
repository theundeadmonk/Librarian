use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let crate_directory =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo provides a manifest path"));
    let native_directory = crate_directory
        .parent()
        .expect("platform crate has a parent")
        .join("windows-passkey");

    for path in [
        "include/librarian/windows_passkey/agent_bridge.h",
        "src/agent_bridge.cpp",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            native_directory.join(path).display()
        );
    }

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .include(native_directory.join("include"))
        .file(native_directory.join("src/agent_bridge.cpp"))
        .std("c++20")
        .define("UNICODE", None)
        .define("_UNICODE", None)
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("NOMINMAX", None)
        .warnings(true)
        .warnings_into_errors(true);

    if build.get_compiler().is_like_msvc() {
        build.flag("/permissive-").flag("/sdl").flag("/EHsc");
    }

    build.compile("librarian_windows_passkey_agent_bridge");
    println!("cargo:rustc-link-lib=Bcrypt");
    println!("cargo:rustc-link-lib=Ncrypt");
}
