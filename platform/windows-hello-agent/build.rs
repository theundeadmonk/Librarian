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
        .join("windows-hello");

    for path in [
        "include/librarian/windows_hello/bridge.h",
        "include/librarian/windows_hello/client.h",
        "src/bridge.cpp",
        "src/client.cpp",
        "src/validation.cpp",
        "src/validation.h",
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
        .include(native_directory.join("src"))
        .file(native_directory.join("src/bridge.cpp"))
        .file(native_directory.join("src/client.cpp"))
        .file(native_directory.join("src/validation.cpp"))
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

    build.compile("librarian_windows_hello_agent_bridge");
    println!("cargo:rustc-link-lib=Bcrypt");
    println!("cargo:rustc-link-lib=OneCoreUAP");
}
