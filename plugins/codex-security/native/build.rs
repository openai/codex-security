fn main() {
    napi_build::setup();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // The linker otherwise embeds its absolute output path as the install name.
        println!("cargo:rustc-link-arg-cdylib=-Wl,-install_name,@rpath/unix.node");
    }
}
