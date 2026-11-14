fn main() {
    // Link the runtime library by its soname, so the build does not need the
    // nftables development package.
    println!("cargo:rustc-link-lib=dylib:+verbatim=libnftables.so.1");
}
