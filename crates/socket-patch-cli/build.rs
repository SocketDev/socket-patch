fn main() {
    // Embed the exact compile target so `--update` downloads the right
    // release asset. Compiled-in beats runtime `uname` probing: the binary
    // *is* gnu or musl (install.sh's ldd heuristic can only guess), and
    // the Windows arches fall out for free.
    println!(
        "cargo:rustc-env=SOCKET_PATCH_TARGET={}",
        std::env::var("TARGET").expect("cargo always sets TARGET for build scripts")
    );
    println!("cargo:rerun-if-changed=build.rs");
}
