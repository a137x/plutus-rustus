// Compile the batched-EC shim against the libsecp256k1 submodule source.
//
// The shim (csrc/shim.c) #includes depend/secp256k1/src/secp256k1.c to reach the
// library's file-local `static` internals (batch affine-normalisation etc.), which
// the secp256k1 crate does not export. We compile that plus the two precomputed-table
// translation units it references. depend/secp256k1 is a git submodule pinned to
// bitcoin-core/secp256k1 v0.2.0; the defines below configure it to match.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dep = root.join("depend/secp256k1");
    let src = dep.join("src");

    let mut b = cc::Build::new();
    b.include(&src);
    b.include(dep.join("include"));
    b.include(&dep);
    // Size the ecmult tables so the submodule's precomputed_ecmult*.c agree
    // with secp256k1.c at link time (upstream's v0.2.0 defaults).
    b.define("ECMULT_WINDOW_SIZE", "15");
    b.define("ECMULT_GEN_PREC_BITS", "4");
    b.define("SECP256K1_API", Some(""));
    b.flag_if_supported("-Wno-unused-function");
    b.flag_if_supported("-Wno-unused-parameter");
    b.opt_level(3);

    b.file(src.join("precomputed_ecmult_gen.c"));
    b.file(src.join("precomputed_ecmult.c"));
    b.file(root.join("csrc/shim.c"));
    b.compile("ecshim");

    // aarch64-only SIMD hash160 (ARMv8 SHA-256 + 4-way NEON RIPEMD-160). Other
    // targets fall back to the sha2/ripemd crates, so this stays optional.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch == "aarch64" {
        let mut h = cc::Build::new();
        h.file(root.join("csrc/hash_neon.c"));
        h.opt_level(3);
        // Apple arm64 enables the crypto (SHA-256) extension by default. Other
        // aarch64 toolchains need it requested explicitly.
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        if os != "macos" && os != "ios" {
            h.flag_if_supported("-march=armv8-a+crypto");
        }
        h.compile("hashneon");
        println!("cargo:rustc-cfg=neon_hash");
        println!("cargo:rerun-if-changed=csrc/hash_neon.c");
    }

    println!("cargo:rustc-check-cfg=cfg(neon_hash)");
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-changed=build.rs");
}
