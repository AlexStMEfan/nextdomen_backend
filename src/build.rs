// build.rs

use std::env;
use std::path::PathBuf;

fn main() {
    tonic_build::configure()
        .out_dir("src/grpc/gen")
        .compile(&[
            "proto/user.proto",
            "proto/organization.proto",
            "proto/audit.proto",
            "proto/auth.proto",
        ], &["proto"])
        .unwrap_or_else(|e| panic!("Failed to compile protos: {}", e));

    println!("cargo:rerun-if-changed=proto");
}