fn main() -> std::io::Result<()> {
    // Hermetic protoc: the compiler ships with the build instead of being
    // apt-installed per CI run — a wedged package mirror once held a CI job
    // (and its runner slot) for an hour installing protobuf-compiler.
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("vendored protoc for this platform"),
    );
    println!("cargo:rerun-if-changed=proto/reachpad.proto");
    prost_build::compile_protos(&["proto/reachpad.proto"], &["proto/"])
}
