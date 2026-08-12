fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=proto/reachpad.proto");
    prost_build::compile_protos(&["proto/reachpad.proto"], &["proto/"])
}
