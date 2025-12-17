fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());

    let protos = [
        "../protos/common.proto",
        "../protos/error.proto",
        "../protos/event.proto",
        "../protos/ring.proto",
        "../protos/group.proto",
        "../protos/member.proto",
        "../protos/storage.proto",
        "../protos/billing.proto",
        "../protos/admin.proto",
        "../protos/auth.proto",
    ];

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let mut config = tonic_build::configure();
    // Avoid generating transport-dependent clients/servers for wasm builds to keep
    // mandate-core compilable on `wasm32-unknown-unknown`.
    if target_arch == "wasm32" {
        config = config.build_server(false).build_client(false);
    } else {
        config = config.build_server(true).build_client(true);
    }

    config.compile_protos(&protos, &["../protos"])?;
    Ok(())
}
