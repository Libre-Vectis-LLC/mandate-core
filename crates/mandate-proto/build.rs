fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use vendored protoc if available, otherwise fall back to system protoc.
    // protoc-bin-vendored doesn't ship binaries for all targets (e.g. aarch64-android).
    if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
        std::env::set_var("PROTOC", path);
    }

    let protos = [
        "../protos/common.proto",
        "../protos/error.proto",
        "../protos/event.proto",
        "../protos/ring.proto",
        "../protos/organization.proto",
        "../protos/member.proto",
        "../protos/storage.proto",
        "../protos/billing.proto",
        "../protos/admin.proto",
        "../protos/auth.proto",
        "../protos/edge_admin.proto",
        "../protos/config.proto",
        "../protos/invite.proto",
        "../protos/credential.proto",
    ];

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let grpc_client_feature = std::env::var("CARGO_FEATURE_GRPC_CLIENT").is_ok();

    let mut config = tonic_build::configure();

    // For WASM builds:
    // - Never generate servers (no server runtime on WASM)
    // - Only generate clients if `grpc-client` feature is enabled
    // - Disable transport code generation (no tonic::transport on WASM)
    //
    // For native builds:
    // - Always generate both servers and clients with transport
    if target_arch == "wasm32" {
        config = config
            .build_server(false)
            .build_client(grpc_client_feature)
            .build_transport(false); // Disable transport::Channel connect methods for WASM
    } else {
        config = config.build_server(true).build_client(true);
    }

    config.compile_protos(&protos, &["../protos"])?;
    Ok(())
}
