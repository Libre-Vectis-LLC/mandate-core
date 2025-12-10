fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());

    let protos = [
        "../protos/common.proto",
        "../protos/error.proto",
        "../protos/event.proto",
        "../protos/ring.proto",
        "../protos/group.proto",
        "../protos/member.proto",
        "../protos/billing.proto",
        "../protos/auth.proto",
    ];

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &["../protos"])?;
    Ok(())
}
