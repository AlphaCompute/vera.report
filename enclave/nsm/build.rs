fn main() {
    println!("cargo:rerun-if-changed=src/recipient_envelope.c");
    let openssl = pkg_config::Config::new()
        .probe("openssl")
        .expect("OpenSSL development headers are required");
    let mut build = cc::Build::new();
    build
        .file("src/recipient_envelope.c")
        .flag_if_supported("-std=c11");
    for path in openssl.include_paths {
        build.include(path);
    }
    build
        .warnings_into_errors(true)
        .compile("vera_recipient_envelope");
}
