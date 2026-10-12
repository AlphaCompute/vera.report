pub mod authenticated_read;
pub mod broker;
pub mod key_handles;
pub mod recipient;

#[cfg(target_os = "linux")]
pub fn attest(nonce: Vec<u8>, context: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    attest_with_recipient(nonce, context, None)
}

#[cfg(target_os = "linux")]
fn attest_with_recipient(
    nonce: Vec<u8>,
    context: &[u8],
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aws_nitro_enclaves_nsm_api::{
        api::{Request, Response},
        driver::{nsm_exit, nsm_init, nsm_process_request},
    };
    let request = Request::Attestation {
        public_key: public_key.map(serde_bytes::ByteBuf::from),
        nonce: Some(serde_bytes::ByteBuf::from(nonce)),
        user_data: Some(serde_bytes::ByteBuf::from(context.to_vec())),
    };
    let fd = nsm_init();
    if fd < 0 {
        return Err("cannot open Nitro /dev/nsm".into());
    }
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);
    match response {
        Response::Attestation { document } if !document.is_empty() && document.len() <= 16384 => {
            Ok(document)
        }
        _ => Err("NSM attestation failed".into()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn attest(_: Vec<u8>, _: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("Nitro attestation requires Linux /dev/nsm".into())
}

#[cfg(not(target_os = "linux"))]
fn attest_with_recipient(
    _: Vec<u8>,
    _: &[u8],
    _: Option<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("Nitro attestation requires Linux /dev/nsm".into())
}
