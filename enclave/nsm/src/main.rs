use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::io::{self, Read};

const CONTEXT: &[u8] = b"VERA-ENCLAVE-IDENTITY-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    nonce: String,
}

fn parse(input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if input.len() > 256 {
        return Err("request too large".into());
    }
    let input: Input = serde_json::from_slice(input)?;
    let nonce = STANDARD.decode(input.nonce)?;
    if nonce.len() != 32 {
        return Err("nonce must contain 32 bytes".into());
    }
    Ok(nonce)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().take(257).read_to_end(&mut input)?;
    let document = vera_nsm::attest(parse(&input)?, CONTEXT)?;
    println!(
        "{}",
        serde_json::json!({"document": STANDARD.encode(document)})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(nonce: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"nonce": STANDARD.encode(nonce)})).unwrap()
    }
    #[test]
    fn preserves_challenge_bytes() {
        assert_eq!(parse(&request(&[42; 32])).unwrap(), vec![42; 32]);
    }
    #[test]
    fn rejects_missing_malformed_and_oversized_requests() {
        for input in [
            vec![b' '; 257],
            b"{}".to_vec(),
            b"{\"nonce\":\"***\"}".to_vec(),
            request(&[0; 31]),
            request(&[0; 33]),
        ] {
            assert!(parse(&input).is_err());
        }
    }
    #[test]
    fn rejects_external_key_context_and_duplicate_fields() {
        let nonce = STANDARD.encode([0; 32]);
        for extra in [
            "\"public_key\":\"parent\"",
            "\"user_data\":\"other\"",
            "\"nonce\":\"duplicate\"",
        ] {
            assert!(parse(format!("{{\"nonce\":\"{nonce}\",{extra}}}").as_bytes()).is_err());
        }
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn refuses_non_nitro_platform() {
        assert!(vera_nsm::attest(vec![0; 32], CONTEXT).is_err());
    }
}
