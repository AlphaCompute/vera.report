use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    nonce: String,
    certificate_sha256: String,
}
fn parse(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if bytes.len() > 256 {
        return Err("channel request too large".into());
    }
    let value: Input = serde_json::from_slice(bytes)?;
    let nonce = STANDARD.decode(value.nonce)?;
    let binding = STANDARD.decode(value.certificate_sha256)?;
    if nonce.len() != 32 || binding.len() != 32 {
        return Err("invalid channel challenge or certificate digest".into());
    }
    let mut context = b"VERA-ENCLAVE-CHANNEL-v1".to_vec();
    context.extend(binding);
    Ok((nonce, context))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().take(257).read_to_end(&mut input)?;
    let (nonce, context) = parse(&input)?;
    let document = vera_nsm::attest(nonce, &context)?;
    println!(
        "{}",
        serde_json::json!({"document": STANDARD.encode(document)})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_only_fixed_context_and_exact_digest() {
        let bytes = serde_json::to_vec(&serde_json::json!({"nonce": STANDARD.encode([1;32]), "certificate_sha256": STANDARD.encode([2;32])})).unwrap();
        let (nonce, context) = parse(&bytes).unwrap();
        assert_eq!(nonce, vec![1; 32]);
        assert_eq!(
            context,
            [b"VERA-ENCLAVE-CHANNEL-v1".as_slice(), &[2; 32]].concat()
        );
        assert!(parse(b"{}").is_err());
        assert!(parse(&vec![0; 257]).is_err());
        let extra = serde_json::to_vec(&serde_json::json!({"nonce": STANDARD.encode([1;32]), "certificate_sha256": STANDARD.encode([2;32]), "public_key":"caller"})).unwrap();
        assert!(parse(&extra).is_err());
    }
}
