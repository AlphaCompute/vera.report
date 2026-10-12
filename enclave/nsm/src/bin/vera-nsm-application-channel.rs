//! Internal helper, not a network API. The measured application generates its
//! own channel key and supplies its digest. Never expose a caller-selected digest.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    nonce: String,
    channel_key_sha256: String,
}

fn parse(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if bytes.len() > 256 {
        return Err("application channel request too large".into());
    }
    let value: Input = serde_json::from_slice(bytes)?;
    let nonce = STANDARD.decode(value.nonce)?;
    let digest = STANDARD.decode(value.channel_key_sha256)?;
    if nonce.len() != 32 || digest.len() != 32 {
        return Err("invalid application channel challenge or key digest".into());
    }
    let mut context = b"VERA-CONFIDENTIAL-CHANNEL-v1".to_vec();
    context.extend(digest);
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

    fn request(nonce: &[u8], digest: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "nonce": STANDARD.encode(nonce), "channel_key_sha256": STANDARD.encode(digest)
        }))
        .unwrap()
    }

    #[test]
    fn binds_fixed_domain_and_exact_key_digest() {
        let (nonce, context) = parse(&request(&[1; 32], &[2; 32])).unwrap();
        assert_eq!(nonce, [1; 32]);
        assert_eq!(
            context,
            [b"VERA-CONFIDENTIAL-CHANNEL-v1".as_slice(), &[2; 32]].concat()
        );
        assert_ne!(
            context,
            [b"VERA-ENCLAVE-CHANNEL-v1".as_slice(), &[2; 32]].concat()
        );
    }

    #[test]
    fn rejects_lengths_fields_duplicates_and_trailing_input() {
        for length in [0, 1, 31, 33, 64] {
            assert!(parse(&request(&vec![1; length], &[2; 32])).is_err());
            assert!(parse(&request(&[1; 32], &vec![2; length])).is_err());
        }
        assert!(parse(&vec![0; 257]).is_err());
        assert!(parse(b"{}").is_err());
        let valid = String::from_utf8(request(&[1; 32], &[2; 32])).unwrap();
        for extra in [
            "\"context\":\"other\"",
            "\"public_key\":\"other\"",
            "\"nonce\":\"duplicate\"",
        ] {
            assert!(
                parse(format!("{},{} }}", &valid[..valid.len() - 1], extra).as_bytes()).is_err()
            );
        }
        assert!(parse(format!("{} {{}}", valid).as_bytes()).is_err());
    }
}
