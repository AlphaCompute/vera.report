//! Private stdin/stdout transport for the measured enclave service. Never expose
//! these commands directly on vsock or forward a parent-supplied install frame.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Deserialize};
use std::io::{self, Read, Write};
use vera_nsm::broker::{Broker, Frame};
use zeroize::Zeroizing;
const MAX_FRAME: usize = 12 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Init {
    session: String,
    certificate: String,
}
fn fixed(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 44 {
        return Err("Invalid binding".into());
    }
    let decoded = STANDARD.decode(value)?;
    if STANDARD.encode(&decoded) != value {
        return Err("Invalid binding".into());
    }
    decoded.try_into().map_err(|_| "Invalid binding".into())
}
fn read<T: DeserializeOwned>(
    input: &mut impl Read,
    limit: usize,
) -> Result<Option<T>, Box<dyn std::error::Error>> {
    let mut header = [0; 4];
    if input.read(&mut header[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut header[1..])?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > limit {
        return Err("Invalid frame size".into());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    input.read_exact(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    // This check is only an early refusal. Actual NSM attestation must succeed
    // in Broker::Prepare before any recipient key can be installed.
    if !cfg!(target_os = "linux") || !std::path::Path::new("/dev/nsm").exists() {
        return Err("NSM required".into());
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let init: Init = read(&mut input, 1024)?.ok_or("Missing initialization")?;
    let mut broker = Broker::new(fixed(&init.session)?, fixed(&init.certificate)?)?;
    while let Some(frame) = read::<Frame>(&mut input, MAX_FRAME)? {
        let id = frame.id;
        let reply = broker.handle(frame)?;
        let bytes = Zeroizing::new(serde_json::to_vec(
            &serde_json::json!({"id":id,"result":reply}),
        )?);
        if bytes.len() > MAX_FRAME {
            return Err("Reply too large".into());
        }
        output.write_all(&(bytes.len() as u32).to_be_bytes())?;
        output.write_all(&bytes)?;
        output.flush()?;
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("Recipient broker failed");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_partial_oversized_and_ambiguous_frames() {
        for data in [
            vec![0],
            vec![0, 0, 0],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 5, b'{'],
            (1025u32).to_be_bytes().to_vec(),
        ] {
            assert!(read::<Init>(&mut data.as_slice(), 1024).is_err());
        }
        let body = br#"{"session":"a","session":"b","certificate":"c"}"#;
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(body);
        assert!(read::<Init>(&mut bytes.as_slice(), 1024).is_err());
        assert!(read::<Init>(&mut [].as_slice(), 1024).unwrap().is_none());
    }
    #[test]
    fn reads_exact_frame_without_consuming_next_and_bounds_bindings() {
        let body=serde_json::to_vec(&serde_json::json!({"session":STANDARD.encode([1;32]),"certificate":STANDARD.encode([2;32])})).unwrap();
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        bytes.push(99);
        let mut input = bytes.as_slice();
        let init = read::<Init>(&mut input, 1024).unwrap().unwrap();
        assert_eq!(fixed(&init.session).unwrap(), [1; 32]);
        assert_eq!(input, &[99]);
        assert!(fixed(&STANDARD.encode([0; 31])).is_err());
    }
}
