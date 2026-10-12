//! Bounded GCM reader. No plaintext can be read before final authentication.
use openssl::symm::{Cipher, Crypter, Mode};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MAX_TOTAL: usize = 256 * 1024 * 1024;
pub const MAX_CHUNK: usize = 1024 * 1024;
enum State {
    Receiving,
    Ready(usize),
    Closed,
}
pub struct AuthenticatedRead {
    cipher: Option<Crypter>,
    plaintext: Zeroizing<Vec<u8>>,
    expected: usize,
    received: usize,
    state: State,
    expires: Instant,
}
impl AuthenticatedRead {
    // The handle store checks session, purpose, record and payload format first.
    pub(crate) fn new(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        expected: usize,
    ) -> Result<Self, &'static str> {
        if key.len() != 32
            || ![12, 16].contains(&iv.len())
            || aad.len() > 2048
            || expected > MAX_TOTAL
        {
            return Err("Invalid read bounds");
        }
        let mut cipher = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(iv))
            .map_err(|_| "Read initialization failed")?;
        cipher
            .aad_update(aad)
            .map_err(|_| "Read initialization failed")?;
        Ok(Self {
            cipher: Some(cipher),
            plaintext: Zeroizing::new(Vec::with_capacity(expected)),
            expected,
            received: 0,
            state: State::Receiving,
            expires: Instant::now() + Duration::from_secs(300),
        })
    }
    pub(crate) fn expire_with(&mut self, expires: Instant) {
        self.expires = self.expires.min(expires);
    }
    fn check_expiry(&mut self) -> Result<(), &'static str> {
        if Instant::now() >= self.expires {
            self.close();
            return Err("Read expired");
        }
        Ok(())
    }
    fn close(&mut self) {
        self.state = State::Closed;
        self.cipher = None;
        self.plaintext = Zeroizing::new(Vec::new());
    }
    pub fn append(&mut self, ciphertext: &[u8]) -> Result<(), &'static str> {
        self.check_expiry()?;
        if !matches!(self.state, State::Receiving)
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_CHUNK
            || ciphertext.len() > self.expected - self.received
        {
            self.close();
            return Err("Invalid read chunk");
        }
        let mut output = Zeroizing::new(vec![0; ciphertext.len() + 16]);
        let result = self
            .cipher
            .as_mut()
            .ok_or("Read closed")?
            .update(ciphertext, &mut output);
        match result {
            Ok(size) if self.plaintext.len() + size <= self.expected => {
                self.plaintext.extend_from_slice(&output[..size]);
                self.received += ciphertext.len();
                Ok(())
            }
            _ => {
                self.close();
                Err("Read failed")
            }
        }
    }
    pub fn authenticate(&mut self, tag: &[u8; 16]) -> Result<(), &'static str> {
        self.check_expiry()?;
        if !matches!(self.state, State::Receiving) || self.received != self.expected {
            self.close();
            return Err("Incomplete read");
        }
        let mut output = Zeroizing::new([0; 16]);
        let result = self
            .cipher
            .as_mut()
            .ok_or("Read closed")?
            .set_tag(tag)
            .and_then(|_| self.cipher.as_mut().unwrap().finalize(&mut *output));
        match result {
            Ok(size) if self.plaintext.len() + size == self.expected => {
                self.plaintext.extend_from_slice(&output[..size]);
                self.cipher = None;
                self.state = State::Ready(0);
                Ok(())
            }
            _ => {
                self.close();
                Err("Read authentication failed")
            }
        }
    }
    pub fn read_chunk(&mut self) -> Result<(Zeroizing<Vec<u8>>, bool), &'static str> {
        self.check_expiry()?;
        let State::Ready(offset) = self.state else {
            self.close();
            return Err("Read is not authenticated");
        };
        let end = (offset + MAX_CHUNK).min(self.plaintext.len());
        let chunk = Zeroizing::new(self.plaintext[offset..end].to_vec());
        let done = end == self.plaintext.len();
        if done {
            self.close();
        } else {
            self.state = State::Ready(end);
        }
        Ok((chunk, done))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::symm::encrypt_aead;
    fn fixture() -> (Vec<u8>, [u8; 16]) {
        let mut tag = [0; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &[7; 32],
            Some(&[3; 12]),
            b"binding",
            b"synthetic",
            &mut tag,
        )
        .unwrap();
        (ciphertext, tag)
    }
    #[test]
    fn withholds_plaintext_until_authentication_and_releases_it_once() {
        let (ciphertext, tag) = fixture();
        let mut read =
            AuthenticatedRead::new(&[7; 32], &[3; 12], b"binding", ciphertext.len()).unwrap();
        read.append(&ciphertext[..3]).unwrap();
        read.append(&ciphertext[3..]).unwrap();
        read.authenticate(&tag).unwrap();
        let (plaintext, done) = read.read_chunk().unwrap();
        assert_eq!(&*plaintext, b"synthetic");
        assert!(done);
        assert!(read.read_chunk().is_err());
        assert!(read.plaintext.is_empty());
    }
    #[test]
    fn wrong_tags_incomplete_input_and_early_reads_poison_the_reader() {
        let (ciphertext, tag) = fixture();
        for kind in ["tag", "incomplete", "early", "overflow", "chunk"] {
            let mut read =
                AuthenticatedRead::new(&[7; 32], &[3; 12], b"binding", ciphertext.len()).unwrap();
            match kind {
                "tag" => {
                    read.append(&ciphertext).unwrap();
                    assert!(read.authenticate(&[0; 16]).is_err());
                }
                "incomplete" => {
                    read.append(&ciphertext[..3]).unwrap();
                    assert!(read.authenticate(&tag).is_err());
                }
                "early" => {
                    read.append(&ciphertext).unwrap();
                    assert!(read.read_chunk().is_err());
                }
                "overflow" => {
                    assert!(read.append(&[0; 10]).is_err());
                }
                _ => {
                    assert!(read.append(&vec![0; MAX_CHUNK + 1]).is_err());
                }
            }
            assert!(read.read_chunk().is_err());
            assert!(read.authenticate(&tag).is_err());
            assert!(read.plaintext.is_empty());
        }
        assert!(AuthenticatedRead::new(&[7; 32], &[3; 12], b"binding", MAX_TOTAL + 1).is_err());
    }
    #[test]
    fn expiry_discards_receiving_and_authenticated_plaintext() {
        let (ciphertext, tag) = fixture();
        for authenticated in [false, true] {
            let mut read =
                AuthenticatedRead::new(&[7; 32], &[3; 12], b"binding", ciphertext.len()).unwrap();
            read.append(&ciphertext).unwrap();
            if authenticated {
                read.authenticate(&tag).unwrap();
            }
            read.expire_with(Instant::now() - Duration::from_secs(1));
            assert!(read.read_chunk().is_err());
            assert!(read.append(&ciphertext).is_err());
            assert!(read.authenticate(&tag).is_err());
            assert!(read.plaintext.is_empty());
            assert!(read.cipher.is_none());
        }
    }
    #[test]
    fn reads_a_full_256_mib_independent_node_ciphertext_with_bounded_chunks() {
        use std::{
            io::Read,
            process::{Command, Stdio},
        };
        let script = r#"
          const c=require('node:crypto'),{Readable}=require('node:stream');
          const cipher=c.createCipheriv('aes-256-gcm',Buffer.alloc(32,7),Buffer.alloc(16,3));
          const chunk=Buffer.alloc(1024*1024,97);
          function* source(){for(let i=0;i<256;i++)yield chunk;}
          cipher.once('end',()=>process.stdout.write(cipher.getAuthTag()));
          Readable.from(source()).pipe(cipher).pipe(process.stdout,{end:false});
        "#;
        let mut child = Command::new("node")
            .args(["-e", script])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let mut read = AuthenticatedRead::new(&[7; 32], &[3; 16], &[], MAX_TOTAL).unwrap();
        let mut chunk = vec![0; MAX_CHUNK];
        for _ in 0..256 {
            output.read_exact(&mut chunk).unwrap();
            read.append(&chunk).unwrap();
        }
        let mut tag = [0; 16];
        output.read_exact(&mut tag).unwrap();
        assert!(child.wait().unwrap().success());
        read.authenticate(&tag).unwrap();
        let mut total = 0;
        loop {
            let (plaintext, done) = read.read_chunk().unwrap();
            assert!(plaintext.len() <= MAX_CHUNK);
            assert!(plaintext.iter().all(|&b| b == 97));
            total += plaintext.len();
            if done {
                break;
            }
        }
        assert_eq!(total, MAX_TOTAL);
        assert!(read.plaintext.is_empty());
    }
}
