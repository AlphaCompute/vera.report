//! Enclave-owned recipient key foundation. No caller-supplied key and no private
//! key serialization API. Recipient ciphertext must come from authenticated KMS TLS.
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
};

extern "C" {
    fn vera_recipient_envelope_valid(data: *const u8, length: usize) -> std::ffi::c_int;
}

pub struct RecipientKey {
    private: PKey<Private>,
}
impl RecipientKey {
    /// Internal bootstrap operation only. The caller must authenticate the KMS
    /// HTTPS response inside the enclave before passing CiphertextForRecipient.
    /// CMS encryption does not establish sender identity or content integrity.
    pub(crate) fn decrypt_key(
        &self,
        envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
        let mut plain = self.decrypt_plaintext(envelope)?;
        let mut key = zeroize::Zeroizing::new([0; 32]);
        if plain.len() != 32 {
            return Err("Invalid recipient key size");
        }
        key.copy_from_slice(&plain);
        zeroize::Zeroize::zeroize(&mut *plain);
        Ok(key)
    }

    fn decrypt_plaintext(
        &self,
        envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
        if envelope.is_empty() || envelope.len() > 16384 {
            return Err("Invalid recipient response size");
        }
        // The validator only reads this live slice and retains no pointers.
        if unsafe { vera_recipient_envelope_valid(envelope.as_ptr(), envelope.len()) } != 1 {
            return Err("Invalid recipient envelope");
        }
        let cms = openssl::cms::CmsContentInfo::from_der(envelope)
            .map_err(|_| "Recipient decryption failed")?;
        let plain = zeroize::Zeroizing::new(
            cms.decrypt_without_cert_check(&self.private)
                .map_err(|_| "Recipient decryption failed")?,
        );
        Ok(plain)
    }

    /// Read-only compatibility with EvidenceEncryptionService's historical
    /// PBKDF2-SHA256 profile. Preserve the original UTF-8 hex string, including
    /// its case: decoding then re-encoding would change the password bytes.
    pub(crate) fn decrypt_legacy_evidence_key(
        &self,
        envelope: &[u8],
        salt: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
        let secret = self.decrypt_plaintext(envelope)?;
        if secret.len() != 64 || !secret.iter().all(u8::is_ascii_hexdigit) {
            return Err("Invalid historical evidence secret");
        }
        let mut key = zeroize::Zeroizing::new([0; 32]);
        openssl::pkcs5::pbkdf2_hmac(
            &secret,
            salt,
            100_000,
            openssl::hash::MessageDigest::sha256(),
            &mut *key,
        )
        .map_err(|_| "Historical key derivation failed")?;
        Ok(key)
    }

    /// Existing private secondary fields use the decoded hexadecimal key
    /// directly, unlike the historical PBKDF2 evidence profile.
    pub(crate) fn decrypt_legacy_private_key(
        &self,
        envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
        let secret = self.decrypt_plaintext(envelope)?;
        if secret.len() != 64 || !secret.iter().all(u8::is_ascii_hexdigit) {
            return Err("Invalid historical private key");
        }
        let mut key = zeroize::Zeroizing::new([0; 32]);
        for (output, pair) in key.iter_mut().zip(secret.chunks_exact(2)) {
            let text = std::str::from_utf8(pair).map_err(|_| "Invalid historical private key")?;
            *output = u8::from_str_radix(text, 16).map_err(|_| "Invalid historical private key")?;
        }
        Ok(key)
    }

    pub fn generate() -> Result<Self, openssl::error::ErrorStack> {
        Ok(Self {
            private: PKey::from_rsa(Rsa::generate(2048)?)?,
        })
    }

    fn request(
        &self,
        nonce: &[u8],
        channel_certificate_sha256: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        if nonce.len() != 32 || channel_certificate_sha256.len() != 32 {
            return Err("Invalid recipient challenge or channel binding".into());
        }
        let mut context = b"VERA-ENCLAVE-KMS-RECIPIENT-v1".to_vec();
        context.extend_from_slice(channel_certificate_sha256);
        Ok((nonce.to_vec(), context, self.private.public_key_to_der()?))
    }

    /// The measured caller supplies its own TLS certificate digest, never a
    /// digest accepted from an RPC parameter. Fresh challenges come from the
    /// verifier; attestation alone does not authenticate a KMS response.
    pub fn attest(
        &self,
        nonce: &[u8],
        channel_certificate_sha256: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (nonce, context, public_key) = self.request(nonce, channel_certificate_sha256)?;
        super::attest_with_recipient(nonce, &context, Some(public_key))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn owns_fresh_rsa_key_and_binds_nonce_and_channel() {
        let first = RecipientKey::generate().unwrap();
        let second = RecipientKey::generate().unwrap();
        let (nonce, context, public) = first.request(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(nonce, vec![1; 32]);
        assert_eq!(
            context,
            [b"VERA-ENCLAVE-KMS-RECIPIENT-v1".as_slice(), &[2; 32]].concat()
        );
        let parsed = PKey::public_key_from_der(&public).unwrap();
        assert_eq!(parsed.bits(), 2048);
        assert!(parsed.rsa().is_ok());
        assert_ne!(public, second.request(&[1; 32], &[2; 32]).unwrap().2);
        assert_eq!(public, first.request(&[3; 32], &[4; 32]).unwrap().2);
        for length in [0, 31, 33, 1024] {
            assert!(first.request(&vec![0; length], &[0; 32]).is_err());
            assert!(first.request(&[0; 32], &vec![0; length]).is_err());
        }
    }
    pub(crate) fn kms_fixture(
        recipient: &RecipientKey,
        streaming: bool,
        plaintext: &[u8],
    ) -> Vec<u8> {
        kms_fixture_options(recipient, streaming, plaintext, &[])
    }
    fn kms_fixture_options(
        recipient: &RecipientKey,
        streaming: bool,
        plaintext: &[u8],
        options: &[&str],
    ) -> Vec<u8> {
        use openssl::{
            asn1::Asn1Time,
            hash::MessageDigest,
            x509::{extension::SubjectKeyIdentifier, X509NameBuilder, X509},
        };
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "synthetic-recipient")
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&recipient.private).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let ski = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(ski).unwrap();
        builder
            .sign(&recipient.private, MessageDigest::sha256())
            .unwrap();
        let mut random = [0; 16];
        openssl::rand::rand_bytes(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("vera-recipient-cert-{:x?}", random));
        // This file contains only a synthetic public certificate, never a key.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&builder.build().to_pem().unwrap()).unwrap();
        drop(file);
        let mut command = Command::new("openssl");
        command
            .args([
                "cms",
                "-encrypt",
                "-binary",
                "-aes-256-cbc",
                "-outform",
                "DER",
                "-keyid",
                "-recip",
            ])
            .arg(&path)
            .args([
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha256",
                "-keyopt",
                "rsa_mgf1_md:sha256",
            ]);
        command.args(options);
        if streaming {
            command.arg("-stream");
        }
        let result = (|| {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(plaintext).unwrap();
            child.wait_with_output().unwrap()
        })();
        std::fs::remove_file(&path).unwrap();
        assert!(
            result.status.success(),
            "synthetic CMS encryption failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        result.stdout
    }
    #[test]
    fn refuses_valid_cms_with_unrequested_padding_digests_or_label() {
        let recipient = RecipientKey::generate().unwrap();
        let variants: &[&[&str]] = &[
            &["-keyopt", "rsa_padding_mode:pkcs1"],
            &["-keyopt", "rsa_oaep_md:sha1", "-keyopt", "rsa_mgf1_md:sha1"],
            &["-keyopt", "rsa_mgf1_md:sha1"],
            &["-keyopt", "rsa_oaep_label:010203"],
        ];
        for options in variants {
            let envelope = kms_fixture_options(&recipient, false, &[42; 32], options);
            let cms = openssl::cms::CmsContentInfo::from_der(&envelope).unwrap();
            assert_eq!(
                cms.decrypt_without_cert_check(&recipient.private).unwrap(),
                [42; 32]
            );
            assert!(
                recipient.decrypt_key(&envelope).is_err(),
                "accepted {options:?}"
            );
        }
    }
    #[test]
    fn decrypts_independent_oaep_cms_der_and_streaming_ber() {
        let recipient = RecipientKey::generate().unwrap();
        let wrong = RecipientKey::generate().unwrap();
        for streaming in [false, true] {
            let envelope = kms_fixture(&recipient, streaming, &[42; 32]);
            assert_eq!(*recipient.decrypt_key(&envelope).unwrap(), [42; 32]);
            let mut trailing = envelope.clone();
            trailing.extend_from_slice(b"unconsumed-data");
            assert!(
                recipient.decrypt_key(&trailing).is_err(),
                "trailing CMS bytes accepted"
            );
            assert!(wrong.decrypt_key(&envelope).is_err());
            let legacy = kms_fixture(&recipient, streaming, "2a".repeat(32).as_bytes());
            assert!(recipient.decrypt_key(&legacy).is_err());
            assert!(recipient
                .decrypt_key(&kms_fixture(&recipient, streaming, &[b'x'; 64]))
                .is_err());
            let short = kms_fixture(&recipient, streaming, &[42; 31]);
            assert!(recipient.decrypt_key(&short).is_err());
        }
        assert!(recipient.decrypt_key(&[]).is_err());
        assert!(recipient.decrypt_key(&[0; 16385]).is_err());
        assert!(recipient.decrypt_key(b"not CMS").is_err());
    }
}
