//! Purpose and TLS-session scoped key storage. Bootstrap insertion is internal;
//! there is no key export operation. Not exposed through application RPCs yet.
use openssl::{
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CAPACITY: usize = 64;
const TTL: Duration = Duration::from_secs(300);
const MAX_DATA: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Evidence,
    Narrative,
}
enum PayloadFormat {
    Current,
    LegacyEvidence,
    LegacyPrivate(String),
}
struct Entry {
    key: Zeroizing<[u8; 32]>,
    session: [u8; 32],
    purpose: Purpose,
    record: String,
    expires: Instant,
    format: PayloadFormat,
}
#[derive(Default)]
pub struct KeyHandles {
    entries: HashMap<[u8; 32], Entry>,
}
/// Public encryption output contains no key material.
pub struct Sealed {
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: Vec<u8>,
}

impl KeyHandles {
    fn reap(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expires > now);
    }

    // Only an authenticated enclave bootstrap may call this. Never expose an
    // RPC that imports caller-provided keys or accepts unverified KMS replies.
    pub(crate) fn insert(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        session: [u8; 32],
        purpose: Purpose,
        record: &str,
    ) -> Result<[u8; 32], &'static str> {
        self.insert_at(key, session, purpose, record, Instant::now())
    }
    pub(crate) fn insert_legacy_evidence(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        session: [u8; 32],
        purpose: Purpose,
        record: &str,
    ) -> Result<[u8; 32], &'static str> {
        let handle = self.insert(key, session, purpose, record)?;
        self.entries
            .get_mut(&handle)
            .ok_or("Key handle unavailable")?
            .format = PayloadFormat::LegacyEvidence;
        Ok(handle)
    }
    pub(crate) fn insert_legacy_private(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        session: [u8; 32],
        record: &str,
        field: &str,
    ) -> Result<[u8; 32], &'static str> {
        if field.is_empty() || field.len() > 256 {
            return Err("Invalid private field");
        }
        let handle = self.insert(key, session, Purpose::Narrative, record)?;
        self.entries
            .get_mut(&handle)
            .ok_or("Key handle unavailable")?
            .format = PayloadFormat::LegacyPrivate(field.to_owned());
        Ok(handle)
    }
    fn insert_at(
        &mut self,
        key: Zeroizing<[u8; 32]>,
        session: [u8; 32],
        purpose: Purpose,
        record: &str,
        now: Instant,
    ) -> Result<[u8; 32], &'static str> {
        aad(purpose, record, 0)?;
        self.reap(now);
        if self.entries.len() >= CAPACITY {
            return Err("Key handle capacity exhausted");
        }
        let mut handle = [0; 32];
        // A collision must never overwrite another live key.
        for _ in 0..4 {
            rand_bytes(&mut handle).map_err(|_| "Key handle unavailable")?;
            if !self.entries.contains_key(&handle) {
                self.entries.insert(
                    handle,
                    Entry {
                        key,
                        session,
                        purpose,
                        record: record.to_owned(),
                        expires: now + TTL,
                        format: PayloadFormat::Current,
                    },
                );
                return Ok(handle);
            }
        }
        Err("Key handle unavailable")
    }
    fn get(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        purpose: Purpose,
        record: &str,
    ) -> Result<&Entry, &'static str> {
        self.reap(Instant::now());
        self.entries
            .get(handle)
            .filter(|e| &e.session == session && e.purpose == purpose && e.record == record)
            .ok_or("Key handle unavailable")
    }
    pub fn close_session(&mut self, session: &[u8; 32]) {
        self.entries.retain(|_, e| &e.session != session);
    }
    pub fn begin_read(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        purpose: Purpose,
        record: &str,
        field: Option<&str>,
        iv: &[u8],
        size: usize,
    ) -> Result<crate::authenticated_read::AuthenticatedRead, &'static str> {
        let entry = self.get(handle, session, purpose, record)?;
        let aad = match &entry.format {
            PayloadFormat::Current if iv.len() == 12 && field.is_none() => aad(purpose, record, 0)?,
            PayloadFormat::LegacyEvidence if iv.len() == 16 && field.is_none() => Vec::new(),
            PayloadFormat::LegacyPrivate(bound)
                if iv.len() == 12 && field == Some(bound.as_str()) =>
            {
                serde_json::to_vec(&[record, bound.as_str()])
                    .map_err(|_| "Invalid private field binding")?
            }
            _ => return Err("Wrong key payload format or field"),
        };
        let mut reader =
            crate::authenticated_read::AuthenticatedRead::new(entry.key.as_ref(), iv, &aad, size)?;
        reader.expire_with(entry.expires);
        Ok(reader)
    }
    pub fn encrypt(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        purpose: Purpose,
        record: &str,
        plaintext: &[u8],
    ) -> Result<Sealed, &'static str> {
        let aad = aad(purpose, record, plaintext.len())?;
        let entry = self.get(handle, session, purpose, record)?;
        if !matches!(entry.format, PayloadFormat::Current) {
            return Err("Wrong key payload format");
        }
        let mut iv = [0; 12];
        let mut tag = [0; 16];
        rand_bytes(&mut iv).map_err(|_| "Encryption failed")?;
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            entry.key.as_ref(),
            Some(&iv),
            &aad,
            plaintext,
            &mut tag,
        )
        .map_err(|_| "Encryption failed")?;
        Ok(Sealed {
            iv,
            tag,
            ciphertext,
        })
    }
    pub fn decrypt(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        purpose: Purpose,
        record: &str,
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let aad = aad(purpose, record, sealed.ciphertext.len())?;
        let entry = self.get(handle, session, purpose, record)?;
        if !matches!(entry.format, PayloadFormat::Current) {
            return Err("Wrong key payload format");
        }
        // Fixed-size types require the full GCM tag and IV before decryption.
        decrypt_aead(
            Cipher::aes_256_gcm(),
            entry.key.as_ref(),
            Some(&sealed.iv),
            &aad,
            &sealed.ciphertext,
            &sealed.tag,
        )
        .map(Zeroizing::new)
        .map_err(|_| "Decryption failed")
    }
    /// Historical payloads have a 16-byte IV and no payload AAD. They remain
    /// read-only; record/purpose authorization comes from KMS and handle scope.
    pub fn decrypt_legacy_evidence(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        purpose: Purpose,
        record: &str,
        iv: &[u8; 16],
        tag: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        aad(purpose, record, ciphertext.len())?;
        let entry = self.get(handle, session, purpose, record)?;
        if !matches!(entry.format, PayloadFormat::LegacyEvidence) {
            return Err("Wrong key payload format");
        }
        decrypt_aead(
            Cipher::aes_256_gcm(),
            entry.key.as_ref(),
            Some(iv),
            &[],
            ciphertext,
            tag,
        )
        .map(Zeroizing::new)
        .map_err(|_| "Decryption failed")
    }
    pub fn decrypt_legacy_private(
        &mut self,
        handle: &[u8; 32],
        session: &[u8; 32],
        record: &str,
        field: &str,
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        aad(Purpose::Narrative, record, sealed.ciphertext.len())?;
        let entry = self.get(handle, session, Purpose::Narrative, record)?;
        if !matches!(&entry.format, PayloadFormat::LegacyPrivate(bound) if bound == field) {
            return Err("Wrong key payload format or field");
        }
        let aad =
            serde_json::to_vec(&[record, field]).map_err(|_| "Invalid private field binding")?;
        decrypt_aead(
            Cipher::aes_256_gcm(),
            entry.key.as_ref(),
            Some(&sealed.iv),
            &aad,
            &sealed.ciphertext,
            &sealed.tag,
        )
        .map(Zeroizing::new)
        .map_err(|_| "Decryption failed")
    }
}
fn aad(purpose: Purpose, record: &str, size: usize) -> Result<Vec<u8>, &'static str> {
    if record.is_empty() || record.len() > 256 || size > MAX_DATA {
        return Err("Invalid key operation bounds");
    }
    // Length-prefix the UTF-8 record; fixed purpose discriminants separate uses.
    let mut result = b"VERA-KEY-HANDLE-v1".to_vec();
    result.push(match purpose {
        Purpose::Evidence => 1,
        Purpose::Narrative => 2,
    });
    result.extend_from_slice(&(record.len() as u16).to_be_bytes());
    result.extend_from_slice(record.as_bytes());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_read_enforces_handle_scope_format_and_field_binding() {
        let mut keys = KeyHandles::default();
        let session = [1; 32];
        for format in [0, 1, 2] {
            let purpose = Purpose::Narrative;
            let handle = match format {
                0 => keys
                    .insert(Zeroizing::new([7; 32]), session, purpose, "record")
                    .unwrap(),
                1 => keys
                    .insert_legacy_evidence(Zeroizing::new([7; 32]), session, purpose, "record")
                    .unwrap(),
                _ => keys
                    .insert_legacy_private(Zeroizing::new([7; 32]), session, "record", "field")
                    .unwrap(),
            };
            let field = if format == 2 { Some("field") } else { None };
            let iv = vec![3; if format == 1 { 16 } else { 12 }];
            let binding = match format {
                0 => aad(purpose, "record", 0).unwrap(),
                1 => Vec::new(),
                _ => serde_json::to_vec(&["record", "field"]).unwrap(),
            };
            let mut tag = [0; 16];
            let ciphertext = encrypt_aead(
                Cipher::aes_256_gcm(),
                &[7; 32],
                Some(&iv),
                &binding,
                b"synthetic",
                &mut tag,
            )
            .unwrap();
            assert!(keys
                .begin_read(
                    &handle,
                    &[2; 32],
                    purpose,
                    "record",
                    field,
                    &iv,
                    ciphertext.len()
                )
                .is_err());
            assert!(keys
                .begin_read(
                    &handle,
                    &session,
                    Purpose::Evidence,
                    "record",
                    field,
                    &iv,
                    ciphertext.len()
                )
                .is_err());
            assert!(keys
                .begin_read(
                    &handle,
                    &session,
                    purpose,
                    "other",
                    field,
                    &iv,
                    ciphertext.len()
                )
                .is_err());
            assert!(keys
                .begin_read(
                    &handle,
                    &session,
                    purpose,
                    "record",
                    Some("other"),
                    &iv,
                    ciphertext.len()
                )
                .is_err());
            let wrong_iv = vec![3; if format == 1 { 12 } else { 16 }];
            assert!(keys
                .begin_read(
                    &handle,
                    &session,
                    purpose,
                    "record",
                    field,
                    &wrong_iv,
                    ciphertext.len()
                )
                .is_err());
            let mut reader = keys
                .begin_read(
                    &handle,
                    &session,
                    purpose,
                    "record",
                    field,
                    &iv,
                    ciphertext.len(),
                )
                .unwrap();
            reader.append(&ciphertext).unwrap();
            reader.authenticate(&tag).unwrap();
            assert_eq!(&*reader.read_chunk().unwrap().0, b"synthetic");
            keys.close_session(&session);
            assert!(keys
                .begin_read(
                    &handle,
                    &session,
                    purpose,
                    "record",
                    field,
                    &iv,
                    ciphertext.len()
                )
                .is_err());
        }
    }
    #[test]
    fn roundtrip_denies_wrong_scope_tampering_and_closed_session() {
        let mut store = KeyHandles::default();
        let session = [1; 32];
        let handle = store
            .insert(
                Zeroizing::new([7; 32]),
                session,
                Purpose::Evidence,
                "record",
            )
            .unwrap();
        let mut sealed = store
            .encrypt(&handle, &session, Purpose::Evidence, "record", b"synthetic")
            .unwrap();
        assert_eq!(
            &**store
                .decrypt(&handle, &session, Purpose::Evidence, "record", &sealed)
                .as_ref()
                .unwrap(),
            b"synthetic"
        );
        assert!(store
            .decrypt(&handle, &[2; 32], Purpose::Evidence, "record", &sealed)
            .is_err());
        assert!(store
            .decrypt(&handle, &session, Purpose::Narrative, "record", &sealed)
            .is_err());
        assert!(store
            .decrypt(&handle, &session, Purpose::Evidence, "other", &sealed)
            .is_err());
        assert!(store
            .encrypt(&handle, &session, Purpose::Evidence, "other", b"x")
            .is_err());
        sealed.tag[0] ^= 1;
        assert!(store
            .decrypt(&handle, &session, Purpose::Evidence, "record", &sealed)
            .is_err());
        store.close_session(&session);
        assert!(store
            .encrypt(&handle, &session, Purpose::Evidence, "record", b"x")
            .is_err());
    }
    #[test]
    fn bounds_capacity_expiry_and_session_isolation() {
        let mut store = KeyHandles::default();
        let old = store
            .insert_at(
                Zeroizing::new([1; 32]),
                [1; 32],
                Purpose::Narrative,
                "record",
                Instant::now() - TTL,
            )
            .unwrap();
        assert!(store
            .encrypt(&old, &[1; 32], Purpose::Narrative, "record", b"x")
            .is_err());
        let mut handles = std::collections::HashSet::new();
        for _ in 0..CAPACITY {
            handles.insert(
                store
                    .insert(
                        Zeroizing::new([2; 32]),
                        [2; 32],
                        Purpose::Evidence,
                        "record",
                    )
                    .unwrap(),
            );
        }
        assert_eq!(handles.len(), CAPACITY);
        assert!(store
            .insert(
                Zeroizing::new([3; 32]),
                [3; 32],
                Purpose::Evidence,
                "record"
            )
            .is_err());
        store.close_session(&[1; 32]);
        assert_eq!(store.entries.len(), CAPACITY);
        store.close_session(&[2; 32]);
        assert!(store.entries.is_empty());
        assert!(aad(Purpose::Evidence, "", 0).is_err());
        assert!(aad(Purpose::Evidence, &"x".repeat(257), 0).is_err());
        assert!(aad(Purpose::Evidence, "record", MAX_DATA + 1).is_err());
    }
}
