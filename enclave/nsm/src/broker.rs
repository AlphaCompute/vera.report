//! Internal measured-process protocol. `install` must only receive an AWS TLS-
//! authenticated response from the enclave KMS client, never a public RPC field.
use crate::{
    key_handles::{KeyHandles, Purpose, Sealed},
    recipient::RecipientKey,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub id: u64,
    pub command: Command,
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub enum Command {
    BeginRead {
        handle: String,
        purpose: Purpose,
        record: String,
        field: Option<String>,
        iv: String,
        size: usize,
    },
    AppendRead {
        stream: u64,
        ciphertext: String,
    },
    AuthenticateRead {
        stream: u64,
        tag: String,
    },
    ReadChunk {
        stream: u64,
    },
    Prepare {
        nonce: String,
        purpose: Purpose,
        record: String,
    },
    PrepareLegacyPrivate {
        nonce: String,
        record: String,
        field: String,
    },
    DecryptLegacyPrivate {
        handle: String,
        record: String,
        field: String,
        iv: String,
        tag: String,
        ciphertext: String,
    },
    PrepareLegacyEvidence {
        nonce: String,
        purpose: Purpose,
        record: String,
        salt: String,
    },
    DecryptLegacyEvidence {
        handle: String,
        purpose: Purpose,
        record: String,
        iv: String,
        tag: String,
        ciphertext: String,
    },
    Install {
        envelope: String,
    },
    Cancel {},
    Encrypt {
        handle: String,
        purpose: Purpose,
        record: String,
        plaintext: String,
    },
    Decrypt {
        handle: String,
        purpose: Purpose,
        record: String,
        iv: String,
        tag: String,
        ciphertext: String,
    },
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Reply {
    ReadStarted {
        stream: u64,
    },
    ReadAccepted,
    ReadAuthenticated,
    ReadOutput {
        plaintext: String,
        done: bool,
    },
    Attestation {
        document: String,
    },
    Handle {
        handle: String,
    },
    Cancelled,
    Encrypted {
        iv: String,
        tag: String,
        ciphertext: String,
    },
    Decrypted {
        plaintext: String,
    },
}
struct Pending {
    purpose: Purpose,
    record: String,
    salt: Option<[u8; 32]>,
    field: Option<String>,
}
pub struct Broker {
    recipient: RecipientKey,
    keys: KeyHandles,
    session: [u8; 32],
    certificate: [u8; 32],
    pending: Option<Pending>,
    read: Option<(u64, crate::authenticated_read::AuthenticatedRead)>,
    nonces: HashSet<[u8; 32]>,
    next_id: u64,
    started: Instant,
}
impl Broker {
    pub fn new(session: [u8; 32], certificate: [u8; 32]) -> Result<Self, &'static str> {
        Ok(Self {
            recipient: RecipientKey::generate().map_err(|_| "Recipient unavailable")?,
            keys: KeyHandles::default(),
            session,
            certificate,
            pending: None,
            read: None,
            nonces: HashSet::new(),
            next_id: 0,
            started: Instant::now(),
        })
    }
    // Taking ownership before parsing chunks ensures any error drops buffered plaintext.
    fn take_read(
        &mut self,
        stream: u64,
    ) -> Result<crate::authenticated_read::AuthenticatedRead, &'static str> {
        let (expected, reader) = self.read.take().ok_or("No active read")?;
        if stream != expected {
            return Err("Wrong read stream");
        }
        Ok(reader)
    }
    pub fn handle(&mut self, frame: Frame) -> Result<Reply, &'static str> {
        self.handle_with(frame, |key, nonce, certificate| {
            key.attest(nonce, certificate)
                .map_err(|_| "Attestation unavailable")
        })
    }
    fn handle_with(
        &mut self,
        frame: Frame,
        attest: impl FnOnce(&RecipientKey, &[u8], &[u8]) -> Result<Vec<u8>, &'static str>,
    ) -> Result<Reply, &'static str> {
        if self.started.elapsed() >= Duration::from_secs(300)
            || frame.id != self.next_id
            || self.next_id >= 10000
        {
            self.keys.close_session(&self.session);
            self.pending = None;
            self.read = None;
            // A sequence violation permanently closes this broker.
            self.next_id = u64::MAX;
            return Err("Broker session unavailable");
        }
        self.next_id += 1;
        if self.read.is_some()
            && !matches!(
                &frame.command,
                Command::AppendRead { .. }
                    | Command::AuthenticateRead { .. }
                    | Command::ReadChunk { .. }
                    | Command::Cancel { .. }
            )
        {
            self.read = None;
            return Err("Read already active");
        }
        match frame.command {
            Command::BeginRead {
                handle,
                purpose,
                record,
                field,
                iv,
                size,
            } => {
                if self.pending.is_some() {
                    return Err("Bootstrap pending");
                }
                let reader = self.keys.begin_read(
                    &fixed(&handle)?,
                    &self.session,
                    purpose,
                    &record,
                    field.as_deref(),
                    &decode(&iv, 16)?,
                    size,
                )?;
                self.read = Some((frame.id, reader));
                Ok(Reply::ReadStarted { stream: frame.id })
            }
            Command::AppendRead { stream, ciphertext } => {
                let mut reader = self.take_read(stream)?;
                reader.append(&decode(&ciphertext, crate::authenticated_read::MAX_CHUNK)?)?;
                self.read = Some((stream, reader));
                Ok(Reply::ReadAccepted)
            }
            Command::AuthenticateRead { stream, tag } => {
                let mut reader = self.take_read(stream)?;
                reader.authenticate(&fixed(&tag)?)?;
                self.read = Some((stream, reader));
                Ok(Reply::ReadAuthenticated)
            }
            Command::ReadChunk { stream } => {
                let mut reader = self.take_read(stream)?;
                let (plaintext, done) = reader.read_chunk()?;
                if !done {
                    self.read = Some((stream, reader));
                }
                Ok(Reply::ReadOutput {
                    plaintext: STANDARD.encode(&*plaintext),
                    done,
                })
            }
            Command::Prepare {
                nonce,
                purpose,
                record,
            } => {
                let nonce = fixed::<32>(&nonce)?;
                if self.pending.is_some()
                    || self.nonces.len() >= 64
                    || self.nonces.contains(&nonce)
                    || record.is_empty()
                    || record.len() > 256
                {
                    return Err("Bootstrap unavailable");
                }
                self.nonces.insert(nonce);
                let document = attest(&self.recipient, &nonce, &self.certificate)?;
                self.pending = Some(Pending {
                    purpose,
                    record,
                    salt: None,
                    field: None,
                });
                Ok(Reply::Attestation {
                    document: STANDARD.encode(document),
                })
            }
            Command::PrepareLegacyPrivate {
                nonce,
                record,
                field,
            } => {
                let nonce = fixed::<32>(&nonce)?;
                if self.pending.is_some()
                    || self.nonces.len() >= 64
                    || self.nonces.contains(&nonce)
                    || record.is_empty()
                    || record.len() > 256
                    || field.is_empty()
                    || field.len() > 256
                {
                    return Err("Bootstrap unavailable");
                }
                self.nonces.insert(nonce);
                let document = attest(&self.recipient, &nonce, &self.certificate)?;
                self.pending = Some(Pending {
                    purpose: Purpose::Narrative,
                    record,
                    salt: None,
                    field: Some(field),
                });
                Ok(Reply::Attestation {
                    document: STANDARD.encode(document),
                })
            }
            Command::DecryptLegacyPrivate {
                handle,
                record,
                field,
                iv,
                tag,
                ciphertext,
            } => {
                let sealed = Sealed {
                    iv: fixed(&iv)?,
                    tag: fixed(&tag)?,
                    ciphertext: decode(&ciphertext, 8 * 1024 * 1024)?,
                };
                let plaintext = self.keys.decrypt_legacy_private(
                    &fixed(&handle)?,
                    &self.session,
                    &record,
                    &field,
                    &sealed,
                )?;
                Ok(Reply::Decrypted {
                    plaintext: STANDARD.encode(&*plaintext),
                })
            }
            Command::PrepareLegacyEvidence {
                nonce,
                purpose,
                record,
                salt,
            } => {
                let nonce = fixed::<32>(&nonce)?;
                let salt = fixed::<32>(&salt)?;
                if self.pending.is_some()
                    || self.nonces.len() >= 64
                    || self.nonces.contains(&nonce)
                    || record.is_empty()
                    || record.len() > 256
                {
                    return Err("Bootstrap unavailable");
                }
                self.nonces.insert(nonce);
                let document = attest(&self.recipient, &nonce, &self.certificate)?;
                self.pending = Some(Pending {
                    purpose,
                    record,
                    salt: Some(salt),
                    field: None,
                });
                Ok(Reply::Attestation {
                    document: STANDARD.encode(document),
                })
            }
            Command::Install { envelope } => {
                let pending = self.pending.take().ok_or("No pending bootstrap")?;
                let envelope = decode(&envelope, 16384)?;
                let handle = if let Some(field) = pending.field {
                    let key = self.recipient.decrypt_legacy_private_key(&envelope)?;
                    self.keys
                        .insert_legacy_private(key, self.session, &pending.record, &field)?
                } else if let Some(salt) = pending.salt {
                    let key = self
                        .recipient
                        .decrypt_legacy_evidence_key(&envelope, &salt)?;
                    self.keys.insert_legacy_evidence(
                        key,
                        self.session,
                        pending.purpose,
                        &pending.record,
                    )?
                } else {
                    let key = self.recipient.decrypt_key(&envelope)?;
                    self.keys
                        .insert(key, self.session, pending.purpose, &pending.record)?
                };
                Ok(Reply::Handle {
                    handle: STANDARD.encode(handle),
                })
            }
            Command::DecryptLegacyEvidence {
                handle,
                purpose,
                record,
                iv,
                tag,
                ciphertext,
            } => {
                let plaintext = self.keys.decrypt_legacy_evidence(
                    &fixed(&handle)?,
                    &self.session,
                    purpose,
                    &record,
                    &fixed(&iv)?,
                    &fixed(&tag)?,
                    &decode(&ciphertext, 8 * 1024 * 1024)?,
                )?;
                Ok(Reply::Decrypted {
                    plaintext: STANDARD.encode(&*plaintext),
                })
            }
            Command::Cancel {} => {
                self.pending = None;
                self.read = None;
                Ok(Reply::Cancelled)
            }
            Command::Encrypt {
                handle,
                purpose,
                record,
                plaintext,
            } => {
                let plaintext = Zeroizing::new(decode(&plaintext, 8 * 1024 * 1024)?);
                let result = self.keys.encrypt(
                    &fixed(&handle)?,
                    &self.session,
                    purpose,
                    &record,
                    &plaintext,
                )?;
                Ok(Reply::Encrypted {
                    iv: STANDARD.encode(result.iv),
                    tag: STANDARD.encode(result.tag),
                    ciphertext: STANDARD.encode(result.ciphertext),
                })
            }
            Command::Decrypt {
                handle,
                purpose,
                record,
                iv,
                tag,
                ciphertext,
            } => {
                let sealed = Sealed {
                    iv: fixed(&iv)?,
                    tag: fixed(&tag)?,
                    ciphertext: decode(&ciphertext, 8 * 1024 * 1024)?,
                };
                let plaintext = self.keys.decrypt(
                    &fixed(&handle)?,
                    &self.session,
                    purpose,
                    &record,
                    &sealed,
                )?;
                Ok(Reply::Decrypted {
                    plaintext: STANDARD.encode(&*plaintext),
                })
            }
        }
    }
}
fn decode(value: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() > 4 * ((max + 2) / 3) {
        return Err("Invalid encoding");
    }
    let bytes = STANDARD.decode(value).map_err(|_| "Invalid encoding")?;
    if bytes.len() > max || STANDARD.encode(&bytes) != value {
        return Err("Invalid encoding");
    }
    Ok(bytes)
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    decode(value, N)?.try_into().map_err(|_| "Invalid encoding")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn call(b: &mut Broker, id: u64, command: Command) -> Result<Reply, &'static str> {
        b.handle_with(Frame { id, command }, |_, nonce, cert| {
            assert_eq!(nonce.len(), 32);
            assert_eq!(cert, &[2; 32]);
            Ok(b"synthetic-attestation".to_vec())
        })
    }
    fn read_fixture(size: usize) -> (Broker, String, Sealed) {
        let mut b = Broker::new([1; 32], [2; 32]).unwrap();
        let handle = b
            .keys
            .insert(
                Zeroizing::new([7; 32]),
                b.session,
                Purpose::Evidence,
                "record",
            )
            .unwrap();
        let sealed = b
            .keys
            .encrypt(
                &handle,
                &b.session,
                Purpose::Evidence,
                "record",
                &vec![97; size],
            )
            .unwrap();
        (b, STANDARD.encode(handle), sealed)
    }
    fn begin_read(handle: &str, sealed: &Sealed) -> Command {
        Command::BeginRead {
            handle: handle.into(),
            purpose: Purpose::Evidence,
            record: "record".into(),
            field: None,
            iv: STANDARD.encode(sealed.iv),
            size: sealed.ciphertext.len(),
        }
    }
    #[test]
    fn chunk_protocol_authenticates_before_draining_and_cannot_reuse_stream() {
        let (mut b, handle, sealed) = read_fixture(crate::authenticated_read::MAX_CHUNK + 8);
        assert!(matches!(
            call(&mut b, 0, begin_read(&handle, &sealed)).unwrap(),
            Reply::ReadStarted { stream: 0 }
        ));
        let mut id = 1;
        for chunk in sealed
            .ciphertext
            .chunks(crate::authenticated_read::MAX_CHUNK)
        {
            assert!(matches!(
                call(
                    &mut b,
                    id,
                    Command::AppendRead {
                        stream: 0,
                        ciphertext: STANDARD.encode(chunk)
                    }
                )
                .unwrap(),
                Reply::ReadAccepted
            ));
            id += 1;
        }
        assert!(matches!(
            call(
                &mut b,
                id,
                Command::AuthenticateRead {
                    stream: 0,
                    tag: STANDARD.encode(sealed.tag)
                }
            )
            .unwrap(),
            Reply::ReadAuthenticated
        ));
        id += 1;
        let mut total = 0;
        loop {
            let Reply::ReadOutput { plaintext, done } =
                call(&mut b, id, Command::ReadChunk { stream: 0 }).unwrap()
            else {
                panic!()
            };
            id += 1;
            let bytes = STANDARD.decode(plaintext).unwrap();
            assert!(bytes.len() <= crate::authenticated_read::MAX_CHUNK);
            assert!(bytes.iter().all(|b| *b == 97));
            total += bytes.len();
            if done {
                break;
            }
        }
        assert_eq!(total, sealed.ciphertext.len());
        assert!(b.read.is_none());
        assert!(call(&mut b, id, Command::ReadChunk { stream: 0 }).is_err());
    }
    #[test]
    fn invalid_stream_operations_drop_buffered_plaintext() {
        for attack in [
            "early", "tag", "stream", "encoding", "overflow", "second", "cancel", "sequence",
            "expiry",
        ] {
            let (mut b, handle, sealed) = read_fixture(8);
            call(&mut b, 0, begin_read(&handle, &sealed)).unwrap();
            call(
                &mut b,
                1,
                Command::AppendRead {
                    stream: 0,
                    ciphertext: STANDARD.encode(&sealed.ciphertext),
                },
            )
            .unwrap();
            let command = match attack {
                "early" => Command::ReadChunk { stream: 0 },
                "tag" => Command::AuthenticateRead {
                    stream: 0,
                    tag: STANDARD.encode([0; 16]),
                },
                "stream" => Command::AuthenticateRead {
                    stream: 1,
                    tag: STANDARD.encode(sealed.tag),
                },
                "encoding" => Command::AppendRead {
                    stream: 0,
                    ciphertext: "!".into(),
                },
                "overflow" => Command::AppendRead {
                    stream: 0,
                    ciphertext: STANDARD.encode([0]),
                },
                "second" => begin_read(&handle, &sealed),
                "cancel" => Command::Cancel {},
                _ => Command::AuthenticateRead {
                    stream: 0,
                    tag: STANDARD.encode(sealed.tag),
                },
            };
            if attack == "expiry" {
                b.started = Instant::now() - Duration::from_secs(300);
            }
            let result = call(&mut b, if attack == "sequence" { 1 } else { 2 }, command);
            assert_eq!(result.is_ok(), attack == "cancel");
            assert!(b.read.is_none());
            assert!(call(&mut b, 3, Command::ReadChunk { stream: 0 }).is_err());
        }
    }
    fn legacy_fixture(secret: &str) -> serde_json::Value {
        use std::{
            io::Write,
            process::{Command as Process, Stdio},
        };
        let script = r#"
          const c=require('node:crypto');let input='';
          process.stdin.on('data',b=>input+=b);process.stdin.on('end',()=>{
            const {secret}=JSON.parse(input),salt=Buffer.alloc(32,4),iv=Buffer.alloc(16,3);
            const key=c.pbkdf2Sync(secret,salt,100000,32,'sha256');
            const cipher=c.createCipheriv('aes-256-gcm',key,iv);
            const ciphertext=Buffer.concat([cipher.update('synthetic historical evidence'),cipher.final()]);
            process.stdout.write(JSON.stringify({salt:salt.toString('base64'),iv:iv.toString('base64'),
              tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')}));
          });
        "#;
        let mut child = Process::new("node")
            .args(["-e", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                serde_json::to_string(&serde_json::json!({"secret":secret}))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        serde_json::from_slice(&result.stdout).unwrap()
    }
    #[test]
    fn historical_payloads_use_original_password_bytes_and_read_only_scoped_handles() {
        for secret in ["ab".repeat(32), "AB".repeat(32)] {
            let fixture = legacy_fixture(&secret);
            let text = |name: &str| fixture[name].as_str().unwrap().to_owned();
            let mut broker = Broker::new([1; 32], [2; 32]).unwrap();
            call(
                &mut broker,
                0,
                Command::PrepareLegacyEvidence {
                    nonce: STANDARD.encode([9; 32]),
                    purpose: Purpose::Evidence,
                    record: "record".into(),
                    salt: text("salt"),
                },
            )
            .unwrap();
            let cms =
                crate::recipient::tests::kms_fixture(&broker.recipient, false, secret.as_bytes());
            let Reply::Handle { handle } = call(
                &mut broker,
                1,
                Command::Install {
                    envelope: STANDARD.encode(cms),
                },
            )
            .unwrap() else {
                panic!()
            };
            let decrypt = |record: &str, tag: String, iv: String| Command::DecryptLegacyEvidence {
                handle: handle.clone(),
                purpose: Purpose::Evidence,
                record: record.into(),
                iv,
                tag,
                ciphertext: text("ciphertext"),
            };
            let Reply::Decrypted { plaintext } =
                call(&mut broker, 2, decrypt("record", text("tag"), text("iv"))).unwrap()
            else {
                panic!()
            };
            assert_eq!(
                STANDARD.decode(plaintext).unwrap(),
                b"synthetic historical evidence"
            );
            assert!(call(
                &mut broker,
                3,
                Command::Encrypt {
                    handle: handle.clone(),
                    purpose: Purpose::Evidence,
                    record: "record".into(),
                    plaintext: STANDARD.encode(b"new")
                }
            )
            .is_err());
            assert!(call(
                &mut broker,
                4,
                Command::Decrypt {
                    handle: handle.clone(),
                    purpose: Purpose::Evidence,
                    record: "record".into(),
                    iv: STANDARD.encode([3; 12]),
                    tag: text("tag"),
                    ciphertext: text("ciphertext")
                }
            )
            .is_err());
            assert!(call(
                &mut broker,
                5,
                decrypt("different", text("tag"), text("iv"))
            )
            .is_err());
            assert!(call(
                &mut broker,
                6,
                decrypt("record", STANDARD.encode([0; 16]), text("iv"))
            )
            .is_err());
            assert!(call(
                &mut broker,
                7,
                decrypt("record", text("tag"), STANDARD.encode([3; 12]))
            )
            .is_err());
        }
    }
    #[test]
    fn historical_bootstrap_rejects_binary_keys_and_wrong_salt_does_not_decrypt() {
        let secret = "ab".repeat(32);
        let fixture = legacy_fixture(&secret);
        for binary_key in [false, true] {
            let mut broker = Broker::new([1; 32], [2; 32]).unwrap();
            call(
                &mut broker,
                0,
                Command::PrepareLegacyEvidence {
                    nonce: STANDARD.encode([8; 32]),
                    purpose: Purpose::Narrative,
                    record: "record".into(),
                    salt: STANDARD.encode([5; 32]),
                },
            )
            .unwrap();
            let cms = crate::recipient::tests::kms_fixture(
                &broker.recipient,
                false,
                if binary_key {
                    &[7; 32]
                } else {
                    secret.as_bytes()
                },
            );
            let installed = call(
                &mut broker,
                1,
                Command::Install {
                    envelope: STANDARD.encode(cms),
                },
            );
            if binary_key {
                assert!(installed.is_err());
                continue;
            }
            let Reply::Handle { handle } = installed.unwrap() else {
                panic!()
            };
            assert!(call(
                &mut broker,
                2,
                Command::DecryptLegacyEvidence {
                    handle,
                    purpose: Purpose::Narrative,
                    record: "record".into(),
                    iv: fixture["iv"].as_str().unwrap().into(),
                    tag: fixture["tag"].as_str().unwrap().into(),
                    ciphertext: fixture["ciphertext"].as_str().unwrap().into()
                }
            )
            .is_err());
        }
    }
    #[test]
    fn historical_private_fields_match_node_aad_and_refuse_field_or_format_substitution() {
        use std::{
            io::Write,
            process::{Command as Process, Stdio},
        };
        let record = "record-雪";
        let field = "field-\"\\\n";
        let secret = "AB".repeat(32);
        let script = r#"
          const c=require('node:crypto');let input='';process.stdin.on('data',b=>input+=b);
          process.stdin.on('end',()=>{const {record,field,secret}=JSON.parse(input),iv=Buffer.alloc(12,3);
            const cipher=c.createCipheriv('aes-256-gcm',Buffer.from(secret,'hex'),iv);
            cipher.setAAD(Buffer.from(JSON.stringify([record,field])));
            const plaintext=JSON.stringify({nested:['synthetic',true]});
            const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
            process.stdout.write(JSON.stringify({iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64'),plaintext}));});
        "#;
        let mut child = Process::new("node")
            .args(["-e", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                serde_json::to_string(
                    &serde_json::json!({"record":record,"field":field,"secret":secret}),
                )
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        let fixture: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let text = |name: &str| fixture[name].as_str().unwrap().to_owned();
        let mut broker = Broker::new([1; 32], [2; 32]).unwrap();
        call(
            &mut broker,
            0,
            Command::PrepareLegacyPrivate {
                nonce: STANDARD.encode([9; 32]),
                record: record.into(),
                field: field.into(),
            },
        )
        .unwrap();
        let cms = crate::recipient::tests::kms_fixture(&broker.recipient, false, secret.as_bytes());
        let Reply::Handle { handle } = call(
            &mut broker,
            1,
            Command::Install {
                envelope: STANDARD.encode(cms),
            },
        )
        .unwrap() else {
            panic!()
        };
        let decrypt = |record: &str, field: &str, tag: String| Command::DecryptLegacyPrivate {
            handle: handle.clone(),
            record: record.into(),
            field: field.into(),
            iv: text("iv"),
            tag,
            ciphertext: text("ciphertext"),
        };
        let Reply::Decrypted { plaintext } =
            call(&mut broker, 2, decrypt(record, field, text("tag"))).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            STANDARD.decode(plaintext).unwrap(),
            text("plaintext").as_bytes()
        );
        assert!(call(&mut broker, 3, decrypt("other", field, text("tag"))).is_err());
        assert_eq!(
            call(&mut broker, 4, decrypt(record, "other", text("tag")))
                .err()
                .unwrap(),
            "Wrong key payload format or field"
        );
        assert!(call(
            &mut broker,
            5,
            decrypt(record, field, STANDARD.encode([0; 16]))
        )
        .is_err());
        assert_eq!(
            call(
                &mut broker,
                6,
                Command::Decrypt {
                    handle: handle.clone(),
                    purpose: Purpose::Narrative,
                    record: record.into(),
                    iv: text("iv"),
                    tag: text("tag"),
                    ciphertext: text("ciphertext")
                }
            )
            .err()
            .unwrap(),
            "Wrong key payload format"
        );
        assert_eq!(
            call(
                &mut broker,
                7,
                Command::Encrypt {
                    handle,
                    purpose: Purpose::Narrative,
                    record: record.into(),
                    plaintext: STANDARD.encode(b"new")
                }
            )
            .err()
            .unwrap(),
            "Wrong key payload format"
        );
        call(
            &mut broker,
            8,
            Command::PrepareLegacyPrivate {
                nonce: STANDARD.encode([8; 32]),
                record: record.into(),
                field: field.into(),
            },
        )
        .unwrap();
        let cms = crate::recipient::tests::kms_fixture(&broker.recipient, false, &[7; 32]);
        assert!(call(
            &mut broker,
            9,
            Command::Install {
                envelope: STANDARD.encode(cms)
            }
        )
        .is_err());
    }
    fn prepare(nonce: u8) -> Command {
        Command::Prepare {
            nonce: STANDARD.encode([nonce; 32]),
            purpose: Purpose::Evidence,
            record: "record".into(),
        }
    }
    #[test]
    fn installs_only_after_prepare_and_keeps_key_inside_record_scope() {
        let mut b = Broker::new([1; 32], [2; 32]).unwrap();
        let envelope = crate::recipient::tests::kms_fixture(&b.recipient, false, &[7; 32]);
        assert!(call(
            &mut b,
            0,
            Command::Install {
                envelope: STANDARD.encode(&envelope)
            }
        )
        .is_err());
        call(&mut b, 1, prepare(3)).unwrap();
        let handle = match call(
            &mut b,
            2,
            Command::Install {
                envelope: STANDARD.encode(&envelope),
            },
        )
        .unwrap()
        {
            Reply::Handle { handle } => handle,
            _ => panic!(),
        };
        assert_ne!(STANDARD.decode(&handle).unwrap(), vec![7; 32]);
        assert!(call(
            &mut b,
            3,
            Command::Install {
                envelope: STANDARD.encode(envelope)
            }
        )
        .is_err());
        assert!(call(
            &mut b,
            4,
            Command::Encrypt {
                handle: handle.clone(),
                purpose: Purpose::Evidence,
                record: "other".into(),
                plaintext: STANDARD.encode(b"synthetic")
            }
        )
        .is_err());
        let (iv, tag, ciphertext) = match call(
            &mut b,
            5,
            Command::Encrypt {
                handle: handle.clone(),
                purpose: Purpose::Evidence,
                record: "record".into(),
                plaintext: STANDARD.encode(b"synthetic"),
            },
        )
        .unwrap()
        {
            Reply::Encrypted {
                iv,
                tag,
                ciphertext,
            } => (iv, tag, ciphertext),
            _ => panic!(),
        };
        match call(
            &mut b,
            6,
            Command::Decrypt {
                handle,
                purpose: Purpose::Evidence,
                record: "record".into(),
                iv,
                tag,
                ciphertext,
            },
        )
        .unwrap()
        {
            Reply::Decrypted { plaintext } => {
                assert_eq!(STANDARD.decode(plaintext).unwrap(), b"synthetic")
            }
            _ => panic!(),
        }
    }
    #[test]
    fn replay_and_sequence_violation_cannot_restart_a_session() {
        let mut b = Broker::new([1; 32], [2; 32]).unwrap();
        call(&mut b, 0, prepare(3)).unwrap();
        call(&mut b, 1, Command::Cancel {}).unwrap();
        assert!(call(&mut b, 2, prepare(3)).is_err());
        assert!(call(&mut b, 2, prepare(4)).is_err());
        assert!(call(&mut b, 3, prepare(4)).is_err());
    }
    #[test]
    fn failed_install_consumes_pending_state_and_schema_rejects_extras() {
        let mut b = Broker::new([1; 32], [2; 32]).unwrap();
        call(&mut b, 0, prepare(3)).unwrap();
        assert!(call(
            &mut b,
            1,
            Command::Install {
                envelope: STANDARD.encode(b"bad")
            }
        )
        .is_err());
        assert!(b.pending.is_none());
        assert!(serde_json::from_str::<Frame>(
            r#"{"id":0,"command":{"method":"cancel","key":"external"}}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Frame>(r#"{"id":0,"id":1,"command":{"method":"cancel"}}"#)
                .is_err()
        );
        assert!(fixed::<32>(&STANDARD.encode([0; 31])).is_err());
        b.started = Instant::now() - Duration::from_secs(300);
        assert!(call(&mut b, 2, prepare(4)).is_err());
    }
}
