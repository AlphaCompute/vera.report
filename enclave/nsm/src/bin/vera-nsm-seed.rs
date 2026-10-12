use std::error::Error;

#[cfg(any(target_os = "linux", test))]
const SEED_BYTES: usize = 32;

#[cfg(any(target_os = "linux", test))]
fn collect_seed(
    mut random: impl FnMut() -> Result<Vec<u8>, Box<dyn Error>>,
) -> Result<[u8; SEED_BYTES], Box<dyn Error>> {
    let mut seed = [0u8; SEED_BYTES];
    let mut filled = 0;
    while filled < seed.len() {
        let mut bytes = random()?;
        if bytes.is_empty() || bytes.len() > 256 {
            return Err("invalid NSM random response length".into());
        }
        let count = bytes.len().min(seed.len() - filled);
        seed[filled..filled + count].copy_from_slice(&bytes[..count]);
        bytes.fill(0);
        filled += count;
    }
    Ok(seed)
}

#[cfg(target_os = "linux")]
fn seed_kernel() -> Result<(), Box<dyn Error>> {
    use aws_nitro_enclaves_nsm_api::{
        api::{Request, Response},
        driver::{nsm_exit, nsm_init, nsm_process_request},
    };
    use std::{fs::OpenOptions, os::fd::AsRawFd};

    // Linux rand_pool_info has an eight-byte header followed by a flexible byte array.
    #[repr(C)]
    struct Header {
        entropy_count: i32,
        buf_size: i32,
    }
    #[repr(C)]
    struct Pool {
        header: Header,
        bytes: [u8; SEED_BYTES],
    }
    const _: () = assert!(std::mem::size_of::<Header>() == 8);
    const _: () = assert!(std::mem::size_of::<Pool>() == 40);
    nix::ioctl_write_ptr!(add_entropy, b'R', 0x03, Header);

    let nsm = nsm_init();
    if nsm < 0 {
        return Err("cannot open Nitro /dev/nsm".into());
    }
    let outcome = (|| {
        let mut pool = Pool {
            header: Header {
                entropy_count: (SEED_BYTES * 8) as i32,
                buf_size: SEED_BYTES as i32,
            },
            bytes: collect_seed(|| match nsm_process_request(nsm, Request::GetRandom) {
                Response::GetRandom { random } => Ok(random),
                _ => Err("NSM random request failed".into()),
            })?,
        };
        let device = OpenOptions::new().write(true).open("/dev/random")?;
        // Header is first in repr(C) Pool; the kernel reads exactly buf_size trailing bytes.
        let result = unsafe { add_entropy(device.as_raw_fd(), &pool.header) };
        pool.bytes.fill(0);
        result.map(|_| ()).map_err(Into::into)
    })();
    nsm_exit(nsm);
    outcome
}

#[cfg(not(target_os = "linux"))]
fn seed_kernel() -> Result<(), Box<dyn Error>> {
    Err("Nitro entropy initialization requires Linux /dev/nsm".into())
}

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args_os().len() != 1 {
        return Err("entropy initialization accepts no arguments".into());
    }
    seed_kernel()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accumulates_short_responses_and_bounds_requests() {
        let mut calls = 0;
        let seed = collect_seed(|| {
            calls += 1;
            Ok(vec![calls])
        })
        .unwrap();
        assert_eq!(calls, 32);
        assert_eq!(seed[0], 1);
        assert_eq!(seed[31], 32);
    }
    #[test]
    fn uses_only_required_entropy() {
        let mut calls = 0;
        assert_eq!(
            collect_seed(|| {
                calls += 1;
                Ok(vec![7; 256])
            })
            .unwrap(),
            [7; 32]
        );
        assert_eq!(calls, 1);
    }
    #[test]
    fn refuses_empty_oversized_and_failed_responses() {
        assert!(collect_seed(|| Ok(vec![])).is_err());
        assert!(collect_seed(|| Ok(vec![0; 257])).is_err());
        assert!(collect_seed(|| Err("device failed".into())).is_err());
    }
}
