//! The agent's identity key on disk: a 32-byte Ed25519 seed in `<dir>/key`,
//! mode 0600, written atomically (tmp + rename). Shared by minsec-sync and
//! minsec-id-sync so both keep their keys the same way.

use ed25519_dalek::SigningKey;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn path(dir: &Path) -> PathBuf {
    dir.join("key")
}

/// Load the signing key, generating one on first use.
pub fn load_or_create(dir: &Path) -> io::Result<SigningKey> {
    match std::fs::read(path(dir)) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("corrupt key file {}", path(dir).display()),
                )
            })?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(dir),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("cannot read {}: {e}", path(dir).display()),
        )),
    }
}

/// Replace the key (the server knows the key but the host id was lost).
/// The old key is kept aside as `key.old`.
pub fn rotate(dir: &Path) -> io::Result<SigningKey> {
    let _ = std::fs::rename(path(dir), dir.join("key.old"));
    create(dir)
}

fn create(dir: &Path) -> io::Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| io::Error::other(format!("cannot gather entropy: {e}")))?;
    write(dir, &seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn write(dir: &Path, seed: &[u8; 32]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join("key.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(seed)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_mode_and_rotation() {
        let dir = std::env::temp_dir().join(format!("minsec-proto-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let k1 = load_or_create(&dir).unwrap();
        let k2 = load_or_create(&dir).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let k3 = rotate(&dir).unwrap();
        assert_ne!(k1.to_bytes(), k3.to_bytes());
        assert!(dir.join("key.old").exists());

        std::fs::write(path(&dir), b"short").unwrap();
        assert!(load_or_create(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
