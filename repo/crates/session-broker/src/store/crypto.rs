//! At-rest encryption for the custody columns (INV-5).
//!
//! `custody.refresh_tok` and `custody.access_tok` hold the two things this
//! whole service exists to take custody of. A refresh token on disk in
//! plaintext is a standing grant to act as the user against the upstream IdP
//! for as long as it lives — file-system read access would be enough, so the
//! database file, a stray backup, or a snapshot volume would each be a full
//! compromise of every session's upstream authority.
//!
//! **The key's lifetime is tied to the store's.** [`super::open`] and
//! [`super::open_in_memory`] initialise it, so it is not possible to hold a
//! `Connection` this module cannot decrypt for — the failure mode that would
//! otherwise appear is a store that silently wrote plaintext because some boot
//! path forgot a separate `init_encryption()` call. There is no code path in
//! which [`seal`] returns its input.
//!
//! XChaCha20-Poly1305 with a random 192-bit nonce per value, stored as
//! `nonce || ciphertext`. XChaCha's nonce is large enough that random
//! generation has no practical collision concern, which matters because these
//! rows are rewritten on every keepalive rotation — a counter would have to be
//! persisted and would become a correctness dependency of its own.

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// 32 raw bytes. Not `Vec<u8>`: a fixed size makes "the keyfile is the wrong
/// length" a load-time error rather than a decrypt-time one.
type KeyBytes = [u8; 32];

static KEY: OnceLock<KeyBytes> = OnceLock::new();

/// Load the keyfile at `path`, creating it if absent.
///
/// Created with `0600` on Unix. A keyfile that anyone on the box can read is
/// not meaningfully different from no keyfile at all, so a permissive mode is
/// refused rather than warned about — the operator who would ignore the
/// warning is exactly the one this protects.
pub fn init_from_keyfile(path: &Path) -> io::Result<()> {
    let key = match std::fs::read(path) {
        Ok(bytes) => {
            let len = bytes.len();
            KeyBytes::try_from(bytes.as_slice()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "keyfile {} is {len} bytes; a 32-byte key is required. Refusing to \
                         start rather than derive one, which would silently make every \
                         existing custody row undecryptable.",
                        path.display()
                    ),
                )
            })?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => create_keyfile(path)?,
        Err(e) => return Err(e),
    };

    // First initialisation wins for the process. A production boot calls this
    // exactly once (from `store::open`); the repeat case is the test suite,
    // where in-memory and on-disk stores share one process and whichever ran
    // first has already chosen. Silently keeping the first key is right there
    // — every row written in that process is sealed under it, so switching
    // mid-process is what would actually cause damage.
    if let Err(_existing) = KEY.set(key) {
        tracing::debug!("custody encryption key already initialised; keeping the existing one");
    }
    Ok(())
}

/// A process-lifetime random key, for stores that do not outlive the process.
///
/// Correct for `:memory:` databases and tests: seal/open round-trip within the
/// process, and nothing survives to be read back under a different key. It is
/// deliberately NOT a fallback for the on-disk path — losing the key across a
/// restart would make every custody row undecryptable, which is why
/// [`super::open`] takes a keyfile path and this is reachable only through
/// [`super::open_in_memory`].
pub fn init_ephemeral() {
    let _ = KEY.set(random_key());
}

fn create_keyfile(path: &Path) -> io::Result<KeyBytes> {
    let key = random_key();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, key)?;
    restrict(path)?;
    tracing::info!(
        keyfile = %path.display(),
        "generated a new custody encryption key; back it up — losing it makes every \
         stored upstream token undecryptable and forces org-wide re-login"
    );
    Ok(key)
}

#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn random_key() -> KeyBytes {
    let mut key = [0u8; 32];
    crate::token::fill_random(&mut key);
    key
}

fn cipher() -> XChaCha20Poly1305 {
    // Reaching here without a key means a `Connection` was obtained without
    // going through `store::open`/`open_in_memory`, which the module docs make
    // the only two ways in. Panicking is right: the alternative is writing a
    // token to disk under a key nobody chose.
    let key = KEY
        .get()
        .expect("custody encryption key not initialised — store::open must be called first");
    XChaCha20Poly1305::new(key.into())
}

/// `nonce || ciphertext`. Infallible in signature because there is nothing a
/// caller could do about an AEAD failure here except refuse to run, and
/// XChaCha20-Poly1305 encryption does not fail for well-formed input.
pub(crate) fn seal(plaintext: &[u8]) -> Vec<u8> {
    // 24 random bytes straight from the same OS CSPRNG the key came from,
    // rather than the AEAD crate's nonce helper. XChaCha20's nonce is large
    // enough that random generation is the intended construction, and routing
    // it through `fill_random` means every byte of secret material in this
    // service has one provenance to audit instead of two.
    let mut nonce_bytes = [0u8; 24];
    crate::token::fill_random(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher()
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption cannot fail for well-formed input");
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// The inverse. Fails on a wrong key, a truncated value, or any tampering —
/// the authentication tag is what makes "someone edited the database file"
/// detectable rather than silently effective.
pub(crate) fn open(sealed: &[u8]) -> Result<Vec<u8>, String> {
    const NONCE_LEN: usize = 24;
    if sealed.len() < NONCE_LEN {
        return Err(format!(
            "sealed value is {} bytes, shorter than the {NONCE_LEN}-byte nonce prefix",
            sealed.len()
        ));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    // `TryFrom` rather than the deprecated `from_slice`. The length was already
    // checked above, so this cannot fail — but a panicking `expect` on the
    // decrypt path of every custody read is not worth the one line it saves.
    let Ok(nonce) = XNonce::try_from(nonce) else {
        return Err("sealed value has a malformed nonce prefix".to_owned());
    };
    cipher().decrypt(&nonce, ciphertext).map_err(|_| {
        "custody value failed authenticated decryption (wrong key, or the row was altered)"
            .to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_key() {
        init_ephemeral();
    }

    #[test]
    fn a_sealed_value_round_trips() {
        ensure_key();
        let secret = b"upstream-refresh-token-value";
        let sealed = seal(secret);
        assert_eq!(open(&sealed).unwrap(), secret);
    }

    /// The property that makes INV-5 mean something: the plaintext must not be
    /// recoverable by reading the column. A regression here — someone
    /// restoring the identity function "just for a debugging session" — would
    /// be invisible to a round-trip test alone.
    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        ensure_key();
        let secret = b"upstream-refresh-token-value";
        let sealed = seal(secret);
        assert_ne!(sealed.as_slice(), secret.as_slice());
        assert!(
            !sealed
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "the plaintext must not appear anywhere in the sealed bytes"
        );
    }

    /// Two seals of the same value must differ, or the column leaks equality —
    /// an observer could tell which sessions share an upstream grant.
    #[test]
    fn sealing_twice_gives_different_ciphertexts() {
        ensure_key();
        assert_ne!(seal(b"same"), seal(b"same"));
    }

    #[test]
    fn tampering_is_detected_rather_than_decrypted() {
        ensure_key();
        let mut sealed = seal(b"upstream-refresh-token-value");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(open(&sealed).is_err(), "a flipped tag byte must not open");
    }

    #[test]
    fn a_truncated_value_is_an_error_not_a_panic() {
        ensure_key();
        assert!(open(&[0u8; 8]).is_err());
    }

    #[test]
    fn a_keyfile_is_created_once_and_then_reused() {
        let path = std::env::temp_dir().join(format!(
            "session-broker-keyfile-test-{}-{:?}.key",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        init_from_keyfile(&path).expect("first call creates the keyfile");
        let first = std::fs::read(&path).unwrap();
        assert_eq!(first.len(), 32);

        // Idempotent: a second boot against the same file must not rewrite it,
        // which would strand every row sealed under the original key.
        init_from_keyfile(&path).expect("second call reuses it");
        assert_eq!(std::fs::read(&path).unwrap(), first);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_wrong_length_keyfile_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "session-broker-shortkey-test-{}-{:?}.key",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"too-short").unwrap();

        let err = init_from_keyfile(&path).expect_err("a 9-byte keyfile must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let _ = std::fs::remove_file(&path);
    }
}
