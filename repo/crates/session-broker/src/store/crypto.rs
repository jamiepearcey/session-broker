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
//! ## Format and rotation
//!
//! A sealed value is `0x01 || key_id || nonce(24) || ciphertext`, using
//! XChaCha20-Poly1305 with a random 192-bit nonce (large enough that random
//! generation has no practical collision concern, which matters because these
//! rows are rewritten on every keepalive rotation — a counter would have to be
//! persisted and would become a correctness dependency of its own).
//!
//! The leading bytes are authenticated, together with a caller-supplied
//! **context** naming the row and column. Two consequences: a ciphertext cannot
//! be lifted from one custody row into another (it fails to open there), and
//! the key id cannot be flipped to steer a decrypt at a different key.
//!
//! The keyfile is a **keyring**: every key ever issued, the highest id being
//! the active one. Old keys stay in the file so rows sealed under them still
//! open; `Command::Reseal` (run at boot) moves them to the active key, after
//! which an operator may delete the old entries. A bare 32-byte file — the
//! original format — is read as key id 1 so an existing deployment keeps
//! working and can be rotated in place.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// 32 raw bytes. Not `Vec<u8>`: a fixed size makes "the key is the wrong
/// length" a load-time error rather than a decrypt-time one.
type KeyBytes = [u8; 32];

const FORMAT_V1: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 2;
const KEYRING_MAGIC: &str = "session-broker-keyring v1";

/// Every key this process may decrypt with, and which one it encrypts with.
#[derive(Clone)]
pub struct KeyRing {
    active: u8,
    keys: BTreeMap<u8, KeyBytes>,
}

impl std::fmt::Debug for KeyRing {
    // Never prints key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("active", &self.active)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

static KEYRING: OnceLock<KeyRing> = OnceLock::new();

impl KeyRing {
    pub(crate) fn single(id: u8, key: KeyBytes) -> KeyRing {
        KeyRing {
            active: id,
            keys: BTreeMap::from([(id, key)]),
        }
    }

    pub fn active_id(&self) -> u8 {
        self.active
    }

    fn aad(kid: u8, context: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + context.len());
        aad.extend_from_slice(&[FORMAT_V1, kid]);
        aad.extend_from_slice(context);
        aad
    }

    pub(crate) fn seal(&self, plaintext: &[u8], context: &[u8]) -> Vec<u8> {
        let key = &self.keys[&self.active];
        // 24 random bytes straight from the same OS CSPRNG the key came from,
        // rather than the AEAD crate's nonce helper: every byte of secret
        // material in this service has one provenance to audit instead of two.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        crate::token::fill_random(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = XChaCha20Poly1305::new(key.into())
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(self.active, context),
                },
            )
            .expect("XChaCha20-Poly1305 encryption cannot fail for well-formed input");
        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&[FORMAT_V1, self.active]);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub(crate) fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < HEADER_LEN + NONCE_LEN {
            return Err(format!(
                "sealed value is {} bytes, shorter than its {}-byte header and nonce",
                sealed.len(),
                HEADER_LEN + NONCE_LEN
            ));
        }
        if sealed[0] != FORMAT_V1 {
            return Err(format!(
                "sealed value has unknown format byte {}",
                sealed[0]
            ));
        }
        let kid = sealed[1];
        let key = self.keys.get(&kid).ok_or_else(|| {
            format!(
                "sealed under key id {kid}, which is not in the keyfile — it was removed too \
                 early, or this is another deployment's database"
            )
        })?;
        let (nonce, ciphertext) = sealed[HEADER_LEN..].split_at(NONCE_LEN);
        let Ok(nonce) = XNonce::try_from(nonce) else {
            return Err("sealed value has a malformed nonce".to_owned());
        };
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &Self::aad(kid, context),
                },
            )
            .map_err(|_| {
                "custody value failed authenticated decryption (wrong key, wrong row, or the \
                 row was altered)"
                    .to_owned()
            })
    }

    fn parse(bytes: &[u8]) -> io::Result<KeyRing> {
        // The original format: exactly 32 raw bytes, no framing.
        if bytes.len() == 32 && !bytes.starts_with(KEYRING_MAGIC.as_bytes()) {
            let key = KeyBytes::try_from(bytes).expect("length checked");
            return Ok(KeyRing::single(1, key));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| {
            invalid(format!(
                "keyfile is {} bytes and is neither a 32-byte raw key nor a text keyring. \
                 Refusing to start rather than derive a key, which would silently make every \
                 existing custody row undecryptable.",
                bytes.len()
            ))
        })?;
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(KEYRING_MAGIC) {
            return Err(invalid(format!(
                "keyfile is not a 32-byte raw key and does not begin with \"{KEYRING_MAGIC}\""
            )));
        }
        let mut keys = BTreeMap::new();
        for line in lines {
            let (id, encoded) = line
                .split_once(char::is_whitespace)
                .ok_or_else(|| invalid(format!("malformed keyring line: {line:?}")))?;
            let id: u8 = id
                .parse()
                .map_err(|_| invalid(format!("keyring key id {id:?} is not 0-255")))?;
            let raw = URL_SAFE_NO_PAD
                .decode(encoded.trim())
                .map_err(|_| invalid(format!("key {id} is not base64url")))?;
            let key = KeyBytes::try_from(raw.as_slice())
                .map_err(|_| invalid(format!("key {id} is {} bytes; 32 required", raw.len())))?;
            if keys.insert(id, key).is_some() {
                return Err(invalid(format!("key id {id} appears twice")));
            }
        }
        let active = *keys
            .keys()
            .next_back()
            .ok_or_else(|| invalid("keyring contains no keys".to_owned()))?;
        Ok(KeyRing { active, keys })
    }

    fn render(&self) -> String {
        let mut out = format!(
            "{KEYRING_MAGIC}\n# Highest id encrypts; the rest only decrypt. Delete an old id \
             only after every row has been resealed past it.\n"
        );
        for (id, key) in &self.keys {
            out.push_str(&format!("{id} {}\n", URL_SAFE_NO_PAD.encode(key)));
        }
        out
    }
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Load the keyring at `path`, creating it if absent.
///
/// Created with `0600` on Unix, and a file readable by group or other is
/// refused rather than warned about: a keyfile anyone on the box can read is not
/// meaningfully different from no keyfile at all, and the operator who would
/// ignore the warning is exactly the one this protects.
pub fn init_from_keyfile(path: &Path) -> io::Result<()> {
    let ring = match std::fs::read(path) {
        Ok(bytes) => {
            refuse_permissive(path)?;
            KeyRing::parse(&bytes)?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => create_keyfile(path)?,
        Err(e) => return Err(e),
    };

    // First initialisation wins for the process. A production boot calls this
    // exactly once (from `store::open`); the repeat case is the test suite,
    // where in-memory and on-disk stores share one process and whichever ran
    // first has already chosen. Silently keeping the first ring is right there
    // — every row written in that process is sealed under it, so switching
    // mid-process is what would actually cause damage.
    if KEYRING.set(ring).is_err() {
        tracing::debug!("custody keyring already initialised; keeping the existing one");
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
    let _ = KEYRING.set(KeyRing::single(1, random_key()));
}

/// Add a fresh key to the keyfile and make it the active one. Returns its id.
///
/// Written to a sibling temp file and renamed, so a crash leaves either the old
/// keyring or the new one — never a truncated file that strands every row. The
/// running broker is unaffected until restart; at boot it reseals under the new
/// key.
pub fn rotate_keyfile(path: &Path) -> io::Result<u8> {
    refuse_permissive(path)?;
    let mut ring = KeyRing::parse(&std::fs::read(path)?)?;
    let next = ring
        .active
        .checked_add(1)
        .ok_or_else(|| invalid("keyring is full (255 rotations); retire old keys first".into()))?;
    ring.keys.insert(next, random_key());
    ring.active = next;
    write_atomically(path, ring.render().as_bytes())?;
    Ok(next)
}

fn create_keyfile(path: &Path) -> io::Result<KeyRing> {
    let ring = KeyRing::single(1, random_key());
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_atomically(path, ring.render().as_bytes())?;
    tracing::info!(
        keyfile = %path.display(),
        "generated a new custody encryption key; back it up — losing it makes every \
         stored upstream token undecryptable and forces org-wide re-login"
    );
    Ok(ring)
}

fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("key.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Created 0600 from the first byte, not chmod-ed afterwards: there is no
        // window in which the key is readable.
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(unix)]
fn refuse_permissive(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "keyfile {} has mode {mode:o}; group/other access must be removed (chmod 600). \
                 Refusing to start with a key other users can read.",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_permissive(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn random_key() -> KeyBytes {
    let mut key = [0u8; 32];
    crate::token::fill_random(&mut key);
    key
}

pub(crate) fn ring() -> &'static KeyRing {
    // Reaching here without a key means a `Connection` was obtained without
    // going through `store::open`/`open_in_memory`, which the module docs make
    // the only two ways in. Panicking is right: the alternative is writing a
    // token to disk under a key nobody chose.
    KEYRING
        .get()
        .expect("custody encryption key not initialised — store::open must be called first")
}

/// Test seam: the process ring plus a newer active key, as after a rotation.
#[cfg(test)]
pub(crate) fn rotated_for_test() -> KeyRing {
    let mut r = ring().clone();
    let next = r.active + 1;
    r.keys.insert(next, random_key());
    r.active = next;
    r
}

/// The context string binding a ciphertext to one custody row and column.
pub(crate) fn context(custody_id: &str, column: &str) -> Vec<u8> {
    format!("custody:{custody_id}:{column}").into_bytes()
}

/// Seal under the active key. Infallible in signature because there is nothing
/// a caller could do about an AEAD failure here except refuse to run.
pub(crate) fn seal(plaintext: &[u8], context: &[u8]) -> Vec<u8> {
    ring().seal(plaintext, context)
}

/// The inverse. Fails on a wrong key, a wrong row, a truncated value, or any
/// tampering — the authentication tag is what makes "someone edited the
/// database file" detectable rather than silently effective.
pub(crate) fn open(sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
    ring().open(sealed, context)
}

/// Which key sealed this value, if it parses as one of ours.
pub(crate) fn key_id_of(sealed: &[u8]) -> Option<u8> {
    (sealed.len() >= HEADER_LEN && sealed[0] == FORMAT_V1).then(|| sealed[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"custody:c1:refresh";

    fn ensure_key() {
        init_ephemeral();
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "session-broker-{name}-{}-{:?}.key",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_sealed_value_round_trips() {
        ensure_key();
        let secret = b"upstream-refresh-token-value";
        assert_eq!(open(&seal(secret, CTX), CTX).unwrap(), secret);
    }

    /// The property that makes INV-5 mean something: the plaintext must not be
    /// recoverable by reading the column. A regression here — someone
    /// restoring the identity function "just for a debugging session" — would
    /// be invisible to a round-trip test alone.
    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        ensure_key();
        let secret = b"upstream-refresh-token-value";
        let sealed = seal(secret, CTX);
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
        assert_ne!(seal(b"same", CTX), seal(b"same", CTX));
    }

    #[test]
    fn tampering_is_detected_rather_than_decrypted() {
        ensure_key();
        let mut sealed = seal(b"upstream-refresh-token-value", CTX);
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(
            open(&sealed, CTX).is_err(),
            "a flipped tag byte must not open"
        );
    }

    #[test]
    fn a_truncated_value_is_an_error_not_a_panic() {
        ensure_key();
        assert!(open(&[0u8; 8], CTX).is_err());
    }

    /// The point of the context: a ciphertext copied from one custody row (or
    /// column) into another must not open there.
    #[test]
    fn a_value_does_not_open_under_a_different_row_or_column() {
        ensure_key();
        let sealed = seal(b"token", &context("c1", "refresh"));
        assert!(open(&sealed, &context("c2", "refresh")).is_err());
        assert!(open(&sealed, &context("c1", "access")).is_err());
        assert!(open(&sealed, &context("c1", "refresh")).is_ok());
    }

    #[test]
    fn the_key_id_is_authenticated() {
        let ring = KeyRing {
            active: 2,
            keys: BTreeMap::from([(1, random_key()), (2, random_key())]),
        };
        let mut sealed = ring.seal(b"token", CTX);
        sealed[1] = 1; // point the decrypt at the other (present) key
        assert!(ring.open(&sealed, CTX).is_err());
    }

    #[test]
    fn an_unknown_key_id_names_the_problem() {
        let ring = KeyRing::single(1, random_key());
        let mut sealed = ring.seal(b"token", CTX);
        sealed[1] = 9;
        let err = ring.open(&sealed, CTX).unwrap_err();
        assert!(err.contains("key id 9"), "{err}");
    }

    #[test]
    fn a_new_keyfile_is_created_once_and_then_reused() {
        let path = tmp("created");
        init_from_keyfile(&path).expect("first call creates the keyfile");
        let first = std::fs::read(&path).unwrap();
        assert!(first.starts_with(KEYRING_MAGIC.as_bytes()));

        // Idempotent: a second boot against the same file must not rewrite it,
        // which would strand every row sealed under the original key.
        init_from_keyfile(&path).expect("second call reuses it");
        assert_eq!(std::fs::read(&path).unwrap(), first);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_legacy_raw_32_byte_keyfile_still_loads_as_key_one() {
        let ring = KeyRing::parse(&[7u8; 32]).unwrap();
        assert_eq!(ring.active_id(), 1);
        assert_eq!(ring.keys[&1], [7u8; 32]);
    }

    #[test]
    fn a_wrong_length_keyfile_is_refused() {
        let path = tmp("shortkey");
        std::fs::write(&path, b"too-short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = init_from_keyfile(&path).expect_err("a 9-byte keyfile must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_keyfile_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("permissive");
        std::fs::write(&path, [1u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = init_from_keyfile(&path).expect_err("0644 must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_file(&path);
    }

    /// Rotation's whole contract: new writes use the new key, rows sealed under
    /// the old one still open, and the file stays private.
    #[test]
    fn rotation_keeps_old_rows_readable_and_seals_new_ones_under_the_new_key() {
        let path = tmp("rotate");
        std::fs::write(&path, [3u8; 32]).unwrap(); // legacy: key 1
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before = KeyRing::parse(&std::fs::read(&path).unwrap()).unwrap();
        let old = before.seal(b"token", CTX);

        assert_eq!(rotate_keyfile(&path).unwrap(), 2);
        let after = KeyRing::parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(after.active_id(), 2);
        assert_eq!(key_id_of(&old), Some(1));
        assert_eq!(after.open(&old, CTX).unwrap(), b"token");
        assert_eq!(key_id_of(&after.seal(b"x", CTX)), Some(2));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // And a second rotation stacks on the first.
        assert_eq!(rotate_keyfile(&path).unwrap(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_debug_output_never_contains_key_material() {
        let ring = KeyRing::single(1, [0xAB; 32]);
        let shown = format!("{ring:?}");
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab, ab"));
    }
}
