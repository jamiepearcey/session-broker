//! Session token material.
//!
//! INV-5: cookie values are 256-bit CSPRNG tokens and durable storage only ever
//! sees `SHA-256(token)`. The plaintext exists in two places and no others — the
//! `Set-Cookie` header on its way out, and (for the *current* generation only)
//! process memory, so that a coalesced refresh can re-issue the identical cookie
//! instead of minting a fresh generation per concurrent caller. It is never
//! written to the store; after a restart the plaintext is gone and coalescing
//! degrades to minting, which is correct, just marginally less efficient.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::SysRng;
use rand::TryRng as _;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fill `dst` from the operating system's CSPRNG, or abort.
///
/// One function rather than a call at each site, because this is the INV-5
/// boundary: every 256-bit token, the custody encryption key, each nonce, and
/// every `state`/PKCE/nonce value comes from here, so "which RNG?" has exactly
/// one answer to review.
///
/// **It panics if the OS RNG fails**, which is the whole point of not using the
/// fallible API's `Result` here. `rand` 0.10 made `SysRng` fallible
/// (`TryRng`), which is an improvement — it forces the question — but for this
/// service the answer is not "handle it". A session token, or a key, built from
/// anything other than full-strength entropy is worse than no session and worse
/// than no key: it fails open, silently, and nothing downstream can tell.
pub(crate) fn fill_random(dst: &mut [u8]) {
    SysRng.try_fill_bytes(dst).expect(
        "the OS CSPRNG is unavailable; refusing to mint secret material from a degraded source",
    );
}

/// A cookie value in the clear. Zeroized on drop; deliberately has no `Display`,
/// `Debug`, or `Serialize` impl that could leak it into a log line.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken(String);

impl SessionToken {
    /// 32 bytes from the OS CSPRNG, base64url-encoded to 43 characters.
    pub fn generate() -> SessionToken {
        let mut bytes = [0u8; 32];
        fill_random(&mut bytes);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        SessionToken(encoded)
    }

    /// Adopt a value presented by a client. Only used to re-issue a token the
    /// caller already holds.
    pub fn from_presented(value: &str) -> SessionToken {
        SessionToken(value.to_owned())
    }

    pub fn hash(&self) -> TokenHash {
        TokenHash::of(&self.0)
    }

    /// The only way to read the plaintext back out. Named to make review easy:
    /// every call site should be a `Set-Cookie`.
    pub fn expose_for_cookie(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(redacted)")
    }
}

/// `SHA-256` of a cookie value — the only form the store and the session index
/// ever hold.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    pub fn of(value: &str) -> TokenHash {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        TokenHash(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct a hash read back from the store, for boot-time rehydration.
    ///
    /// Safe in a way a `SessionToken` constructor would not be: this is the
    /// *hash*, and holding it authenticates nothing — a request still has to
    /// present a cookie value that hashes to it. The plaintext token remains
    /// unreconstructable from anything durable, which is the property that
    /// makes a stolen database file useless for impersonation.
    pub fn from_stored_bytes(bytes: [u8; 32]) -> TokenHash {
        TokenHash(bytes)
    }

    /// Short, non-reversible handle for logs and the meta cookie's `sid` field.
    pub fn short_hex(&self) -> String {
        self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenHash({})", self.short_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_43_chars_and_unique() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        assert_eq!(a.expose_for_cookie().len(), 43);
        assert_ne!(a.expose_for_cookie(), b.expose_for_cookie());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn hashing_a_presented_value_matches_the_original() {
        let token = SessionToken::generate();
        let presented = SessionToken::from_presented(token.expose_for_cookie());
        assert_eq!(token.hash(), presented.hash());
    }

    #[test]
    fn debug_never_reveals_the_token() {
        let token = SessionToken::generate();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(token.expose_for_cookie()));
    }
}
