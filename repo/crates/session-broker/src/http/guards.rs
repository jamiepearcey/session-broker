//! Request guards: cookie extraction and the CSRF boundary.
//!
//! INV-2 is enforced here and nowhere else. `SameSite=Lax` is deliberately *not*
//! the protection — it is defence in depth. The actual boundary is an explicit
//! same-origin check on every state-mutating, cookie-authenticated request, which
//! is why the cookie can safely stay `Lax` and survive the OAuth callback
//! navigation (INV-1).

use axum::http::HeaderMap;

use super::error::{ApiError, ErrorCode};

/// Whether a handler tolerates a direct top-level navigation (`Sec-Fetch-Site:
/// none`), which is how a user arriving from a bookmark or the address bar
/// presents. Only the interactive navigation endpoints set this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowDirectNavigation {
    Yes,
    No,
}

/// INV-2. `Sec-Fetch-Site` is authoritative when present — every browser
/// released since 2020 sends it and it cannot be set by script. When it is
/// absent we fall back to `Origin` equality; when both are absent the caller is
/// not a browser, and a non-browser has no business replaying a cookie against a
/// mutating endpoint, so it is refused.
pub fn require_same_origin(
    headers: &HeaderMap,
    expected_origin: &str,
    direct: AllowDirectNavigation,
) -> Result<(), ApiError> {
    if let Some(site) = header_str(headers, "sec-fetch-site") {
        return match site {
            "same-origin" => Ok(()),
            "none" if direct == AllowDirectNavigation::Yes => Ok(()),
            other => Err(ApiError::new(
                ErrorCode::CsrfRejected,
                format!("cross-origin request rejected (sec-fetch-site: {other})"),
            )),
        };
    }

    match header_str(headers, "origin") {
        Some(origin) if origin == expected_origin => Ok(()),
        Some(other) => Err(ApiError::new(
            ErrorCode::CsrfRejected,
            format!("origin '{other}' is not '{expected_origin}'"),
        )),
        None => Err(ApiError::new(
            ErrorCode::CsrfRejected,
            "request carries neither Sec-Fetch-Site nor Origin",
        )),
    }
}

/// True for a top-level navigation. The interactive refresh form only redirects
/// into the IdP for these: a `fetch` cannot usefully follow a cross-origin
/// redirect chain into a login page, so it gets a JSON error instead.
pub fn is_navigation(headers: &HeaderMap) -> bool {
    header_str(headers, "sec-fetch-mode") == Some("navigate")
}

/// Pull one cookie value out of the `Cookie` header. Hand-rolled because the
/// broker needs exactly this and no cookie-jar semantics.
pub fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim())
}

fn header_str<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// INV-4. A `return_to` may only be a same-origin absolute path: it must start
/// with a single `/`, and must not begin a scheme-relative URL (`//host`) or a
/// backslash variant that some browsers normalise into one. Anything else is
/// dropped rather than sanitised — this is the whole open-redirect defence and
/// it should be boring.
pub fn safe_return_to(candidate: Option<&str>) -> Option<String> {
    let value = candidate?;
    let mut chars = value.chars();
    if chars.next() != Some('/') {
        return None;
    }
    match chars.next() {
        Some('/') | Some('\\') => None,
        _ if value.contains(['\r', '\n']) => None,
        _ => Some(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            let name = HeaderName::from_bytes(k.as_bytes()).unwrap();
            h.append(name, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    const ORIGIN: &str = "https://app.example.com";

    #[test]
    fn same_origin_fetches_pass() {
        let h = headers(&[("sec-fetch-site", "same-origin")]);
        assert!(require_same_origin(&h, ORIGIN, AllowDirectNavigation::No).is_ok());
    }

    #[test]
    fn cross_site_requests_are_refused() {
        for site in ["cross-site", "same-site"] {
            let h = headers(&[("sec-fetch-site", site)]);
            let err = require_same_origin(&h, ORIGIN, AllowDirectNavigation::No).unwrap_err();
            assert_eq!(err.error, ErrorCode::CsrfRejected);
        }
    }

    #[test]
    fn direct_navigation_is_refused_unless_the_handler_allows_it() {
        let h = headers(&[("sec-fetch-site", "none")]);
        assert!(require_same_origin(&h, ORIGIN, AllowDirectNavigation::No).is_err());
        assert!(require_same_origin(&h, ORIGIN, AllowDirectNavigation::Yes).is_ok());
    }

    #[test]
    fn a_spoofed_origin_cannot_beat_sec_fetch_site() {
        // Sec-Fetch-Site wins when both are present: script can set Origin on
        // some request types, but never Sec-Fetch-*.
        let h = headers(&[("sec-fetch-site", "cross-site"), ("origin", ORIGIN)]);
        assert!(require_same_origin(&h, ORIGIN, AllowDirectNavigation::No).is_err());
    }

    #[test]
    fn origin_is_the_fallback_when_sec_fetch_is_absent() {
        let ok = headers(&[("origin", ORIGIN)]);
        assert!(require_same_origin(&ok, ORIGIN, AllowDirectNavigation::No).is_ok());

        let bad = headers(&[("origin", "https://evil.example.com")]);
        assert!(require_same_origin(&bad, ORIGIN, AllowDirectNavigation::No).is_err());
    }

    #[test]
    fn a_bare_request_with_neither_header_is_refused() {
        let h = headers(&[]);
        assert!(require_same_origin(&h, ORIGIN, AllowDirectNavigation::No).is_err());
    }

    #[test]
    fn cookies_are_extracted_by_exact_name() {
        let h = headers(&[(
            "cookie",
            "other=1; __Host-broker_session=abc123; broker_meta=xyz",
        )]);
        assert_eq!(cookie(&h, "__Host-broker_session"), Some("abc123"));
        assert_eq!(cookie(&h, "broker_meta"), Some("xyz"));
        assert_eq!(cookie(&h, "broker_session"), None);
    }

    #[test]
    fn return_to_rejects_everything_that_could_leave_the_origin() {
        assert_eq!(
            safe_return_to(Some("/dashboard")).as_deref(),
            Some("/dashboard")
        );
        assert_eq!(
            safe_return_to(Some("/a/b?c=d#e")).as_deref(),
            Some("/a/b?c=d#e")
        );
        for bad in [
            "//evil.example.com",
            "/\\evil.example.com",
            "https://evil.example.com",
            "evil",
            "",
            "/ok\r\nSet-Cookie: x=1",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "accepted {bad:?}");
        }
        assert_eq!(safe_return_to(None), None);
    }
}
