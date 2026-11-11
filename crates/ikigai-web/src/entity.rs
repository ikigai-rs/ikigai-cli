//! Response headers an ENDPOINT asks for: the HTTP entity envelope (ledger #117).
//!
//! A kernel [`Representation`] is a media type and bytes; it has nowhere to say "and set this
//! cookie". So an endpoint that needs a response header answers with an **entity**: the
//! representation it means to serve, wrapped with the header lines it asks for, as the media
//! type [`HTTP_ENTITY`]. The door unwraps it, checks every line against a closed allowlist
//! ([`EndpointHeader`]) and against the headers the door itself accepts
//! ([`EdgeConfig::endpoint_headers`](crate::EdgeConfig::endpoint_headers)), and serves the
//! wrapped content with those headers. Anything it cannot accept is REFUSED, never dropped:
//! the client gets `500` naming the header, because a cookie an endpoint believes it set and
//! the client never received is a failure nobody would otherwise see.
//!
//! The envelope is a MIME entity, the shape of a multipart body part (RFC 2046 §5.1): header
//! lines, an empty line, then the content byte for byte. `Content-Type` is required and is
//! the media type of the content. Lines end in CRLF (a bare LF is accepted, for authors in
//! languages that write one). Build one in Rust with [`with_headers`]; any other language
//! writes the same bytes.
//!
//! ```text
//! Content-Type: application/json
//! Set-Cookie: session=abc; Path=/; HttpOnly; SameSite=Strict
//!
//! {"signed_in":true}
//! ```
//!
//! ⚠ The envelope is an HTTP concern carried through a transport-neutral kernel, so every
//! OTHER face (a CLI `source`, QUIC, MCP) sees the envelope bytes as they are. Use it only on
//! resources whose callers are browsers.
use ikigai_core::{Expiry, ReprType, Representation};

/// The media type of an entity envelope: header lines, an empty line, then the content.
pub const HTTP_ENTITY: &str = "application/vnd.ikigai.http-entity";

/// The longest header value an endpoint may set, in bytes. 4096 is the size RFC 6265 §6.1
/// asks a browser to accept for one cookie (name, value and attributes together), and no
/// other header on the allowlist needs more.
pub const MAX_HEADER_VALUE: usize = 4096;

/// The most header lines one envelope may carry, `Content-Type` included.
pub const MAX_HEADER_LINES: usize = 32;

/// The longest the header block of an envelope may be, in bytes, through its empty line.
/// Past it the envelope is refused rather than searched further.
pub const MAX_HEADER_BLOCK: usize = 16 * 1024;

/// A response header an endpoint may set. The list is CLOSED: everything else the door
/// either owns itself (`Content-Length`, `ETag`, `Allow`, the security and CORS headers),
/// must never come from content (`Connection`, `Transfer-Encoding` and the other hop-by-hop
/// headers), or has no use here yet. A name outside it is refused by name.
///
/// | header | merged how |
/// |--------|------------|
/// | `Cache-Control` | REPLACES the value the door projects from the answer's expiry; when the request's credentials shaped the answer, `public` is dropped and `private` is added, because only the door can see that |
/// | `Vary` | ADDED to the names the door already varies on |
/// | `Set-Cookie` | one header per line; only on an answer no cache can hold (a write, or a read whose answer is uncacheable), and only at a door that opts in |
/// | `Content-Disposition` | as given; left off a `304` (RFC 9110 §15.4.5) |
/// | `Content-Language` | as given; left off a `304` |
/// | `Location` | makes the answer `303 See Other` (RFC 9110 §15.4.4); only on a write's answer, and only to a same-origin relative reference: a path (`/…`, never `//…`) or a query alone (`?…`, the same path) |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EndpointHeader {
    /// `Cache-Control`.
    CacheControl,
    /// `Content-Disposition`.
    ContentDisposition,
    /// `Content-Language`.
    ContentLanguage,
    /// `Location`, which answers the write `303 See Other`: Post/Redirect/Get (ledger #1879),
    /// so a page a browser restores after a form POST is the GET it was sent to, never the POST
    /// again. Only on a mutating request (a read that redirects would be cacheable and
    /// followable by any prefetcher), and only to a same-origin relative reference, so an
    /// endpoint can never send a browser to another host: an absolute path (`/done`, not
    /// `//host`) or a query alone (`?outcome=recorded`, which a browser resolves against the
    /// request's own path, so the endpoint need not know where a door routes it). The value
    /// is a URL a browser shows and may log, so it must carry no personal data: that is the
    /// endpoint's to keep.
    Location,
    /// `Set-Cookie`. Not in [`EndpointHeader::DEFAULTS`]: a cookie is authority over the
    /// whole origin, so a door that serves stored content must not let that content set one
    /// unless it says so.
    SetCookie,
    /// `Vary`.
    Vary,
}

impl EndpointHeader {
    /// Every header an endpoint can ever set.
    pub const ALL: [EndpointHeader; 6] = [
        EndpointHeader::CacheControl,
        EndpointHeader::ContentDisposition,
        EndpointHeader::ContentLanguage,
        EndpointHeader::Location,
        EndpointHeader::SetCookie,
        EndpointHeader::Vary,
    ];

    /// What a door accepts unless it says otherwise: all of [`ALL`](Self::ALL) but
    /// `Set-Cookie`. `Location` is in: it can only send a browser that just wrote to another
    /// page of the same origin.
    pub const DEFAULTS: [EndpointHeader; 5] = [
        EndpointHeader::CacheControl,
        EndpointHeader::ContentDisposition,
        EndpointHeader::ContentLanguage,
        EndpointHeader::Location,
        EndpointHeader::Vary,
    ];

    /// The header's name as it is written on the wire.
    pub fn name(self) -> &'static str {
        match self {
            EndpointHeader::CacheControl => "Cache-Control",
            EndpointHeader::ContentDisposition => "Content-Disposition",
            EndpointHeader::ContentLanguage => "Content-Language",
            EndpointHeader::Location => "Location",
            EndpointHeader::SetCookie => "Set-Cookie",
            EndpointHeader::Vary => "Vary",
        }
    }

    /// The header a name (in any case) spells, or `None` when it is not on the allowlist.
    pub fn parse(name: &str) -> Option<EndpointHeader> {
        EndpointHeader::ALL
            .into_iter()
            .find(|h| h.name().eq_ignore_ascii_case(name))
    }
}

/// Why a response header was refused: one an endpoint asked for (its display text is the body
/// of the `500` the door answers with), or one a door's own code set on a [`Response`] it
/// handed to [`write_response`] (carried inside the `InvalidInput` error the writer returns).
///
/// [`Response`]: crate::Response
/// [`write_response`]: crate::write_response
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRefusal {
    /// The header's name as the endpoint wrote it (empty when the envelope itself is
    /// malformed, or when a door's [`Response`](crate::Response) is refused for its status
    /// line: a status outside `200..=599`, or content on a `204` or `304`).
    pub header: String,
    /// What is wrong with it.
    pub why: String,
}

impl HeaderRefusal {
    pub(crate) fn new(header: &str, why: impl Into<String>) -> HeaderRefusal {
        HeaderRefusal {
            header: header.to_string(),
            why: why.into(),
        }
    }
}

impl std::fmt::Display for HeaderRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.header.is_empty() {
            write!(f, "refused the response headers: {}", self.why)
        } else {
            write!(
                f,
                "refused the response header `{}`: {}",
                self.header, self.why
            )
        }
    }
}

impl std::error::Error for HeaderRefusal {}

/// Wrap `repr` in an entity envelope that asks the door for `headers`.
///
/// Every name must be on the [`EndpointHeader`] allowlist and every value must pass the same
/// check the door makes ([`MAX_HEADER_VALUE`] bytes at most; visible ASCII, space and tab
/// only, so no CR or LF can start a header of its own), or nothing is built. The expiry and
/// golden threads of `repr` are kept, so wrapping changes nothing about how the kernel caches
/// the answer.
///
/// ```
/// use ikigai_core::{ReprType, Representation};
/// use ikigai_web::{with_headers, HTTP_ENTITY};
///
/// let page = Representation::new(ReprType::new("text/plain"), b"hi".to_vec());
/// let entity = with_headers(page, &[("Content-Language", "en")]).unwrap();
/// assert_eq!(entity.repr_type.to_string(), HTTP_ENTITY);
/// assert_eq!(entity.bytes, b"Content-Type: text/plain\r\nContent-Language: en\r\n\r\nhi");
///
/// // A value that would start a header of its own is refused by name.
/// let page = Representation::new(ReprType::new("text/plain"), b"hi".to_vec());
/// let refused = with_headers(page, &[("Set-Cookie", "a=b\r\nLocation: /evil")]).unwrap_err();
/// assert_eq!(refused.header, "Set-Cookie");
/// ```
pub fn with_headers(
    mut repr: Representation,
    headers: &[(&str, &str)],
) -> Result<Representation, HeaderRefusal> {
    if headers.len() + 1 > MAX_HEADER_LINES {
        return Err(HeaderRefusal::new(
            "",
            format!("more than {MAX_HEADER_LINES} header lines"),
        ));
    }
    let content_type = repr.repr_type.to_string();
    check_value("Content-Type", &content_type)?;
    let mut block = format!("Content-Type: {content_type}\r\n");
    for (name, value) in headers {
        let Some(header) = EndpointHeader::parse(name) else {
            return Err(not_allowed(name));
        };
        check_value(name, value)?;
        if header == EndpointHeader::Location {
            check_same_origin(name, value)?;
        }
        block.push_str(&format!("{name}: {value}\r\n"));
    }
    block.push_str("\r\n");
    if block.len() > MAX_HEADER_BLOCK {
        return Err(HeaderRefusal::new(
            "",
            format!("the header block is longer than {MAX_HEADER_BLOCK} bytes"),
        ));
    }
    let mut bytes = block.into_bytes();
    bytes.append(&mut repr.bytes);
    repr.repr_type = ReprType::new(HTTP_ENTITY);
    repr.bytes = bytes;
    Ok(repr)
}

/// An entity envelope, opened: the content to serve and the headers asked for.
#[derive(Debug)]
pub(crate) struct Entity {
    /// The content's own media type, from the envelope's `Content-Type`.
    pub(crate) content_type: String,
    /// The headers asked for, in order, `Content-Type` excluded.
    pub(crate) headers: Vec<(EndpointHeader, String)>,
}

/// Whether `repr` is an entity envelope.
pub(crate) fn is_entity(repr: &Representation) -> bool {
    repr.repr_type.media_type.eq_ignore_ascii_case(HTTP_ENTITY)
}

/// Open the envelope `repr` (see [`is_entity`]): its bytes become the content alone, and the
/// headers come back checked against the allowlist and `accepted`. `mutating` and the
/// answer's expiry decide whether a `Set-Cookie` may ride (see [`EndpointHeader`]).
pub(crate) fn open(
    repr: &mut Representation,
    accepted: &[EndpointHeader],
    mutating: bool,
) -> Result<Entity, HeaderRefusal> {
    let window = &repr.bytes[..repr.bytes.len().min(MAX_HEADER_BLOCK)];
    let mut lines = Vec::new();
    let mut at = 0;
    let body_start = loop {
        let Some(nl) = window[at..].iter().position(|&b| b == b'\n') else {
            return Err(HeaderRefusal::new(
                "",
                format!("no empty line ends the header block within {MAX_HEADER_BLOCK} bytes"),
            ));
        };
        let line = &window[at..at + nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        at += nl + 1;
        if line.is_empty() {
            break at;
        }
        lines.push(line);
    };
    if lines.len() > MAX_HEADER_LINES {
        return Err(HeaderRefusal::new(
            "",
            format!("more than {MAX_HEADER_LINES} header lines"),
        ));
    }
    let mut content_type = None;
    let mut headers = Vec::new();
    for line in lines {
        let text = std::str::from_utf8(line)
            .map_err(|_| HeaderRefusal::new("", "a header line is not ASCII"))?;
        let Some((name, value)) = text.split_once(':') else {
            return Err(HeaderRefusal::new(
                "",
                format!("`{text}` is not a header line"),
            ));
        };
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(HeaderRefusal::new(
                name.trim(),
                "not a header name (a continuation line, or a character a name cannot hold)",
            ));
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        check_value(name, value)?;
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.to_string()).is_some() {
                return Err(HeaderRefusal::new(name, "given more than once"));
            }
            continue;
        }
        let Some(header) = EndpointHeader::parse(name) else {
            return Err(not_allowed(name));
        };
        if !accepted.contains(&header) {
            return Err(HeaderRefusal::new(
                name,
                "this door does not accept it from an endpoint (EdgeConfig::endpoint_headers)",
            ));
        }
        if header == EndpointHeader::Location {
            if !mutating {
                return Err(HeaderRefusal::new(
                    name,
                    "set on a read: only a write's answer may redirect (Post/Redirect/Get)",
                ));
            }
            check_same_origin(name, value)?;
            if headers.iter().any(|(h, _)| *h == EndpointHeader::Location) {
                return Err(HeaderRefusal::new(name, "given more than once"));
            }
        }
        if header == EndpointHeader::SetCookie && !mutating && repr.expiry != Expiry::Always {
            return Err(HeaderRefusal::new(
                name,
                "set on a cacheable read: a cached copy would hand one caller's cookie to the next",
            ));
        }
        headers.push((header, value.to_string()));
    }
    let Some(content_type) = content_type.filter(|ct| !ct.is_empty()) else {
        return Err(HeaderRefusal::new(
            "Content-Type",
            "missing: the envelope must name its content's media type",
        ));
    };
    repr.bytes.drain(..body_start);
    repr.repr_type = media_type(&content_type);
    Ok(Entity {
        content_type,
        headers,
    })
}

/// A `Location` an endpoint may set: a same-origin relative reference (RFC 3986 §4.2), an
/// absolute path or a query alone. Refused: a scheme or an authority (`https://x`, `//x`), a
/// backslash (which browsers read as `/`, so `/\x` is `//x`), a tab (which browsers remove
/// from a URL before parsing it, WHATWG URL, so `/<TAB>/x` is `//x` too; a CR or LF is
/// refused by [`check_value`]), and anything else (`done`, a relative path a browser would
/// resolve against a directory the endpoint cannot see).
pub(crate) fn check_same_origin(name: &str, value: &str) -> Result<(), HeaderRefusal> {
    let path_absolute = value.starts_with('/') && !value.starts_with("//");
    if !(path_absolute || value.starts_with('?')) || value.contains(['\\', '\t']) {
        return Err(HeaderRefusal::new(
            name,
            "not a same-origin relative reference (an absolute path `/…` or a query `?…`)",
        ));
    }
    Ok(())
}

/// A refusal for a name off the allowlist.
fn not_allowed(name: &str) -> HeaderRefusal {
    HeaderRefusal::new(
        name,
        "not one an endpoint may set (Cache-Control, Content-Disposition, Content-Language, \
         Location, Set-Cookie, Vary)",
    )
}

/// A header value is at most [`MAX_HEADER_VALUE`] bytes of visible ASCII, space and tab
/// (RFC 9110 §5.5 field-content, without obs-text). A CR or LF is refused here, so a value
/// cannot end its own line and start another header.
pub(crate) fn check_value(name: &str, value: &str) -> Result<(), HeaderRefusal> {
    if value.len() > MAX_HEADER_VALUE {
        return Err(HeaderRefusal::new(
            name,
            format!("its value is longer than {MAX_HEADER_VALUE} bytes"),
        ));
    }
    if let Some(b) = value
        .bytes()
        .find(|&b| !(b == b'\t' || (0x20..=0x7e).contains(&b)))
    {
        let why = match b {
            b'\r' | b'\n' => "its value holds a CR or LF".to_string(),
            _ => format!("its value holds the byte {b:#04x}, which a header value cannot"),
        };
        return Err(HeaderRefusal::new(name, why));
    }
    Ok(())
}

/// The headers the response writer owns, refused from any caller's list (ledger #1593).
/// `Content-Length` and `Connection: close` frame every answer (`Content-Length` on every
/// status but `204` and `304`, ledger #1597) and are written by the writer alone; `Content-Type` is written from the response's own content type, so a second would
/// make two; and the hop-by-hop headers (RFC 9110 §7.6.1) describe this connection, which the
/// writer closes after one answer, so none of them can be true when a caller sets it.
pub(crate) const WRITER_OWNED: [&str; 9] = [
    "Connection",
    "Content-Length",
    "Content-Type",
    "Keep-Alive",
    "Proxy-Connection",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

/// One header a door's OWN code sets on a response it writes (ledger #1593): the name is a
/// `token` and not one the writer owns ([`WRITER_OWNED`]), and the value passes the check an
/// endpoint's does ([`check_value`]). Unlike an endpoint's, the name need not be on the
/// [`EndpointHeader`] allowlist: a door sets `Allow`, `WWW-Authenticate`, `Retry-After` and the
/// like for itself.
pub(crate) fn check_door_header(name: &str, value: &str) -> Result<(), HeaderRefusal> {
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return Err(HeaderRefusal::new(
            name,
            "not a header name (empty, or a character a name cannot hold)",
        ));
    }
    if WRITER_OWNED.iter().any(|o| o.eq_ignore_ascii_case(name)) {
        return Err(HeaderRefusal::new(
            name,
            "the response writer sets it itself (framing, the content type, or a hop-by-hop \
             header); it cannot come from the caller",
        ));
    }
    check_value(name, value)
}

/// RFC 9110 §5.6.2 `tchar`: what a header name is made of.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A `Content-Type` value as a [`ReprType`], its parameters kept.
fn media_type(value: &str) -> ReprType {
    let mut parts = value.split(';');
    let mut ty = ReprType::new(parts.next().unwrap_or("").trim());
    for param in parts {
        if let Some((k, v)) = param.split_once('=') {
            ty = ty.with_param(k.trim(), v.trim().trim_matches('"'));
        }
    }
    ty
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(bytes: &[u8]) -> Representation {
        Representation::new(ReprType::new(HTTP_ENTITY), bytes.to_vec())
    }

    #[test]
    fn an_envelope_opens_to_its_content_and_headers() {
        let mut repr = envelope(
            b"Content-Type: text/html; charset=utf-8\r\nContent-Language: en\r\nVary: Cookie\r\n\r\n<p>hi</p>",
        );
        let entity = open(&mut repr, &EndpointHeader::DEFAULTS, false).unwrap();
        assert_eq!(repr.bytes, b"<p>hi</p>");
        assert_eq!(repr.repr_type.to_string(), "text/html;charset=utf-8");
        assert_eq!(entity.content_type, "text/html; charset=utf-8");
        assert_eq!(
            entity.headers,
            vec![
                (EndpointHeader::ContentLanguage, "en".to_string()),
                (EndpointHeader::Vary, "Cookie".to_string())
            ]
        );
    }

    #[test]
    fn a_bare_lf_envelope_opens_too() {
        let mut repr = envelope(b"Content-Type: text/plain\nContent-Language: fr\n\nbonjour");
        let entity = open(&mut repr, &EndpointHeader::DEFAULTS, false).unwrap();
        assert_eq!(repr.bytes, b"bonjour");
        assert_eq!(entity.headers.len(), 1);
    }

    #[test]
    fn a_hop_by_hop_or_door_owned_header_is_refused_by_name() {
        for name in [
            "Connection",
            "Transfer-Encoding",
            "Content-Length",
            "Keep-Alive",
            "Upgrade",
            "ETag",
            "Content-Security-Policy",
            "Access-Control-Allow-Origin",
        ] {
            let raw = format!("Content-Type: text/plain\r\n{name}: x\r\n\r\nhi");
            let refused =
                open(&mut envelope(raw.as_bytes()), &EndpointHeader::ALL, true).unwrap_err();
            assert_eq!(refused.header, name);
        }
    }

    #[test]
    fn a_control_byte_in_a_value_is_refused() {
        // A bare CR mid-line (a LF would end the line, and the rest would be refused as a
        // header of its own), NUL and DEL.
        for value in ["a\rb", "a\0b", "a\x7fb"] {
            let raw = format!("Content-Type: text/plain\r\nVary: {value}\r\n\r\nhi");
            let refused =
                open(&mut envelope(raw.as_bytes()), &EndpointHeader::ALL, true).unwrap_err();
            assert_eq!(refused.header, "Vary", "{value:?}");
        }
    }

    #[test]
    fn a_continuation_line_is_refused() {
        let raw = b"Content-Type: text/plain\r\nVary: Cookie\r\n Accept\r\n\r\nhi";
        assert!(open(&mut envelope(raw), &EndpointHeader::ALL, true).is_err());
    }

    #[test]
    fn an_oversized_value_is_refused_and_one_at_the_bound_is_not() {
        let at = "a".repeat(MAX_HEADER_VALUE);
        let raw = format!("Content-Type: text/plain\r\nContent-Disposition: {at}\r\n\r\nhi");
        assert!(open(&mut envelope(raw.as_bytes()), &EndpointHeader::ALL, true).is_ok());
        let over = "a".repeat(MAX_HEADER_VALUE + 1);
        let raw = format!("Content-Type: text/plain\r\nContent-Disposition: {over}\r\n\r\nhi");
        let refused = open(&mut envelope(raw.as_bytes()), &EndpointHeader::ALL, true).unwrap_err();
        assert_eq!(refused.header, "Content-Disposition");
        assert!(refused.why.contains("longer than 4096"), "{refused}");
    }

    #[test]
    fn too_many_lines_or_no_end_is_refused() {
        let mut raw = String::from("Content-Type: text/plain\r\n");
        for _ in 0..MAX_HEADER_LINES {
            raw.push_str("Vary: Cookie\r\n");
        }
        raw.push_str("\r\nhi");
        assert!(open(&mut envelope(raw.as_bytes()), &EndpointHeader::ALL, true).is_err());
        let endless = format!("Content-Type: text/plain\r\nVary: {}", "a".repeat(20_000));
        assert!(open(
            &mut envelope(endless.as_bytes()),
            &EndpointHeader::ALL,
            true
        )
        .is_err());
    }

    #[test]
    fn content_type_is_required_once() {
        assert!(open(
            &mut envelope(b"Vary: Cookie\r\n\r\nhi"),
            &EndpointHeader::ALL,
            true
        )
        .is_err());
        let twice = b"Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nhi";
        assert!(open(&mut envelope(twice), &EndpointHeader::ALL, true).is_err());
    }

    #[test]
    fn set_cookie_needs_the_door_and_an_uncacheable_answer() {
        let raw = b"Content-Type: text/plain\r\nSet-Cookie: s=1; HttpOnly\r\n\r\nhi";
        // The default door does not take it.
        let refused = open(&mut envelope(raw), &EndpointHeader::DEFAULTS, true).unwrap_err();
        assert!(refused.why.contains("endpoint_headers"), "{refused}");
        // A door that does: on a write, and on an uncacheable read.
        assert!(open(&mut envelope(raw), &EndpointHeader::ALL, true).is_ok());
        assert!(open(&mut envelope(raw), &EndpointHeader::ALL, false).is_ok());
        // Never on a read the kernel may cache.
        let refused =
            open(&mut envelope(raw).cacheable(), &EndpointHeader::ALL, false).unwrap_err();
        assert!(refused.why.contains("cacheable"), "{refused}");
    }

    #[test]
    fn with_headers_round_trips_and_keeps_the_expiry() {
        let repr = Representation::new(ReprType::new("application/json"), b"{}".to_vec())
            .cacheable()
            .depends_on("urn:x");
        let mut wrapped = with_headers(repr, &[("Cache-Control", "max-age=60")]).unwrap();
        assert_eq!(wrapped.expiry, Expiry::Never);
        assert_eq!(wrapped.threads().len(), 1);
        let entity = open(&mut wrapped, &EndpointHeader::DEFAULTS, false).unwrap();
        assert_eq!(wrapped.bytes, b"{}");
        assert_eq!(entity.content_type, "application/json");
        assert_eq!(
            entity.headers,
            vec![(EndpointHeader::CacheControl, "max-age=60".to_string())]
        );
    }

    #[test]
    fn with_headers_refuses_what_the_door_would() {
        let repr = || Representation::new(ReprType::new("text/plain"), b"hi".to_vec());
        assert_eq!(
            with_headers(repr(), &[("Connection", "close")])
                .unwrap_err()
                .header,
            "Connection"
        );
        assert_eq!(
            with_headers(repr(), &[("Vary", "a\nb")])
                .unwrap_err()
                .header,
            "Vary"
        );
        let long = "a".repeat(MAX_HEADER_VALUE + 1);
        assert_eq!(
            with_headers(repr(), &[("Set-Cookie", long.as_str())])
                .unwrap_err()
                .header,
            "Set-Cookie"
        );
    }
}
