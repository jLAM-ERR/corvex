use anyhow::{Context, Result};
use log::debug;
use std::collections::BTreeMap;
use std::io::Read;

const MAX_BODY_SIZE: u64 = 5 * 1024 * 1024; // 5 MB

/// Default User-Agent for subscription downloads; v2rayNG-compatible so panels
/// that content-negotiate on UA return plain base64 rather than filtered/broken output.
pub const DEFAULT_SUBS_USER_AGENT: &str = "v2rayNG/1.10.2";

/// Resolve the User-Agent to send: the configured value when present and non-empty,
/// otherwise the default.
pub fn resolve_user_agent(configured: Option<&str>) -> &str {
    match configured {
        Some(ua) if !ua.trim().is_empty() => ua,
        _ => DEFAULT_SUBS_USER_AGENT,
    }
}

/// The value of the `User-Agent` key in extra_headers, if any (case-insensitive).
fn user_agent_override(extra_headers: &BTreeMap<String, String>) -> Option<&str> {
    extra_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        .map(|(_, value)| value.as_str())
}

/// The User-Agent that will actually be sent: an extra_headers override wins over
/// the resolved value, so a caller-supplied `User-Agent`/`user-agent` header is
/// never duplicated alongside the resolved one.
pub fn effective_user_agent<'a>(
    resolved: &'a str,
    extra_headers: &'a BTreeMap<String, String>,
) -> &'a str {
    user_agent_override(extra_headers).unwrap_or(resolved)
}

/// Stand-in for every part of a URL that may carry a secret.
pub const REDACTED_MARKER: &str = "<redacted>";

/// Reduce a subscription URL to the part that is safe to write down: scheme, host
/// and — when it is not the scheme's default — port.
///
/// Subscription tokens live in the URL *path* (`https://panel.example/sub/<TOKEN>`),
/// so any line rendering a raw subscription URL publishes a credential. Corvex does
/// exactly that today at `warn!`, the default level, and once it writes a log file
/// the same line lands on disk. Userinfo, path, query and fragment are therefore all
/// replaced by a single marker; scheme and host are enough to tell two configured
/// subscriptions apart, which is all a diagnostic line needs.
///
/// Input that does not parse as an absolute URL, or that parses without a host, is
/// rendered as the marker alone rather than echoed back — a string corvex could not
/// parse is a string it cannot prove is free of secrets.
pub fn redact_url(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return REDACTED_MARKER.to_string();
    };
    let Some(host) = parsed.host_str() else {
        return REDACTED_MARKER.to_string();
    };
    let base = match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), host, port),
        None => format!("{}://{}", parsed.scheme(), host),
    };
    let path = parsed.path();
    let has_path = !path.is_empty() && path != "/";
    let carries_secret = !parsed.username().is_empty()
        || parsed.password().is_some()
        || has_path
        || parsed.query().is_some()
        || parsed.fragment().is_some();
    if carries_secret {
        format!("{base}/{REDACTED_MARKER}")
    } else {
        base
    }
}

/// The HTTP client configuration used for every subscription download.
///
/// Extracted from `download_subscription` so the proxy decision is assertable in a
/// unit test without making a network call.
///
/// The proxy is explicitly disabled. ureq's `Config::default` picks a proxy up from
/// `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` (and their lowercase spellings), and a user
/// whose shell exports `HTTP_PROXY=http://localhost:<proxy.port>` points that straight
/// at corvex's own listener. The subscription fetch is infrastructure for bringing the
/// tunnel up — it runs before xray is spawned — so routing it through the tunnel
/// deadlocks `corvex start` against itself and surfaces as `timeout: global` followed by
/// `no supported proxy servers found in subscriptions`. Downloads must never traverse
/// the tunnel they are being used to establish.
pub fn subscription_agent_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .proxy(None)
        .build()
}

/// Render a transport failure as a line that is safe to log.
///
/// The configured URL never reaches a log whole — [`redact_url`] guards every
/// site that interpolates it — but that only covers the string corvex chose.
/// `{err:#}` walks the whole cause chain, and several `ureq::Error` variants
/// interpolate bytes the *server* chose: `Protocol` carries ureq-proto's
/// `BadLocationHeader(String)`, which is the raw `Location` header of a redirect
/// ureq could not parse, and `BadUri(String)` renders a whole URI, which on a
/// redirect is derived from that same header. A panel that reflects the request
/// path back in a malformed `Location` therefore writes corvex's own
/// subscription token into `corvex.log` and onto the terminal, straight past the
/// redaction — and a hostile one can put arbitrary bytes, terminal escapes
/// included, in the same place.
///
/// So the boundary is drawn here instead: a `ureq::Error` is turned into text
/// corvex composed before it ever becomes an `anyhow::Error`, and the arms that
/// interpolate anything only interpolate values corvex, the OS or ureq's own
/// static strings supplied. The reason `{err:#}` was used in the first place —
/// telling DNS from connect from TLS from timeout, which is the only part of a
/// failed fetch worth reading — survives intact. `Error` is `#[non_exhaustive]`,
/// so the catch-all is load-bearing: a variant added by a future ureq is safe by
/// default rather than leaky by default.
fn describe_fetch_error(err: &ureq::Error) -> String {
    match err {
        ureq::Error::StatusCode(code) => format!("http status {code}"),
        ureq::Error::HostNotFound => "host not found".to_string(),
        // `Timeout` is an enum of ureq's own static reasons (`global`, `connect`,
        // `recv response`, ...), which is what makes the start-path deadlock
        // recognisable as `timeout: global`.
        ureq::Error::Timeout(reason) => format!("timeout: {reason}"),
        ureq::Error::Io(e) => describe_io_error(e),
        // `&'static str`, chosen by ureq.
        ureq::Error::Tls(reason) => format!("tls: {reason}"),
        ureq::Error::ConnectionFailed => "connection failed".to_string(),
        ureq::Error::TooManyRedirects => "too many redirects".to_string(),
        ureq::Error::RedirectFailed => "redirect failed".to_string(),
        ureq::Error::InvalidProxyUrl => "invalid proxy url".to_string(),
        ureq::Error::LargeResponseHeader(size, max) => {
            format!("the response header is too big: {size} > {max}")
        }
        ureq::Error::BodyExceedsLimit(limit) => {
            format!("the response body exceeds {limit} bytes")
        }
        // The two server-controlled-payload variants, named but not quoted.
        ureq::Error::BadUri(_) => "the server redirected to a URL corvex cannot fetch".to_string(),
        ureq::Error::Protocol(_) => "the server sent a malformed HTTP response".to_string(),
        _ => "the request failed".to_string(),
    }
}

/// Reading the response body yields a bare `io::Error`, and ureq boxes its own
/// `Error` inside one when it has to cross an `io` boundary — a chunked-encoding
/// fault surfaces exactly that way, as an `io::Error` wrapping
/// `Error::Protocol`. Rendering it with `{e}` would print the wrapped error's
/// `Display` and undo [`describe_fetch_error`], so unwrap first and route it
/// back. Everything else is a real OS error, whose text comes from `strerror`.
///
/// The two functions recurse into each other; the recursion terminates because
/// each hop strictly descends an owned, finite error chain.
fn describe_io_error(err: &std::io::Error) -> String {
    match err.get_ref().and_then(|e| e.downcast_ref::<ureq::Error>()) {
        Some(inner) => describe_fetch_error(inner),
        None => format!("io: {err}"),
    }
}

/// Download a subscription from the given URL, returning the raw body.
pub fn download_subscription(
    url: &str,
    user_agent: &str,
    extra_headers: &BTreeMap<String, String>,
) -> Result<String> {
    debug!("downloading subscription from {}", redact_url(url));
    // Rejected here rather than by ureq. ureq's `BadUri` renders the whole URI
    // it was handed — `"<url> is missing scheme"`, `"<url> is missing host"` —
    // and that string is carried verbatim into `{err:#}` by the contexts below,
    // past every `redact_url`. A `subs-url` pasted without a scheme would then
    // publish its token at `warn!`, into the terminal and into `corvex.log`.
    //
    // Parsing is not enough on its own: `url::Url` accepts any scheme, so
    // `mailto:<token>@panel.example` parses cleanly here and still reaches the
    // echoing branch inside ureq. The guard therefore demands exactly what a
    // subscription download needs — an http/https scheme and a host — which is
    // both a better error for the user and the whole class closed.
    let scheme_and_host_are_fetchable = url::Url::parse(url)
        .map(|parsed| matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some())
        .unwrap_or(false);
    if !scheme_and_host_are_fetchable {
        anyhow::bail!(
            "{} is not a fetchable subscription URL: subs-url needs an http:// or https:// scheme and a host",
            redact_url(url)
        );
    }
    let agent = ureq::Agent::new_with_config(subscription_agent_config());
    let ua = effective_user_agent(user_agent, extra_headers);
    let mut request = agent.get(url).header("User-Agent", ua);
    for (name, value) in extra_headers {
        // already set above (either the resolved UA or this override) — skip to avoid a duplicate header
        if name.eq_ignore_ascii_case("user-agent") {
            continue;
        }
        request = request.header(name, value);
    }
    let mut body = String::new();
    // Both errors are described before they become `anyhow::Error`s, so the
    // cause chain `{err:#}` renders holds corvex's words and nothing the server
    // wrote — see [`describe_fetch_error`].
    request
        .call()
        .map_err(|e| anyhow::anyhow!("{}", describe_fetch_error(&e)))
        .with_context(|| format!("failed to fetch {}", redact_url(url)))?
        .body_mut()
        .as_reader()
        .take(MAX_BODY_SIZE)
        .read_to_string(&mut body)
        .map_err(|e| anyhow::anyhow!("{}", describe_io_error(&e)))
        .with_context(|| format!("failed to read body from {}", redact_url(url)))?;
    debug!("downloaded {} bytes from {}", body.len(), redact_url(url));
    Ok(body)
}

/// Decode a base64-encoded subscription into a list of URIs.
pub fn decode_subscription(data: &str) -> Result<Vec<String>> {
    let decoded_bytes = crate::protocol::decode_base64(data.trim())
        .context("failed to decode base64 subscription data")?;
    let decoded =
        String::from_utf8(decoded_bytes).context("subscription data is not valid UTF-8")?;
    let uris: Vec<String> = decoded
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    debug!("decoded {} URIs from subscription", uris.len());
    Ok(uris)
}

/// Keep only URIs with supported proxy protocols (VLESS, VMess, Trojan, Shadowsocks).
pub fn filter_supported(uris: &[String]) -> Vec<String> {
    let filtered: Vec<String> = uris
        .iter()
        .filter(|uri| {
            crate::protocol::SUPPORTED_SCHEMES
                .iter()
                .any(|scheme| uri.starts_with(scheme))
        })
        .cloned()
        .collect();
    debug!("filtered {}/{} supported URIs", filtered.len(), uris.len());
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    /// A fake token, never a real one: pushed through the redaction paths and
    /// asserted absent, so a new log line that forgets `redact_url` fails the suite
    /// instead of shipping a credential to disk.
    const SENTINEL_TOKEN: &str = "SENTINEL-TOKEN-9f3a2c";

    /// The `ALL_PROXY` value the proxy-bypass test hands its child process.
    /// Doubles as the marker that tells the child it is the child.
    const PROXY_ENV_SENTINEL: &str = "http://127.0.0.1:21080";
    /// Printed by the child branch once the proxy-bypass assertions have
    /// actually run, and grepped for by the parent. See the parent branch for
    /// why a green child is not on its own evidence of anything.
    const CHILD_ASSERTIONS_RAN: &str = "corvex-test: proxy-bypass assertions ran";

    #[test]
    fn test_redact_url_keeps_scheme_and_host_only() {
        let cases = [
            (
                "token path removed",
                "https://panel.example/sub/SENTINEL-TOKEN-9f3a2c",
                "https://panel.example/<redacted>",
            ),
            (
                "query removed",
                "https://panel.example/sub?token=SENTINEL-TOKEN-9f3a2c",
                "https://panel.example/<redacted>",
            ),
            (
                "fragment removed",
                "https://panel.example/sub#SENTINEL-TOKEN-9f3a2c",
                "https://panel.example/<redacted>",
            ),
            (
                "userinfo removed",
                "https://user:SENTINEL-TOKEN-9f3a2c@panel.example/sub",
                "https://panel.example/<redacted>",
            ),
            (
                "URL with no path is left whole",
                "https://panel.example",
                "https://panel.example",
            ),
            (
                "bare root path is not a secret",
                "https://panel.example/",
                "https://panel.example",
            ),
            (
                "non-default port is kept, it identifies the endpoint",
                "https://panel.example:8443/sub/SENTINEL-TOKEN-9f3a2c",
                "https://panel.example:8443/<redacted>",
            ),
            (
                "default port is normalised away by the parser",
                "https://panel.example:443/sub/SENTINEL-TOKEN-9f3a2c",
                "https://panel.example/<redacted>",
            ),
            (
                "unparseable input yields the marker alone",
                "SENTINEL-TOKEN-9f3a2c",
                "<redacted>",
            ),
            (
                "hostless URL yields the marker alone",
                "mailto:SENTINEL-TOKEN-9f3a2c@panel.example",
                "<redacted>",
            ),
            ("empty input yields the marker alone", "", "<redacted>"),
        ];
        for (label, input, want) in cases {
            assert_eq!(redact_url(input), want, "{label}");
        }
    }

    #[test]
    fn test_redact_url_never_echoes_the_token() {
        // Every place a token can hide in a URL, at once.
        let url = format!(
            "https://user:{SENTINEL_TOKEN}@panel.example/sub/{SENTINEL_TOKEN}\
             ?key={SENTINEL_TOKEN}#{SENTINEL_TOKEN}"
        );
        let redacted = redact_url(&url);
        assert!(
            !redacted.contains(SENTINEL_TOKEN),
            "token leaked into {redacted}"
        );
        assert_eq!(redacted, "https://panel.example/<redacted>");
    }

    /// The failure contexts `download_subscription` attaches are rendered by
    /// `subscription_failure_message` at `warn!`, so they must be redacted at the
    /// point they are built — not at the point they are printed.
    ///
    /// Drives the real function: port 1 on loopback is refused immediately, so
    /// this needs no network and no DNS, and the error that comes back is the
    /// one a user would see. Asserting on a locally rebuilt context string would
    /// pass even if `download_subscription` went back to interpolating the raw
    /// URL, which is the regression this test exists to catch.
    #[test]
    fn test_download_failure_is_redacted() {
        let url = format!("http://127.0.0.1:1/sub/{SENTINEL_TOKEN}");

        let error = download_subscription(&url, DEFAULT_SUBS_USER_AGENT, &BTreeMap::new())
            .expect_err("a refused connection cannot succeed");
        let rendered = format!("{error:#}");

        assert!(
            !rendered.contains(SENTINEL_TOKEN),
            "token leaked: {rendered}"
        );
        assert!(!rendered.contains("/sub/"), "path leaked: {rendered}");
        assert!(
            rendered.contains("http://127.0.0.1:1"),
            "the host is what tells two subscriptions apart: {rendered}"
        );
    }

    /// A URL ureq would reject itself never reaches ureq, because ureq's
    /// `BadUri` echoes the whole URI — token and all — into the error chain.
    #[test]
    fn test_download_rejects_a_schemeless_url_without_echoing_it() {
        let url = format!("panel.example/sub/{SENTINEL_TOKEN}");

        let error = download_subscription(&url, DEFAULT_SUBS_USER_AGENT, &BTreeMap::new())
            .expect_err("a schemeless URL is not fetchable");
        let rendered = format!("{error:#}");

        assert!(
            !rendered.contains(SENTINEL_TOKEN),
            "token leaked: {rendered}"
        );
        assert!(
            rendered.contains(REDACTED_MARKER),
            "an unparseable URL renders as the marker alone: {rendered}"
        );
    }

    /// Guards the deadlock this branch exists to fix, by reproducing its cause:
    /// with `ALL_PROXY` exported, ureq's default config picks the proxy up, and
    /// `subscription_agent_config` must still come back with none. Asserting
    /// `is_none()` with no variable set passes on any machine even if
    /// `.proxy(None)` is deleted, which is no guard at all.
    ///
    /// The variable is set for a **child process** rather than for this one.
    /// `set_var` is a data race against every other thread in the binary, and
    /// libtest runs the suite multi-threaded: siblings call `std::env::var` for
    /// `HOME`, `XDG_CONFIG_HOME`, `USER` and `CORVEX_DEBUG` throughout, and
    /// glibc's `setenv` can reallocate `environ` out from under a concurrent
    /// `getenv`. A mutex here would serialize this test only against itself.
    /// So the parent pass re-runs this same test binary with `ALL_PROXY` in the
    /// child's environment, and the child — which recognizes itself by the
    /// sentinel value already being set — does the asserting. Nothing mutates
    /// a live environment, and the guard keeps its full strength.
    #[test]
    fn test_subscription_agent_config_has_no_proxy_even_with_all_proxy_set() {
        if std::env::var("ALL_PROXY").as_deref() == Ok(PROXY_ENV_SENTINEL) {
            assert!(
                ureq::Agent::config_builder().build().proxy().is_some(),
                "ureq no longer reads ALL_PROXY, so this test proves nothing — rewrite it"
            );
            assert!(
                subscription_agent_config().proxy().is_none(),
                "the subscription agent must never inherit the environment proxy: \
                 HTTP_PROXY pointing at corvex's own port makes `start` fetch the \
                 subscription through an xray it has not launched yet"
            );
            println!("{CHILD_ASSERTIONS_RAN}");
            return;
        }

        let output = std::process::Command::new(
            std::env::current_exe().expect("the test binary must have a path"),
        )
        .args([
            "--exact",
            "--nocapture",
            "subscription::tests::test_subscription_agent_config_has_no_proxy_even_with_all_proxy_set",
        ])
        .env("ALL_PROXY", PROXY_ENV_SENTINEL)
        .output()
        .expect("failed to re-run the test binary");

        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            output.status.success(),
            "the proxy-bypass assertions failed in the child process:\n{rendered}"
        );
        // A green child proves nothing on its own: libtest exits 0 when a
        // filter matches no test at all. Rename or move this test and the
        // parent would go on spawning a child that runs zero tests, sees
        // success, and reports the deadlock guard as passing forever while
        // guarding nothing. The marker is printed by the child branch above,
        // so it appears only if the assertions really executed - which is also
        // why `--nocapture` stays in the argument list.
        assert!(
            rendered.contains(CHILD_ASSERTIONS_RAN),
            "the child ran no assertions - the filter above no longer names this test, so the \
             proxy-bypass guard is vacuous:\n{rendered}"
        );
    }

    /// A URL with a scheme ureq cannot fetch is rejected here, not by ureq:
    /// `mailto:<token>@host` parses as a `url::Url`, so a guard that only
    /// checked "does it parse" would hand it to ureq, whose `BadUri` echoes the
    /// whole URI — token included — into the error chain.
    #[test]
    fn test_download_rejects_a_non_http_scheme_without_echoing_it() {
        let url = format!("mailto:{SENTINEL_TOKEN}@panel.example");

        let error = download_subscription(&url, DEFAULT_SUBS_USER_AGENT, &BTreeMap::new())
            .expect_err("a mailto: URL is not fetchable");
        let rendered = format!("{error:#}");

        assert!(
            !rendered.contains(SENTINEL_TOKEN),
            "token leaked: {rendered}"
        );
        assert!(
            rendered.contains(REDACTED_MARKER),
            "a hostless URL renders as the marker alone: {rendered}"
        );
    }

    /// A malformed `Location` is the one string a *server* gets to put into
    /// corvex's error chain. ureq-proto's `BadLocationHeader` carries the header
    /// verbatim, `ureq::Error::Protocol` renders it, and `{err:#}` in
    /// `subscription_failure_message` writes it to the terminal and to
    /// `corvex.log` at the default level. So a panel that reflects the request
    /// path back in a redirect it knows corvex cannot follow launders the
    /// subscription token straight past `redact_url` — which guards the URL
    /// corvex chose and can say nothing about the one the server sent.
    ///
    /// `../../../` from `/sub` walks above the root, which ureq-proto refuses
    /// with the header attached. Driven through the real `download_subscription`
    /// against a loopback listener, in the style of the body-cap test: asserting
    /// on a locally rebuilt string would stay green with the boundary deleted.
    #[test]
    fn test_download_does_not_echo_a_malformed_redirect_location() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one client");
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch);
            let response = format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: ../../../{SENTINEL_TOKEN}\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
        });

        let error = download_subscription(
            &format!("http://127.0.0.1:{port}/sub"),
            DEFAULT_SUBS_USER_AGENT,
            &BTreeMap::new(),
        )
        .expect_err("a redirect above the root cannot be followed");
        let rendered = format!("{error:#}");

        assert!(
            !rendered.contains(SENTINEL_TOKEN),
            "the server chose that string; it must not reach the log: {rendered}"
        );
        assert!(
            rendered.contains(&format!("http://127.0.0.1:{port}")),
            "the failure must still name which subscription it was: {rendered}"
        );
        let _ = server.join();
    }

    /// `BadUri` is the other server-controlled payload, and the only one this
    /// crate can construct directly — on a redirect ureq derives the URI it
    /// renders from the very `Location` header the test above sends.
    #[test]
    fn test_describe_fetch_error_never_quotes_a_server_supplied_payload() {
        let leaky = ureq::Error::BadUri(format!("https://panel.example/sub/{SENTINEL_TOKEN}"));

        let described = describe_fetch_error(&leaky);

        assert!(
            !described.contains(SENTINEL_TOKEN),
            "token leaked: {described}"
        );
        assert!(
            !described.contains("panel.example"),
            "a server-chosen host is no safer than the path: {described}"
        );
    }

    /// The body read hands back a bare `io::Error`, and ureq boxes its own error
    /// inside one to cross that boundary — so `describe_io_error` has to unwrap,
    /// or the `Display` it was meant to replace prints anyway.
    #[test]
    fn test_describe_io_error_unwraps_a_boxed_ureq_error() {
        let wrapped = std::io::Error::other(ureq::Error::BadUri(format!(
            "https://panel.example/sub/{SENTINEL_TOKEN}"
        )));

        let described = describe_io_error(&wrapped);

        assert!(
            !described.contains(SENTINEL_TOKEN),
            "token leaked through the io wrapper: {described}"
        );
    }

    /// Safety is only half of it: the reason the chain is rendered with `{err:#}`
    /// at all is to tell a refused connection from a timeout from a DNS failure.
    /// A `describe_fetch_error` that answered "the request failed" to everything
    /// would pass every assertion above and be worthless.
    #[test]
    fn test_describe_fetch_error_still_says_what_went_wrong() {
        assert_eq!(
            describe_fetch_error(&ureq::Error::HostNotFound),
            "host not found"
        );
        assert_eq!(
            describe_fetch_error(&ureq::Error::StatusCode(403)),
            "http status 403"
        );
        let refused =
            describe_io_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(
            refused.starts_with("io: ") && refused.len() > "io: ".len(),
            "an OS error keeps its own text: {refused}"
        );
    }

    #[test]
    fn test_subscription_agent_config_keeps_global_timeout() {
        assert_eq!(
            subscription_agent_config().timeouts().global,
            Some(std::time::Duration::from_secs(30))
        );
    }

    /// The cap that keeps a hostile or misconfigured panel from exhausting
    /// memory is `.take(MAX_BODY_SIZE)` in `download_subscription`, not the
    /// constant itself — asserting the constant equals its own definition would
    /// stay green with the `.take` deleted. So this serves an oversized body
    /// from a loopback listener and checks the read actually stops.
    ///
    /// Loopback only: the listener is bound to `127.0.0.1:0`, so this needs no
    /// network and no DNS, in keeping with the rest of the suite.
    #[test]
    fn test_download_stops_reading_at_the_body_cap() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().unwrap().port();
        let oversized = MAX_BODY_SIZE as usize + 4096;

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one client");
            // Read just enough of the request to let the client finish sending.
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch);
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\n\r\n");
            if stream.write_all(header.as_bytes()).is_err() {
                return;
            }
            // Ignored on purpose: the client hangs up the moment it has read
            // its cap, so the tail of this body reliably fails with EPIPE.
            let chunk = vec![b'A'; 64 * 1024];
            let mut sent = 0usize;
            while sent < oversized {
                let n = chunk.len().min(oversized - sent);
                if stream.write_all(&chunk[..n]).is_err() {
                    return;
                }
                sent += n;
            }
        });

        let body = download_subscription(
            &format!("http://127.0.0.1:{port}/sub"),
            DEFAULT_SUBS_USER_AGENT,
            &BTreeMap::new(),
        )
        .expect("an oversized body is truncated, not an error");

        assert_eq!(
            body.len(),
            MAX_BODY_SIZE as usize,
            "the read must stop at the cap, not follow Content-Length"
        );
        let _ = server.join();
    }

    #[test]
    fn test_decode_subscription() {
        let raw = "vless://uuid@host:443?type=grpc\nvmess://data\ntrojan://pass@host:443\n";
        let encoded = STANDARD.encode(raw);
        let result = decode_subscription(&encoded).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "vless://uuid@host:443?type=grpc");
        assert_eq!(result[1], "vmess://data");
        assert_eq!(result[2], "trojan://pass@host:443");
    }

    #[test]
    fn test_decode_subscription_with_whitespace() {
        let raw = "vless://a\n\nvless://b\n";
        let encoded = format!("  {}  ", STANDARD.encode(raw));
        let result = decode_subscription(&encoded).unwrap();
        assert_eq!(result, vec!["vless://a", "vless://b"]);
    }

    #[test]
    fn test_decode_subscription_invalid_base64() {
        let result = decode_subscription("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_supported_keeps_all_protocols() {
        let uris = vec![
            "vless://uuid@host:443?type=grpc#VLESS".to_string(),
            "vmess://base64data".to_string(),
            "trojan://password@host:443#Trojan".to_string(),
            "ss://base64data@host:8388#SS".to_string(),
            "http://not-a-proxy".to_string(),
        ];
        let filtered = filter_supported(&uris);
        assert_eq!(filtered.len(), 4);
        assert!(filtered[0].starts_with("vless://"));
        assert!(filtered[1].starts_with("vmess://"));
        assert!(filtered[2].starts_with("trojan://"));
        assert!(filtered[3].starts_with("ss://"));
    }

    #[test]
    fn test_filter_supported_none_match() {
        let uris = vec![
            "http://example.com".to_string(),
            "socks5://proxy:1080".to_string(),
        ];
        let filtered = filter_supported(&uris);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_default_subs_user_agent_is_v2rayng_flavored() {
        assert!(DEFAULT_SUBS_USER_AGENT.starts_with("v2rayNG/"));
    }

    #[test]
    fn test_resolve_user_agent_none_returns_default() {
        assert_eq!(resolve_user_agent(None), DEFAULT_SUBS_USER_AGENT);
    }

    #[test]
    fn test_resolve_user_agent_some_returns_configured() {
        assert_eq!(resolve_user_agent(Some("Happ/3.13.0")), "Happ/3.13.0");
    }

    #[test]
    fn test_resolve_user_agent_empty_string_falls_back_to_default() {
        assert_eq!(resolve_user_agent(Some("")), DEFAULT_SUBS_USER_AGENT);
        assert_eq!(resolve_user_agent(Some("   ")), DEFAULT_SUBS_USER_AGENT);
    }

    #[test]
    fn test_effective_user_agent_no_override_uses_resolved() {
        let headers = BTreeMap::new();
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "v2rayNG/1.10.2"
        );
    }

    #[test]
    fn test_effective_user_agent_header_override_wins() {
        let mut headers = BTreeMap::new();
        headers.insert("User-Agent".to_string(), "Happ/3.13.0".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "Happ/3.13.0"
        );
    }

    #[test]
    fn test_effective_user_agent_header_override_case_insensitive() {
        let mut headers = BTreeMap::new();
        headers.insert("user-agent".to_string(), "Happ/3.13.0".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "Happ/3.13.0"
        );
    }

    #[test]
    fn test_effective_user_agent_unrelated_headers_ignored() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Hwid".to_string(), "abc".to_string());
        assert_eq!(
            effective_user_agent("v2rayNG/1.10.2", &headers),
            "v2rayNG/1.10.2"
        );
    }
}
