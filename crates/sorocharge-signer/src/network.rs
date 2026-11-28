use crate::SorochargeError;

use std::time::Duration;

const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Maximum number of attempts for [`retry_get`] before giving up.
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Maps a Stellar network passphrase to its CAIP-2 identifier.
///
/// Exists so the x402 and MPP adapters share one mapping instead of each
/// keeping a copy that could drift. Any passphrase other than mainnet's or
/// testnet's fails closed rather than guessing a network.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedNetwork`] for any other passphrase.
///
/// # Examples
///
/// ```
/// use sorocharge_signer::{caip2_for_passphrase, SorochargeError};
///
/// assert_eq!(
///     caip2_for_passphrase("Test SDF Network ; September 2015"),
///     Ok("stellar:testnet"),
/// );
/// assert_eq!(
///     caip2_for_passphrase("Public Global Stellar Network ; September 2015"),
///     Ok("stellar:pubnet"),
/// );
///
/// // Anything else fails closed — including a CAIP-2 id passed where a
/// // passphrase was expected — and the error carries the input verbatim.
/// assert_eq!(
///     caip2_for_passphrase("stellar:testnet"),
///     Err(SorochargeError::UnsupportedNetwork {
///         network: "stellar:testnet".to_string(),
///     }),
/// );
/// ```
pub fn caip2_for_passphrase(network_passphrase: &str) -> Result<&'static str, SorochargeError> {
    match network_passphrase {
        PUBNET_PASSPHRASE => Ok("stellar:pubnet"),
        TESTNET_PASSPHRASE => Ok("stellar:testnet"),
        other => Err(SorochargeError::UnsupportedNetwork {
            network: other.to_string(),
        }),
    }
}

/// Retries an HTTP GET request with bounded backoff for transient failures.
///
/// This is the single home of the retry/backoff logic shared by the
/// `sorocharge-x402` and `sorocharge-mpp` clients. Each client supplies its
/// own `map_error` closure so the error type stays crate-specific; the
/// retry/backoff semantics themselves live here and cannot drift between the
/// two adapters.
///
/// - Retries up to [`MAX_RETRY_ATTEMPTS`] times.
/// - Only connection-level failures (the `Err` arm of `send()`) are retried.
///   Protocol-level responses (`200`, `402`, `5xx`, …) are returned to the
///   caller immediately — they are deliberate server responses, not transient
///   failures.
/// - On each retry, waits with exponential backoff (`1s`, `2s`, `4s`, …).
/// - Every attempt respects the HTTP client's `request_timeout`, so total
///   wall-clock time is bounded by `timeout * attempts` plus backoff.
/// - On success, returns the successful response immediately.
/// - On final failure, returns the last error, produced by `map_error`.
///
/// # Parameters
///
/// - `http` — the (already timeout-configured) `reqwest::Client`.
/// - `url` — the URL to GET, cloned per attempt.
/// - `map_error` — converts a failure reason string into the caller's error
///   type.
pub async fn retry_get<F, E>(
    http: &reqwest::Client,
    url: impl reqwest::IntoUrl + Clone,
    map_error: F,
) -> Result<reqwest::Response, E>
where
    F: Fn(String) -> E,
{
    let mut attempt = 0u32;
    let mut last_error = map_error("exhausted retries".to_string());
    while attempt < MAX_RETRY_ATTEMPTS {
        attempt += 1;
        match http.get(url.clone()).send().await {
            Ok(resp) => {
                // Protocol-level responses (200, 402, 5xx, …) are deliberate
                // server answers, not transient failures: return them as-is.
                return Ok(resp);
            }
            Err(e) => {
                last_error = map_error(format!("request attempt {attempt} failed: {e}"));
                if attempt < MAX_RETRY_ATTEMPTS {
                    // Exponential backoff: 1s, 2s, 4s, …
                    let backoff =
                        Duration::from_secs(2u64.saturating_pow(attempt.saturating_sub(1)));
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_passphrases_to_caip2() {
        assert_eq!(
            caip2_for_passphrase(PUBNET_PASSPHRASE),
            Ok("stellar:pubnet")
        );
        assert_eq!(
            caip2_for_passphrase(TESTNET_PASSPHRASE),
            Ok("stellar:testnet")
        );
    }

    /// `UnsupportedNetwork` is the only failure here, and it carries the
    /// rejected passphrase verbatim — including a CAIP-2 id mistakenly
    /// passed where a passphrase was expected.
    #[test]
    fn unknown_passphrase_is_unsupported_network_carrying_it_verbatim() {
        for bad in [
            "stellar:testnet",
            "",
            "Test SDF Future Network ; October 2022",
        ] {
            assert_eq!(
                caip2_for_passphrase(bad),
                Err(SorochargeError::UnsupportedNetwork {
                    network: bad.to_string(),
                })
            );
        }
    }

    #[cfg(test)]
    mod retry_get_tests {
        use super::*;

        /// A connection-refused address: nothing is listening, so every
        /// attempt fails at the transport level immediately. This exercises
        /// the retry-exhaustion path without needing an HTTP server.
        async fn refused_client() -> (reqwest::Client, String) {
            // Bind then drop so the port is (almost certainly) closed.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral port");
            let addr = listener.local_addr().expect("read bound address");
            drop(listener);
            let url = format!("http://{addr}/");
            let http = reqwest::Client::builder()
                .timeout(Duration::from_millis(10))
                .build()
                .expect("http client");
            (http, url)
        }

        #[tokio::test]
        async fn connection_refusal_exhausts_all_attempts_and_reports_final_attempt() {
            let (http, url) = refused_client().await;
            let result = retry_get(&http, url, |reason| TestError { reason }).await;
            assert!(
                matches!(result, Err(TestError { ref reason }) if reason.contains("request attempt 3")),
                "expected all {MAX_RETRY_ATTEMPTS} attempts to be reported, got {result:?}"
            );
        }

        #[derive(Debug, PartialEq, Eq)]
        struct TestError {
            reason: String,
        }
    }
}
