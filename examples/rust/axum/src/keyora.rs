//! Everything that talks to Keyora: configuration, the REST client and token verification.

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::time::{Duration, Instant};

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::RwLock;

/// Cached keys are replaced after this long, so a key removed in Keyora stops being trusted.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// Minimum time between two JWKS fetches. Tokens with made-up key IDs must not
/// be able to make this application hammer Keyora.
const JWKS_COOLDOWN: Duration = Duration::from_secs(10);

pub struct Config {
    /// Where this application reaches Keyora (API calls and JWKS).
    pub url: String,
    /// The `iss` value tokens must carry.
    pub issuer: String,
    /// The application's client ID. Also the `aud` value tokens must carry.
    pub client_id: String,
    /// The application's secret. It never leaves this process except as HTTP
    /// Basic credentials on calls to Keyora.
    pub client_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| env::var(name).ok().filter(|v| !v.is_empty());
        let url = var("KEYORA_URL").unwrap_or_else(|| "http://localhost:8080".into());
        let url = url.trim_end_matches('/').to_owned();
        let (Some(client_id), Some(client_secret)) = (var("KEYORA_CLIENT_ID"), var("KEYORA_CLIENT_SECRET")) else {
            return Err("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh)".into());
        };
        Ok(Self { issuer: var("KEYORA_ISSUER").unwrap_or_else(|| url.clone()), url, client_id, client_secret })
    }
}

/// The part of an access token the application uses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// `"access"` for access tokens, `"id"` for OIDC ID tokens. Checked in `verify_token`.
    #[serde(default, skip_serializing)]
    token_use: String,
}

/// Keyora's answer to an introspection request.
#[derive(Debug, Deserialize)]
pub struct Introspection {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

/// Keyora could not be reached or gave an unusable answer.
#[derive(Debug)]
pub struct Unavailable(String);

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
pub enum TokenError {
    /// The token is genuine but past its `exp`. The client should refresh and retry.
    Expired,
    /// The token failed any other check, or the signing keys could not be fetched.
    /// The reason is for the server log, not for the HTTP response.
    Invalid(String),
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

pub struct Keyora {
    config: Config,
    http: reqwest::Client,
    validation: Validation,
    jwks: RwLock<JwksCache>,
}

impl Keyora {
    pub fn new(config: Config) -> Self {
        // Checks 1, 3, 4 and 5 from examples/README.md are configured here once.
        // The algorithm is fixed to RS256: the token's own `alg` header is never
        // used to pick one, which is what "alg: none" and RS256/HS256 confusion
        // attacks rely on.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&config.issuer]);
        // Without the audience check, a token issued to any other application
        // on the same Keyora would be accepted here.
        validation.set_audience(&[&config.client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        // The library's default tolerates 60 seconds of clock skew, which would
        // double the life of a 60-second token. Two seconds is enough for two
        // machines with synchronised clocks: without any, a token issued this
        // very second is refused as "not valid yet" whenever this machine's
        // clock is a few milliseconds behind Keyora's.
        validation.leeway = 2;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("HTTP client");
        Self { config, http, validation, jwks: RwLock::default() }
    }

    // --- REST calls (server side only: they carry the client secret) --------

    /// POST a JSON body to Keyora. Returns the status and the `{data|error, meta}`
    /// envelope, or `None` for an empty body (204 on logout).
    pub async fn post(&self, path: &str, body: &Value) -> Result<(u16, Option<Map<String, Value>>), Unavailable> {
        let res = self
            .http
            .post(format!("{}{}", self.config.url, path))
            // HTTP Basic with client_id:client_secret identifies this application to Keyora.
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .json(body)
            .send()
            .await
            // Not `e.to_string()` alone: reqwest's message names the URL but not the cause.
            .map_err(|e| Unavailable(format!("{e:?}")))?;
        let status = res.status().as_u16();
        let raw = res.bytes().await.map_err(|e| Unavailable(e.to_string()))?;
        if raw.is_empty() {
            return Ok((status, None));
        }
        match serde_json::from_slice(&raw) {
            Ok(Value::Object(envelope)) => Ok((status, Some(envelope))),
            _ => Err(Unavailable(format!("unexpected response from keyora (status {status})"))),
        }
    }

    /// Ask Keyora for the live state of an access token.
    pub async fn introspect(&self, token: &str) -> Result<Introspection, Unavailable> {
        let (status, envelope) = self.post("/api/v1/auth/introspect", &json!({ "token": token })).await?;
        let data = envelope.and_then(|mut e| e.remove("data")).filter(|_| status == 200);
        data.and_then(|d| serde_json::from_value(d).ok())
            .ok_or_else(|| Unavailable(format!("introspection failed with status {status}")))
    }

    // --- Local verification (no call to Keyora per request) -----------------

    /// Verify an access token and return its claims.
    pub async fn verify_token(&self, token: &str) -> Result<Claims, TokenError> {
        let invalid = |reason: String| TokenError::Invalid(reason);

        // The header is read before the signature is checked, so it is untrusted.
        // It is used for one thing only: to choose which of Keyora's keys to try.
        let header = decode_header(token).map_err(|e| invalid(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| invalid("the token has no key ID".into()))?;
        let key = self.signing_key(&kid).await.map_err(invalid)?;

        // Signature first, then exp, iss and aud, with the rules set up in `new`.
        let claims = decode::<Claims>(token, &key, &self.validation)
            .map_err(|e| match e.kind() {
                ErrorKind::ExpiredSignature => TokenError::Expired,
                _ => invalid(e.to_string()),
            })?
            .claims;

        // Keyora signs OIDC ID tokens with the same key, issuer and audience.
        // An ID token says who signed in; it is not a permission to call an API
        // and carries no session that could be revoked. Only access tokens pass.
        if claims.token_use != "access" {
            return Err(invalid(format!("token_use is {:?}, not \"access\"", claims.token_use)));
        }
        Ok(claims)
    }

    /// The public key with the given key ID, from the cache or from Keyora.
    async fn signing_key(&self, kid: &str) -> Result<DecodingKey, String> {
        {
            let cache = self.jwks.read().await;
            let fresh = cache.fetched_at.is_some_and(|t| t.elapsed() < JWKS_TTL);
            if let (true, Some(key)) = (fresh, cache.keys.get(kid)) {
                return Ok(key.clone());
            }
        }

        // The key ID is unknown (Keyora may have rotated its keys) or the cache
        // is old: fetch once. The write lock makes concurrent requests wait for
        // this fetch instead of starting their own.
        let mut cache = self.jwks.write().await;
        let recently_tried = cache.last_attempt.is_some_and(|t| t.elapsed() < JWKS_COOLDOWN);
        if !recently_tried {
            cache.last_attempt = Some(Instant::now());
            match self.fetch_jwks().await {
                Ok(keys) => {
                    cache.keys = keys;
                    cache.fetched_at = Some(Instant::now());
                }
                // Keep the keys already cached: tokens stay verifiable while Keyora is down.
                Err(e) => eprintln!("fetching the JWKS failed: {e}"),
            }
        }
        cache.keys.get(kid).cloned().ok_or_else(|| format!("no signing key with key ID {kid:?}"))
    }

    async fn fetch_jwks(&self) -> Result<HashMap<String, DecodingKey>, String> {
        let url = format!("{}/.well-known/jwks.json", self.config.url);
        let res = self.http.get(url).send().await.map_err(|e| format!("{e:?}"))?;
        let res = res.error_for_status().map_err(|e| e.to_string())?;
        let set: JwkSet = res.json().await.map_err(|e| e.to_string())?;
        Ok(set
            .keys
            .into_iter()
            .filter(|k| k.kty == "RSA" && !k.kid.is_empty())
            .filter_map(|k| Some((k.kid, DecodingKey::from_rsa_components(&k.n, &k.e).ok()?)))
            .collect())
    }
}
