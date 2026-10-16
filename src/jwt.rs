use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::ValueEnum;
#[cfg(feature = "crypto-verify")]
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    #[value(name = "eddsa", alias = "ed-dsa")]
    EdDSA,
}

impl std::fmt::Display for JwtAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::EdDSA => "EdDSA",
        })
    }
}

#[cfg(feature = "crypto-verify")]
impl From<JwtAlgorithm> for Algorithm {
    fn from(value: JwtAlgorithm) -> Self {
        match value {
            JwtAlgorithm::HS256 => Self::HS256,
            JwtAlgorithm::HS384 => Self::HS384,
            JwtAlgorithm::HS512 => Self::HS512,
            JwtAlgorithm::RS256 => Self::RS256,
            JwtAlgorithm::RS384 => Self::RS384,
            JwtAlgorithm::RS512 => Self::RS512,
            JwtAlgorithm::PS256 => Self::PS256,
            JwtAlgorithm::PS384 => Self::PS384,
            JwtAlgorithm::PS512 => Self::PS512,
            JwtAlgorithm::ES256 => Self::ES256,
            JwtAlgorithm::ES384 => Self::ES384,
            JwtAlgorithm::EdDSA => Self::EdDSA,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtReport {
    pub header: Value,
    pub payload: Value,
    pub signature: SignatureInfo,
    pub time_claims: Vec<TimeClaim>,
    pub security_notes: Vec<SecurityNote>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureInfo {
    pub present: bool,
    pub encoded_length: usize,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeClaim {
    pub name: String,
    pub unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityNote {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtVerifyReport {
    pub verified: bool,
    pub algorithm: JwtAlgorithm,
    pub header: Value,
    pub payload: Value,
    pub time_claims_validated: bool,
    pub audience_validated: bool,
    pub issuer_validated: bool,
}

pub struct JwtVerifyOptions<'a> {
    pub secret: Option<&'a str>,
    pub pem_key: Option<&'a [u8]>,
    pub validate_time: bool,
    pub leeway: u64,
    pub audience: &'a [String],
    pub issuer: &'a [String],
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::High => "high",
        };
        formatter.write_str(label)
    }
}

pub fn inspect(token: &str) -> Result<JwtReport> {
    let token = token.trim();
    let segments = token.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments[0].is_empty() || segments[1].is_empty() {
        bail!("invalid JWT: expected three compact-serialization segments");
    }

    let header = decode_segment(segments[0], "header")?;
    let payload = decode_segment(segments[1], "payload")?;
    if !header.is_object() {
        bail!("invalid JWT header: expected a JSON object");
    }
    if !payload.is_object() {
        bail!("invalid JWT payload: expected a JSON object");
    }

    let signature = SignatureInfo {
        present: !segments[2].is_empty(),
        encoded_length: segments[2].len(),
        verified: false,
    };
    let time_claims = extract_time_claims(&payload);
    let security_notes = security_notes(&header, &signature);

    Ok(JwtReport {
        header,
        payload,
        signature,
        time_claims,
        security_notes,
    })
}

pub fn verify(
    token: &str,
    algorithm: JwtAlgorithm,
    options: JwtVerifyOptions<'_>,
) -> Result<JwtVerifyReport> {
    #[cfg(feature = "crypto-verify")]
    {
        verify_signature(token, algorithm, options)
    }
    #[cfg(not(feature = "crypto-verify"))]
    {
        let _ = (token, algorithm, options);
        bail!(
            "JWT signature verification is not available in this build (crypto-verify feature disabled)"
        )
    }
}

#[cfg(feature = "crypto-verify")]
fn verify_signature(
    token: &str,
    algorithm: JwtAlgorithm,
    options: JwtVerifyOptions<'_>,
) -> Result<JwtVerifyReport> {
    let token = token.trim();
    let decoding_key = match algorithm {
        JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
            let secret = options.secret.context("HS algorithms require --secret")?;
            if options.pem_key.is_some() {
                bail!("HS algorithms use --secret, not --key");
            }
            DecodingKey::from_secret(secret.as_bytes())
        }
        JwtAlgorithm::RS256
        | JwtAlgorithm::RS384
        | JwtAlgorithm::RS512
        | JwtAlgorithm::PS256
        | JwtAlgorithm::PS384
        | JwtAlgorithm::PS512 => {
            let key = options
                .pem_key
                .context("RSA algorithms require --key with a PEM key")?;
            if options.secret.is_some() {
                bail!("RSA algorithms use --key, not --secret");
            }
            DecodingKey::from_rsa_pem(key).context("invalid RSA public key PEM")?
        }
        JwtAlgorithm::ES256 | JwtAlgorithm::ES384 => {
            let key = options
                .pem_key
                .context("ES algorithms require --key with an EC PEM key")?;
            if options.secret.is_some() {
                bail!("ES algorithms use --key, not --secret");
            }
            DecodingKey::from_ec_pem(key).context("invalid EC public key PEM")?
        }
        JwtAlgorithm::EdDSA => {
            let key = options
                .pem_key
                .context("EdDSA requires --key with an Ed25519 PEM key")?;
            if options.secret.is_some() {
                bail!("EdDSA uses --key, not --secret");
            }
            DecodingKey::from_ed_pem(key).context("invalid EdDSA public key PEM")?
        }
    };

    let mut validation = Validation::new(algorithm.into());
    validation.required_spec_claims.clear();
    validation.validate_exp = options.validate_time;
    validation.validate_nbf = options.validate_time;
    validation.leeway = options.leeway;
    validation.validate_aud = !options.audience.is_empty();
    if !options.audience.is_empty() {
        validation.set_audience(options.audience);
    }
    if !options.issuer.is_empty() {
        validation.set_issuer(options.issuer);
    }
    let data = decode::<Value>(token, &decoding_key, &validation)
        .context("JWT signature verification failed")?;
    if options.validate_time {
        ensure_numeric_time_claims(&data.claims)?;
    }

    Ok(JwtVerifyReport {
        verified: true,
        algorithm,
        header: serde_json::to_value(data.header).context("failed to serialize JWT header")?,
        payload: data.claims,
        time_claims_validated: options.validate_time,
        audience_validated: !options.audience.is_empty(),
        issuer_validated: !options.issuer.is_empty(),
    })
}

/// jsonwebtoken before 10.3.0 skips the `exp` and `nbf` checks when the claim
/// has the wrong JSON type (CVE-2026-25537), so a string `nbf` would pass as
/// "time validated". Refuse such tokens instead of reporting them as valid.
#[cfg(feature = "crypto-verify")]
fn ensure_numeric_time_claims(claims: &Value) -> Result<()> {
    for name in ["exp", "nbf"] {
        if let Some(value) = claims.get(name)
            && value.as_u64().is_none()
        {
            bail!(
                "JWT claim '{name}' is not a non-negative integer, so its time check cannot be trusted"
            );
        }
    }
    Ok(())
}

fn decode_segment(segment: &str, name: &str) -> Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .with_context(|| format!("invalid JWT {name}: segment is not unpadded Base64URL"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JWT {name}: invalid JSON"))
}

fn extract_time_claims(payload: &Value) -> Vec<TimeClaim> {
    ["iat", "nbf", "exp"]
        .into_iter()
        .filter_map(|name| {
            payload
                .get(name)
                .and_then(Value::as_i64)
                .map(|unix_seconds| TimeClaim {
                    name: name.to_owned(),
                    unix_seconds,
                })
        })
        .collect()
}

fn security_notes(header: &Value, signature: &SignatureInfo) -> Vec<SecurityNote> {
    let mut notes = vec![SecurityNote {
        severity: Severity::Info,
        message: "Signature was not verified; inspect only decodes public token data.".to_owned(),
    }];

    let algorithm = header.get("alg").and_then(Value::as_str);
    match algorithm {
        Some("none") => notes.push(SecurityNote {
            severity: Severity::High,
            message: "The token declares alg: none; do not trust it for authentication.".to_owned(),
        }),
        Some(algorithm) => notes.push(SecurityNote {
            severity: Severity::Info,
            message: format!("Declared signing algorithm: {algorithm}."),
        }),
        None => notes.push(SecurityNote {
            severity: Severity::Warning,
            message: "JWT header has no alg field.".to_owned(),
        }),
    }

    if !signature.present {
        notes.push(SecurityNote {
            severity: Severity::High,
            message: "JWT signature segment is empty.".to_owned(),
        });
    }

    notes
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "crypto-verify")]
    use jsonwebtoken::{EncodingKey, Header, encode};
    #[cfg(feature = "crypto-verify")]
    use serde_json::json;

    #[cfg(feature = "crypto-verify")]
    use super::{JwtAlgorithm, JwtVerifyOptions, verify};
    use super::{Severity, inspect};

    #[cfg(feature = "crypto-verify")]
    fn hmac_options<'a>(secret: &'a str, validate_time: bool) -> JwtVerifyOptions<'a> {
        JwtVerifyOptions {
            secret: Some(secret),
            pem_key: None,
            validate_time,
            leeway: 0,
            audience: &[],
            issuer: &[],
        }
    }

    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature";

    #[test]
    fn decodes_header_and_payload() {
        let report = inspect(VALID_TOKEN).expect("valid token");
        assert_eq!(report.header["alg"], "HS256");
        assert_eq!(report.payload["name"], "John Doe");
        assert_eq!(report.time_claims[0].unix_seconds, 1_516_239_022);
        assert!(!report.signature.verified);
    }

    #[test]
    fn flags_unsigned_tokens() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";
        let report = inspect(token).expect("structurally valid unsigned token");
        assert!(
            report
                .security_notes
                .iter()
                .any(|note| matches!(note.severity, Severity::High))
        );
    }

    #[test]
    fn rejects_non_jwt_values() {
        assert!(inspect("not-a-jwt").is_err());
    }

    #[cfg(feature = "crypto-verify")]
    #[test]
    fn verifies_hs256_with_explicit_algorithm() {
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"sub": "123"}),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("encode token");
        let report = verify(
            &token,
            JwtAlgorithm::HS256,
            hmac_options("test-secret", true),
        )
        .expect("valid signature");
        assert!(report.verified);
        assert_eq!(report.payload["sub"], "123");
    }

    #[cfg(feature = "crypto-verify")]
    #[test]
    fn rejects_time_claims_that_are_not_integers() {
        for claims in [
            json!({"sub": "1", "nbf": "99999999999"}),
            json!({"sub": "1", "exp": "99999999999"}),
            json!({"sub": "1", "exp": 4_102_444_800.5}),
            json!({"sub": "1", "nbf": null}),
        ] {
            let token = encode(
                &Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(b"test-secret"),
            )
            .expect("encode token");
            let error = verify(
                &token,
                JwtAlgorithm::HS256,
                hmac_options("test-secret", true),
            )
            .expect_err("malformed time claim must be refused");
            assert!(format!("{error:#}").contains("time check cannot be trusted"));
            // Without time validation the claim is not relied on.
            assert!(
                verify(
                    &token,
                    JwtAlgorithm::HS256,
                    hmac_options("test-secret", false)
                )
                .is_ok()
            );
        }
    }

    #[cfg(feature = "crypto-verify")]
    #[test]
    fn rejects_wrong_hmac_secret() {
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"sub": "123"}),
            &EncodingKey::from_secret(b"correct-secret"),
        )
        .expect("encode token");
        assert!(
            verify(
                &token,
                JwtAlgorithm::HS256,
                hmac_options("wrong-secret", true)
            )
            .is_err()
        );
    }

    #[cfg(feature = "crypto-verify")]
    #[test]
    fn rejects_expired_tokens_unless_time_is_ignored() {
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"sub": "123", "exp": 1}),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("encode token");
        assert!(
            verify(
                &token,
                JwtAlgorithm::HS256,
                hmac_options("test-secret", true)
            )
            .is_err()
        );
        assert!(
            verify(
                &token,
                JwtAlgorithm::HS256,
                hmac_options("test-secret", false)
            )
            .is_ok()
        );
    }

    #[cfg(feature = "crypto-verify")]
    #[test]
    fn validates_expected_audience_and_issuer() {
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &json!({"aud": "banshee", "iss": "local"}),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("encode token");
        let audience = ["banshee".to_owned()];
        let issuer = ["local".to_owned()];
        let report = verify(
            &token,
            JwtAlgorithm::HS256,
            JwtVerifyOptions {
                secret: Some("test-secret"),
                pem_key: None,
                validate_time: true,
                leeway: 0,
                audience: &audience,
                issuer: &issuer,
            },
        )
        .expect("valid claims");
        assert!(report.audience_validated);
        assert!(report.issuer_validated);
    }
}

#[cfg(all(test, not(feature = "crypto-verify")))]
mod no_crypto_tests {
    use super::{JwtAlgorithm, JwtVerifyOptions, verify};

    #[test]
    fn verification_reports_that_it_is_unavailable() {
        let options = JwtVerifyOptions {
            secret: Some("secret"),
            pem_key: None,
            validate_time: true,
            leeway: 0,
            audience: &[],
            issuer: &[],
        };
        let error = verify("a.b.c", JwtAlgorithm::HS256, options)
            .expect_err("no verifier")
            .to_string();
        assert!(error.contains("not available in this build"), "{error}");
    }
}
