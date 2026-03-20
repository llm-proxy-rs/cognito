use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use rand::Rng;
use url::Url;

pub struct AuthorizeUrlBuilder {
    pub client_id: String,
    pub code_challenge: PkceCodeChallenge,
    pub csrf_token: CsrfToken,
    pub domain: String,
    pub identity_provider: Option<String>,
    pub nonce: String,
    pub pkce_code_verifier: PkceCodeVerifier,
    pub redirect_uri: String,
    pub region: String,
}

impl Default for AuthorizeUrlBuilder {
    fn default() -> Self {
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut data = [0u8; 16];
        rand::rng().fill_bytes(&mut data);
        let nonce = URL_SAFE_NO_PAD.encode(data);

        Self {
            client_id: String::new(),
            code_challenge: pkce_code_challenge,
            csrf_token: CsrfToken::new_random(),
            domain: String::new(),
            identity_provider: None,
            nonce,
            pkce_code_verifier,
            redirect_uri: String::new(),
            region: String::new(),
        }
    }
}

impl AuthorizeUrlBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = client_id.to_string();
        self
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub fn region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = nonce.to_string();
        self
    }

    pub fn redirect_uri(mut self, redirect_uri: &str) -> Self {
        self.redirect_uri = redirect_uri.to_string();
        self
    }

    pub fn identity_provider(mut self, identity_provider: &str) -> Self {
        self.identity_provider = Some(identity_provider.to_string());
        self
    }

    pub fn build(self) -> Result<(Url, CsrfToken, String, PkceCodeVerifier)> {
        if self.client_id.is_empty()
            || self.domain.is_empty()
            || self.redirect_uri.is_empty()
            || self.region.is_empty()
        {
            bail!("client_id, domain, redirect_uri, and region must not be empty");
        }

        let base = format!(
            "https://{}.auth.{}.amazoncognito.com/oauth2/authorize",
            self.domain, self.region
        );
        let mut params = vec![
            ("client_id", self.client_id.as_str()),
            ("code_challenge_method", "S256"),
            ("code_challenge", self.code_challenge.as_str()),
            ("nonce", &self.nonce),
            ("redirect_uri", &self.redirect_uri),
            ("response_type", "code"),
            ("scope", "openid email"),
            ("state", self.csrf_token.secret()),
        ];
        if let Some(ref idp) = self.identity_provider {
            params.push(("identity_provider", idp));
        }
        let url = Url::parse_with_params(&base, &params)?;

        Ok((url, self.csrf_token, self.nonce, self.pkce_code_verifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_builder() -> AuthorizeUrlBuilder {
        AuthorizeUrlBuilder::new()
            .client_id("test-client")
            .domain("mypool")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
    }

    #[test]
    fn build_produces_valid_cognito_url() {
        let (url, _csrf, _nonce, _pkce) = base_builder().build().unwrap();
        assert_eq!(
            url.origin().unicode_serialization(),
            "https://mypool.auth.us-east-1.amazoncognito.com"
        );
        assert_eq!(url.path(), "/oauth2/authorize");
    }

    #[test]
    fn build_includes_required_query_params() {
        let (url, csrf, nonce, _pkce) = base_builder().build().unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs["client_id"], "test-client");
        assert_eq!(pairs["redirect_uri"], "https://example.com/callback");
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["scope"], "openid email");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["state"], csrf.secret().as_str());
        assert_eq!(pairs["nonce"], nonce.as_str());
        assert!(!pairs.contains_key("identity_provider"));
    }

    #[test]
    fn build_includes_identity_provider_when_set() {
        let (url, ..) = base_builder().identity_provider("PoolA").build().unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs["identity_provider"], "PoolA");
    }

    #[test]
    fn build_omits_identity_provider_when_not_set() {
        let (url, ..) = base_builder().build().unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert!(!pairs.contains_key("identity_provider"));
    }

    #[test]
    fn build_fails_when_client_id_empty() {
        let result = AuthorizeUrlBuilder::new()
            .domain("mypool")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_domain_empty() {
        let result = AuthorizeUrlBuilder::new()
            .client_id("test-client")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_region_empty() {
        let result = AuthorizeUrlBuilder::new()
            .client_id("test-client")
            .domain("mypool")
            .redirect_uri("https://example.com/callback")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_redirect_uri_empty() {
        let result = AuthorizeUrlBuilder::new()
            .client_id("test-client")
            .domain("mypool")
            .region("us-east-1")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn nonce_override_is_used() {
        let (url, ..) = base_builder().nonce("custom-nonce").build().unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(pairs["nonce"], "custom-nonce");
    }
}
