use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Default)]
pub struct TokenRequestBuilder {
    pub client_id: String,
    pub client_secret: String,
    pub code_verifier: String,
    pub code: String,
    pub domain: String,
    pub redirect_uri: String,
    pub region: String,
}

impl TokenRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = client_id.to_string();
        self
    }

    pub fn client_secret(mut self, client_secret: &str) -> Self {
        self.client_secret = client_secret.to_string();
        self
    }

    pub fn code(mut self, code: &str) -> Self {
        self.code = code.to_string();
        self
    }

    pub fn code_verifier(mut self, code_verifier: &str) -> Self {
        self.code_verifier = code_verifier.to_string();
        self
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub fn redirect_uri(mut self, redirect_uri: &str) -> Self {
        self.redirect_uri = redirect_uri.to_string();
        self
    }

    pub fn region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn build(self) -> Result<reqwest::RequestBuilder> {
        if self.client_id.is_empty()
            || self.client_secret.is_empty()
            || self.domain.is_empty()
            || self.redirect_uri.is_empty()
            || self.region.is_empty()
        {
            bail!("client_id, client_secret, domain, redirect_uri, and region must not be empty");
        }

        let url = format!(
            "https://{}.auth.{}.amazoncognito.com/oauth2/token",
            self.domain, self.region
        );

        let basic = STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));

        let grant_type = "authorization_code".to_string();
        let form_params = vec![
            ("code_verifier", &self.code_verifier),
            ("code", &self.code),
            ("grant_type", &grant_type),
            ("redirect_uri", &self.redirect_uri),
        ];

        Ok(reqwest::Client::new()
            .post(url)
            .header("Authorization", format!("Basic {}", basic))
            .form(&form_params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_builder() -> TokenRequestBuilder {
        TokenRequestBuilder::new()
            .client_id("test-client")
            .client_secret("test-secret")
            .domain("mypool")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .code("auth-code-123")
    }

    #[test]
    fn build_succeeds_with_all_required_fields() {
        let result = base_builder().build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_succeeds_without_code_verifier() {
        let result = base_builder().build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_succeeds_with_code_verifier() {
        let result = base_builder().code_verifier("pkce-verifier").build();
        assert!(result.is_ok());
    }

    #[test]
    fn build_fails_when_client_id_empty() {
        let result = TokenRequestBuilder::new()
            .client_secret("test-secret")
            .domain("mypool")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .code("auth-code")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_client_secret_empty() {
        let result = TokenRequestBuilder::new()
            .client_id("test-client")
            .domain("mypool")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .code("auth-code")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_domain_empty() {
        let result = TokenRequestBuilder::new()
            .client_id("test-client")
            .client_secret("test-secret")
            .region("us-east-1")
            .redirect_uri("https://example.com/callback")
            .code("auth-code")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_region_empty() {
        let result = TokenRequestBuilder::new()
            .client_id("test-client")
            .client_secret("test-secret")
            .domain("mypool")
            .redirect_uri("https://example.com/callback")
            .code("auth-code")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn build_fails_when_redirect_uri_empty() {
        let result = TokenRequestBuilder::new()
            .client_id("test-client")
            .client_secret("test-secret")
            .domain("mypool")
            .region("us-east-1")
            .code("auth-code")
            .build();
        assert!(result.is_err());
    }
}
