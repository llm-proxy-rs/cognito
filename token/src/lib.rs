use anyhow::Result;
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

    pub fn build(&self) -> Result<reqwest::RequestBuilder> {
        if self.client_id.is_empty()
            || self.client_secret.is_empty()
            || self.domain.is_empty()
            || self.redirect_uri.is_empty()
            || self.region.is_empty()
        {
            anyhow::bail!(
                "client_id, client_secret, domain, redirect_uri, and region must not be empty"
            );
        }

        let url = format!(
            "https://{}.auth.{}.amazoncognito.com/oauth2/token",
            self.domain, self.region
        );

        let basic = STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));

        Ok(reqwest::Client::new()
            .post(url)
            .header("Authorization", format!("Basic {}", basic))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[
                ("code_verifier", &self.code_verifier),
                ("code", &self.code),
                ("grant_type", &"authorization_code".to_string()),
                ("redirect_uri", &self.redirect_uri),
            ]))
    }
}
