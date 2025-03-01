use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use rand::RngCore;
use url::Url;

pub struct AuthorizeUrlBuilder {
    pub client_id: String,
    pub code_challenge: PkceCodeChallenge,
    pub csrf_token: CsrfToken,
    pub nonce: String,
    pub pkce_code_verifier: PkceCodeVerifier,
    pub redirect_uri: String,
    pub region: String,
    pub user_pool_id: String,
}

impl Default for AuthorizeUrlBuilder {
    fn default() -> Self {
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut data = [0u8; 8];
        rand::rng().fill_bytes(&mut data);
        let nonce = URL_SAFE_NO_PAD.encode(data);

        Self {
            client_id: String::new(),
            code_challenge: pkce_code_challenge,
            csrf_token: CsrfToken::new_random(),
            nonce,
            pkce_code_verifier,
            redirect_uri: String::new(),
            region: String::new(),
            user_pool_id: String::new(),
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

    pub fn region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn user_pool_id(mut self, user_pool_id: &str) -> Self {
        self.user_pool_id = user_pool_id.to_string();
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

    pub fn build(self) -> Result<(Url, CsrfToken, String, PkceCodeVerifier)> {
        let mut url = Url::parse(&format!(
            "https://{}.auth.{}.amazoncognito.com/oauth2/authorize",
            self.user_pool_id, self.region
        ))?;

        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", self.code_challenge.as_str())
            .append_pair("nonce", &self.nonce)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email")
            .append_pair("state", self.csrf_token.secret());

        Ok((url, self.csrf_token, self.nonce, self.pkce_code_verifier))
    }
}
