use anyhow::Result;
use jsonwebtoken::{Algorithm, Validation};

#[derive(Default)]
pub struct ValidationBuilder {
    client_id: String,
    region: String,
    user_pool_id: String,
}

impl ValidationBuilder {
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

    pub fn build(self) -> Result<Validation> {
        if self.client_id.is_empty() || self.region.is_empty() || self.user_pool_id.is_empty() {
            anyhow::bail!("client_id, region, and user_pool_id must not be empty");
        }

        let issuer = format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            self.region, self.user_pool_id
        );
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[&issuer]);
        validation.set_required_spec_claims(&["aud", "exp", "iss"]);
        Ok(validation)
    }
}
