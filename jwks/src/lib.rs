use anyhow::Result;
use jsonwebtoken::DecodingKey;

#[derive(serde::Deserialize)]
pub struct Jwks {
    pub keys: Vec<Key>,
}

#[derive(serde::Deserialize, Clone)]
pub struct Key {
    pub alg: String,
    pub e: String,
    pub kid: String,
    pub kty: String,
    pub n: String,
    pub r#use: String,
}

#[derive(Default)]
pub struct JwksBuilder {
    pub region: String,
    pub user_pool_id: String,
}

impl JwksBuilder {
    pub fn region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn user_pool_id(mut self, user_pool_id: &str) -> Self {
        self.user_pool_id = user_pool_id.to_string();
        self
    }

    pub async fn build(self) -> Result<Jwks> {
        if self.region.is_empty() || self.user_pool_id.is_empty() {
            anyhow::bail!("region and user_pool_id must not be empty");
        }

        let url = format!(
            "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
            self.region, self.user_pool_id
        );
        let response = reqwest::get(&url).await?;
        let jwks: Jwks = response.json().await?;
        Ok(jwks)
    }
}

impl Jwks {
    pub fn builder() -> JwksBuilder {
        JwksBuilder::default()
    }

    pub fn find_jwk(&self, kid: &str) -> Option<Key> {
        self.keys.iter().find(|key| key.kid == kid).cloned()
    }
}

pub fn jwk_to_decoding_key(jwk: &Key) -> Result<DecodingKey> {
    Ok(DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?)
}
