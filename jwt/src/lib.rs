use anyhow::Result;
use jsonwebtoken::{TokenData, decode, decode_header};
use jwks::{Jwks, jwk_to_decoding_key};
use serde::Deserialize;
use validation::ValidationBuilder;

#[derive(Deserialize)]
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub token_use: String,
}

fn get_kid_from_jwt(jwt: &str) -> Result<String> {
    let header = decode_header(jwt)?;
    header
        .kid
        .ok_or(anyhow::anyhow!("kid not found in JWT header"))
}

#[derive(Default)]
pub struct JwtDecoder {
    client_id: String,
    region: String,
    user_pool_id: String,
}

impl JwtDecoder {
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

    pub async fn decode(&self, jwt: &str) -> Result<TokenData<Claims>> {
        let kid = get_kid_from_jwt(jwt)?;
        let jwks = Jwks::builder()
            .region(&self.region)
            .user_pool_id(&self.user_pool_id)
            .build()
            .await?;
        let jwk = jwks
            .find_jwk(&kid)
            .ok_or(anyhow::anyhow!("JWK not found"))?;
        let validation = ValidationBuilder::new()
            .client_id(&self.client_id)
            .region(&self.region)
            .user_pool_id(&self.user_pool_id)
            .build();
        let token_data = decode::<Claims>(jwt, &jwk_to_decoding_key(&jwk)?, &validation)?;
        Ok(token_data)
    }
}
