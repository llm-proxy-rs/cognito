use actix_session::Session;
use actix_web::{HttpResponse, web};
use anyhow::Result;
use authorize::AuthorizeUrlBuilder;
use jwt::{JwtDecoder, validate_claims};
use oauth2::PkceCodeVerifier;
use serde::Deserialize;
use token::TokenRequestBuilder;

pub struct AppState {
    pub client_id: String,
    pub client_secret: String,
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct CallbackRequest {
    pub code: String,
    pub state: String,
}

pub async fn login(data: web::Data<AppState>, session: Session) -> Result<HttpResponse> {
    let authorize_url_builder = AuthorizeUrlBuilder::new()
        .client_id(&data.client_id)
        .domain(&data.domain)
        .region(&data.region)
        .redirect_uri(&data.redirect_uri);
    let (authorize_url, csrf_token, nonce, pkce_code_verifier) = authorize_url_builder.build()?;
    session.insert("csrf_token", csrf_token)?;
    session.insert("nonce", nonce)?;
    session.insert("pkce_code_verifier", pkce_code_verifier)?;
    Ok(HttpResponse::Found()
        .append_header(("Location", authorize_url.to_string()))
        .finish())
}

pub async fn callback(
    data: web::Data<AppState>,
    session: Session,
    web::Query(info): web::Query<CallbackRequest>,
) -> Result<HttpResponse> {
    let csrf_token: String = session
        .get("csrf_token")?
        .ok_or_else(|| anyhow::anyhow!("CSRF token not found in session"))?;
    if info.state != csrf_token {
        anyhow::bail!("Invalid state: CSRF token does not match");
    }
    let pkce_code_verifier = session
        .get::<PkceCodeVerifier>("pkce_code_verifier")?
        .ok_or_else(|| anyhow::anyhow!("PKCE code verifier not found in session"))?;
    let code_verifier = pkce_code_verifier.secret();
    let res = TokenRequestBuilder::new()
        .client_id(&data.client_id)
        .client_secret(&data.client_secret)
        .code_verifier(code_verifier)
        .code(&info.code)
        .domain(&data.domain)
        .redirect_uri(&data.redirect_uri)
        .region(&data.region)
        .build()
        .send()
        .await?;
    let json: serde_json::Value = res.json().await?;
    let id_token = json["id_token"].as_str().unwrap();
    let token_data = JwtDecoder::new()
        .client_id(&data.client_id)
        .region(&data.region)
        .user_pool_id(&data.user_pool_id)
        .decode(id_token)
        .await?;
    let claims = &token_data.claims;
    let nonce = session
        .remove_as::<String>("nonce")
        .ok_or_else(|| anyhow::anyhow!("Nonce not found in session"))?
        .map_err(anyhow::Error::msg)?;
    let issued_threshold = chrono::Duration::minutes(5);
    validate_claims(claims, &nonce, issued_threshold)?;
    session.insert("email", claims.email.clone())?;
    session.insert("sub", claims.sub.clone())?;
    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish())
}
