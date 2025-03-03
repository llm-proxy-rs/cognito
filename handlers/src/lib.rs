use anyhow::Result;
use authorize::AuthorizeUrlBuilder;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use jwt::{JwtDecoder, validate_claims};
use oauth2::PkceCodeVerifier;
use serde::Deserialize;
use token::TokenRequestBuilder;
use tower_sessions::Session;

#[derive(Clone)]
pub struct AppState {
    pub client_id: String,
    pub client_secret: String,
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn login(session: Session, State(state): State<AppState>) -> Result<Response> {
    let authorize_url_builder = AuthorizeUrlBuilder::new()
        .client_id(&state.client_id)
        .domain(&state.domain)
        .region(&state.region)
        .redirect_uri(&state.redirect_uri);
    let (authorize_url, csrf_token, nonce, pkce_code_verifier) = authorize_url_builder.build()?;
    session.insert("csrf_token", &csrf_token).await?;
    session.insert("nonce", &nonce).await?;
    session
        .insert("pkce_code_verifier", &pkce_code_verifier)
        .await?;
    Ok(Redirect::to(authorize_url.as_str()).into_response())
}

pub async fn callback(
    Query(query): Query<CallbackQuery>,
    session: Session,
    State(state): State<AppState>,
) -> Result<Response> {
    let csrf_token: String = session
        .get("csrf_token")
        .await?
        .ok_or_else(|| anyhow::anyhow!("CSRF token not found in session"))?;
    if query.state != csrf_token {
        anyhow::bail!("Invalid state: CSRF token does not match");
    }
    let pkce_code_verifier = session
        .get::<PkceCodeVerifier>("pkce_code_verifier")
        .await?
        .ok_or_else(|| anyhow::anyhow!("PKCE code verifier not found in session"))?;
    let code_verifier = pkce_code_verifier.secret();
    let res = TokenRequestBuilder::new()
        .client_id(&state.client_id)
        .client_secret(&state.client_secret)
        .code_verifier(code_verifier)
        .code(&query.code)
        .domain(&state.domain)
        .redirect_uri(&state.redirect_uri)
        .region(&state.region)
        .build()?
        .send()
        .await?;
    let json: serde_json::Value = res.json().await?;
    let id_token = json["id_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("ID token not found"))?;
    let token_data = JwtDecoder::new()
        .client_id(&state.client_id)
        .region(&state.region)
        .user_pool_id(&state.user_pool_id)
        .decode(id_token)
        .await?;
    let claims = &token_data.claims;
    let nonce = session
        .remove::<String>("nonce")
        .await?
        .ok_or_else(|| anyhow::anyhow!("Nonce not found in session"))?;
    let issued_threshold = chrono::Duration::minutes(5);
    validate_claims(claims, &nonce, issued_threshold)?;
    session.insert("email", &claims.email).await?;
    session.insert("sub", &claims.sub).await?;
    Ok(Redirect::to("/").into_response())
}
