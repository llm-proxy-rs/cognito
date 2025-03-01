use actix_session::Session;
use actix_web::{HttpResponse, Responder, web};
use anyhow::Result;
use authorize::AuthorizeUrlBuilder;
use jwt::JwtDecoder;
use oauth2::PkceCodeVerifier;
use token::TokenRequestBuilder;

pub struct AppState {
    pub client_id: String,
    pub client_secret: String,
    pub region: String,
    pub user_pool_id: String,
    pub redirect_uri: String,
}

pub struct CallbackRequest {
    pub code: String,
    pub state: String,
}

pub async fn login(data: web::Data<AppState>, session: Session) -> Result<impl Responder> {
    let authorize_url_builder = AuthorizeUrlBuilder::new()
        .client_id(&data.client_id)
        .region(&data.region)
        .user_pool_id(&data.user_pool_id)
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
    web::Query(info): web::Query<CallbackRequest>,
    data: web::Data<AppState>,
    session: Session,
) -> Result<impl Responder> {
    let pkce_code_verifier = session
        .get::<PkceCodeVerifier>("pkce_code_verifier")?
        .ok_or_else(|| anyhow::anyhow!("PKCE code verifier not found in session"))?;
    let code_verifier = pkce_code_verifier.secret();
    let res = TokenRequestBuilder::new()
        .client_id(&data.client_id)
        .client_secret(&data.client_secret)
        .code_verifier(code_verifier)
        .code(&info.code)
        .redirect_uri(&data.redirect_uri)
        .user_pool_id(&data.user_pool_id)
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
    let _claims = token_data.claims;
    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish())
}
