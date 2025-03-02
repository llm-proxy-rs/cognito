use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use dotenv::dotenv;
use handlers::{AppState, CallbackQuery};
use std::env;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer, cookie::SameSite};
use tracing::info;

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

async fn index(session: Session) -> Result<Response, AppError> {
    let email = session.get::<String>("email").await?;

    let html = match email {
        Some(email) => format!(
            r#"
            <!DOCTYPE html>
            <html>
            <body>
                <div>
                    <h1>Welcome, {email}!</h1>
                    <a href="/logout">Logout</a>
                </div>
            </body>
            </html>
            "#
        ),
        None => r#"
            <!DOCTYPE html>
            <html>
            <body>
                <div>
                    <a href="/login">Login</a>
                </div>
            </body>
            </html>
        "#
        .to_string(),
    };

    Ok(Html(html).into_response())
}

async fn logout(session: Session) -> Result<Response, AppError> {
    session.delete().await?;
    Ok(Redirect::to("/").into_response())
}

async fn login(session: Session, state: State<AppState>) -> Result<Response, AppError> {
    Ok(handlers::login(session, state).await?)
}

async fn callback(
    info: Query<CallbackQuery>,
    session: Session,
    state: State<AppState>,
) -> Result<Response, AppError> {
    Ok(handlers::callback(info, session, state).await?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    let client_id = env::var("COGNITO_CLIENT_ID").expect("COGNITO_CLIENT_ID must be set");
    let client_secret =
        env::var("COGNITO_CLIENT_SECRET").expect("COGNITO_CLIENT_SECRET must be set");
    let region = env::var("COGNITO_REGION").expect("COGNITO_REGION must be set");
    let user_pool_id = env::var("COGNITO_USER_POOL_ID").expect("COGNITO_USER_POOL_ID must be set");
    let redirect_uri = env::var("COGNITO_REDIRECT_URI").expect("COGNITO_REDIRECT_URI must be set");
    let domain = env::var("COGNITO_DOMAIN").expect("COGNITO_DOMAIN must be set");

    let state = AppState {
        client_id,
        client_secret,
        domain,
        redirect_uri,
        region,
        user_pool_id,
    };

    info!("Server running at http://localhost:8080");

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax);

    let app = Router::new()
        .route("/", get(index))
        .route("/callback", get(callback))
        .route("/login", get(login))
        .route("/logout", get(logout))
        .layer(session_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
