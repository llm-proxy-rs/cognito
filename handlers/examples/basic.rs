use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{App, HttpResponse, HttpServer, cookie::Key, get, web};
use anyhow::Result;
use dotenv::dotenv;
use handlers::{AppState, CallbackRequest};
use std::env;
use std::fmt;
use tracing::info;

#[derive(Debug)]
pub struct AppError(anyhow::Error);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status_code = if self.0.to_string().contains("Streaming is required") {
            actix_web::http::StatusCode::BAD_REQUEST
        } else {
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        };

        HttpResponse::build(status_code)
            .content_type("text/plain; charset=utf-8")
            .body(format!("Error: {}", self.0))
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

#[get("/")]
async fn index(session: actix_session::Session) -> Result<HttpResponse, AppError> {
    let email = session.get::<String>("email").map_err(AppError::from)?;

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

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html))
}

#[get("/logout")]
async fn logout(session: actix_session::Session) -> Result<HttpResponse, AppError> {
    session.purge();

    Ok(HttpResponse::Found()
        .append_header(("Location", "/"))
        .finish())
}

async fn login(
    data: web::Data<AppState>,
    session: actix_session::Session,
) -> Result<HttpResponse, AppError> {
    handlers::login(data, session).await.map_err(AppError::from)
}

async fn callback(
    data: web::Data<AppState>,
    info: web::Query<CallbackRequest>,
    session: actix_session::Session,
) -> Result<HttpResponse, AppError> {
    handlers::callback(data, session, info)
        .await
        .map_err(AppError::from)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    let client_id = env::var("COGNITO_CLIENT_ID").expect("COGNITO_CLIENT_ID must be set");
    let client_secret =
        env::var("COGNITO_CLIENT_SECRET").expect("COGNITO_CLIENT_SECRET must be set");
    let region = env::var("COGNITO_REGION").expect("COGNITO_REGION must be set");
    let user_pool_id = env::var("COGNITO_USER_POOL_ID").expect("COGNITO_USER_POOL_ID must be set");
    let redirect_uri = env::var("COGNITO_REDIRECT_URI").expect("COGNITO_REDIRECT_URI must be set");
    let domain = env::var("COGNITO_DOMAIN").expect("COGNITO_DOMAIN must be set");

    let app_state = web::Data::new(AppState {
        client_id,
        client_secret,
        domain,
        redirect_uri,
        region,
        user_pool_id,
    });

    let secret_key = Key::generate();

    info!("Server running at http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_secure(false)
                    .build(),
            )
            .service(index)
            .service(logout)
            .route("/login", web::get().to(login))
            .route("/callback", web::get().to(callback))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
