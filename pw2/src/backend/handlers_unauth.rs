//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use crate::database::{token, user};
use crate::email::send_mail;
use crate::utils::input::{TextualContent, UserEmail};
use crate::utils::webauthn::{begin_authentication, begin_registration, complete_authentication, complete_registration, CREDENTIAL_STORE};
use crate::HBS;
use axum::{
    extract::{Json, Path, Query},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use log::{debug, error};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tower_sessions::Session;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential};

/// Stockage des états d'enregistrement et d'authentification
pub(crate) static REGISTRATION_STATES: Lazy<RwLock<HashMap<String, PasskeyRegistration>>> = Lazy::new(Default::default);
static AUTHENTICATION_STATES: Lazy<RwLock<HashMap<String, PasskeyAuthentication>>> = Lazy::new(Default::default);

/// Ensures that the webauthn is aware of the user's, if it is stored in the database.
async fn ensure_store_contains_known_user_passkey(email: &str) {
    let mut store = CREDENTIAL_STORE.write().await;
    if store.get(email).is_none() {
        if let Ok(Some(passkey)) = user::get_passkey(email) {
            store.insert(email.to_string(), passkey);
        } else {
            debug!("No passkey found for user {}", email);
        }
    }
}

/// Début du processus d'enregistrement WebAuthn
pub async fn register_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .and_then(UserEmail::try_new)
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    // Ensure the user's passkey is loaded if present in the database
    ensure_store_contains_known_user_passkey(email.as_ref()).await;

    // NOTE: the way reset_mode works here introduces a security vulnerability where anyone can
    //       reset the passkey of anyone without going through the recovery token process. This
    //       allows anyone to steal anyone's account.
    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);
    match (reset_mode, user::exists(email.as_ref())) {
        (true, Ok(true)) => (), // If reset mode is enabled, then the use must exist
        (false, Ok(false)) => (), // If reset mode is disabled, then the user must not exist
        (_, _) => return Err((StatusCode::BAD_REQUEST, "Invalid registration request").into()), // Otherwise, it's invalid
    }

    let state_id = Uuid::new_v4();
    let (pk, registration_state) = begin_registration(email.as_ref(), email.as_ref())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start registration"))?;

    // Save the registration state
    REGISTRATION_STATES
        .write()
        .await
        .insert(state_id.into(), registration_state);

    Ok(Json(json!({
        "publicKey": pk,
        "state_id": state_id,
    })))
}

/// Fin du processus d'enregistrement WebAuthn
pub async fn register_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .and_then(UserEmail::try_new)
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);

    let first_name = payload
        .get("first_name")
        .and_then(Value::as_str)
        .and_then(TextualContent::try_new_short_form_content)
        .ok_or((StatusCode::BAD_REQUEST, "First name is required"))?;
    let last_name = payload
        .get("last_name")
        .and_then(Value::as_str)
        .and_then(TextualContent::try_new_short_form_content)
        .ok_or((StatusCode::BAD_REQUEST, "Last name is required"))?;

    // Fetch the saved state
    let state_id = payload
        .get("state_id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or((StatusCode::BAD_REQUEST, "Invalid request parameters"))?;
    let stored_state = {
        let mut states = REGISTRATION_STATES.write().await;
        states
            .remove(state_id.to_string().as_str())
            .ok_or((StatusCode::BAD_REQUEST, "Invalid registration session"))?
    };

    let cred = payload
        .get("response")
        .and_then(|v| serde_json::from_value::<RegisterPublicKeyCredential>(v.clone()).ok())
        .ok_or((StatusCode::BAD_REQUEST, "Invalid response"))?;

    // Complete the registration
    complete_registration(email.as_ref(), &cred, &stored_state)
        .await
        .map_err(|_| (StatusCode::FORBIDDEN, "Failed to complete registration"))?;

    let passkey = CREDENTIAL_STORE.read().await.get(email.as_ref()).unwrap().clone();

    if !reset_mode {
        user::create(email.as_ref(), first_name.as_ref(), last_name.as_ref())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to complete registration"))?;

        if let Ok(verification_token) = token::generate(email.as_ref()) {
            // Send verification email
            if let Err(_) = send_mail(
                email.as_ref(),
                "Verify your account",
                &format!(
                    "Welcome! Please verify your account by clicking this link: http://localhost:8080/validate/{}",
                    verification_token
                ),
            ) {
                // Log error but don't fail the registration
                error!("Failed to send verification email to {}", email.as_ref());
            }
        }
    }

    user::set_passkey(email.as_ref(), passkey)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to complete registration"))?;

    Ok(StatusCode::OK)
}

/// Début du processus d'authentification WebAuthn
pub async fn login_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .and_then(UserEmail::try_new)
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    // Ensure the user's passkey is loaded if present in the database
    ensure_store_contains_known_user_passkey(email.as_ref()).await;

    // Check user exists and is verified before starting authentication
    match user::get(email.as_ref()) {
        Some(user_data) if !user_data.verified => Err((StatusCode::BAD_REQUEST, "Invalid authentication request"))?,
        None => Err((StatusCode::BAD_REQUEST, "Invalid authentication request"))?,
        Some(_) => {} // User exists and is verified, continue with authentication
    }

    let state_id = Uuid::new_v4();
    let (pk, state) = begin_authentication(email.as_ref())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start authentication"))?;

    // Save the authn state
    AUTHENTICATION_STATES
        .write()
        .await
        .insert(state_id.into(), state);

    Ok(Json(json!({
        "publicKey": pk,
        "state_id": state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(
    session: Session,
    Json(payload): Json<serde_json::Value>,
) -> axum::response::Result<Redirect> {
    let response = payload.get("response").ok_or_else(|| (StatusCode::BAD_REQUEST, "Response is required"))?;
    let state_id = payload.get("state_id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "State ID is required"))?;

    let cred: PublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response"))?;

    // Fetch the saved state
    let stored_state = {
        let mut states = AUTHENTICATION_STATES.write().await;
        states
            .remove(state_id.to_string().as_str())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Invalid authentication session"))?
    };

    // Complete the authentication
    complete_authentication(&cred, &stored_state)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to complete authentication"))?;

    // Update the session to indicate the user is authenticated
    session
        .insert("authenticated", true)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to set session"))?;

    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout(session: Session) -> impl IntoResponse {
    session.delete();
    Redirect::to("/")
}

/// Valide un compte utilisateur via un token
pub async fn validate_account(Path(token): Path<String>) -> impl IntoResponse {
    match token::consume(&token) {
        Ok(email) => match user::verify(&email) {
            Ok(_) => Redirect::to("/login?validated=true"),
            Err(_) => Redirect::to("/register?error=validation_failed"),
        },
        Err(_) => Redirect::to("/register?error=invalid_token"),
    }
}

/// Envoie un email de récupération de compte à l'utilisateur
pub async fn recover_account(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Html<String>> {
    let email = payload
        .get("email")
        .and_then(Value::as_str)
        .and_then(UserEmail::try_new)
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    match user::get(email.as_ref()) {
        // The user needs to have verified their email
        Some(user) if user.verified => {
            // Generate recovery token
            let recovery_token = token::generate(email.as_ref())
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error."))?;

            // Send recovery email
            let recovery_link = format!("http://localhost:8080/recover/{}", recovery_token);
            if let Err(_) = send_mail(
                email.as_ref(),
                "Account Recovery",
                &format!(
                    "Click the following link to recover your account: {}\n\n\
                     If you did not request this recovery, you can safely ignore this email.",
                    recovery_link
                ),
            ) {
                error!("Failed to send recovery email to {}", email.as_ref());
            }
        }
        _ => (),
    }

    // For security, we always return success even if the email doesn't exist so that the database
    // cannot be enumerated by checking if an email is valid or not.
    HBS.render("recover", &json!({"success": true}))
        .map(Html)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.").into())
}

/// Gère la réinitialisation du compte utilisateur via un token de récupération
pub async fn reset_account(Path(token): Path<String>) -> Html<String> {
    match token::consume(&token) {
        Ok(email) => {
            let redirect_url = format!("/register?reset_mode=true&email={}&success=true", email);
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
        Err(_) => {
            let redirect_url = "/register?error=recovery_failed";
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
    }
}

/// --- Affichage des pages ---
///
/// Affiche la page d'accueil
pub async fn index(session: tower_sessions::Session) -> impl IntoResponse {
    let is_logged_in = session.get::<bool>("authenticated").unwrap_or_default().is_some();
    let mut data = HashMap::new();
    data.insert("authenticated", is_logged_in);

    HBS.render("index", &data)
        .map(Html)
        .unwrap_or_else(|_| Html("Internal Server Error".to_string()))
}

/// Affiche la page de connexion
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../../templates/login.hbs"))
}

/// Affiche la page d'inscription avec des messages contextuels si présents
pub async fn register_page(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut context = HashMap::new();
    if let Some(success) = params.get("success") {
        if success == "true" {
            context.insert("success_message", "Account recovery successful. Please reset your passkey.");
        }
    }
    if let Some(error) = params.get("error") {
        if error == "recovery_failed" {
            context.insert("error_message", "Invalid or expired recovery link. Please try again.");
        }
    }

    HBS.render("register", &context)
        .map(Html)
        .unwrap_or_else(|_| Html("<h1>Internal Server Error</h1>".to_string()))
}

/// Affiche la page de récupération de compte
pub async fn recover_page() -> impl IntoResponse {
    Html(include_str!("../../templates/recover.hbs"))
}
