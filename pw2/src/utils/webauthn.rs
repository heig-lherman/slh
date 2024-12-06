//! Gère l'intégration de WebAuthn pour l'enregistrement, l'authentification, et la récupération.
//! Fournit des fonctions pour démarrer et compléter les processus d'enregistrement et d'authentification.
//! Inclut également des mécanismes pour la gestion sécurisée des passkeys et des tokens de récupération.

use std::collections::HashMap;
use anyhow::{Result, Context};
use webauthn_rs::prelude::*;
use once_cell::sync::Lazy;
use url::Url;
use tokio::sync::RwLock;

// TODO ask if tests in rust code

// Initialisation globale de WebAuthn
static WEBAUTHN: Lazy<Webauthn> = Lazy::new(|| {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid RP origin URL");

    WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Failed to initialize WebAuthn")
        .build()
        .expect("Failed to build WebAuthn instance")
});

// Store sécurisé pour les passkeys
pub static CREDENTIAL_STORE: Lazy<RwLock<HashMap<String, Passkey>>> = Lazy::new(Default::default);

// Structure pour stocker l'état d'enregistrement
pub(crate) struct StoredRegistrationState {
    pub registration_state: PasskeyRegistration,
    pub challenge: String,
}

/// Démarrer l'enregistrement WebAuthn
pub async fn begin_registration(
    user_email: &str,
    user_display_name: &str,
) -> Result<(serde_json::Value, PasskeyRegistration)> {
    let user_id = Uuid::new_v4();

    // Exclude the known passkey for this user
    let store = CREDENTIAL_STORE.read().await;
    let exclude_credentials = store
        .get(user_email)
        .map(|pk| vec![pk.cred_id().clone()]);

    // Start registration
    let (ccr, state) = WEBAUTHN
        .start_passkey_registration(
            user_id,
            user_email,
            user_display_name,
            exclude_credentials, // No credential options
        )
        .context("Failed to start registration")?;

    Ok((
        serde_json::json!({
            "rp": ccr.public_key.rp,
            "user": {
                "id": ccr.public_key.user.id,
                "name": ccr.public_key.user.name,
                "displayName": ccr.public_key.user.display_name,
            },
            "challenge": ccr.public_key.challenge,
            "pubKeyCredParams": ccr.public_key.pub_key_cred_params,
            "timeout": ccr.public_key.timeout,
            "authenticatorSelection": ccr.public_key.authenticator_selection,
            "attestation": ccr.public_key.attestation,
        }),
        state,
    ))
}

/// Compléter l'enregistrement WebAuthn
pub async fn complete_registration(
    user_email: &str,
    response: &RegisterPublicKeyCredential,
    stored_state: &StoredRegistrationState,
) -> Result<()> {
    // TODO: we shouldn't need to validate the challenge ourselves, the library already does that, ask about this
    //       ref stored_state.challenge

    // Complete the registration
    let passkey = WEBAUTHN
        .finish_passkey_registration(
            response,
            &stored_state.registration_state,
        )
        .context("Failed to complete registration")?;

    // Store the credential
    let mut store = CREDENTIAL_STORE.write().await;
    store.insert(user_email.to_string(), passkey);

    Ok(())
}

/// Démarrer l'authentification WebAuthn
pub async fn begin_authentication(user_email: &str) -> Result<(serde_json::Value, PasskeyAuthentication)> {
    let store = CREDENTIAL_STORE.read().await;
    let allowed_credentials = store
        .get(user_email)
        .map(|pk| vec![pk.clone()])
        .unwrap_or_default();

    // Start authentication
    let (rcr, state) = WEBAUTHN
        .start_passkey_authentication(&allowed_credentials)
        .context("Failed to start authentication")?;

    Ok((
        serde_json::json!({
            "challenge": rcr.public_key.challenge,
            "timeout": rcr.public_key.timeout,
            "rpId": rcr.public_key.rp_id,
            "allowCredentials": rcr.public_key.allow_credentials,
         }),
        state,
    ))
}

/// Compléter l'authentification WebAuthn
pub async fn complete_authentication(
    response: &PublicKeyCredential,
    state: &PasskeyAuthentication,
    server_challenge: &str,
) -> Result<()> {
    // TODO ask about the client_data_json and server_challenge given the challenge verification is already done in the library
    // Complete the authentication
    WEBAUTHN
        .finish_passkey_authentication(response, state)
        .context("Failed to complete authentication")?;

    Ok(())
}
