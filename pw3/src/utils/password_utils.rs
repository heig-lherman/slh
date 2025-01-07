//! Hachage et vérification des mots de passe

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHashString, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::LazyLock};

static DEFAULT_HASHER: LazyLock<Argon2<'static>> = LazyLock::new(|| Argon2::default());

/// Le hash d'un mot de passe vide, à utiliser quand l'utilisateur n'existe pas
/// pour éviter une attaque par canal auxiliaire
static EMPTY_HASH: LazyLock<PWHash> = LazyLock::new(|| hash(""));

/// Un mot de passe haché
#[derive(Clone, Debug, Display)]
pub struct PWHash(PasswordHashString);

impl std::hash::Hash for PWHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state)
    }
}

impl Serialize for PWHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PWHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hash = PasswordHashString::from_str(&s)
            .map_err(|_| <D::Error as serde::de::Error>::custom("Invalid PHC string"))?;
        Ok(PWHash(hash))
    }
}

/// Calcule un haché a partir d'un mot de passe en clair, en choisissant un sel au hasard
pub fn hash(password: &str) -> PWHash {
    todo!()
}

/// Vérifie si le mot de passe correspond au hash stocké.
/// 
/// Si un hash n'est pas fourni, on doit quand même tester
/// le mot de passe avec un faux hash pour éviter une timing
/// attack.
pub fn verify(password: &str, maybe_hash: Option<&PWHash>) -> bool {
    todo!()
}