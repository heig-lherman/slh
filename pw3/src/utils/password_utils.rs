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
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);

    // Hash the password using the default hasher and random salt
    let hash = DEFAULT_HASHER
        .hash_password(password.as_bytes(), &salt)
        .expect("Password hashing should not fail with valid parameters");

    PWHash(hash.serialize())
}

/// Vérifie si le mot de passe correspond au hash stocké.
///
/// Si un hash n'est pas fourni, on doit quand même tester
/// le mot de passe avec un faux hash pour éviter une timing
/// attack.
pub fn verify(password: &str, maybe_hash: Option<&PWHash>) -> bool {
    match maybe_hash {
        Some(hash) => {
            // Verify the password against the parsed hash
            DEFAULT_HASHER
                .verify_password(password.as_bytes(), &hash.0.password_hash())
                .is_ok()
        }
        None => {
            // Use empty hash to prevent timing attacks when user doesn't exist
            let _ =
                DEFAULT_HASHER.verify_password(password.as_bytes(), &EMPTY_HASH.0.password_hash());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_different_salts() {
        // Given the same password, hashes should be different due to random salt
        let hash1 = hash("password123");
        let hash2 = hash("password123");
        assert_ne!(hash1.0.as_str(), hash2.0.as_str());
    }

    #[test]
    fn test_hash_empty_password() {
        // Empty password should still produce a valid hash
        let hash = hash("");
        assert!(!hash.0.as_str().is_empty());
    }

    #[test]
    fn test_verify_correct_password() {
        // Test successful verification
        let password = "my_secure_password";
        let hash = hash(password);
        assert!(verify(password, Some(&hash)));
    }

    #[test]
    fn test_verify_incorrect_password() {
        // Test failed verification
        let hash = hash("correct_password");
        assert!(!verify("wrong_password", Some(&hash)));
    }

    #[test]
    fn test_verify_empty_password() {
        // Empty password should work like any other password
        let hash = hash("");
        assert!(verify("", Some(&hash)));
        assert!(!verify("not_empty", Some(&hash)));
    }

    #[test]
    fn test_verify_non_existent_user() {
        // Verification with None should always return false but take constant time
        assert!(!verify("any_password", None));
        assert!(!verify("", None));
    }

    #[test]
    fn test_hash_unicode() {
        // Test that Unicode passwords are handled correctly
        let password = "пароль123🔒";
        let hash = hash(password);
        assert!(verify(password, Some(&hash)));
        assert!(!verify("wrong", Some(&hash)));
    }

    #[test]
    fn test_verify_timing_consistency() {
        use std::time::{Duration, Instant};

        // Helper function to measure verification time
        fn measure_verify_time(password: &str, hash_opt: Option<&PWHash>) -> Duration {
            let start = Instant::now();
            let _ = verify(password, hash_opt);
            start.elapsed()
        }

        // Create a hash for testing
        let hash = hash("test_password");

        // Measure multiple times to account for system variations
        const ITERATIONS: u32 = 25;
        let mut existing_user_times = Vec::with_capacity(ITERATIONS as usize);
        let mut nonexistent_user_times = Vec::with_capacity(ITERATIONS as usize);

        for _ in 0..ITERATIONS {
            existing_user_times.push(measure_verify_time("wrong_password", Some(&hash)));
            nonexistent_user_times.push(measure_verify_time("wrong_password", None));
        }

        // Calculate average times
        let avg_existing: Duration = existing_user_times.iter().sum::<Duration>() / ITERATIONS;
        let avg_nonexistent: Duration =
            nonexistent_user_times.iter().sum::<Duration>() / ITERATIONS;

        // Verify that times are within 50% of each other
        let ratio = avg_existing.as_nanos() as f64 / avg_nonexistent.as_nanos() as f64;
        assert!(
            0.5 < ratio && ratio < 1.5,
            "Timing ratio {ratio} should be close to 1.0 for constant-time behavior"
        );
    }
}
