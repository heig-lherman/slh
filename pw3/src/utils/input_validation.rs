use crate::regex;
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;
use zxcvbn::{zxcvbn, Score};

/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    // Check length constraints (8-64 characters)
    if password.len() < 8 || password.len() > 64 {
        return false;
    }

    // Password shouldn't be the same as username
    // Simple safeguard, zxcvbn will catch most of these cases including variations
    if password.eq_ignore_ascii_case(username) {
        return false;
    }

    // Use zxcvbn to estimate password strength
    let estimate = zxcvbn(password, &[username]);
    estimate.score() >= Score::Three
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    loop {
        let password = inquire::Password::new("Enter password:")
            .with_help_message(
                "Password must be 8-64 characters long and meet complexity requirements",
            )
            .prompt()
            .expect("Failed to read password");

        if password_validation(&password, username) {
            return password;
        }

        println!("Password is too weak. Please try again. Possible reasons are:");
        println!("- It is too short or too long (should be 8-64 characters)");
        println!("- It is too common or similar to your username");

        let estimate = zxcvbn(&password, &[username]);
        if estimate.score() < Score::Three {
            println!("- It is too weak (score: {}/4)", estimate.score());
            if let Some(feedback) = estimate.feedback() {
                if let Some(warning) = feedback.warning() {
                    println!("- {}", warning);
                }

                for suggestion in feedback.suggestions() {
                    println!("- {}", suggestion);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Display, Error)]
pub struct InvalidInput;

/// Wrapper type for a username that has been validated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = InvalidInput;

    fn try_from(username: String) -> Result<Self, Self::Error> {
        username_validation(&username)?;
        Ok(Self(username))
    }
}

impl TryFrom<&str> for Username {
    type Error = InvalidInput;

    fn try_from(username: &str) -> Result<Self, Self::Error> {
        username_validation(username)?;
        Ok(Self(username.to_owned()))
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn username_validation(username: &str) -> Result<(), InvalidInput> {
    // Check if username is empty or too long
    if username.len() > 32 {
        return Err(InvalidInput);
    }

    // Use regex to validate username format
    // Must start and end with alphanumeric character
    // Can contain alphanumeric characters, underscore, hyphen, and dot in between
    // Requires length to be at least 3 characters, intentional
    let username_regex = regex!(r"^[a-zA-Z0-9][a-zA-Z0-9._-]+[a-zA-Z0-9]$");
    if !username_regex.is_match(username) {
        return Err(InvalidInput);
    }

    Ok(())
}

pub fn username_input_validation(message: &str) -> Result<Username, InvalidInput> {
    let username = inquire::Text::new(message)
        .with_help_message(
            "Username must be 1-32 characters long, contain only alphanumeric characters, _, -, or ."
        )
        .prompt()
        .expect("Failed to read username");

    Username::try_from(username)
}

/// Wrapper type for an AVS number that has been validated
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct AVSNumber(String);

impl Display for AVSNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.len() == 13 {
            write!(
                f,
                "{}.{}.{}.{}",
                &self.0[0..3],
                &self.0[3..7],
                &self.0[7..11],
                &self.0[11..13]
            )
        } else {
            write!(f, "{}", &self.0)
        }
    }
}

impl TryFrom<String> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if validate_avs_number(&value) {
            Ok(AVSNumber(value))
        } else {
            Err(InvalidInput)
        }
    }
}

impl TryFrom<&str> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if validate_avs_number(value) {
            Ok(AVSNumber(value.to_owned()))
        } else {
            Err(InvalidInput)
        }
    }
}

fn validate_avs_number(avs_number: &str) -> bool {
    let avs_regex = regex!(r"^756\.?\d{4}\.?\d{4}\.?\d{2}$");
    if !avs_regex.is_match(avs_number) {
        return false;
    }

    // Validate check digit using GTIN rules
    gtin_validate::gtin13::check(&avs_number.replace('.', ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        // Test valid passwords
        assert!(password_validation("ahXeedea6i", "username"));
        assert!(password_validation("Compl3x!Pass123", "different_user"));

        // Test length constraints
        assert!(!password_validation("short", "username"));
        assert!(!password_validation("a".repeat(65).as_str(), "username"));

        // Test username similarity
        assert!(!password_validation("username", "username"));
        assert!(!password_validation("USERNAME", "username"));

        // Test common passwords
        assert!(!password_validation("password123", "username"));
        assert!(!password_validation("qwerty123", "username"));
    }

    #[test]
    fn test_username_validation() {
        // Test valid usernames
        assert!(username_validation("john_doe").is_ok());
        assert!(username_validation("user123").is_ok());
        assert!(username_validation("a1-b2.c3").is_ok());

        // Test length constraints
        assert!(username_validation("a".repeat(33).as_str()).is_err());

        // Test invalid characters
        assert!(username_validation("user@name").is_err());
        assert!(username_validation("user name").is_err());
        assert!(username_validation("_username").is_err());
        assert!(username_validation("username_").is_err());

        // Test empty username
        assert!(username_validation("").is_err());
    }

    #[test]
    fn test_username_try_from() {
        // Test valid conversions
        assert!(Username::try_from("valid_user123").is_ok());
        assert!(Username::try_from(String::from("valid-user123")).is_ok());

        // Test invalid conversions
        assert!(Username::try_from("invalid@user").is_err());
        assert!(Username::try_from(String::from("")).is_err());
    }

    #[test]
    fn test_avs_number_validation() {
        // Test valid AVS numbers
        assert!(validate_avs_number("756.0000.0000.02"));
        assert!(validate_avs_number("7560000000002")); // Without dots

        // Test invalid formats
        assert!(!validate_avs_number("756.1234.5678")); // Too short
        assert!(!validate_avs_number("abc.1234.5678.90")); // Invalid prefix
        assert!(!validate_avs_number("756.abcd.5678.90")); // Non-numeric

        // Test invalid check digit
        assert!(!validate_avs_number("756.0000.0000.01"));
        assert!(!validate_avs_number("7560000000009"));
    }

    #[test]
    fn test_avs_number_display() {
        let avs = AVSNumber::try_from("7560000000002").unwrap();
        assert_eq!(avs.to_string(), "756.0000.0000.02");

        // Test with already formatted input
        let avs = AVSNumber::try_from("756.0000.0000.02").unwrap();
        assert_eq!(avs.to_string(), "756.0000.0000.02");
    }
}
