use crate::regex;
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
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
            // Confirm password
            let confirm = inquire::Password::new("Confirm password:")
                .prompt()
                .expect("Failed to read password confirmation");

            if password == confirm {
                return password;
            }

            println!("Passwords do not match. Please try again.");
        } else {
            println!("Password is too weak. Please try again. Possible reasons are:");
            println!("- It is too short or too long (should be 8-64 characters)");
            println!("- It is too common or similar to your username");

            let estimate = zxcvbn(&password, &[username]);
            if estimate.score() < Score::Three {
                println!("- It is too weak (score: {:?}/4)", estimate.score());
                if let Some(feedback) = estimate.feedback() {
                    if let Some(suggestions) = feedback.warning() {
                        println!("- {:?}", suggestions);
                    }

                    for suggestion in feedback.suggestions() {
                        println!("- {:?}", suggestion);
                    }
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

// TODO do we need to validate username uniqueness here?
fn username_validation(username: &str) -> Result<(), InvalidInput> {
    // Check if username is empty or too long
    if username.is_empty() || username.len() > 32 {
        return Err(InvalidInput);
    }

    // Use regex to validate username format
    // Must start and end with alphanumeric character
    // Can contain alphanumeric characters, underscore, hyphen, and dot in between
    let username_regex = regex!(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$");
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
#[derive(Debug, Clone, Display, Serialize, Deserialize, Hash)]
pub struct AVSNumber(String);

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
