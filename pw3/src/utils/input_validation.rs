use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    todo!()
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    todo!()
}

#[derive(Debug, Clone, Copy, Display, Error)]
pub struct InvalidInput;

/// Wrapper type for a username thas has been validated
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
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
    todo!()
}

pub fn username_input_validation(message: &str) -> Result<Username, InvalidInput> {
    todo!()
}

/// Wrapper type for an AVS number that has been validated
#[derive(Debug, Display, Serialize, Deserialize, Hash)]
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

fn validate_avs_number(avs_number: &str) -> bool {
    todo!()
}