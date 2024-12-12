// TODO ask about email validation for unauth handlers???

use ammonia::is_html;
use anyhow::{bail, Result};
use image::ImageFormat;
use std::path::Path;
use validator::ValidateEmail;

/// Wrapper around an email address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserEmail(String);

impl UserEmail {
    /// Attempts to create a new `UserEmail` instance from a string
    ///
    /// # Arguments
    /// * `email` - The raw email address to validate
    ///
    /// # Returns
    /// * `Some(UserEmail)` if email is valid
    /// * `None` if email is empty or invalid
    pub fn try_new(email: &str) -> Option<Self> {
        let trimmed = email.trim();
        if trimmed.is_empty() || !trimmed.validate_email() {
            None
        } else {
            Some(Self(trimmed.to_owned()))
        }
    }
}

/// Implementation of `AsRef<str>` for `UserEmail`
///
/// Allows for cheap conversion to a string slice for use in other functions
impl AsRef<str> for UserEmail {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Maximum size allowed for uploaded images in bytes (5MB)
const MAX_IMAGE_SIZE: usize = 5 * 1024 * 1024;

/// Validates an uploaded image file
///
/// # Arguments
/// * `bytes` - The raw bytes of the uploaded file
/// * `filename` - The original filename to check extension
///
/// # Returns
/// * `Ok(())` if validation passes
/// * `Err` with message if validation fails
pub fn validate_image(bytes: &[u8], filename: &str) -> Result<()> {
    // Check file size
    if bytes.len() > MAX_IMAGE_SIZE {
        bail!("File is too large. Maximum size is 5MB");
    }

    // Check file extension
    match {
        Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
    } {
        "jpg" | "jpeg" => (),
        _ => bail!("File must have a .jpg or .jpeg extension"),
    }

    // Validate image format using image crate
    // TODO ask if this is enough? should we add checks for whether we can decode?
    match image::guess_format(bytes) {
        Ok(format) if format == ImageFormat::Jpeg => Ok(()),
        Ok(_) => bail!("File must be a valid JPEG image"),
        Err(_) => bail!("Invalid image format"),
    }
}

/// Sanitizes a filename to prevent directory traversal and ensure uniqueness
///
/// # Arguments
/// * `original_filename` - The original uploaded filename
///
/// # Returns
/// * A sanitized unique filename
pub fn sanitize_filename(original_filename: &str) -> String {
    let extension = Path::new(original_filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("jpg");

    format!("{}.{}", uuid::Uuid::new_v4(), extension)
}

/// Wrapper around textual content given by an external source
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TextualContent(String);

/// Implementation of `TextualContent`
impl TextualContent {
    /// Attempts to create a new `TextualContent` instance from a string
    ///
    /// # Arguments
    /// * `content` - The raw content to validate
    ///
    /// # Returns
    /// * `Some(TextualContent)` if content is valid
    /// * `None` if content is empty or unsafe
    pub fn try_new(content: &str) -> Option<Self> {
        let trimmed = content.trim();
        if trimmed.is_empty() || is_html(trimmed) {
            None
        } else {
            Some(Self(trimmed.to_owned()))
        }
    }
}

/// Implementation of `AsRef<str>` for `TextualContent`
///
/// Allows for cheap conversion to a string slice for use in other functions
impl AsRef<str> for TextualContent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_image_valid_jpeg() {
        let bytes = include_bytes!("../../tests/test_files/valid.jpg");
        assert!(validate_image(bytes, "test.jpg").is_ok());
    }

    #[test]
    fn test_validate_image_invalid_extension() {
        let bytes = include_bytes!("../../tests/test_files/valid.jpg");
        assert!(validate_image(bytes, "test.png").is_err());
    }

    #[test]
    fn test_validate_image_invalid_format() {
        let bytes = include_bytes!("../../tests/test_files/fake.jpg");
        assert!(validate_image(bytes, "fake.jpg").is_err());
    }

    #[test]
    fn test_validate_image_too_large() {
        // Create a byte vector larger than MAX_IMAGE_SIZE
        let large_bytes = vec![0; MAX_IMAGE_SIZE + 1];
        assert!(validate_image(&large_bytes, "large.jpg").is_err());
    }

    #[test]
    fn test_sanitize_filename() {
        let filename = sanitize_filename("../../../dangerous.jpg");
        assert!(filename.ends_with(".jpg"));
        assert!(!filename.contains(".."));
        assert!(uuid::Uuid::parse_str(&filename[..36]).is_ok());
    }

    #[test]
    fn test_validate_image_empty() {
        assert!(validate_image(&[], "empty.jpg").is_err());
    }

    #[test]
    fn test_sanitize_filename_no_extension() {
        let filename = sanitize_filename(".noextension");
        assert!(filename.ends_with(".jpg"));
        assert!(uuid::Uuid::parse_str(&filename[..36]).is_ok());
    }

    #[test]
    fn test_textual_content_strips_all_tags() {
        let input = "<p>Hello <strong>World</strong>!</p>";
        assert!(TextualContent::try_new(input).is_none());
    }

    #[test]
    fn test_textual_content_empty() {
        let input = "   ";
        assert!(TextualContent::try_new(input).is_none());
    }

    #[test]
    fn test_textual_content_only_tags() {
        let input = "<div><span></span></div>";
        assert!(TextualContent::try_new(input).is_none());
    }

    #[test]
    fn test_textual_content_with_script() {
        let input = "<script>alert('xss')</script>Hello";
        assert!(TextualContent::try_new(input).is_none());
    }

    #[test]
    fn test_textual_content_mixed_content() {
        let input = "Hello <b>there</b> & welcome";
        assert!(TextualContent::try_new(input).is_none());
    }

    #[test]
    fn test_textual_content_valid() {
        let input = "   Hello there & welcome   ";
        let clean = TextualContent::try_new(input).unwrap();
        assert_eq!(clean.as_ref(), input.trim());
    }

    #[test]
    fn test_textual_content_clean() {
        let input = "Hello there & welcome";
        let clean = TextualContent::try_new(input).unwrap();
        assert_eq!(clean.as_ref(), input);
    }

    #[test]
    fn test_valid_email_addresses() {
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user@subdomain.example.com",
            "123@example.com",
            "user@example.co.uk",
            "user-name@example.com",
            "u@example.com",
            "user@example-site.com",
            "user.name+tag@example.com",
        ];

        for email in valid_emails {
            assert!(UserEmail::try_new(email).is_some(), "Email should be valid: {}", email);

            // Verify the email is stored exactly as provided
            if let Some(user_email) = UserEmail::try_new(email) {
                assert_eq!(user_email.as_ref(), email);
            }
        }
    }

    #[test]
    fn test_invalid_email_addresses() {
        let invalid_emails = vec![
            "",
            " ",
            "invalid",
            "@example.com",
            "user@",
            "user@.com",
            "user@example.",
            "user name@example.com",
            "user@exam ple.com",
            "user@@example.com",
            "user@example..com",
        ];

        for email in invalid_emails {
            assert!(UserEmail::try_new(email).is_none(), "Email should be invalid: {}", email);
        }
    }

    #[test]
    fn test_email_whitespace_handling() {
        // Test that leading/trailing whitespace is properly trimmed
        let email_with_whitespace = vec![
            " user@example.com",
            "user@example.com ",
            "\tuser@example.com\t",
            "\nuser@example.com\n",
            "  user@example.com  ",
        ];

        for email in email_with_whitespace {
            let cleaned_email = "user@example.com";
            let user_email = UserEmail::try_new(email);

            assert!(user_email.is_some(), "Email should be valid after trimming: {}", email);
            assert_eq!(user_email.unwrap().as_ref(), cleaned_email);
        }
    }

    #[test]
    fn test_email_as_ref_implementation() {
        let email = "user@example.com";
        let user_email = UserEmail::try_new(email).unwrap();

        // Test AsRef<str> implementation
        let reference: &str = user_email.as_ref();
        assert_eq!(reference, email);

        // Verify it works in contexts requiring AsRef<str>
        fn takes_str_ref<T: AsRef<str>>(value: &T) -> &str {
            value.as_ref()
        }
        assert_eq!(takes_str_ref(&user_email), email);
    }
}
