use ammonia::is_html;
use anyhow::{bail, Result};
use image::ImageFormat;
use std::path::Path;
use validator::{ValidateEmail, ValidateNonControlCharacter};

/// Wrapper around an email address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserEmail(String);

/// Implementation of `UserEmail`
impl UserEmail {
    /// Attempts to create a new `UserEmail` instance from a string representing an email address
    ///
    /// NOTE: this follows the HTML5 specification for email validation rather than RFC 5322,
    ///       which has differences in the handling of formats which are usually considered
    ///       cumbersome or unfamiliar for users.
    ///
    /// # Arguments
    /// * `email` - The raw email address to validate
    ///
    /// # Returns
    /// * `Some(UserEmail)` if email is valid
    /// * `None` if email is empty or invalid
    pub fn try_new(email: &str) -> Option<Self> {
        let trimmed = email.trim();
        // NOTE: validate_email also validates for size-constraints
        if !trimmed.validate_email() {
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
    match image::guess_format(bytes) {
        Ok(format) if format == ImageFormat::Jpeg => (),
        Ok(_) => bail!("File must be a valid JPEG image"),
        Err(_) => bail!("Invalid image format"),
    }

    // Validate the image contents
    match image::load_from_memory_with_format(bytes, ImageFormat::Jpeg) {
        Ok(_) => Ok(()),
        Err(_) => bail!("Invalid image format"),
    }
}

/// Wrapper around textual content given by an external source
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TextualContent(String);

/// Implementation of `TextualContent`
impl TextualContent {
    /// Attempts to create a new `TextualContent` instance from a string representing
    /// long-form textual content (e.g. blog post, article)
    ///
    /// # Arguments
    /// * `content` - The raw content to validate
    ///
    /// # Returns
    /// * `Some(TextualContent)` if content is valid
    /// * `None` if content is empty or unsafe
    pub fn try_new_long_form_content(content: &str) -> Option<Self> {
        Self::try_new(content, 2_000)
    }

    /// Attempts to create a new `TextualContent` instance from a string representing
    /// short form content (e.g. a title or tagline)
    ///
    /// # Arguments
    /// * `content` - The raw content to validate
    ///
    /// # Returns
    /// * `Some(TextualContent)` if content is valid
    /// * `None` if content is empty or unsafe
    pub fn try_new_short_form_content(content: &str) -> Option<Self> {
        Self::try_new(content, 250)
    }

    fn try_new(content: &str, max_length: usize) -> Option<Self> {
        let trimmed = content.trim();
        if {
            trimmed.is_empty()
                || trimmed.len() > max_length
                || !trimmed.validate_non_control_character()
                || is_html(trimmed)
        } {
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
    fn test_validate_image_empty() {
        assert!(validate_image(&[], "empty.jpg").is_err());
    }

    // Helper function to create test strings of specific lengths
    fn create_string_of_length(length: usize) -> String {
        "a".repeat(length)
    }

    #[test]
    fn test_long_form_content_valid() {
        let content = "This is a valid long-form content piece that should be accepted.";
        let result = TextualContent::try_new_long_form_content(content);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, content.trim());
    }

    #[test]
    fn test_long_form_content_max_length() {
        let content = create_string_of_length(2_000);
        let result = TextualContent::try_new_long_form_content(&content);
        assert!(result.is_some());

        let too_long = create_string_of_length(2_001);
        let result = TextualContent::try_new_long_form_content(&too_long);
        assert!(result.is_none());
    }

    #[test]
    fn test_short_form_content_valid() {
        let content = "This is a valid short title";
        let result = TextualContent::try_new_short_form_content(content);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, content.trim());
    }

    #[test]
    fn test_short_form_content_max_length() {
        let content = create_string_of_length(250);
        let result = TextualContent::try_new_short_form_content(&content);
        assert!(result.is_some());

        let too_long = create_string_of_length(251);
        let result = TextualContent::try_new_short_form_content(&too_long);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_content() {
        assert!(TextualContent::try_new_long_form_content("").is_none());
        assert!(TextualContent::try_new_short_form_content("").is_none());
        assert!(TextualContent::try_new_long_form_content("   ").is_none());
        assert!(TextualContent::try_new_short_form_content("   ").is_none());
    }

    #[test]
    fn test_whitespace_trimming() {
        let content = "  Hello World  ";
        let result = TextualContent::try_new_short_form_content(content);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "Hello World");
    }

    #[test]
    fn test_control_characters() {
        // Test with various control characters
        let content_with_null = "Hello\0World";
        assert!(TextualContent::try_new_short_form_content(content_with_null).is_none());

        let content_with_escape = "Hello\x1bWorld";
        assert!(TextualContent::try_new_short_form_content(content_with_escape).is_none());
    }

    #[test]
    fn test_html_content() {
        let html_content = "<p>This is HTML content</p>";
        assert!(TextualContent::try_new_short_form_content(html_content).is_none());

        let html_content_with_attributes = "<div class='test'>Content</div>";
        assert!(TextualContent::try_new_short_form_content(html_content_with_attributes).is_none());
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
