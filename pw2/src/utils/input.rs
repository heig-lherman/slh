// TODO ask about email validation for unauth handlers???

use anyhow::{bail, Result};
use image::ImageFormat;
use std::path::Path;

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

/// Sanitizes content that may contain HTML to only extract the inner text.
/// Behind the scenes, this uses DOM parsing to extract textual nodes and remove any HTML tags.
///
/// # Arguments
/// * `content` - The raw content to sanitize
///
/// # Returns
/// * `Some(String)` containing sanitized content if valid
/// * `None` if content is empty
pub fn sanitize_html(content: &str) -> Option<String> {
    sanitize_html::sanitize_str(&sanitize_html::rules::predefined::DEFAULT, content)
        .ok()
        .map(|clean| clean.trim().to_owned())
        .filter(|clean| !clean.is_empty())
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
    fn test_sanitize_html_strips_all_tags() {
        let input = "<p>Hello <strong>World</strong>!</p>";
        let clean = sanitize_html(input).unwrap();
        assert_eq!(clean, "Hello World!");
    }

    #[test]
    fn test_sanitize_html_empty() {
        let input = "   ";
        assert!(sanitize_html(input).is_none());
    }

    #[test]
    fn test_sanitize_html_only_tags() {
        let input = "<div><span></span></div>";
        assert!(sanitize_html(input).is_none());
    }

    #[test]
    fn test_sanitize_html_with_script() {
        let input = "<script>alert('xss')</script>Hello";
        let clean = sanitize_html(input).unwrap();
        assert_eq!(clean, "Hello");
    }

    #[test]
    fn test_sanitize_html_mixed_content() {
        let input = "Hello <b>there</b> & welcome";
        let clean = sanitize_html(input).unwrap();
        assert_eq!(clean, "Hello there &amp; welcome");
    }
}
