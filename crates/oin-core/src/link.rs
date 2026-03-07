use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::DataKey;
use crate::error::{OinError, Result};

pub const DEFAULT_GATEWAY: &str = "https://oin.vinavildev.com";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareLink {
    pub manifest_id: String,
    pub key_fragment: String,
    pub gateway: String,
}

impl ShareLink {
    pub fn new(manifest_id: &str, manifest_key: &DataKey) -> Self {
        Self {
            manifest_id: manifest_id.to_string(),
            key_fragment: URL_SAFE_NO_PAD.encode(manifest_key.as_bytes()),
            gateway: DEFAULT_GATEWAY.to_string(),
        }
    }

    pub fn with_gateway(manifest_id: &str, manifest_key: &DataKey, gateway: &str) -> Self {
        let mut link = Self::new(manifest_id, manifest_key);
        link.gateway = gateway.trim_end_matches('/').to_string();
        link
    }

    pub fn to_view_url(&self) -> String {
        format!("{}/#/v/{}#{}", self.gateway, self.manifest_id, self.key_fragment)
    }

    pub fn to_image_url(&self, extension: &str) -> String {
        format!("{}/{}.{}#{}", self.gateway, self.manifest_id, extension, self.key_fragment)
    }

    pub fn to_short_url(&self) -> String {
        format!("{}/{}#{}", self.gateway, self.manifest_id, self.key_fragment)
    }

    pub fn to_thumb_url(&self) -> String {
        format!("{}/{}/thumb#{}", self.gateway, self.manifest_id, self.key_fragment)
    }

    pub fn to_manage_url(&self, control_token: &str) -> String {
        format!("{}/#/manage/{}?token={}", self.gateway, self.manifest_id, control_token)
    }

    pub fn parse(url: &str) -> Result<Self> {
        let (gateway, path_and_fragment) = if url.starts_with("http") {
            let after_scheme = url.find("://").map(|i| i + 3)
                .ok_or_else(|| OinError::LinkEncoding("invalid URL scheme".into()))?;

            let path_start = url[after_scheme..].find('/').map(|i| after_scheme + i)
                .ok_or_else(|| OinError::LinkEncoding("no path in URL".into()))?;

            (url[..path_start].to_string(), url[path_start + 1..].to_string())
        } else {
            (DEFAULT_GATEWAY.to_string(), url.to_string())
        };

        let parts: Vec<&str> = path_and_fragment.splitn(2, '#').collect();
        if parts.len() != 2 {
            return Err(OinError::LinkEncoding("missing key fragment (expected #)".into()));
        }

        let manifest_id = parts[0]
            .trim_start_matches("#/v/")
            .trim_start_matches("/")
            .to_string();

        Ok(Self {
            manifest_id,
            key_fragment: parts[1].to_string(),
            gateway,
        })
    }

    pub fn decryption_key(&self) -> Result<DataKey> {
        let bytes = URL_SAFE_NO_PAD.decode(&self.key_fragment)
            .map_err(|e| OinError::LinkEncoding(format!("base64 decode: {}", e)))?;

        if bytes.len() != 32 {
            return Err(OinError::LinkEncoding(format!(
                "key fragment wrong length: {} bytes, expected 32", bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(DataKey(key))
    }
}

#[derive(Debug, Serialize)]
pub struct EmbedCodes {
    pub view_url: String,
    pub direct_url: String,
    pub thumb_url: String,
    pub html: String,
    pub markdown: String,
    pub bbcode: String,
}

impl EmbedCodes {
    pub fn generate(link: &ShareLink, extension: &str) -> Self {
        let direct = link.to_image_url(extension);
        let view = link.to_short_url();
        let thumb = link.to_thumb_url();

        Self {
            html: format!("<img src=\"{}\" alt=\"OIN image\" />", direct),
            markdown: format!("![image]({})", direct),
            bbcode: format!("[img]{}[/img]", direct),
            view_url: view,
            direct_url: direct,
            thumb_url: thumb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_roundtrip() {
        let key = DataKey::generate();
        let link = ShareLink::new("a7xK2m", &key);

        let url = link.to_short_url();
        assert!(url.contains("a7xK2m"));
        assert!(url.contains('#'));

        let parsed = ShareLink::parse(&url).unwrap();
        assert_eq!(parsed.manifest_id, "a7xK2m");

        let recovered_key = parsed.decryption_key().unwrap();
        assert_eq!(recovered_key.0, key.0);
    }

    #[test]
    fn link_formats() {
        let key = DataKey::generate();
        let link = ShareLink::new("abc123", &key);

        assert!(link.to_short_url().starts_with("https://oin.io/abc123#"));
        assert!(link.to_image_url("png").contains("abc123.png#"));
        assert!(link.to_thumb_url().contains("abc123/thumb#"));
    }

    #[test]
    fn custom_gateway() {
        let key = DataKey::generate();
        let link = ShareLink::with_gateway("test", &key, "https://my-gateway.com");
        assert!(link.to_short_url().starts_with("https://my-gateway.com/test#"));
    }

    #[test]
    fn embed_codes() {
        let key = DataKey::generate();
        let link = ShareLink::new("img123", &key);
        let codes = EmbedCodes::generate(&link, "png");

        assert!(codes.html.contains("<img src="));
        assert!(codes.markdown.contains("![image]"));
        assert!(codes.bbcode.contains("[img]"));
    }

    #[test]
    fn manage_url() {
        let key = DataKey::generate();
        let link = ShareLink::new("img123", &key);
        let manage = link.to_manage_url("ctrl-token-xyz");

        assert!(manage.contains("manage"));
        assert!(manage.contains("ctrl-token-xyz"));
    }
}
