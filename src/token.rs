use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::definition::Result;

/// Token缓存结构体
#[derive(Serialize, Deserialize)]
struct TokenCache {
    access_token: String,
    token_type: String,
    expires_at: i64, // Unix timestamp
}

/// Spotify API Token响应结构体
#[derive(Deserialize)]
struct SpotifyTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64, // 秒数
}

/// 获取缓存文件路径
fn get_cache_file_path() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or("Cannot find home directory")?;
    let cache_dir = home_dir.join(".spotify-toolbox-cli");
    fs::create_dir_all(&cache_dir)?;
    Ok(cache_dir.join("spotify_token"))
}

/// 生成固定的加密密钥（基于用户home目录）
fn get_encryption_key() -> Result<[u8; 32]> {
    let home_dir = dirs::home_dir().ok_or("Cannot find home directory")?;
    let key_source = format!("spotify-toolbox-{}", home_dir.to_string_lossy());
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key_source.hash(&mut hasher);
    let hash1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    format!("{}-mikumiku", key_source).hash(&mut hasher);
    let hash2 = hasher.finish();

    let mut key = [0u8; 32];
    key[0..8].copy_from_slice(&hash1.to_le_bytes());
    key[8..16].copy_from_slice(&hash2.to_le_bytes());
    key[16..24].copy_from_slice(&hash1.to_be_bytes());
    key[24..32].copy_from_slice(&hash2.to_be_bytes());

    Ok(key)
}

async fn get_client_id_and_secret() -> Result<(String, String)> {
    let client_id = std::env::var("SPOTIFY_CLIENT_ID")
        .map_err(|_| "SPOTIFY_CLIENT_ID not found in environment variables")?;
    let client_secret = std::env::var("SPOTIFY_CLIENT_SECRET")
        .map_err(|_| "SPOTIFY_CLIENT_SECRET not found in environment variables")?;

    Ok((client_id, client_secret))
}

/// 从Spotify获取新的token（使用客户端凭证流程）
async fn fetch_new_token() -> Result<TokenCache> {
    let (client_id, client_secret) = get_client_id_and_secret().await?;

    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", &client_id);
    params.insert("client_secret", &client_secret);

    let response = client
        .post("https://accounts.spotify.com/api/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Spotify API error: {}", error_text).into());
    }

    let token_response: SpotifyTokenResponse = response.json().await?;

    let expires_at = chrono::Utc::now().timestamp() + token_response.expires_in;

    Ok(TokenCache {
        access_token: token_response.access_token,
        token_type: token_response.token_type,
        expires_at,
    })
}

/// 根据缓存的时间，判断是否过期来刷新缓存 (3600秒)
/// 如果没有缓存，则创建一个新的token
/// aes-gcm 加密存储在 home 目录下的 .spotify-toolbox-cli/spotify_token 文件中
async fn flush_or_create_token() -> Result<()> {
    let cache_file_path = get_cache_file_path()?;
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let now = chrono::Utc::now().timestamp();
    let mut need_refresh = true;

    // 尝试读取现有缓存
    if cache_file_path.exists()
        && let Ok(encrypted_data) = fs::read(&cache_file_path)
        && encrypted_data.len() > 12
    {
        // 至少需要nonce的长度
        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        if let Ok(decrypted_data) = cipher.decrypt(nonce, &encrypted_data[12..])
            && let Ok(token_cache) = serde_json::from_slice::<TokenCache>(&decrypted_data)
        {
            // 检查是否还有至少5分钟有效期
            if token_cache.expires_at > now + 300 {
                need_refresh = false;
            }
        }
    }

    if need_refresh {
        let new_token = fetch_new_token().await?;
        let token_json = serde_json::to_vec(&new_token)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted_token = cipher
            .encrypt(&nonce, token_json.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        let mut file_data = Vec::new();
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&encrypted_token);

        fs::write(&cache_file_path, file_data)?;
    }

    Ok(())
}

/// 获取 token
pub async fn get_token() -> Result<String> {
    flush_or_create_token().await?;

    let cache_file_path = get_cache_file_path()?;
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let encrypted_data = fs::read(&cache_file_path)?;
    let nonce = Nonce::from_slice(&encrypted_data[0..12]);
    let decrypted_data = cipher
        .decrypt(nonce, &encrypted_data[12..])
        .map_err(|e| format!("Decryption failed: {}", e))?;
    let token_cache: TokenCache = serde_json::from_slice(&decrypted_data)?;

    Ok(token_cache.access_token)
}

#[cfg(test)]
mod test {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_token_cache() {
        // 测试加密密钥生成
        let key1 = get_encryption_key().unwrap();
        let key2 = get_encryption_key().unwrap();
        assert_eq!(key1, key2); // 密钥应该是确定性的

        // 测试缓存文件路径
        let path = get_cache_file_path().unwrap();
        assert!(path.to_string_lossy().contains(".spotify-toolbox-cli"));
        assert!(path.to_string_lossy().contains("spotify_token"));
    }

    #[ignore]
    #[tokio::test]
    async fn test_fetch_new_token() {
        match fetch_new_token().await {
            Ok(token) => {
                assert!(!token.access_token.is_empty());
                assert_eq!(token.token_type, "Bearer");
                assert!(token.expires_at > chrono::Utc::now().timestamp());
                eprintln!(
                    "Successfully fetched token: {} characters",
                    token.access_token.len()
                );
            }
            Err(e) => {
                panic!("Token fetch failed: {}", e);
            }
        }
    }

    #[ignore]
    #[tokio::test]
    async fn test_get_token_integration() {
        // 测试完整的token获取流程（包括缓存）
        match get_token().await {
            Ok(token) => {
                eprintln!("Successfully got formatted token: {}", &token);
            }
            Err(e) => {
                panic!("Integration test failed: {}", e);
            }
        }
    }
}
