use bytes::Bytes;

use crate::definition::{Result, SpotifyID};

// 返回图片名字和图片数据
pub(crate) async fn get_image_cover(id: SpotifyID, access_token: &str) -> Result<(String, Bytes)> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("https://api.spotify.com/v1/tracks/{}", id.0))
        .bearer_auth(access_token)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let images = resp["album"]["images"]
        .as_array()
        .ok_or("No images array found")?;

    if images.is_empty() {
        return Err("No images available".into());
    }

    // 找到分辨率最高的图片
    let highest_res_image = images
        .iter()
        .max_by_key(|img| {
            let width = img["width"].as_u64().unwrap_or(0);
            let height = img["height"].as_u64().unwrap_or(0);
            width * height // 按像素总数排序
        })
        .ok_or("Failed to find highest resolution image")?;

    let image_url = highest_res_image["url"]
        .as_str()
        .ok_or("No image URL found")?;

    println!("Selected highest resolution image: {}", image_url);
    let album_name = resp["album"]["name"]
        .as_str()
        .unwrap_or("unknown_album")
        .replace("/", "_");
    let image_bytes = reqwest::get(image_url).await?.bytes().await?;
    Ok((album_name, image_bytes))
}

#[cfg(test)]
mod test {
    use super::get_image_cover;
    use crate::{definition::SpotifyID, token::get_token};

    #[ignore]
    #[tokio::test]
    async fn test_get_image_cover() {
        dotenv::dotenv().ok();
        let id = SpotifyID("49ey1Q2urymICndIuwUkxp".to_string());
        let token = get_token().await.unwrap();
        let (name, image_bytes) = get_image_cover(id, token.as_str()).await.unwrap();
        assert!(!image_bytes.is_empty());
        println!(
            "Downloaded {} image size: {} bytes",
            name,
            image_bytes.len()
        );
    }
}
