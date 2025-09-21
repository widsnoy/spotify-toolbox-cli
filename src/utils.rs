use lazy_regex::lazy_regex;

use crate::definition::{Result, SpotifyID};

/// https://open.spotify.com/track/49ey1Q2urymICndIuwUkxp?si=e945263c45834403
pub fn extract_spotify_id(url: &str) -> Result<SpotifyID> {
    if url.starts_with("spotify:") {
        let parts: Vec<&str> = url.split(':').collect();
        if parts.len() >= 3 {
            return Ok(SpotifyID(parts[2].to_string()));
        }
    }
    let re = lazy_regex!(r"https://open\.spotify\.com/track/([a-zA-Z0-9]+).");
    if let Some(captures) = re.captures(url)
        && let Some(id_match) = captures.get(1)
    {
        return Ok(SpotifyID(id_match.as_str().to_string()));
    }
    Err("Invalid Spotify URL format".into())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_extract_spotify_id() {
        let url1 = "spotify:track:49ey1Q2urymICndIuwUkxp";
        let url2 = "https://open.spotify.com/track/49ey1Q2urymICndIuwUkxp?si=e945263c45834403";
        let id1 = extract_spotify_id(url1).unwrap();
        let id2 = extract_spotify_id(url2).unwrap();
        assert_eq!(id1.0, "49ey1Q2urymICndIuwUkxp");
        assert_eq!(id2.0, "49ey1Q2urymICndIuwUkxp");
    }
}
