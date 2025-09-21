pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// base62
pub(crate) struct SpotifyID(pub(crate) String);
