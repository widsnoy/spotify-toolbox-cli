use clap::{Parser, Subcommand};

use definition::*;
use tokio::fs;

use crate::{image::get_image_cover, utils::extract_spotify_id};

mod definition;
mod image;
mod token;
mod utils;

#[derive(Parser, Debug)]
#[command(name = "spotify-toolbox-cli")]
#[command(
    about = "a cli tool to download Spotify track cover images and descrypt downloaded songs"
)]
#[command(author = "widsnoy")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 下载封面图片
    Image {
        /// 下载路径
        #[arg(
            short = 'p',
            long = "path",
            help = "image save path, default is current directory"
        )]
        path: Option<String>,

        /// 歌曲链接
        #[arg(short = 'u', long = "url", help = "spotify track url")]
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();
    let token = token::get_token().await?;
    match args.command {
        Command::Image { path, url } => {
            let song_id = extract_spotify_id(&url)?;
            let (image_name, image) = get_image_cover(song_id, &token).await?;
            let dir_path = path.unwrap_or(".".to_string());
            let path = format!("{}/{}.jpg", dir_path, image_name);
            fs::write(&path, &image).await?;
            println!("image saved to {}", path);
        }
    }
    Ok(())
}
