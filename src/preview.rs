use crate::{cache, read_entry};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

const ARCHIVE: &str = "B.TextureDx9";
const ASSET: &str = "Temp/Lotus/Interface/SigninReward/0_flashu.bmp";
pub const WIDTH: i32 = 256;
pub const HEIGHT: i32 = 32;
const TOP_MIP_BYTES: usize = (WIDTH * HEIGHT * 4) as usize;
const TEXTURE_BYTES: usize = 43_708;

pub fn load(folder: &Path) -> io::Result<Vec<u8>> {
    let table = folder.join(format!("{ARCHIVE}.toc"));
    let entry = cache::read_toc(&table)?
        .into_iter()
        .find(|entry| entry.path.eq_ignore_ascii_case(ASSET))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing {ASSET} in {ARCHIVE}"),
            )
        })?;
    if entry.size as usize != TEXTURE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected decoded size for {ASSET}"),
        ));
    }
    let mut archive = BufReader::new(File::open(table.with_extension("cache"))?);
    let (bytes, frames) = read_entry(&mut archive, &entry)?;
    let pixels = bitmap_pixels(&bytes);
    println!(
        "Loaded {ASSET} from {ARCHIVE}: {} decoded bytes, {WIDTH} x {HEIGHT} pixels, {} compressed frames and {} stored frames.",
        bytes.len(), frames.compressed, frames.stored
    );
    Ok(pixels)
}

fn bitmap_pixels(texture: &[u8]) -> Vec<u8> {
    // The cooked texture stores BGRA mip levels from smallest to largest.
    let mut pixels = texture[TEXTURE_BYTES - TOP_MIP_BYTES..].to_vec();
    for pixel in pixels.chunks_exact_mut(4) {
        let alpha = u16::from(pixel[3]);
        // GDI treats 32-bit BI_RGB as BGRX. Composite the texture over black first.
        for channel in &mut pixel[..3] {
            *channel = ((u16::from(*channel) * alpha + 127) / 255) as u8;
        }
        pixel[3] = 0;
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_largest_mip_and_composites_bgra_over_black() {
        let mut texture = vec![255; TEXTURE_BYTES];
        let base = TEXTURE_BYTES - TOP_MIP_BYTES;
        texture[base..base + 8].copy_from_slice(&[200, 100, 50, 128, 255, 255, 255, 0]);
        let pixels = bitmap_pixels(&texture);
        assert_eq!(pixels.len(), TOP_MIP_BYTES);
        assert_eq!(
            &pixels[..12],
            &[100, 50, 25, 0, 0, 0, 0, 0, 255, 255, 255, 0]
        );
    }
}
