//! PNG encode/decode between arboard RGBA and on-the-wire PNG bytes.
//!
//! arboard gives us raw RGBA buffers; we PNG-encode before encryption so
//! every platform sees a normalized format, and so history thumbnails can
//! reuse the same bytes.

use anyhow::{Context, Result, anyhow};
use png::{BitDepth, ColorType, Decoder, Encoder};

use crate::clipboard::ImageBytes;

pub fn encode_png(image: &ImageBytes) -> Result<Vec<u8>> {
    if image.width == 0 || image.height == 0 {
        return Err(anyhow!("image has zero dimension"));
    }
    let expected = image.width.saturating_mul(image.height).saturating_mul(4);
    if image.rgba.len() != expected {
        return Err(anyhow!(
            "rgba buffer len {} does not match {}x{}x4 = {}",
            image.rgba.len(),
            image.width,
            image.height,
            expected
        ));
    }

    let mut out = Vec::with_capacity(expected / 2);
    {
        let mut encoder = Encoder::new(&mut out, image.width as u32, image.height as u32);
        encoder.set_color(ColorType::Rgba);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header().context("png header")?;
        writer.write_image_data(&image.rgba).context("png pixels")?;
    }
    Ok(out)
}

pub fn decode_png(bytes: &[u8]) -> Result<ImageBytes> {
    let decoder = Decoder::new(bytes);
    let mut reader = decoder.read_info().context("png read_info")?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).context("decoding png frame")?;
    buf.truncate(info.buffer_size());

    let rgba = match info.color_type {
        ColorType::Rgba => buf,
        ColorType::Rgb => rgb_to_rgba(&buf),
        ColorType::Grayscale => gray_to_rgba(&buf),
        ColorType::GrayscaleAlpha => gray_alpha_to_rgba(&buf),
        other => return Err(anyhow!("unsupported png color type: {other:?}")),
    };

    Ok(ImageBytes {
        width: info.width as usize,
        height: info.height as usize,
        rgba,
    })
}

fn rgb_to_rgba(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() / 3 * 4);
    for px in src.chunks_exact(3) {
        out.extend_from_slice(px);
        out.push(0xFF);
    }
    out
}

fn gray_to_rgba(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 4);
    for &g in src {
        out.extend_from_slice(&[g, g, g, 0xFF]);
    }
    out
}

fn gray_alpha_to_rgba(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 2);
    for ga in src.chunks_exact(2) {
        out.extend_from_slice(&[ga[0], ga[0], ga[0], ga[1]]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_rgba() {
        let image = ImageBytes {
            width: 2,
            height: 2,
            rgba: vec![
                255, 0, 0, 255, //
                0, 255, 0, 255, //
                0, 0, 255, 255, //
                255, 255, 255, 128,
            ],
        };
        let png = encode_png(&image).unwrap();
        let decoded = decode_png(&png).unwrap();
        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        assert_eq!(decoded.rgba, image.rgba);
    }
}
