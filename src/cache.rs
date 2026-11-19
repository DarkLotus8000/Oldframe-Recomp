use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub struct Entry {
    pub path: String,
    pub offset: u64,
    pub packed_size: u32,
    pub size: u32,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn read_toc(path: &Path) -> io::Result<Vec<Entry>> {
    let mut toc = BufReader::new(File::open(path)?);
    let mut header = [0; 8];
    toc.read_exact(&mut header)?;
    if header[..4] != [0x4e, 0xc6, 0x67, 0x18] {
        return Err(invalid("unexpected TOC signature"));
    }
    let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if !matches!(version, 16 | 20) {
        return Err(invalid(format!("unsupported TOC version {version}")));
    }

    let mut directories = vec![String::new()];
    let mut entries = Vec::new();
    let mut record = [0; 96];
    // A clean EOF ends the table. A partial 96-byte record is an error.
    while toc.read(&mut record[..1])? != 0 {
        toc.read_exact(&mut record[1..])?;
        let offset = i64::from_le_bytes(record[..8].try_into().unwrap());
        let packed_size = i32::from_le_bytes(record[16..20].try_into().unwrap());
        let size = i32::from_le_bytes(record[20..24].try_into().unwrap());
        let parent = u32::from_le_bytes(record[28..32].try_into().unwrap()) as usize;
        let name = record[32..].split(|&byte| byte == 0).next().unwrap();
        let name = String::from_utf8_lossy(name);
        let directory = directories
            .get(parent)
            .ok_or_else(|| invalid(format!("unknown parent directory {parent} for {name}")))?;
        let path = if directory.is_empty() {
            name.into_owned()
        } else {
            format!("{directory}/{name}")
        };

        if offset == -1 {
            directories.push(path);
        } else if offset >= 0 && packed_size >= 0 && size >= 0 {
            entries.push(Entry {
                path,
                offset: offset as u64,
                packed_size: packed_size as u32,
                size: size as u32,
            });
        } else {
            return Err(invalid(format!("invalid offset or size for {path}")));
        }
    }
    Ok(entries)
}

pub fn extract(
    cache: &mut (impl Read + Seek),
    entry: &Entry,
    output: &mut impl Write,
) -> io::Result<()> {
    cache.seek(SeekFrom::Start(entry.offset))?;
    let mut input = cache.take(u64::from(entry.packed_size));
    if entry.packed_size == entry.size {
        if io::copy(&mut input, output)? != u64::from(entry.size) {
            return Err(invalid("truncated uncompressed entry"));
        }
        return Ok(());
    }

    let mut remaining = entry.size as usize;
    let mut packed = Vec::new();
    let mut decoded = Vec::new();
    // Each block has big-endian packed and unpacked lengths.
    while remaining != 0 {
        let mut header = [0; 4];
        input.read_exact(&mut header)?;
        let packed_len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let decoded_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if packed_len == 0 || decoded_len == 0 || decoded_len > remaining {
            return Err(invalid("invalid legacy LZ block lengths"));
        }
        packed.resize(packed_len, 0);
        input.read_exact(&mut packed)?;
        if packed_len == decoded_len {
            output.write_all(&packed)?;
        } else {
            decode_lz(&packed, decoded_len, &mut decoded)?;
            output.write_all(&decoded)?;
        }
        remaining -= decoded_len;
    }
    if input.limit() != 0 {
        return Err(invalid("extra bytes after the last legacy LZ block"));
    }
    Ok(())
}

fn decode_lz(mut input: &[u8], expected: usize, output: &mut Vec<u8>) -> io::Result<()> {
    output.clear();
    while let Some((&control, rest)) = input.split_first() {
        input = rest;
        if control < 32 {
            let length = usize::from(control) + 1;
            if length > input.len() || length > expected - output.len() {
                return Err(invalid("invalid LZ literal length"));
            }
            let (literals, rest) = input.split_at(length);
            output.extend_from_slice(literals);
            input = rest;
            continue;
        }

        let mut length = usize::from(control >> 5) + 2;
        if control >> 5 == 7 {
            let (&extra, rest) = input
                .split_first()
                .ok_or_else(|| invalid("missing LZ length"))?;
            length += usize::from(extra);
            input = rest;
        }
        let (&low, rest) = input
            .split_first()
            .ok_or_else(|| invalid("missing LZ distance"))?;
        input = rest;
        let distance = (usize::from(control & 31) << 8) + usize::from(low) + 1;
        if distance > output.len() || length > expected - output.len() {
            return Err(invalid("invalid LZ back-reference"));
        }
        // A match may read bytes copied earlier in the same match.
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }
    if output.len() != expected {
        return Err(invalid("LZ block produced the wrong number of bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_raw_and_compressed_blocks_from_one_entry() {
        let data = [0, 1, 0, 1, b'X', 0, 4, 0, 6, 0, b'A', 0x60, 0];
        let entry = Entry {
            path: "test".into(),
            offset: 0,
            packed_size: data.len() as u32,
            size: 7,
        };
        let mut output = Vec::new();

        extract(&mut io::Cursor::new(data), &entry, &mut output).unwrap();
        assert_eq!(output, b"XAAAAAA");
    }

    #[test]
    fn rejects_a_reference_before_the_start_of_a_block() {
        assert!(decode_lz(&[0x20, 0], 3, &mut Vec::new()).is_err());
    }
}
