mod cache;

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use warframe_u51_decoder_recomp::archive::{plan_read, PAGE_SIZE};
use warframe_u51_decoder_recomp::{decode_entry, FrameCounts};

fn read_planned_entry(archive: &mut BufReader<File>, entry: &cache::Entry) -> io::Result<Vec<u8>> {
    let plan = plan_read(entry.offset, entry.packed_size, entry.size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read planner rejected {}", entry.path),
        )
    })?;
    let mut bytes = vec![0; plan.bytes as usize];
    let end = plan.offset + plan.bytes;
    archive.seek(SeekFrom::Start(plan.offset))?;
    for page in plan.first_page..=plan.last_page {
        let page_start = page * PAGE_SIZE;
        let start = page_start.max(plan.offset) - plan.offset;
        let stop = page_start.saturating_add(PAGE_SIZE).min(end) - plan.offset;
        archive.read_exact(&mut bytes[start as usize..stop as usize])?;
    }
    Ok(bytes)
}

fn compare_entry(archive: &mut BufReader<File>, entry: &cache::Entry) -> io::Result<FrameCounts> {
    let mut expected = Vec::new();
    cache::extract(archive, entry, &mut expected)?;
    let packed = read_planned_entry(archive, entry)?;

    let (output, stats) = if entry.packed_size == entry.size {
        (
            packed,
            FrameCounts {
                compressed: 0,
                stored: 0,
            },
        )
    } else {
        let mut output = vec![0; expected.len()];
        let stats = decode_entry(&packed, &mut output).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stream rejected {}", entry.path),
            )
        })?;
        (output, stats)
    };
    if let Some(offset) = output
        .iter()
        .zip(&expected)
        .position(|(actual, expected)| actual != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "stream mismatch at output offset {offset} in {}",
                entry.path
            ),
        ));
    }
    Ok(stats)
}

fn compare_caches(input: &Path) -> Result<(), Box<dyn Error>> {
    let nested = input.join("Cache.Windows");
    let folder = if nested.is_dir() { &nested } else { input };
    let mut tables = Vec::new();
    for dir_entry in fs::read_dir(folder)? {
        let path = dir_entry?.path();
        if path.extension().is_some_and(|ext| ext == "toc") {
            tables.push(path);
        }
    }
    tables.sort();

    let mut blocks = 0;
    let mut stored = 0;
    let mut archives = 0;
    let mut entries_checked = 0;
    let mut raw_entries = 0;
    for table in tables {
        let name = table.file_stem().unwrap().to_string_lossy();
        let mut count = 0;
        let mut checked_raw = false;
        let entries = cache::read_toc(&table)?;
        let mut archive = BufReader::new(File::open(table.with_extension("cache"))?);
        for entry in entries {
            if entry.packed_size == entry.size {
                if !checked_raw && entry.size != 0 {
                    compare_entry(&mut archive, &entry)?;
                    checked_raw = true;
                    raw_entries += 1;
                }
                continue;
            }
            let path = entry.path.to_ascii_lowercase();
            let example = path.contains("signinreward")
                || path.ends_with("/hangingwarehouseblocks.lua")
                || (name == "B.TextureDx9" && path == "ee/materials/basic/shineblue_cube0.png");
            if example || count == 0 {
                let stats = compare_entry(&mut archive, &entry)?;
                count += stats.compressed;
                stored += stats.stored;
                entries_checked += 1;
            }
        }
        if count > 0 {
            println!("{name}: {count} blocks matched");
            blocks += count;
            archives += 1;
        }
    }

    if blocks == 0 {
        return Err("no compressed blocks found in the supplied cache".into());
    }
    println!("Whole entries matched: {entries_checked}.");
    println!("Unframed entries matched: {raw_entries}.");
    println!("Stored frames matched: {stored}.");
    println!("PASS: {blocks} compressed blocks matched across {archives} archives.");
    Ok(())
}

fn main() -> ExitCode {
    let Some(input) = std::env::args_os().nth(1) else {
        eprintln!("Usage: cargo run --release -- <Warframe folder or Cache.Windows>");
        return ExitCode::from(2);
    };
    match compare_caches(&PathBuf::from(input)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[Error] {error}");
            ExitCode::FAILURE
        }
    }
}
