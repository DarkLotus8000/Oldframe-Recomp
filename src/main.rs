mod cache;
mod preview;
#[cfg(windows)]
mod window;

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::Path;
use std::process::ExitCode;
use warframe_u51_decoder_recomp::archive::plan_read;
use warframe_u51_decoder_recomp::{decode_entry, FrameCounts};

fn read_entry(
    archive: &mut BufReader<File>,
    entry: &cache::Entry,
) -> io::Result<(Vec<u8>, FrameCounts)> {
    let plan = plan_read(entry.offset, entry.packed_size, entry.size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read planner rejected {}", entry.path),
        )
    })?;
    let packed = plan.read_from(archive)?;
    if entry.packed_size == entry.size {
        return Ok((
            packed,
            FrameCounts {
                compressed: 0,
                stored: 0,
            },
        ));
    }
    let mut output = vec![0; entry.size as usize];
    let stats = decode_entry(&packed, &mut output).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stream rejected {}", entry.path),
        )
    })?;
    Ok((output, stats))
}

fn compare_entry(archive: &mut BufReader<File>, entry: &cache::Entry) -> io::Result<FrameCounts> {
    let mut expected = Vec::new();
    cache::extract(archive, entry, &mut expected)?;
    let (output, stats) = read_entry(archive, entry)?;
    if output != expected {
        let offset = output
            .iter()
            .zip(&expected)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| output.len().min(expected.len()));
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

fn cache_folder(input: &Path) -> std::path::PathBuf {
    let nested = input.join("Cache.Windows");
    if nested.is_dir() {
        nested
    } else {
        input.to_path_buf()
    }
}

fn compare_caches(folder: &Path) -> Result<(), Box<dyn Error>> {
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
    let mut args = std::env::args_os().skip(1);
    let usage = || {
        eprintln!("Usage: warframe-u51-decoder-recomp <Warframe folder or Cache.Windows> [--window | --asset-info | --startup]");
        ExitCode::from(2)
    };
    let Some(input) = args.next() else {
        return usage();
    };
    let mode = args.next();
    if args.next().is_some() {
        return usage();
    }
    let folder = cache_folder(Path::new(&input));
    let result = match mode.as_deref().and_then(|arg| arg.to_str()) {
        Some("--startup") => warframe_u51_decoder_recomp::startup::run_checkpoints().map_err(Into::into),
        None if mode.is_none() => compare_caches(&folder),
        Some("--asset-info") => preview::load(&folder).map(|_| ()).map_err(Into::into),
        #[cfg(windows)]
        Some("--window") => preview::load(&folder)
            .and_then(window::show)
            .map_err(Into::into),
        #[cfg(not(windows))]
        Some("--window") => {
            eprintln!(
                "[Error] --window requires Windows. Use --asset-info to check the texture here."
            );
            return ExitCode::FAILURE;
        }
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[Error] {error}");
            ExitCode::FAILURE
        }
    }
}
