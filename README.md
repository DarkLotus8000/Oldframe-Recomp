# Warframe U5.1 decoder recompilation

This project statically translates twelve cache routines in the 32-bit U5.1
`Warframe.exe`. `CacheThreadImpl::CalculateReadPages` at `0x004A5C60`
determines the byte span and its inclusive range of 64 KiB archive pages.
The stream constructor at `0x004B3460`
initializes the stream. The setup routine at `0x004B3AA0` binds an input and
output buffer, selects an output mode, and returns the bytes read and written.
The whole-entry driver at `0x004B3930` reads the framed data
for a cache entry in one call. Its block reader at `0x004B3860` reads the
four-byte headers, copies stored blocks, and calls the decoder at
`0x00F372B0` for compressed blocks. The original decoder wrapper at
`0x004B1C10` is also available through `decode_block`.

`lift.py` uses Capstone to decode the routines and resolve the decoder's
32-entry jump table. It writes their Rust translation to `src/lifted.rs`,
including the x86 call and return through the original stack convention. Cargo
compiles the result. The harness reads TOC records with the Rust reader,
uses the lifted routine to plan each archive read, then uses Rust file I/O to
read the requested parts of those pages. Framed entries go through the
translated stream code. Rust validates frame bounds and supplies the
memory-copy and allocation calls. A
`VirtualQuery` shim reports the guest buffer as ordinary read/write memory.

See [INTERNALS.md](INTERNALS.md) for the routine map, host boundaries, and verification details.

## Run on Windows

Unzip the project and open CMD in the folder containing `Cargo.toml`.
Use Python 3 and the Rust toolchain you used to build the cache extractor.
Replace both example paths with the locations of your U5.1 executable and
installation.

```cmd
py -m pip install -r requirements.txt && py lift.py "D:\Warframe 2012\Warframe.exe" && cargo test --offline && cargo run --release --offline -- "D:\Warframe 2012"
```

The last command also accepts the `Cache.Windows` folder. The harness checks
each decoded entry against the existing Rust cache extractor. It samples
`SigninReward`, both copies of
`HangingWarehouseBlocks.lua`, and a texture containing a stored frame. On the
archived U5.1 cache, expect 40 framed entries, 9 unframed entries, one stored
frame, and
`PASS: 187 compressed blocks matched across 21 archives.`
The Windows installation with four additional English `_en` archives samples
192 compressed blocks across 25 archives.

The translator checks the routines' instruction bytes and the table against the
verified U5.1 build. If generation reports a mismatch, use the matching
`2012.12.31.16.20` U5.1 executable. Generation needs the executable, and the
compiled program only needs the cache. The ZIP contains the translator and
harness source. Generate `src/lifted.rs` locally before running Cargo.

To inspect the generated LLVM IR, run this after generation and look under
`target\release\deps` for the `.ll` file.

```cmd
cargo rustc --release --lib --offline -- --emit=llvm-ir
```

## Code

- `lift.py` decodes the routines, resolves the jump table, and writes Rust.
- `src/archive.rs` calls the translated archive page planner.
- `src/lib.rs` supplies the buffers, ring state, and 32-bit stack arguments.
- `src/main.rs` compares the compiled result with the reference decoder.
- `src/cache.rs` is the TOC reader and reference decoder from the Rust extractor.

The harness selects ordinary synchronous cache decompression and reads nonempty
whole entries. The unit tests cover 64-bit archive offsets, page boundaries,
constructor setup, direct output, mixed stored and compressed entries, failure
partway through an entry, and frames split across the input ring.
