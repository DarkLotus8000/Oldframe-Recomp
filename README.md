# Oldframe Recomp

Oldframe Recomp is a native Windows recompilation project for Warframe U5.1.
The current executable verifies cache reads, displays a real game texture,
and runs the original PE entry through CRT cookie, SEH, heap, per-thread,
locale, lock, and standard-handle initialization. These checkpoints are verified against original x86;
engine startup, the title screen, and the playable tutorial remain future work.

This project statically translates selected cache code from the 32-bit U5.1
`Warframe.exe`. `CacheThreadImpl::CalculateReadPages` at `0x004A5C60`
determines the byte span and its inclusive range of 64 KiB archive pages.
`CacheThreadImpl::StartIOBufferLoad` at `0x004A6C20` builds the corresponding
`ReadFileEx` request for each page. The callback at `0x004A6BA0` passes a
successful read to `CacheThreadImpl::FinishIOBufferLoad`, which marks the
buffer ready and signals the I/O semaphore. The first part of
`CacheThreadImpl::LoadBufferIntoOp` at `0x004AA550` selects the entry's bytes
within the ready page.
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
uses the lifted routines to plan and submit the reads, and fills the guest
buffers synchronously with Rust file I/O. It delivers each successful read to
the lifted completion callback and uses the guest pointers returned by the
span selector to assemble the entry. Framed entries go through the translated
stream code. Rust validates frame bounds and supplies the
memory-copy and allocation calls. A
`VirtualQuery` shim reports the guest buffer as ordinary read/write memory.

See [INTERNALS.md](INTERNALS.md) for the routine map, host boundaries, and verification details.

## Continue in Codex

Open `D:\GitHub\Oldframe-Recomp` as a local project in Codex on Windows.
[AGENTS.md](AGENTS.md) records the original executable and cache paths, the
working baseline, and the commands Codex can run from CMD for validation.
Start a new thread in the repo and paste this goal.

```text
/goal Read AGENTS.md and INTERNALS.md and continue from the last verified CRT startup checkpoint toward the U5.1 title screen and playable tutorial with movement and basic combat. Verify new translated behavior against original x86, preserve verify-startup.cmd checks, and record checkpoints in INTERNALS.md. Verify the title screen independently of SpaceNinjaServer; use the local server only when login or later steps require it. Keep changes local and the original installation read-only.
```

## Run on Windows

To reproduce the startup milestone and all headless regression checks from CMD:

```cmd
py -m pip install -r requirements-verify.txt
verify-startup.cmd "D:\Warframe 2012"
```

This generates the translations, runs tests and the release build, compares
89 startup cases with original x86 in Unicorn, and checks caches and the
preview asset. Run `target\release\warframe-u51-decoder-recomp.exe . --startup`
for the compiled checkpoint alone. See [INTERNALS.md](INTERNALS.md) for the
deterministic Windows API fixtures, verified state changes, and next boundary.

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

### Open the asset preview window

From the same CMD window, build and run the preview with this command. Skip
`py lift.py` if you already generated `src/lifted.rs` for this version.

```cmd
py lift.py "D:\Warframe 2012\Warframe.exe" && cargo run --release --offline -- "D:\Warframe 2012" --window
```

The window should show a blue bar from the original SigninReward interface on
a black background. The asset comes from `B.TextureDx9` through the same
translated cache path as the verifier. Close the window with Esc or the close
button. Use `--asset-info` in place of `--window` to verify asset loading
without opening a window. The expected asset is 43,708 decoded bytes with a
256 × 32 top mip level.

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
- `src/archive.rs` runs the translated page planner, read submission, completion, and span selection.
- `src/lib.rs` supplies the buffers, ring state, and 32-bit stack arguments.
- `src/main.rs` compares the compiled result with the reference decoder.
- `src/cache.rs` is the TOC reader and reference decoder from the Rust extractor.
- `src/preview.rs` loads the SigninReward texture through the same entry read as the verifier.
- `src/window.rs` opens the Windows preview and paints the decoded texture with GDI.

The harness selects ordinary synchronous cache decompression and reads nonempty
whole entries. The unit tests cover 64-bit archive offsets, short final pages,
completion state and error handling, byte selection on ready pages,
constructor setup, mixed stored and compressed entries, failure partway
through an entry, and frames split across the input ring.
