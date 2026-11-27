# Oldframe Recomp

## Project goal

Build a native Windows executable for Warframe U5.1 by translating original
32-bit x86 game code and supplying the Windows and engine interfaces it
needs. The long-term target is to boot, reach the title screen, and enter
the tutorial with working movement and combat. The cache decoder and asset
preview are the first verified pieces of that work.

## Historical scope

This project targets the closed-beta Warframe U5.1 build, including its
original executable (build label `2012.12.31.16.20`, December 31, 2012),
cache files, assets, and related engine formats. The build label identifies
the executable rather than the publication date of the patch notes.
The purpose is historical game preservation through static recompilation,
local execution, verification against original x86 code, and development of
related cache and asset tools.

The target is a standalone historical client; server-dependent testing uses
a local SpaceNinjaServer instance. The project is independent of modern
Warframe and official live services and is not intended for online cheating.
Keep proprietary game inputs local and respect applicable rights and tool
restrictions.

## Local inputs

- Windows checkout `D:\GitHub\Oldframe-Recomp`. Run commands from the
  repository root containing `Cargo.toml` and `lift.py`.
- Original executable `D:\Warframe 2012\Warframe.exe`. The verified PE32
  build label is `2012.12.31.16.20`. See `INTERNALS.md` for the reference
  hash, addresses, and host interfaces.
- Installation root `D:\Warframe 2012`. The archive files and their
  `.toc` indexes are under `D:\Warframe 2012\Cache.Windows`.
- Use the native Windows environment for game-file access and Win32
  checks. Treat the original installation as read-only. Keep the original
  executable, DLLs, cache files, extracted game assets, and locally
  generated `src/lifted.rs` out of version control. Keep code changes local
  unless asked to publish them. Never commit proprietary game inputs or
  generated analysis databases.

## Session handoff and analysis

At the start of each session, inspect `git status`, the recent commits, and
`INTERNALS.md` for the latest verified checkpoint. The baseline below is a
reference, not a reason to redo completed work. Preserve existing human or
agent changes; do not reset, overwrite, or amend them. Use a separate branch
and worktree if another contributor is actively editing the same checkout.

Use REA with IDA/Hex-Rays or Ghidra when available. Prefer IDA for targeted
pseudocode when its adapter supports the requested operation; use Ghidra or
direct PE/Capstone analysis when necessary. Keep requests focused on changed
or unresolved boundaries rather than dumping large function lists or
reanalyzing known helpers. Treat decompiler output as analysis evidence, not
proof of equivalence; verify translated behavior against original x86.
Do not invent missing evidence or claim untested progress.

## Known working baseline

v0.10.0 currently passes all 20 unit tests on the user's Windows machine and displayed
the original SigninReward texture in a Win32 window. The preview uses Rust
for process startup and painting and translated x86 for archive reading and
decompression. The bounded translated startup path has reached constructor
checkpoint `0107B540` after 1,154 logical constructors, with 218 original-x86
comparisons covering all 19,440 admitted instructions. Continuous engine startup,
WinMain, and the title screen remain unverified. Read `README.md` and
`INTERNALS.md` before extending the lift.

## Local validation

Run the build and headless smoke checks with CMD. Run `py -m pip install -r
requirements.txt` once if Capstone is missing. Generate `src/lifted.rs`
before running Cargo. Change the generator when changing generated code.

```cmd
py lift.py "D:\Warframe 2012\Warframe.exe" && cargo test --offline && cargo run --release --offline -- "D:\Warframe 2012" && target\release\warframe-u51-decoder-recomp.exe "D:\Warframe 2012" --asset-info
```

For focused startup iteration, use the debug executable and Unicorn parity check:

```cmd
verify-startup-debug.cmd "D:\Warframe 2012"
```

Use `verify-startup.cmd "D:\Warframe 2012"` for optimized milestone builds and
the complete startup, cache, and asset regression suite.

The current v0.10.0 baseline is 20 tests. The known Windows archive sample matched
44 framed entries, 12 unframed entries, one stored frame, and 192 compressed
blocks across 25 archives. The preview asset is 43,708 decoded bytes, a
256 × 32 top mip, and three compressed frames. The archive totals describe
the user's installation. The Linux reference installation has a smaller
default sample because it lacks the extra English archives.

The interactive check is optional for routine runs. It stays open until
closed with Esc or the close button. Run it after the release build when
changing Windows rendering or window integration.

```cmd
target\release\warframe-u51-decoder-recomp.exe "D:\Warframe 2012" --window
```

## Next milestone

Continue the bounded original U5.1 startup path from constructor checkpoint
`0107B540`. Use table-derived constructor targets and generic grouped parity
checks while completing required initialization, then transition to a
continuous post-`__cinit` execution path toward `__wincmdln` at `00F22689`
and WinMain at `00401140`. Keep the cache path as a regression check.

Build a repeatable command that executes the translated startup code and logs
a named checkpoint. Verify at least one meaningful return value or state
change against the original x86 in equivalent conditions. Identify unsupported
instructions, calls, and imports by address so the next run can continue from
the first unresolved boundary. Document what Rust supplies and what runs as
translated game code.

Work through implementation, local builds, and recoverable failures without
waiting for a manual test after each edit. Keep changes small and update
`INTERNALS.md` with verified addresses, host calls, and the reproduction
command. Record the last verified checkpoint and the next concrete step if
progress stops. Report desktop-only checks that actually need someone at the
machine separately from the headless results.

## Git workflow

Create small, descriptive local commits after verified, meaningful milestones,
including the corresponding tests and checkpoint documentation. Review the
staged diff and stage only relevant changes; do not commit unrelated user work,
original binaries, assets, generated output, analysis databases, or local logs.
Do not rewrite history, force-push, or push unless explicitly requested.
If validation fails or the native inputs are unavailable, report the limitation
and distinguish unverified work from the last verified milestone.
