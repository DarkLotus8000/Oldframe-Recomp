@echo off
setlocal
cd /d "%~dp0"
set "GAME_ROOT=%~1"
if not defined GAME_ROOT set "GAME_ROOT=D:\Warframe 2012"
py lift.py "%GAME_ROOT%\Warframe.exe" || exit /b 1
py -m unittest test_startup_lift || exit /b 1
cargo test --offline || exit /b 1
cargo build --release --offline || exit /b 1
py verify_startup.py "%GAME_ROOT%\Warframe.exe" || exit /b 1
target\release\warframe-u51-decoder-recomp.exe "%GAME_ROOT%" || exit /b 1
target\release\warframe-u51-decoder-recomp.exe "%GAME_ROOT%" --asset-info || exit /b 1
