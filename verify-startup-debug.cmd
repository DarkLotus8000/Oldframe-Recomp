@echo off
setlocal
cd /d "%~dp0"
set "GAME_ROOT=%~1"
if not defined GAME_ROOT set "GAME_ROOT=D:\Warframe 2012"
py lift.py "%GAME_ROOT%\Warframe.exe" || exit /b 1
py -m unittest test_startup_lift || exit /b 1
cargo build --offline || exit /b 1
py verify_startup.py "%GAME_ROOT%\Warframe.exe" --native target\debug\warframe-u51-decoder-recomp.exe || exit /b 1
