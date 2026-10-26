@echo off
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" scripts\open_inspector.py --isolated --chrome
) else if exist "..\zta-207a\.venv\Scripts\python.exe" (
  "..\zta-207a\.venv\Scripts\python.exe" scripts\open_inspector.py --isolated --chrome
) else (
  py scripts\open_inspector.py --isolated --chrome
)
if errorlevel 1 pause
