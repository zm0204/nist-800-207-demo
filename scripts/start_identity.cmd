@echo off
pushd "%~dp0.."
".venv\Scripts\python.exe" scripts\start_identity.py %*
set "INSPECTOR_EXIT=%ERRORLEVEL%"
popd
exit /b %INSPECTOR_EXIT%
