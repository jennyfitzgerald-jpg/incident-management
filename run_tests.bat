@echo off
cd /d "%~dp0"
python tests\test_auth.py
if errorlevel 1 exit /b 1
echo.
echo All tests passed.
exit /b 0
