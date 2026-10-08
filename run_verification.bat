@echo off
setlocal
cd /d "%~dp0"
echo ==============================================================================
echo  CYBERION DEFENSE LABS - ONE-CLICK VERIFICATION LAUNCHER
echo ==============================================================================

set "PYTHON_EXE=C:\Users\Hp\AppData\Local\Python\bin\python.exe"
if not exist "%PYTHON_EXE%" (
    set "PYTHON_EXE=python"
)

"%PYTHON_EXE%" verify_all.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Verification encountered errors.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [+] All deliverables, tests, and rules verified successfully!
pause
