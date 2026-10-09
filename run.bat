@echo off
setlocal
title AI PII ^& DLP Security Firewall

cd /d "%~dp0"

echo ===============================================================================
echo                 AI PII ^& DLP Security Firewall System
echo ===============================================================================
echo [INFO] Initializing runtime environment...
echo.

set "PY="

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY="%LOCALAPPDATA%\Programs\Python\Python311\python.exe""
    goto :PYTHON_READY
)

python -c "import sys" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PY=python
    goto :PYTHON_READY
)

py -3 -c "import sys" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PY=py -3
    goto :PYTHON_READY
)

for /f "delims=" %%I in ('where python 2^>nul') do (
    "%%I" -c "import sys" >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "PY="%%I""
        goto :PYTHON_READY
    )
)

echo [ERROR] No valid Python 3 installation found in PATH or standard directories.
echo [ERROR] Please install Python 3.10+ or disable Microsoft Store App execution aliases.
echo.
pause
exit /b 1

:PYTHON_READY
echo [OK] Python detected:
%PY% --version
echo.

:: Verify Streamlit installation
echo [INFO] Checking dependencies...
%PY% -c "import streamlit" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing required dependencies from requirements.txt...
    %PY% -m pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)
echo [OK] All dependencies verified.
echo.

echo ===============================================================================
echo  Launching Streamlit Web Dashboard:
echo  URL: http://localhost:8501
echo  Press Ctrl+C in this window to stop the server.
echo ===============================================================================
echo.

%PY% -m streamlit run app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] The application terminated with an error.
    pause
)
