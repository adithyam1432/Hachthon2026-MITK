@echo off
setlocal
title AI PII Firewall - Full Test Suite Runner

cd /d "%~dp0"

echo ===============================================================================
echo            AI PII Firewall - Automated Test Suite Runner (341 Tests)
echo ===============================================================================
echo [INFO] Detecting Python runtime...
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

echo [ERROR] No valid Python installation detected.
pause
exit /b 1

:PYTHON_READY
echo [OK] Using Python:
%PY% --version
echo.

echo [INFO] Executing comprehensive test matrix (341 test cases)...
echo.
%PY% run_tests.py

echo.
echo ===============================================================================
echo  Execution finished. Press any key to close.
echo ===============================================================================
pause
