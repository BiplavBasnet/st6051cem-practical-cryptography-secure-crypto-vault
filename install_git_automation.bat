@echo off
set SCRIPT_PATH=%~dp0git_automator_v2.py
set PYTHON_EXE=C:\Users\ACER\AppData\Local\Programs\Python\Python313\python.exe

echo Creating Windows Scheduled Task for Pro Git Automation...
schtasks /create /tn "SecureCryptGitAutomator" /tr "\"%PYTHON_EXE%\" \"%SCRIPT_PATH%\"" /sc hourly /mo 4 /f

if %errorlevel% equ 0 (
    echo [OK] Task created successfully. It will run every 4 hours.
    echo [OK] Your future commits (Feb 16, 18, 20) will be dripped to GitHub automatically.
) else (
    echo [ERROR] Failed to create scheduled task. Please run as Administrator.
)
pause
