@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  NULLSEC WINDOWS BATCH TOOLKIT
REM  Windows batch scripts for security analysis
REM  @author bad-antics | x.com/AnonAntics
REM ═══════════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

set VERSION=2.0.0
set AUTHOR=bad-antics
set TWITTER=x.com/AnonAntics

:banner
echo.
echo  ╭──────────────────────────────────────────╮
echo  │      🪟 NULLSEC WINDOWS BATCH TOOLS      │
echo  │      ════════════════════════════        │
echo  │                                          │
echo  │   🔧 Legacy Windows Compatibility        │
echo  │   📡 No Dependencies Required            │
echo  │   💾 Portable Security Scripts           │
echo  │                                          │
echo  │          bad-antics ^| NullSec           │
echo  ╰──────────────────────────────────────────╯
echo.

:main_menu
echo  ═══════════════════════════════════════════
echo   NULLSEC BATCH MENU
echo  ═══════════════════════════════════════════
echo.
echo   [1] System Information
echo   [2] Security Status
echo   [3] Network Analysis
echo   [4] Service Audit
echo   [5] User Enumeration
echo   [6] Installed Software
echo   [7] Scheduled Tasks
echo   [8] Environment Variables
echo   [9] Full Security Scan
echo   [0] Exit
echo.
set /p choice=Select Option: 

if "%choice%"=="1" goto system_info
if "%choice%"=="2" goto security_status
if "%choice%"=="3" goto network_analysis
if "%choice%"=="4" goto service_audit
if "%choice%"=="5" goto user_enum
if "%choice%"=="6" goto installed_software
if "%choice%"=="7" goto scheduled_tasks
if "%choice%"=="8" goto env_vars
if "%choice%"=="9" goto full_scan
if "%choice%"=="0" goto end
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM SYSTEM INFORMATION
REM ═══════════════════════════════════════════════════════════════════
:system_info
echo.
echo  ═══════════════════════════════════════════
echo   💻 SYSTEM INFORMATION
echo  ═══════════════════════════════════════════
echo.

echo  [+] Computer Name: %COMPUTERNAME%
echo  [+] Username: %USERNAME%
echo  [+] Domain: %USERDOMAIN%
echo  [+] Architecture: %PROCESSOR_ARCHITECTURE%
echo  [+] Processors: %NUMBER_OF_PROCESSORS%
echo.

echo  [+] Windows Version:
for /f "tokens=2 delims==" %%i in ('wmic os get caption /value ^| find "Caption"') do echo      %%i

echo.
echo  [+] System Boot Time:
for /f "tokens=2 delims==" %%i in ('wmic os get lastbootuptime /value ^| find "LastBootUpTime"') do echo      %%i

echo.
echo  [+] System Directory: %SystemRoot%
echo  [+] Temp Directory: %TEMP%
echo.

pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM SECURITY STATUS
REM ═══════════════════════════════════════════════════════════════════
:security_status
echo.
echo  ═══════════════════════════════════════════
echo   🔒 SECURITY STATUS
echo  ═══════════════════════════════════════════
echo.

echo  [+] Checking Windows Defender...
sc query WinDefend > nul 2>&1
if %errorlevel% equ 0 (
    echo      ✅ Windows Defender Service: Found
    sc query WinDefend | find "RUNNING" > nul 2>&1
    if !errorlevel! equ 0 (
        echo      ✅ Status: Running
    ) else (
        echo      ⚠️  Status: Not Running
    )
) else (
    echo      ❌ Windows Defender: Not Found
)

echo.
echo  [+] Checking Windows Firewall...
for %%P in (Domain Standard Public) do (
    netsh advfirewall show %%Pprofile state | find "ON" > nul 2>&1
    if !errorlevel! equ 0 (
        echo      ✅ %%P Profile: Enabled
    ) else (
        echo      ⚠️  %%P Profile: Disabled
    )
)

echo.
echo  [+] Checking UAC Status...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul | find "0x1" >nul
if %errorlevel% equ 0 (
    echo      ✅ UAC: Enabled
) else (
    echo      ⚠️  UAC: Disabled
)

echo.
echo  [+] Checking BitLocker Status...
manage-bde -status %SystemDrive% 2>nul | find "Protection On" >nul
if %errorlevel% equ 0 (
    echo      ✅ BitLocker (%SystemDrive%): Enabled
) else (
    echo      ⚠️  BitLocker (%SystemDrive%): Not Enabled or Not Available
)

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM NETWORK ANALYSIS
REM ═══════════════════════════════════════════════════════════════════
:network_analysis
echo.
echo  ═══════════════════════════════════════════
echo   🌐 NETWORK ANALYSIS
echo  ═══════════════════════════════════════════
echo.

echo  [+] IP Configuration:
echo  ─────────────────────
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo      IPv4:%%a

echo.
echo  [+] Gateway:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"Default Gateway" ^| findstr /v "0.0.0.0"') do echo      Gateway:%%a

echo.
echo  [+] DNS Servers:
for /f "tokens=2 delims=:" %%a in ('ipconfig /all ^| findstr /c:"DNS Servers"') do echo      DNS:%%a

echo.
echo  [+] Active Connections (Established):
echo  ─────────────────────────────────────
netstat -an | find "ESTABLISHED"

echo.
echo  [+] Listening Ports:
echo  ────────────────────
netstat -an | find "LISTENING" | find "0.0.0.0"

echo.
echo  [+] ARP Cache:
echo  ──────────────
arp -a | findstr /v "Interface"

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM SERVICE AUDIT
REM ═══════════════════════════════════════════════════════════════════
:service_audit
echo.
echo  ═══════════════════════════════════════════
echo   ⚙️  SERVICE AUDIT
echo  ═══════════════════════════════════════════
echo.

echo  [+] Running Services Count:
for /f %%i in ('sc query state^= running ^| find /c "SERVICE_NAME"') do echo      %%i services running

echo.
echo  [+] Security-Related Services:
echo  ──────────────────────────────

set SECURITY_SERVICES=WinDefend mpssvc wscsvc Sense SecurityHealthService

for %%S in (%SECURITY_SERVICES%) do (
    sc query %%S > nul 2>&1
    if !errorlevel! equ 0 (
        sc query %%S | find "RUNNING" > nul 2>&1
        if !errorlevel! equ 0 (
            echo      ✅ %%S: Running
        ) else (
            echo      ⚠️  %%S: Stopped
        )
    ) else (
        echo      ❌ %%S: Not Found
    )
)

echo.
echo  [+] Recently Modified Services (check manually):
echo      Use: sc query state= all ^| more
echo.

pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM USER ENUMERATION
REM ═══════════════════════════════════════════════════════════════════
:user_enum
echo.
echo  ═══════════════════════════════════════════
echo   👤 USER ENUMERATION
echo  ═══════════════════════════════════════════
echo.

echo  [+] Current User: %USERNAME%
echo  [+] User Domain: %USERDOMAIN%
echo.

echo  [+] Local Users:
echo  ────────────────
net user 2>nul | findstr /v "command completed"

echo.
echo  [+] Local Administrators:
echo  ─────────────────────────
net localgroup administrators 2>nul | findstr /v "command completed" | findstr /v "Alias" | findstr /v "Comment" | findstr /v "Members" | findstr /v "----"

echo.
echo  [+] Logged On Users:
query user 2>nul
if %errorlevel% neq 0 (
    echo      Unable to query users or no users logged on
)

echo.
echo  [+] User Privileges:
whoami /priv 2>nul | findstr /i "enabled"

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM INSTALLED SOFTWARE
REM ═══════════════════════════════════════════════════════════════════
:installed_software
echo.
echo  ═══════════════════════════════════════════
echo   📦 INSTALLED SOFTWARE
echo  ═══════════════════════════════════════════
echo.

echo  [+] Installed Programs (via Registry):
echo  ───────────────────────────────────────
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /i "DisplayName" | findstr /v "KB" | sort

echo.
echo  [+] Security Software:
echo  ──────────────────────
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul | findstr /i "DisplayName" | findstr /i "security antivirus defender norton mcafee kaspersky bitdefender avg avast malware" 2>nul

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM SCHEDULED TASKS
REM ═══════════════════════════════════════════════════════════════════
:scheduled_tasks
echo.
echo  ═══════════════════════════════════════════
echo   📅 SCHEDULED TASKS
echo  ═══════════════════════════════════════════
echo.

echo  [+] Scheduled Tasks (Top 30):
echo  ─────────────────────────────
schtasks /query /fo table 2>nul | findstr /v "^$" | findstr /v "Folder" | head -30

echo.
echo  [+] Tasks Running as SYSTEM:
schtasks /query /fo csv /v 2>nul | findstr /i "SYSTEM" | findstr /v "Microsoft" | head -10

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM ENVIRONMENT VARIABLES
REM ═══════════════════════════════════════════════════════════════════
:env_vars
echo.
echo  ═══════════════════════════════════════════
echo   🔧 ENVIRONMENT VARIABLES
echo  ═══════════════════════════════════════════
echo.

echo  [+] System Environment:
echo  ───────────────────────
echo      SystemRoot: %SystemRoot%
echo      SystemDrive: %SystemDrive%
echo      ProgramFiles: %ProgramFiles%
echo      ProgramData: %ProgramData%
echo      CommonProgramFiles: %CommonProgramFiles%

echo.
echo  [+] User Environment:
echo  ─────────────────────
echo      UserProfile: %USERPROFILE%
echo      AppData: %APPDATA%
echo      LocalAppData: %LOCALAPPDATA%
echo      Temp: %TEMP%

echo.
echo  [+] Path (first 5 entries):
echo  ───────────────────────────
for /f "tokens=1-5 delims=;" %%a in ("%PATH%") do (
    echo      1: %%a
    echo      2: %%b
    echo      3: %%c
    echo      4: %%d
    echo      5: %%e
)

echo.
pause
goto main_menu

REM ═══════════════════════════════════════════════════════════════════
REM FULL SECURITY SCAN
REM ═══════════════════════════════════════════════════════════════════
:full_scan
echo.
echo  ═══════════════════════════════════════════
echo   🔍 FULL SECURITY SCAN
echo  ═══════════════════════════════════════════
echo.
echo   This will run all security checks...
echo.

set REPORT_FILE=%TEMP%\nullsec_scan_%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.txt
set REPORT_FILE=%REPORT_FILE: =0%

echo  [+] Saving report to: %REPORT_FILE%
echo.

(
    echo ═══════════════════════════════════════════════════════════════════
    echo  NULLSEC WINDOWS SECURITY SCAN REPORT
    echo  Generated: %DATE% %TIME%
    echo  Computer: %COMPUTERNAME%
    echo  User: %USERNAME%
    echo ═══════════════════════════════════════════════════════════════════
    echo.
    
    echo [SYSTEM INFORMATION]
    echo ────────────────────
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory"
    echo.
    
    echo [SECURITY STATUS]
    echo ─────────────────
    echo Checking Windows Defender...
    sc query WinDefend 2>nul | findstr "STATE"
    echo.
    echo Firewall Status:
    netsh advfirewall show allprofiles state
    echo.
    
    echo [NETWORK CONNECTIONS]
    echo ─────────────────────
    netstat -an | find "ESTABLISHED"
    echo.
    
    echo [LOCAL USERS]
    echo ─────────────
    net user
    echo.
    
    echo [ADMINISTRATORS]
    echo ────────────────
    net localgroup administrators
    echo.
    
    echo [LISTENING PORTS]
    echo ─────────────────
    netstat -an | find "LISTENING"
    echo.
    
    echo ═══════════════════════════════════════════════════════════════════
    echo  End of Report
    echo  NullSec Windows Batch Tools v%VERSION%
    echo  bad-antics ^| x.com/AnonAntics
    echo ═══════════════════════════════════════════════════════════════════
) > "%REPORT_FILE%" 2>&1

echo  ✅ Scan complete!
echo  📄 Report saved to: %REPORT_FILE%
echo.

set /p open_report=Open report? (Y/N): 
if /i "%open_report%"=="Y" notepad "%REPORT_FILE%"

pause
goto main_menu

:end
echo.
echo  ─────────────────────────────────────────
echo   🪟 NullSec Windows Batch Tools
echo   🔑 Premium: x.com/AnonAntics
echo   🐦 GitHub: bad-antics
echo  ─────────────────────────────────────────
echo.
echo  Thanks for using NullSec!
echo.
endlocal
exit /b 0
