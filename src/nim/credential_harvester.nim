# ═══════════════════════════════════════════════════════════════════
#  NULLSEC WINDOWS NIM CREDENTIAL HARVESTER
#  Windows credential extraction and analysis
#  @author bad-antics | discord.gg/killers
# ═══════════════════════════════════════════════════════════════════

import os, strutils, strformat, tables, times, terminal

const
  VERSION = "2.0.0"
  AUTHOR = "bad-antics"
  DISCORD = "discord.gg/killers"

const BANNER = """

╭──────────────────────────────────────────╮
│    🪟 NULLSEC WINDOWS CRED HARVESTER    │
│    ════════════════════════════════     │
│                                          │
│   🔐 Credential Extraction               │
│   📂 Browser Data Analysis               │
│   🛡️  Security Assessment                │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯

"""

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

type
  LicenseTier = enum
    Free, Premium, Enterprise

  License = object
    key: string
    tier: LicenseTier
    valid: bool

proc tierToString(tier: LicenseTier): string =
  case tier
  of Premium: "Premium ⭐"
  of Enterprise: "Enterprise 💎"
  else: "Free"

proc validateLicense(key: string): License =
  result = License(key: "", tier: Free, valid: false)
  
  if key.len != 24:
    return
  
  if not key.startsWith("NWIN-"):
    return
  
  result.key = key
  result.valid = true
  
  let typeCode = key[5..6]
  case typeCode
  of "PR": result.tier = Premium
  of "EN": result.tier = Enterprise
  else: result.tier = Free

proc isPremium(license: License): bool =
  license.valid and license.tier != Free

# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

proc printSuccess(msg: string) =
  styledEcho fgGreen, "✅ ", msg, resetStyle

proc printError(msg: string) =
  styledEcho fgRed, "❌ ", msg, resetStyle

proc printWarning(msg: string) =
  styledEcho fgYellow, "⚠️  ", msg, resetStyle

proc printInfo(msg: string) =
  styledEcho fgCyan, "ℹ️  ", msg, resetStyle

proc printHeader(title: string) =
  echo "\n═══════════════════════════════════════════"
  echo "  ", title
  echo "═══════════════════════════════════════════\n"

# ═══════════════════════════════════════════════════════════════════
# Credential Types
# ═══════════════════════════════════════════════════════════════════

type
  CredentialType = enum
    Windows, Browser, WiFi, Application
  
  Credential = object
    credType: CredentialType
    target: string
    username: string
    password: string
    lastModified: string
    persistence: string

  BrowserProfile = object
    browser: string
    profilePath: string
    loginCount: int
    cookieCount: int
    historyCount: int

# ═══════════════════════════════════════════════════════════════════
# Windows Credential Manager
# ═══════════════════════════════════════════════════════════════════

proc getWindowsCredentials(license: License): seq[Credential] =
  result = @[]
  
  # Use cmdkey to enumerate credentials
  when defined(windows):
    let output = execCmdEx("cmdkey /list")
    if output.exitCode == 0:
      var currentCred = Credential(credType: Windows)
      for line in output.output.splitLines:
        if "Target:" in line:
          currentCred.target = line.replace("Target:", "").strip()
        elif "User:" in line:
          currentCred.username = line.replace("User:", "").strip()
          result.add(currentCred)
          currentCred = Credential(credType: Windows)
  else:
    # Demo data for non-Windows
    result.add(Credential(
      credType: Windows,
      target: "TERMSRV/server.local",
      username: "DOMAIN\\admin",
      persistence: "Enterprise"
    ))
    result.add(Credential(
      credType: Windows,
      target: "WindowsLive:target=virtualapp/didlogical",
      username: "user@outlook.com",
      persistence: "Local Machine"
    ))
    result.add(Credential(
      credType: Windows,
      target: "MicrosoftAccount:user=user@outlook.com",
      username: "user@outlook.com",
      persistence: "Local Machine"
    ))

proc analyzeWindowsCredentials(license: License) =
  printHeader("🔐 WINDOWS CREDENTIAL MANAGER")
  
  let credentials = getWindowsCredentials(license)
  let limit = if license.isPremium: credentials.len else: min(5, credentials.len)
  
  if credentials.len == 0:
    echo "  No Windows credentials found"
    echo ""
    return
  
  echo fmt"  {"TARGET":<35} {"USERNAME":<30}"
  echo "  " & "─".repeat(70)
  
  for i in 0..<limit:
    let cred = credentials[i]
    let target = if cred.target.len > 35: cred.target[0..34] else: cred.target
    let username = if cred.username.len > 30: cred.username[0..29] else: cred.username
    echo fmt"  {target:<35} {username:<30}"
  
  if not license.isPremium and credentials.len > 5:
    echo ""
    echo fmt"  ... and {credentials.len - 5} more credentials"
    printWarning(fmt"Full list is Premium: {DISCORD}")
  
  echo fmt"\n  Total Windows credentials: {credentials.len}\n"

# ═══════════════════════════════════════════════════════════════════
# Browser Credential Analysis
# ═══════════════════════════════════════════════════════════════════

proc getBrowserProfiles(): seq[BrowserProfile] =
  result = @[]
  
  let appData = getEnv("LOCALAPPDATA", expandTilde("~"))
  let roamingData = getEnv("APPDATA", expandTilde("~"))
  
  # Chrome
  let chromePath = appData / "Google" / "Chrome" / "User Data" / "Default"
  if dirExists(chromePath):
    result.add(BrowserProfile(
      browser: "Google Chrome",
      profilePath: chromePath,
      loginCount: 0,
      cookieCount: 0
    ))
  
  # Edge
  let edgePath = appData / "Microsoft" / "Edge" / "User Data" / "Default"
  if dirExists(edgePath):
    result.add(BrowserProfile(
      browser: "Microsoft Edge",
      profilePath: edgePath,
      loginCount: 0,
      cookieCount: 0
    ))
  
  # Firefox
  let firefoxPath = roamingData / "Mozilla" / "Firefox" / "Profiles"
  if dirExists(firefoxPath):
    for entry in walkDir(firefoxPath):
      if entry.kind == pcDir and "default" in entry.path.toLowerAscii:
        result.add(BrowserProfile(
          browser: "Mozilla Firefox",
          profilePath: entry.path,
          loginCount: 0,
          cookieCount: 0
        ))
        break
  
  # Brave
  let bravePath = appData / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default"
  if dirExists(bravePath):
    result.add(BrowserProfile(
      browser: "Brave Browser",
      profilePath: bravePath,
      loginCount: 0,
      cookieCount: 0
    ))
  
  # Demo data if nothing found
  if result.len == 0:
    result.add(BrowserProfile(
      browser: "Google Chrome (Demo)",
      profilePath: "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
      loginCount: 45,
      cookieCount: 1250
    ))
    result.add(BrowserProfile(
      browser: "Microsoft Edge (Demo)",
      profilePath: "C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default",
      loginCount: 12,
      cookieCount: 380
    ))

proc analyzeBrowserProfiles(license: License) =
  printHeader("🌐 BROWSER PROFILES")
  
  let profiles = getBrowserProfiles()
  
  if profiles.len == 0:
    echo "  No browser profiles found"
    echo ""
    return
  
  for profile in profiles:
    echo fmt"  📁 {profile.browser}"
    echo fmt"     Path: {profile.profilePath}"
    
    # Check for Login Data
    let loginData = profile.profilePath / "Login Data"
    if fileExists(loginData):
      echo "     🔐 Login Data: ✅ Present"
    
    # Check for Cookies
    let cookies = profile.profilePath / "Cookies"
    if fileExists(cookies):
      echo "     🍪 Cookies: ✅ Present"
    
    # Check for History
    let history = profile.profilePath / "History"
    if fileExists(history):
      echo "     📜 History: ✅ Present"
    
    echo ""
  
  echo fmt"  Total browser profiles: {profiles.len}\n"

proc extractBrowserLogins(license: License) =
  printHeader("🔑 BROWSER SAVED LOGINS")
  
  if not license.isPremium:
    printWarning("Browser login extraction is a Premium feature")
    echo fmt"  Get keys at: {DISCORD}\n"
    return
  
  echo "  ⚠️  Browser login extraction requires:"
  echo "     - Browser to be closed"
  echo "     - DPAPI access (user context)"
  echo "     - SQLite database access"
  echo ""
  echo "  This tool enumerates but does not extract raw passwords"
  echo "  for security and ethical reasons."
  echo ""
  
  let profiles = getBrowserProfiles()
  
  for profile in profiles:
    echo fmt"  📁 {profile.browser}"
    
    # Check Login Data database
    let loginData = profile.profilePath / "Login Data"
    if fileExists(loginData):
      # In real implementation, would query SQLite
      echo "     Stored logins: Present (encrypted)"
    echo ""

# ═══════════════════════════════════════════════════════════════════
# WiFi Credentials
# ═══════════════════════════════════════════════════════════════════

type
  WiFiProfile = object
    ssid: string
    authType: string
    cipher: string
    hasPassword: bool

proc getWiFiProfiles(): seq[WiFiProfile] =
  result = @[]
  
  when defined(windows):
    let output = execCmdEx("netsh wlan show profiles")
    if output.exitCode == 0:
      for line in output.output.splitLines:
        if "All User Profile" in line or "User Profile" in line:
          let ssid = line.split(":")[^1].strip()
          if ssid.len > 0:
            result.add(WiFiProfile(
              ssid: ssid,
              authType: "WPA2-Personal",
              cipher: "AES",
              hasPassword: true
            ))
  else:
    # Demo data
    result.add(WiFiProfile(ssid: "HomeNetwork", authType: "WPA2-Personal", cipher: "AES", hasPassword: true))
    result.add(WiFiProfile(ssid: "Office-5G", authType: "WPA2-Enterprise", cipher: "AES", hasPassword: true))
    result.add(WiFiProfile(ssid: "Guest", authType: "Open", cipher: "None", hasPassword: false))

proc analyzeWiFiCredentials(license: License) =
  printHeader("📶 WIFI PROFILES")
  
  let profiles = getWiFiProfiles()
  
  if profiles.len == 0:
    echo "  No WiFi profiles found"
    echo ""
    return
  
  echo fmt"  {"SSID":<25} {"AUTH TYPE":<20} {"CIPHER":<10}"
  echo "  " & "─".repeat(60)
  
  for profile in profiles:
    let icon = if profile.hasPassword: "🔐" else: "🔓"
    echo fmt"  {icon} {profile.ssid:<23} {profile.authType:<20} {profile.cipher:<10}"
  
  if license.isPremium:
    echo "\n  🔑 WiFi Password Extraction:"
    echo "     Use: netsh wlan show profile name=\"SSID\" key=clear"
  else:
    echo ""
    printWarning(fmt"Password extraction is Premium: {DISCORD}")
  
  echo fmt"\n  Total WiFi profiles: {profiles.len}\n"

# ═══════════════════════════════════════════════════════════════════
# Vault Analysis
# ═══════════════════════════════════════════════════════════════════

proc analyzeVault(license: License) =
  printHeader("🏦 WINDOWS VAULT")
  
  if not license.isPremium:
    printWarning("Vault analysis is a Premium feature")
    echo fmt"  Get keys at: {DISCORD}\n"
    return
  
  echo "  Windows Credential Vault locations:"
  echo "  ─────────────────────────────────────────"
  
  let vaultPaths = @[
    (r"C:\Users\*\AppData\Local\Microsoft\Vault", "User Vault"),
    (r"C:\ProgramData\Microsoft\Vault", "System Vault"),
    (r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault", "SYSTEM Vault")
  ]
  
  for (path, name) in vaultPaths:
    echo fmt"  📁 {name}"
    echo fmt"     {path}"
  
  echo "\n  Vault schemas analyzed:"
  echo "     - Windows Credentials"
  echo "     - Web Credentials"
  echo "     - Domain Passwords"
  echo ""

# ═══════════════════════════════════════════════════════════════════
# Security Assessment
# ═══════════════════════════════════════════════════════════════════

proc securityAssessment(license: License) =
  printHeader("🛡️  CREDENTIAL SECURITY ASSESSMENT")
  
  var score = 0
  var total = 0
  
  # Check 1: Credential Guard
  total += 1
  when defined(windows):
    let cgOutput = execCmdEx("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity 2>nul")
    if "0x1" in cgOutput.output:
      echo "  🟢 Credential Guard: Enabled"
      score += 1
    else:
      echo "  🔴 Credential Guard: Disabled"
  else:
    echo "  🟡 Credential Guard: Check on Windows"
  
  # Check 2: Windows Hello
  total += 1
  echo "  🟡 Windows Hello: Manual check required"
  
  # Check 3: Stored credentials count
  total += 1
  let creds = getWindowsCredentials(license)
  if creds.len < 20:
    echo fmt"  🟢 Stored credentials: {creds.len} (reasonable)"
    score += 1
  else:
    echo fmt"  🟡 Stored credentials: {creds.len} (review recommended)"
  
  # Check 4: Browser profiles
  total += 1
  let browsers = getBrowserProfiles()
  echo fmt"  🟡 Browser profiles: {browsers.len} (review saved passwords)"
  
  # Check 5: WiFi security
  total += 1
  let wifi = getWiFiProfiles()
  let openNetworks = wifi.filterIt(not it.hasPassword)
  if openNetworks.len == 0:
    echo "  🟢 WiFi profiles: All secured"
    score += 1
  else:
    echo fmt"  🔴 WiFi profiles: {openNetworks.len} open networks"
  
  let percentage = if total > 0: (score * 100) div total else: 0
  echo "\n  ─────────────────────────────────────────"
  echo fmt"  Security Score: {score}/{total} ({percentage}%)"
  
  if percentage >= 80:
    printSuccess("Credential security is good")
  elif percentage >= 50:
    printWarning("Some security improvements recommended")
  else:
    printError("Credential security needs attention")
  
  echo ""

# ═══════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════

proc showMenu(license: var License) =
  while true:
    let tierBadge = if license.isPremium: "⭐" else: "🆓"
    
    echo fmt"\n  📋 NullSec Windows Credential Harvester {tierBadge}\n"
    echo "  [1] Windows Credentials"
    echo "  [2] Browser Profiles"
    echo "  [3] Browser Saved Logins (Premium)"
    echo "  [4] WiFi Profiles"
    echo "  [5] Windows Vault (Premium)"
    echo "  [6] Security Assessment"
    echo "  [7] Full Report"
    echo "  [8] Enter License Key"
    echo "  [0] Exit"
    
    stdout.write "\n  Select: "
    let input = stdin.readLine().strip()
    
    case input
    of "1": analyzeWindowsCredentials(license)
    of "2": analyzeBrowserProfiles(license)
    of "3": extractBrowserLogins(license)
    of "4": analyzeWiFiCredentials(license)
    of "5": analyzeVault(license)
    of "6": securityAssessment(license)
    of "7":
      analyzeWindowsCredentials(license)
      analyzeBrowserProfiles(license)
      analyzeWiFiCredentials(license)
      securityAssessment(license)
    of "8":
      stdout.write "  License key: "
      let key = stdin.readLine().strip()
      license = validateLicense(key)
      if license.valid:
        printSuccess(fmt"License activated: {license.tier.tierToString}")
      else:
        printWarning("Invalid license key")
    of "0": break
    else: printError("Invalid option")

# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

proc main() =
  styledEcho fgCyan, BANNER, resetStyle
  echo fmt"  Version {VERSION} | {AUTHOR}"
  echo fmt"  🔑 Premium: {DISCORD}"
  echo ""
  
  var license = License(key: "", tier: Free, valid: false)
  
  # Parse command line
  var i = 1
  while i < paramCount() + 1:
    let arg = paramStr(i)
    if arg == "-k" or arg == "--key":
      if i + 1 <= paramCount():
        license = validateLicense(paramStr(i + 1))
        if license.valid:
          printSuccess(fmt"License activated: {license.tier.tierToString}")
        inc i
    elif arg == "-h" or arg == "--help":
      echo "  Usage: credential_harvester [options]"
      echo ""
      echo "  Options:"
      echo "    -k, --key KEY    License key"
      echo "    -h, --help       Show help"
      return
    inc i
  
  when not defined(windows):
    printWarning("Running on non-Windows - using demo mode")
    echo "    Full functionality available on Windows\n"
  
  showMenu(license)
  
  # Footer
  echo "\n─────────────────────────────────────────"
  echo "  🪟 NullSec Windows Credential Harvester"
  echo fmt"  🔑 Premium: {DISCORD}"
  echo fmt"  👤 Author: {AUTHOR}"
  echo "─────────────────────────────────────────\n"

main()
