#Requires -Version 5.1
<#
.SYNOPSIS
    NullSec Windows PowerShell Security Module
    
.DESCRIPTION
    Native Windows security analysis and hardening tools
    
.AUTHOR
    bad-antics
    
.DISCORD
    discord.gg/killers
#>

$Script:VERSION = "2.0.0"
$Script:AUTHOR = "bad-antics"
$Script:DISCORD = "discord.gg/killers"

$Script:BANNER = @"
╭──────────────────────────────────────────╮
│      🪟 NULLSEC WINDOWS POWERSHELL       │
│       ════════════════════════════       │
│                                          │
│   🔧 Security Analysis Module v2.0       │
│   📡 Defender • Registry • Network       │
│   💾 Services & Scheduled Tasks          │
│                                          │
│            bad-antics | NullSec         │
╰──────────────────────────────────────────╯
"@

#region License Management

class NullSecLicense {
    [string]$Key
    [string]$Tier
    [bool]$Valid
    
    NullSecLicense([string]$key) {
        $this.Key = if ($key) { $key } else { "" }
        $this.Tier = "Free"
        $this.Valid = $false
        $this.Validate()
    }
    
    [void]Validate() {
        if ($this.Key.Length -ne 24 -or -not $this.Key.StartsWith("NWIN-")) {
            $this.Tier = "Free"
            $this.Valid = $false
            return
        }
        
        $parts = $this.Key.Split("-")
        if ($parts.Count -ne 5) {
            $this.Tier = "Free"
            $this.Valid = $false
            return
        }
        
        $tierCode = $parts[1].Substring(0, [Math]::Min(2, $parts[1].Length))
        switch ($tierCode) {
            "PR" { $this.Tier = "Premium" }
            "EN" { $this.Tier = "Enterprise" }
            default { $this.Tier = "Free" }
        }
        $this.Valid = $true
    }
    
    [bool]IsPremium() {
        return $this.Valid -and $this.Tier -ne "Free"
    }
}

$Script:License = [NullSecLicense]::new($null)

#endregion

#region Console Helpers

function Write-NullSecSuccess {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-NullSecError {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-NullSecWarning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-NullSecInfo {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

#endregion

#region Security Checks

function Get-NullSecDefenderStatus {
    <#
    .SYNOPSIS
        Get Windows Defender status
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n🛡️  Windows Defender Status:`n" -ForegroundColor Cyan
    
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($mpStatus.AntivirusEnabled) {
            Write-NullSecSuccess "Windows Defender is ENABLED"
        } else {
            Write-NullSecWarning "Windows Defender is DISABLED"
        }
        
        $rtIcon = if ($mpStatus.RealTimeProtectionEnabled) { "✅" } else { "⚠️" }
        $rtStatus = if ($mpStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $rtIcon Real-Time Protection: $rtStatus"
        
        $asIcon = if ($mpStatus.AntispywareEnabled) { "✅" } else { "⚠️" }
        $asStatus = if ($mpStatus.AntispywareEnabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $asIcon Antispyware: $asStatus"
        
        $bhIcon = if ($mpStatus.BehaviorMonitorEnabled) { "✅" } else { "⚠️" }
        $bhStatus = if ($mpStatus.BehaviorMonitorEnabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $bhIcon Behavior Monitor: $bhStatus"
        
        Write-Host "  📅 Last Signature Update: $($mpStatus.AntivirusSignatureLastUpdated)"
        Write-Host "  📊 Signature Version: $($mpStatus.AntivirusSignatureVersion)"
        
        return $mpStatus
    } catch {
        Write-NullSecError "Failed to get Defender status: $_"
    }
}

function Get-NullSecFirewallStatus {
    <#
    .SYNOPSIS
        Get Windows Firewall status for all profiles
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n🔥 Windows Firewall Status:`n" -ForegroundColor Cyan
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $true }).Count -eq $profiles.Count
        
        if ($allEnabled) {
            Write-NullSecSuccess "Firewall is ENABLED on all profiles"
        } else {
            Write-NullSecWarning "Firewall is partially enabled"
        }
        
        foreach ($profile in $profiles) {
            $icon = if ($profile.Enabled) { "✅" } else { "⚠️" }
            $status = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
            Write-Host "  $icon $($profile.Name): $status"
            Write-Host "      Default Inbound: $($profile.DefaultInboundAction)"
            Write-Host "      Default Outbound: $($profile.DefaultOutboundAction)"
        }
        
        return $profiles
    } catch {
        Write-NullSecError "Failed to get firewall status: $_"
    }
}

function Get-NullSecBitLockerStatus {
    <#
    .SYNOPSIS
        Get BitLocker encryption status for all drives
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n🔐 BitLocker Status:`n" -ForegroundColor Cyan
    
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        
        foreach ($vol in $volumes) {
            $icon = if ($vol.ProtectionStatus -eq "On") { "🔒" } else { "🔓" }
            Write-Host "  $icon Drive $($vol.MountPoint):"
            Write-Host "      Protection: $($vol.ProtectionStatus)"
            Write-Host "      Encryption: $($vol.VolumeStatus)"
            Write-Host "      Percentage: $($vol.EncryptionPercentage)%"
            
            if ($vol.KeyProtector) {
                Write-Host "      Key Protectors:"
                foreach ($kp in $vol.KeyProtector) {
                    Write-Host "        • $($kp.KeyProtectorType)"
                }
            }
        }
        
        return $volumes
    } catch {
        Write-NullSecWarning "BitLocker information not available"
        Write-NullSecInfo "Run as Administrator for full access"
    }
}

function Get-NullSecUACStatus {
    <#
    .SYNOPSIS
        Get UAC configuration status
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n🛡️  UAC Status:`n" -ForegroundColor Cyan
    
    try {
        $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $enableLUA = (Get-ItemProperty -Path $uacKey -Name EnableLUA -ErrorAction Stop).EnableLUA
        $consentPrompt = (Get-ItemProperty -Path $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $secureDesktop = (Get-ItemProperty -Path $uacKey -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop
        
        if ($enableLUA -eq 1) {
            Write-NullSecSuccess "UAC is ENABLED"
        } else {
            Write-NullSecError "UAC is DISABLED"
        }
        
        $level = switch ($true) {
            { $consentPrompt -eq 0 } { "Never notify (lowest security)"; "⚠️" }
            { $consentPrompt -eq 5 -and $secureDesktop -eq 0 } { "Notify without dimming"; "⚠️" }
            { $consentPrompt -eq 5 -and $secureDesktop -eq 1 } { "Default - Notify with dimming"; "✅" }
            { $consentPrompt -eq 2 } { "Always notify (highest security)"; "✅" }
            default { "Unknown"; "❓" }
        }
        
        Write-Host "  $($level[1]) Level: $($level[0])"
        
        return @{
            Enabled = $enableLUA -eq 1
            Level = $level[0]
        }
    } catch {
        Write-NullSecError "Failed to get UAC status: $_"
    }
}

#endregion

#region Network Analysis

function Get-NullSecActiveConnections {
    <#
    .SYNOPSIS
        Get active network connections
    #>
    [CmdletBinding()]
    param(
        [int]$Limit = 30
    )
    
    Write-Host "`n🌐 Active Connections:`n" -ForegroundColor Cyan
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Select-Object -First $Limit
        
        Write-Host "  Found $($connections.Count) established connections`n"
        
        foreach ($conn in $connections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($process) { $process.ProcessName } else { "Unknown" }
            
            Write-Host "  $($conn.LocalAddress):$($conn.LocalPort) → $($conn.RemoteAddress):$($conn.RemotePort)"
            Write-Host "      Process: $procName (PID: $($conn.OwningProcess))"
        }
        
        return $connections
    } catch {
        Write-NullSecError "Failed to get connections: $_"
    }
}

function Get-NullSecListeningPorts {
    <#
    .SYNOPSIS
        Get listening ports
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n📡 Listening Ports:`n" -ForegroundColor Cyan
    
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Sort-Object LocalPort
        
        Write-Host "  Found $($listeners.Count) listening ports`n"
        
        foreach ($listener in $listeners | Select-Object -First 30) {
            $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($process) { $process.ProcessName } else { "Unknown" }
            
            Write-Host "  :$($listener.LocalPort) - $procName (PID: $($listener.OwningProcess))"
        }
        
        return $listeners
    } catch {
        Write-NullSecError "Failed to get listening ports: $_"
    }
}

#endregion

#region Service Analysis

function Get-NullSecServiceAudit {
    <#
    .SYNOPSIS
        Audit Windows services
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n⚙️  Services Audit:`n" -ForegroundColor Cyan
    
    $services = Get-Service
    
    $running = ($services | Where-Object { $_.Status -eq "Running" }).Count
    $stopped = ($services | Where-Object { $_.Status -eq "Stopped" }).Count
    
    Write-Host "  Total Services: $($services.Count)"
    Write-Host "  Running: $running"
    Write-Host "  Stopped: $stopped"
    
    # Suspicious: Auto-start but stopped
    $suspicious = Get-WmiObject Win32_Service |
        Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Stopped" } |
        Select-Object -First 10
    
    if ($suspicious) {
        Write-Host "`n  ⚠️  Auto-start services that are stopped:" -ForegroundColor Yellow
        foreach ($svc in $suspicious) {
            Write-Host "      • $($svc.DisplayName)"
        }
    }
    
    # Unusual services (non-Microsoft)
    $nonMS = Get-WmiObject Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notlike "*\Windows\*" -and $_.PathName -notlike "*\Microsoft*" } |
        Select-Object -First 10
    
    if ($nonMS) {
        Write-Host "`n  📋 Non-Microsoft services:" -ForegroundColor Cyan
        foreach ($svc in $nonMS) {
            Write-Host "      • $($svc.DisplayName)"
            Write-Host "        Path: $($svc.PathName)"
        }
    }
    
    return $services
}

#endregion

#region Scheduled Tasks

function Get-NullSecScheduledTasks {
    <#
    .SYNOPSIS
        Analyze scheduled tasks
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n📅 Scheduled Tasks:`n" -ForegroundColor Cyan
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.State -eq "Ready" }
        
        Write-Host "  Found $($tasks.Count) active scheduled tasks`n"
        
        # Non-Microsoft tasks
        $customTasks = $tasks |
            Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
            Select-Object -First 20
        
        if ($customTasks) {
            Write-Host "  📋 Custom/Third-party tasks:" -ForegroundColor Cyan
            foreach ($task in $customTasks) {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                Write-Host "      • $($task.TaskName)"
                if ($info.LastRunTime) {
                    Write-Host "        Last Run: $($info.LastRunTime)"
                }
            }
        }
        
        return $tasks
    } catch {
        Write-NullSecError "Failed to get scheduled tasks: $_"
    }
}

#endregion

#region Startup Items

function Get-NullSecStartupItems {
    <#
    .SYNOPSIS
        Get startup items from registry and startup folders
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n🚀 Startup Items:`n" -ForegroundColor Cyan
    
    $startupItems = @()
    
    # Registry locations
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = $path
                }
            }
        }
    }
    
    Write-Host "  Found $($startupItems.Count) startup items`n"
    
    foreach ($item in $startupItems) {
        Write-Host "  • $($item.Name)"
        Write-Host "    $($item.Command)"
    }
    
    return $startupItems
}

#endregion

#region Premium Features

function Get-NullSecEventLogAnalysis {
    <#
    .SYNOPSIS
        Analyze security event logs (Premium)
    #>
    [CmdletBinding()]
    param(
        [int]$Count = 50
    )
    
    Write-Host "`n📋 Security Event Log:`n" -ForegroundColor Cyan
    
    if (-not $Script:License.IsPremium()) {
        Write-NullSecWarning "Event log analysis requires premium license"
        Write-NullSecInfo "Get premium at discord.gg/killers"
        return
    }
    
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents $Count -ErrorAction Stop
        
        Write-Host "  Found $($events.Count) recent security events`n"
        
        foreach ($event in $events | Select-Object -First 20) {
            Write-Host "  [$($event.TimeCreated)] Event $($event.Id)"
            Write-Host "      $($event.Message.Substring(0, [Math]::Min(80, $event.Message.Length)))..."
        }
        
        return $events
    } catch {
        Write-NullSecError "Failed to read event log: $_"
        Write-NullSecInfo "Run as Administrator"
    }
}

#endregion

#region Main Menu

function Show-NullSecMenu {
    <#
    .SYNOPSIS
        Show interactive menu
    #>
    
    Write-Host $Script:BANNER -ForegroundColor Cyan
    
    $tierBadge = switch ($Script:License.Tier) {
        "Premium" { "⭐" }
        "Enterprise" { "💎" }
        default { "🆓" }
    }
    
    $running = $true
    while ($running) {
        Write-Host "`n📋 NullSec Windows Menu $tierBadge`n" -ForegroundColor Cyan
        Write-Host "  [1] Windows Defender Status"
        Write-Host "  [2] Firewall Status"
        Write-Host "  [3] BitLocker Status"
        Write-Host "  [4] UAC Status"
        Write-Host "  [5] Active Connections"
        Write-Host "  [6] Listening Ports"
        Write-Host "  [7] Services Audit"
        Write-Host "  [8] Scheduled Tasks"
        Write-Host "  [9] Startup Items"
        Write-Host "  [10] Event Log (Premium)"
        Write-Host "  [0] Exit"
        Write-Host ""
        
        $choice = Read-Host "Select"
        
        switch ($choice) {
            "1" { Get-NullSecDefenderStatus }
            "2" { Get-NullSecFirewallStatus }
            "3" { Get-NullSecBitLockerStatus }
            "4" { Get-NullSecUACStatus }
            "5" { Get-NullSecActiveConnections }
            "6" { Get-NullSecListeningPorts }
            "7" { Get-NullSecServiceAudit }
            "8" { Get-NullSecScheduledTasks }
            "9" { Get-NullSecStartupItems }
            "10" { Get-NullSecEventLogAnalysis }
            "0" { $running = $false }
            default { Write-NullSecError "Invalid option" }
        }
    }
    
    Write-Host "`n─────────────────────────────────────────"
    Write-Host "🪟 NullSec Windows PowerShell"
    Write-Host "🔑 Premium: discord.gg/killers"
    Write-Host "🐦 GitHub: bad-antics"
    Write-Host "─────────────────────────────────────────`n"
}

# Export functions
Export-ModuleMember -Function @(
    'Get-NullSecDefenderStatus',
    'Get-NullSecFirewallStatus',
    'Get-NullSecBitLockerStatus',
    'Get-NullSecUACStatus',
    'Get-NullSecActiveConnections',
    'Get-NullSecListeningPorts',
    'Get-NullSecServiceAudit',
    'Get-NullSecScheduledTasks',
    'Get-NullSecStartupItems',
    'Get-NullSecEventLogAnalysis',
    'Show-NullSecMenu'
)

# Run menu if executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Show-NullSecMenu
}
