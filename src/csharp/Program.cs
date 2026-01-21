// NullSec Windows Security Toolkit - C#
// Native Windows security analysis
// @author @AnonAntics
// @discord discord.gg/killers

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;

namespace NullSecWindows
{
    #region Constants and Configuration
    
    public static class Config
    {
        public const string VERSION = "2.0.0";
        public const string AUTHOR = "@AnonAntics";
        public const string DISCORD = "discord.gg/killers";
        
        public const string BANNER = @"
╭──────────────────────────────────────────╮
│        🪟 NULLSEC WINDOWS TOOLKIT        │
│       ════════════════════════════       │
│                                          │
│   🔧 Native Security Analysis v2.0       │
│   📡 Defender • BitLocker • Network      │
│   💾 Registry & Event Log Analysis       │
│                                          │
│            @AnonAntics | NullSec         │
╰──────────────────────────────────────────╯";
    }
    
    #endregion
    
    #region License Management
    
    public enum LicenseTier { Free, Premium, Enterprise }
    
    public class License
    {
        public string Key { get; set; }
        public LicenseTier Tier { get; set; }
        public bool Valid { get; set; }
        
        public License(string key = null)
        {
            Key = key ?? "";
            Tier = LicenseTier.Free;
            Valid = false;
            Validate();
        }
        
        private void Validate()
        {
            if (Key.Length != 24 || !Key.StartsWith("NWIN-"))
            {
                Tier = LicenseTier.Free;
                Valid = false;
                return;
            }
            
            var parts = Key.Split('-');
            if (parts.Length != 5)
            {
                Tier = LicenseTier.Free;
                Valid = false;
                return;
            }
            
            var tierCode = parts[1].Substring(0, Math.Min(2, parts[1].Length));
            Tier = tierCode switch
            {
                "PR" => LicenseTier.Premium,
                "EN" => LicenseTier.Enterprise,
                _ => LicenseTier.Free
            };
            Valid = true;
        }
        
        public bool IsPremium() => Valid && Tier != LicenseTier.Free;
    }
    
    #endregion
    
    #region Console Helpers
    
    public static class Console
    {
        public static void Success(string msg) => 
            System.Console.WriteLine($"\u001b[32m✅ {msg}\u001b[0m");
            
        public static void Error(string msg) => 
            System.Console.WriteLine($"\u001b[31m❌ {msg}\u001b[0m");
            
        public static void Warning(string msg) => 
            System.Console.WriteLine($"\u001b[33m⚠️  {msg}\u001b[0m");
            
        public static void Info(string msg) => 
            System.Console.WriteLine($"\u001b[34mℹ️  {msg}\u001b[0m");
            
        public static void Cyan(string msg) => 
            System.Console.WriteLine($"\u001b[36m{msg}\u001b[0m");
    }
    
    #endregion
    
    #region Windows Defender Checker
    
    public class DefenderChecker
    {
        public (bool enabled, bool realTimeProtection, bool antispywareEnabled, string lastUpdate) GetStatus()
        {
            bool enabled = false;
            bool realTime = false;
            bool antispyware = false;
            string lastUpdate = "Unknown";
            
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT * FROM MSFT_MpComputerStatus");
                    
                foreach (ManagementObject obj in searcher.Get())
                {
                    enabled = (bool)obj["AntivirusEnabled"];
                    realTime = (bool)obj["RealTimeProtectionEnabled"];
                    antispyware = (bool)obj["AntispywareEnabled"];
                    
                    var updateTime = (DateTime)ManagementDateTimeConverter.ToDateTime(
                        obj["AntivirusSignatureLastUpdated"]?.ToString());
                    lastUpdate = updateTime.ToString("yyyy-MM-dd HH:mm:ss");
                }
            }
            catch { }
            
            return (enabled, realTime, antispyware, lastUpdate);
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n🛡️  Windows Defender Status:\n");
            
            var (enabled, realTime, antispyware, lastUpdate) = GetStatus();
            
            if (enabled)
                Console.Success("Windows Defender is ENABLED");
            else
                Console.Warning("Windows Defender is DISABLED");
                
            var rtIcon = realTime ? "✅" : "⚠️";
            var rtStatus = realTime ? "Enabled" : "Disabled";
            System.Console.WriteLine($"  {rtIcon} Real-Time Protection: {rtStatus}");
            
            var asIcon = antispyware ? "✅" : "⚠️";
            var asStatus = antispyware ? "Enabled" : "Disabled";
            System.Console.WriteLine($"  {asIcon} Antispyware: {asStatus}");
            
            System.Console.WriteLine($"  📅 Last Signature Update: {lastUpdate}");
        }
    }
    
    #endregion
    
    #region Firewall Checker
    
    public class FirewallChecker
    {
        public Dictionary<string, bool> GetProfileStatus()
        {
            var profiles = new Dictionary<string, bool>();
            
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = "advfirewall show allprofiles state",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                string currentProfile = "";
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("Profile Settings"))
                    {
                        if (line.Contains("Domain"))
                            currentProfile = "Domain";
                        else if (line.Contains("Private"))
                            currentProfile = "Private";
                        else if (line.Contains("Public"))
                            currentProfile = "Public";
                    }
                    else if (line.Contains("State") && !string.IsNullOrEmpty(currentProfile))
                    {
                        profiles[currentProfile] = line.ToLower().Contains("on");
                        currentProfile = "";
                    }
                }
            }
            catch { }
            
            return profiles;
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n🔥 Windows Firewall Status:\n");
            
            var profiles = GetProfileStatus();
            
            bool allEnabled = profiles.Values.All(v => v);
            
            if (allEnabled)
                Console.Success("Windows Firewall is ENABLED on all profiles");
            else if (profiles.Values.Any(v => v))
                Console.Warning("Windows Firewall is partially enabled");
            else
                Console.Error("Windows Firewall is DISABLED");
            
            foreach (var (profile, enabled) in profiles)
            {
                var icon = enabled ? "✅" : "⚠️";
                var status = enabled ? "Enabled" : "Disabled";
                System.Console.WriteLine($"  {icon} {profile}: {status}");
            }
        }
    }
    
    #endregion
    
    #region BitLocker Checker
    
    public class BitLockerChecker
    {
        public List<(string drive, string status, int percentEncrypted)> GetStatus()
        {
            var drives = new List<(string, string, int)>();
            
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    "SELECT * FROM Win32_EncryptableVolume");
                    
                foreach (ManagementObject obj in searcher.Get())
                {
                    string driveLetter = obj["DriveLetter"]?.ToString() ?? "Unknown";
                    int protectionStatus = Convert.ToInt32(obj["ProtectionStatus"]);
                    int encryptionPercentage = Convert.ToInt32(obj["EncryptionPercentage"]);
                    
                    string status = protectionStatus switch
                    {
                        0 => "Unprotected",
                        1 => "Protected",
                        2 => "Unknown",
                        _ => "Unknown"
                    };
                    
                    drives.Add((driveLetter, status, encryptionPercentage));
                }
            }
            catch { }
            
            return drives;
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n🔐 BitLocker Status:\n");
            
            var drives = GetStatus();
            
            if (drives.Count == 0)
            {
                Console.Warning("BitLocker information not available");
                Console.Info("Run as Administrator for full access");
                return;
            }
            
            foreach (var (drive, status, percent) in drives)
            {
                var icon = status == "Protected" ? "🔒" : "🔓";
                System.Console.WriteLine($"  {icon} Drive {drive}:");
                System.Console.WriteLine($"      Status: {status}");
                System.Console.WriteLine($"      Encrypted: {percent}%");
            }
        }
    }
    
    #endregion
    
    #region UAC Checker
    
    public class UACChecker
    {
        public (bool enabled, int level) GetStatus()
        {
            bool enabled = true;
            int level = 2; // Default
            
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    
                if (key != null)
                {
                    var enableLUA = key.GetValue("EnableLUA");
                    enabled = Convert.ToInt32(enableLUA) == 1;
                    
                    var consentPrompt = Convert.ToInt32(key.GetValue("ConsentPromptBehaviorAdmin") ?? 5);
                    var secureDesktop = Convert.ToInt32(key.GetValue("PromptOnSecureDesktop") ?? 1);
                    
                    // Determine level
                    if (consentPrompt == 0)
                        level = 0; // Never notify
                    else if (consentPrompt == 5 && secureDesktop == 0)
                        level = 1; // Notify without dimming
                    else if (consentPrompt == 5 && secureDesktop == 1)
                        level = 2; // Default - notify with dimming
                    else if (consentPrompt == 2)
                        level = 3; // Always notify
                }
            }
            catch { }
            
            return (enabled, level);
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n🛡️  UAC Status:\n");
            
            var (enabled, level) = GetStatus();
            
            if (enabled)
                Console.Success("UAC is ENABLED");
            else
                Console.Error("UAC is DISABLED");
            
            var levelNames = new[] {
                "Never notify (lowest security)",
                "Notify without dimming",
                "Default - Notify with dimming",
                "Always notify (highest security)"
            };
            
            var levelIcons = new[] { "⚠️", "⚠️", "✅", "✅" };
            
            System.Console.WriteLine($"  {levelIcons[level]} Level: {levelNames[level]}");
        }
    }
    
    #endregion
    
    #region Network Analyzer
    
    public class NetworkAnalyzer
    {
        public List<TcpConnectionInformation> GetActiveConnections()
        {
            var connections = new List<TcpConnectionInformation>();
            
            try
            {
                var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
                connections.AddRange(ipProperties.GetActiveTcpConnections());
            }
            catch { }
            
            return connections;
        }
        
        public Dictionary<string, string> GetNetworkInterfaces()
        {
            var interfaces = new Dictionary<string, string>();
            
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    var props = ni.GetIPProperties();
                    var ipv4 = props.UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == 
                            System.Net.Sockets.AddressFamily.InterNetwork);
                    
                    if (ipv4 != null)
                        interfaces[ni.Name] = ipv4.Address.ToString();
                }
            }
            
            return interfaces;
        }
        
        public void DisplayConnections()
        {
            System.Console.WriteLine("\n🌐 Active Connections:\n");
            
            var connections = GetActiveConnections()
                .Where(c => c.State == TcpState.Established)
                .Take(30)
                .ToList();
            
            System.Console.WriteLine($"  Found {connections.Count} established connections\n");
            
            foreach (var conn in connections)
            {
                System.Console.WriteLine($"  {conn.LocalEndPoint} → {conn.RemoteEndPoint}");
            }
        }
        
        public void DisplayInterfaces()
        {
            System.Console.WriteLine("\n📡 Network Interfaces:\n");
            
            var interfaces = GetNetworkInterfaces();
            
            foreach (var (name, ip) in interfaces)
            {
                System.Console.WriteLine($"  {name}: {ip}");
            }
        }
    }
    
    #endregion
    
    #region Service Auditor
    
    public class ServiceAuditor
    {
        private readonly License _license;
        
        public ServiceAuditor(License license) => _license = license;
        
        public List<(string name, string displayName, string status, string startType)> GetServices()
        {
            var services = new List<(string, string, string, string)>();
            
            try
            {
                foreach (var service in ServiceController.GetServices())
                {
                    services.Add((
                        service.ServiceName,
                        service.DisplayName,
                        service.Status.ToString(),
                        GetStartType(service.ServiceName)
                    ));
                }
            }
            catch { }
            
            return services;
        }
        
        private string GetStartType(string serviceName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
                    
                var start = Convert.ToInt32(key?.GetValue("Start") ?? 4);
                return start switch
                {
                    0 => "Boot",
                    1 => "System",
                    2 => "Automatic",
                    3 => "Manual",
                    4 => "Disabled",
                    _ => "Unknown"
                };
            }
            catch { return "Unknown"; }
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n⚙️  Services Audit:\n");
            
            var services = GetServices()
                .OrderBy(s => s.name)
                .ToList();
            
            var running = services.Count(s => s.status == "Running");
            var stopped = services.Count(s => s.status == "Stopped");
            
            System.Console.WriteLine($"  Total Services: {services.Count}");
            System.Console.WriteLine($"  Running: {running}");
            System.Console.WriteLine($"  Stopped: {stopped}");
            
            // Show suspicious services (auto-start but stopped)
            var suspicious = services
                .Where(s => s.startType == "Automatic" && s.status == "Stopped")
                .Take(10)
                .ToList();
            
            if (suspicious.Any())
            {
                System.Console.WriteLine("\n  ⚠️  Auto-start services that are stopped:");
                foreach (var s in suspicious)
                {
                    System.Console.WriteLine($"      • {s.displayName}");
                }
            }
        }
    }
    
    #endregion
    
    #region Event Log Analyzer
    
    public class EventLogAnalyzer
    {
        private readonly License _license;
        
        public EventLogAnalyzer(License license) => _license = license;
        
        public List<(DateTime time, string source, string message, int id)> GetSecurityEvents(int count = 50)
        {
            var events = new List<(DateTime, string, string, int)>();
            
            if (!_license.IsPremium())
            {
                Console.Warning("Event log analysis requires premium license");
                Console.Info("Get premium at discord.gg/killers");
                return events;
            }
            
            try
            {
                using var log = new EventLog("Security");
                
                foreach (EventLogEntry entry in log.Entries.Cast<EventLogEntry>()
                    .OrderByDescending(e => e.TimeGenerated)
                    .Take(count))
                {
                    events.Add((
                        entry.TimeGenerated,
                        entry.Source,
                        entry.Message?.Substring(0, Math.Min(100, entry.Message?.Length ?? 0)) ?? "",
                        entry.InstanceId.GetHashCode()
                    ));
                }
            }
            catch { }
            
            return events;
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n📋 Security Event Log:\n");
            
            var events = GetSecurityEvents(20);
            
            if (events.Count == 0)
            {
                if (!_license.IsPremium())
                    return;
                    
                Console.Warning("No events found or access denied");
                Console.Info("Run as Administrator");
                return;
            }
            
            foreach (var (time, source, message, id) in events)
            {
                System.Console.WriteLine($"  [{time:yyyy-MM-dd HH:mm:ss}] Event {id}");
                System.Console.WriteLine($"      Source: {source}");
                System.Console.WriteLine($"      {message}...\n");
            }
        }
    }
    
    #endregion
    
    #region System Info
    
    public class SystemInfo
    {
        public Dictionary<string, string> GetInfo()
        {
            var info = new Dictionary<string, string>();
            
            info["Computer Name"] = Environment.MachineName;
            info["User Name"] = Environment.UserName;
            info["OS Version"] = Environment.OSVersion.ToString();
            info["64-bit OS"] = Environment.Is64BitOperatingSystem ? "Yes" : "No";
            info["Processor Count"] = Environment.ProcessorCount.ToString();
            
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher.Get())
                {
                    info["Manufacturer"] = obj["Manufacturer"]?.ToString() ?? "Unknown";
                    info["Model"] = obj["Model"]?.ToString() ?? "Unknown";
                    var ram = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                    info["RAM"] = $"{ram / 1024 / 1024 / 1024} GB";
                }
            }
            catch { }
            
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    info["CPU"] = obj["Name"]?.ToString() ?? "Unknown";
                    break;
                }
            }
            catch { }
            
            return info;
        }
        
        public void Display()
        {
            System.Console.WriteLine("\n💻 System Information:\n");
            
            var info = GetInfo();
            
            foreach (var (key, value) in info.OrderBy(kv => kv.Key))
            {
                System.Console.WriteLine($"  {key}: {value}");
            }
        }
    }
    
    #endregion
    
    #region Main Program
    
    class Program
    {
        static License _license = new License();
        
        static void ShowBanner()
        {
            Console.Cyan(Config.BANNER);
        }
        
        static void ShowMenu()
        {
            var tierBadge = _license.Tier switch
            {
                LicenseTier.Premium => "⭐",
                LicenseTier.Enterprise => "💎",
                _ => "🆓"
            };
            
            System.Console.WriteLine($"\n📋 NullSec Windows Menu {tierBadge}\n");
            System.Console.WriteLine("  [1] Windows Defender Status");
            System.Console.WriteLine("  [2] Firewall Status");
            System.Console.WriteLine("  [3] BitLocker Status");
            System.Console.WriteLine("  [4] UAC Status");
            System.Console.WriteLine("  [5] Network Interfaces");
            System.Console.WriteLine("  [6] Active Connections");
            System.Console.WriteLine("  [7] System Info");
            System.Console.WriteLine("  [8] Services Audit");
            System.Console.WriteLine("  [9] Event Log (Premium)");
            System.Console.WriteLine("  [0] Exit");
            System.Console.WriteLine();
        }
        
        static void Main(string[] args)
        {
            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                if ((args[i] == "-k" || args[i] == "--key") && i + 1 < args.Length)
                {
                    _license = new License(args[i + 1]);
                    Console.Info($"License tier: {_license.Tier}");
                    i++;
                }
                else if (args[i] == "-h" || args[i] == "--help")
                {
                    System.Console.WriteLine($"NullSec Windows Toolkit v{Config.VERSION}");
                    System.Console.WriteLine($"{Config.AUTHOR} | {Config.DISCORD}\n");
                    System.Console.WriteLine("Usage: nullsec-windows [options]\n");
                    System.Console.WriteLine("Options:");
                    System.Console.WriteLine("  -k, --key KEY    License key");
                    System.Console.WriteLine("  -h, --help       Show help");
                    System.Console.WriteLine("  -v, --version    Show version");
                    return;
                }
                else if (args[i] == "-v" || args[i] == "--version")
                {
                    System.Console.WriteLine($"NullSec Windows Toolkit v{Config.VERSION}");
                    return;
                }
            }
            
            ShowBanner();
            
            bool running = true;
            while (running)
            {
                ShowMenu();
                System.Console.Write("Select: ");
                
                if (!int.TryParse(System.Console.ReadLine(), out int choice))
                    continue;
                
                switch (choice)
                {
                    case 1: new DefenderChecker().Display(); break;
                    case 2: new FirewallChecker().Display(); break;
                    case 3: new BitLockerChecker().Display(); break;
                    case 4: new UACChecker().Display(); break;
                    case 5: new NetworkAnalyzer().DisplayInterfaces(); break;
                    case 6: new NetworkAnalyzer().DisplayConnections(); break;
                    case 7: new SystemInfo().Display(); break;
                    case 8: new ServiceAuditor(_license).Display(); break;
                    case 9: new EventLogAnalyzer(_license).Display(); break;
                    case 0: running = false; break;
                    default: Console.Error("Invalid option"); break;
                }
            }
            
            System.Console.WriteLine("\n─────────────────────────────────────────");
            System.Console.WriteLine("🪟 NullSec Windows Toolkit");
            System.Console.WriteLine("🔑 Premium: discord.gg/killers");
            System.Console.WriteLine("🐦 Twitter: @AnonAntics");
            System.Console.WriteLine("─────────────────────────────────────────\n");
        }
    }
    
    #endregion
}
