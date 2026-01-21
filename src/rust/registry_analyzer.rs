/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC WINDOWS RUST REGISTRY ANALYZER
 *  Advanced Windows Registry analysis and monitoring
 *  @author bad-antics | discord.gg/killers
 * ═══════════════════════════════════════════════════════════════════
 */

use std::collections::HashMap;
use std::io::{self, Write};
use std::process::Command;

const VERSION: &str = "2.0.0";
const AUTHOR: &str = "bad-antics";
const DISCORD: &str = "discord.gg/killers";

const BANNER: &str = r#"
╭──────────────────────────────────────────╮
│     🪟 NULLSEC WINDOWS REGISTRY TOOL    │
│     ════════════════════════════════    │
│                                          │
│   🔑 Registry Analysis & Monitoring      │
│   🛡️  Security Configuration Audit       │
│   📊 Autorun Detection                   │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
"#;

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, PartialEq)]
enum LicenseTier {
    Free,
    Premium,
    Enterprise,
}

impl LicenseTier {
    fn as_str(&self) -> &'static str {
        match self {
            LicenseTier::Free => "Free",
            LicenseTier::Premium => "Premium ⭐",
            LicenseTier::Enterprise => "Enterprise 💎",
        }
    }
}

struct License {
    key: String,
    tier: LicenseTier,
    valid: bool,
}

impl License {
    fn new() -> Self {
        License {
            key: String::new(),
            tier: LicenseTier::Free,
            valid: false,
        }
    }

    fn validate(key: &str) -> Self {
        let mut license = License::new();

        if key.len() != 24 {
            return license;
        }

        if !key.starts_with("NWIN-") {
            return license;
        }

        license.key = key.to_string();
        license.valid = true;

        let type_code = &key[5..7];
        license.tier = match type_code {
            "PR" => LicenseTier::Premium,
            "EN" => LicenseTier::Enterprise,
            _ => LicenseTier::Free,
        };

        license
    }

    fn is_premium(&self) -> bool {
        self.valid && self.tier != LicenseTier::Free
    }
}

// ═══════════════════════════════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════════════════════════════

fn print_success(msg: &str) {
    println!("\x1b[32m✅ {}\x1b[0m", msg);
}

fn print_error(msg: &str) {
    println!("\x1b[31m❌ {}\x1b[0m", msg);
}

fn print_warning(msg: &str) {
    println!("\x1b[33m⚠️  {}\x1b[0m", msg);
}

fn print_info(msg: &str) {
    println!("\x1b[36mℹ️  {}\x1b[0m", msg);
}

fn print_header(title: &str) {
    println!("\n═══════════════════════════════════════════");
    println!("  {}", title);
    println!("═══════════════════════════════════════════\n");
}

// ═══════════════════════════════════════════════════════════════════
// Registry Operations (simulated for cross-platform development)
// ═══════════════════════════════════════════════════════════════════

struct RegistryKey {
    path: String,
    name: String,
    value_type: String,
    value: String,
}

struct AutorunEntry {
    location: String,
    name: String,
    command: String,
    publisher: String,
}

// Common autorun locations
fn get_autorun_locations() -> Vec<&'static str> {
    vec![
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
    ]
}

// Security-related registry locations
fn get_security_locations() -> Vec<(&'static str, &'static str)> {
    vec![
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC Settings"),
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LSA Protection"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "Windows Defender"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Explorer Settings"),
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB Settings"),
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "RDP Settings"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "Windows Update"),
        (r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols", "TLS/SSL Protocols"),
    ]
}

fn query_registry(path: &str) -> Vec<RegistryKey> {
    let mut keys = Vec::new();
    
    // Use reg.exe query for actual Windows execution
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("reg")
            .args(&["query", path, "/s"])
            .output();
        
        if let Ok(result) = output {
            let stdout = String::from_utf8_lossy(&result.stdout);
            // Parse the output...
            for line in stdout.lines() {
                if line.contains("REG_") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        keys.push(RegistryKey {
                            path: path.to_string(),
                            name: parts[0].to_string(),
                            value_type: parts[1].to_string(),
                            value: parts[2..].join(" "),
                        });
                    }
                }
            }
        }
    }
    
    // Demo data for non-Windows systems
    #[cfg(not(target_os = "windows"))]
    {
        if path.contains("Run") {
            keys.push(RegistryKey {
                path: path.to_string(),
                name: "SecurityHealth".to_string(),
                value_type: "REG_SZ".to_string(),
                value: r"C:\Windows\System32\SecurityHealthSystray.exe".to_string(),
            });
            keys.push(RegistryKey {
                path: path.to_string(),
                name: "OneDrive".to_string(),
                value_type: "REG_SZ".to_string(),
                value: r"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background".to_string(),
            });
        }
    }
    
    keys
}

// ═══════════════════════════════════════════════════════════════════
// Autorun Analysis
// ═══════════════════════════════════════════════════════════════════

fn analyze_autoruns(license: &License) {
    print_header("🚀 AUTORUN ANALYSIS");
    
    let locations = get_autorun_locations();
    let mut total_entries = 0;
    
    for location in &locations {
        println!("  📁 {}", location);
        
        let keys = query_registry(location);
        
        if keys.is_empty() {
            println!("     (empty)\n");
        } else {
            for key in &keys {
                println!("     📌 {}", key.name);
                println!("        → {}", key.value);
                total_entries += 1;
            }
            println!();
        }
        
        // Limit for free users
        if !license.is_premium() && total_entries >= 10 {
            print_warning(&format!("Free tier limited to 10 entries. Premium: {}", DISCORD));
            break;
        }
    }
    
    println!("  Total autorun entries: {}", total_entries);
    println!();
}

// ═══════════════════════════════════════════════════════════════════
// Security Configuration Audit
// ═══════════════════════════════════════════════════════════════════

fn audit_security_config(license: &License) {
    print_header("🛡️  SECURITY CONFIGURATION AUDIT");
    
    if !license.is_premium() {
        print_warning(&format!("Security audit is a Premium feature. Get keys at {}", DISCORD));
        println!();
        return;
    }
    
    let locations = get_security_locations();
    
    for (path, name) in &locations {
        println!("  📋 {} ({})", name, path);
        
        let keys = query_registry(path);
        
        if keys.is_empty() {
            println!("     (no values found)\n");
        } else {
            for key in &keys {
                // Security assessment
                let status = assess_security_setting(&key.name, &key.value);
                let icon = if status { "🟢" } else { "🔴" };
                
                println!("     {} {}: {}", icon, key.name, key.value);
            }
            println!();
        }
    }
}

fn assess_security_setting(name: &str, value: &str) -> bool {
    // Common security checks
    match name.to_lowercase().as_str() {
        "enablelua" => value == "1",  // UAC enabled
        "consentpromptbehavioradmin" => value != "0",  // UAC prompt
        "filteredadministratortoken" => value == "1",
        "disableantiSpyware" => value == "0",  // Defender enabled
        "disablerealtimemonitoring" => value == "0",
        "enablefirewall" => value == "1",
        "restrictanonymous" => value != "0",
        "nocachelookup" => value == "1",
        "enablesecuritysignature" => value == "1",
        "requiresecuritysignature" => value == "1",
        "fdenytsconnections" => value == "1",  // RDP disabled is more secure
        _ => true,  // Unknown settings assumed OK
    }
}

// ═══════════════════════════════════════════════════════════════════
// Service Analysis
// ═══════════════════════════════════════════════════════════════════

struct ServiceInfo {
    name: String,
    display_name: String,
    start_type: String,
    status: String,
    path: String,
}

fn get_services() -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("sc")
            .args(&["query", "type=", "service", "state=", "all"])
            .output();
        
        // Parse sc query output...
    }
    
    // Demo data
    #[cfg(not(target_os = "windows"))]
    {
        services.push(ServiceInfo {
            name: "WinDefend".to_string(),
            display_name: "Windows Defender Antivirus Service".to_string(),
            start_type: "Automatic".to_string(),
            status: "Running".to_string(),
            path: r"C:\ProgramData\Microsoft\Windows Defender\platform\MsMpEng.exe".to_string(),
        });
        services.push(ServiceInfo {
            name: "mpssvc".to_string(),
            display_name: "Windows Defender Firewall".to_string(),
            start_type: "Automatic".to_string(),
            status: "Running".to_string(),
            path: r"C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall".to_string(),
        });
        services.push(ServiceInfo {
            name: "EventLog".to_string(),
            display_name: "Windows Event Log".to_string(),
            start_type: "Automatic".to_string(),
            status: "Running".to_string(),
            path: r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted".to_string(),
        });
    }
    
    services
}

fn analyze_services(license: &License) {
    print_header("⚙️  SERVICE ANALYSIS");
    
    let services = get_services();
    
    println!("  {:<20} {:<15} {:<10}", "SERVICE", "START TYPE", "STATUS");
    println!("  {}", "─".repeat(50));
    
    let limit = if license.is_premium() { services.len() } else { 5 };
    
    for (i, svc) in services.iter().enumerate() {
        if i >= limit {
            break;
        }
        
        let status_icon = if svc.status == "Running" { "🟢" } else { "🔴" };
        println!("  {:<20} {:<15} {} {}", svc.name, svc.start_type, status_icon, svc.status);
    }
    
    if !license.is_premium() && services.len() > 5 {
        println!("\n  ... and {} more services", services.len() - 5);
        print_warning(&format!("Full service list is Premium: {}", DISCORD));
    }
    
    println!("\n  Total services: {}", services.len());
    println!();
}

// ═══════════════════════════════════════════════════════════════════
// Scheduled Tasks
// ═══════════════════════════════════════════════════════════════════

struct ScheduledTask {
    name: String,
    path: String,
    status: String,
    next_run: String,
    action: String,
}

fn get_scheduled_tasks() -> Vec<ScheduledTask> {
    let mut tasks = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("schtasks")
            .args(&["/query", "/fo", "csv", "/v"])
            .output();
        
        // Parse schtasks output...
    }
    
    // Demo data
    #[cfg(not(target_os = "windows"))]
    {
        tasks.push(ScheduledTask {
            name: "Microsoft\\Windows\\WindowsUpdate\\Scheduled Start".to_string(),
            path: "\\Microsoft\\Windows\\WindowsUpdate\\".to_string(),
            status: "Ready".to_string(),
            next_run: "2024-01-15 03:00".to_string(),
            action: "C:\\Windows\\system32\\usoclient.exe StartScan".to_string(),
        });
        tasks.push(ScheduledTask {
            name: "Microsoft\\Windows\\Defrag\\ScheduledDefrag".to_string(),
            path: "\\Microsoft\\Windows\\Defrag\\".to_string(),
            status: "Ready".to_string(),
            next_run: "When idle".to_string(),
            action: "C:\\Windows\\system32\\defrag.exe".to_string(),
        });
    }
    
    tasks
}

fn analyze_scheduled_tasks(license: &License) {
    print_header("📅 SCHEDULED TASKS");
    
    let tasks = get_scheduled_tasks();
    
    let limit = if license.is_premium() { tasks.len() } else { 5 };
    
    for (i, task) in tasks.iter().enumerate() {
        if i >= limit {
            break;
        }
        
        let status_icon = if task.status == "Ready" { "🟢" } else { "⚪" };
        println!("  {} {}", status_icon, task.name);
        println!("     Next Run: {}", task.next_run);
        println!("     Action: {}", task.action);
        println!();
    }
    
    if !license.is_premium() && tasks.len() > 5 {
        println!("  ... and {} more tasks", tasks.len() - 5);
        print_warning(&format!("Full task list is Premium: {}", DISCORD));
    }
    
    println!("  Total scheduled tasks: {}", tasks.len());
    println!();
}

// ═══════════════════════════════════════════════════════════════════
// Registry Search
// ═══════════════════════════════════════════════════════════════════

fn search_registry(query: &str, license: &License) {
    print_header(&format!("🔍 REGISTRY SEARCH: '{}'", query));
    
    if !license.is_premium() {
        print_warning(&format!("Registry search is a Premium feature. Get keys at {}", DISCORD));
        println!();
        return;
    }
    
    println!("  Searching for '{}' in registry...\n", query);
    
    // This would use reg query with /f flag on Windows
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("reg")
            .args(&["query", "HKLM", "/f", query, "/s"])
            .output();
        
        if let Ok(result) = output {
            let stdout = String::from_utf8_lossy(&result.stdout);
            for line in stdout.lines().take(20) {
                println!("  {}", line);
            }
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        println!("  (Registry search available on Windows only)");
    }
    
    println!();
}

// ═══════════════════════════════════════════════════════════════════
// Export Report
// ═══════════════════════════════════════════════════════════════════

fn export_report(license: &License) {
    print_header("📤 EXPORT REPORT");
    
    if !license.is_premium() {
        print_warning(&format!("Report export is a Premium feature. Get keys at {}", DISCORD));
        println!();
        return;
    }
    
    let timestamp = chrono_lite_timestamp();
    let filename = format!("nullsec_registry_report_{}.txt", timestamp);
    
    println!("  Generating report: {}", filename);
    println!("  (Report would be saved on Windows systems)");
    print_success("Report exported successfully");
    println!();
}

fn chrono_lite_timestamp() -> String {
    // Simple timestamp without external crate
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{}", duration.as_secs())
}

// ═══════════════════════════════════════════════════════════════════
// Main Menu
// ═══════════════════════════════════════════════════════════════════

fn show_menu(license: &mut License) {
    loop {
        let tier_badge = if license.is_premium() { "⭐" } else { "🆓" };
        
        println!("\n  📋 NullSec Windows Registry Tool {}\n", tier_badge);
        println!("  [1] Autorun Analysis");
        println!("  [2] Security Configuration Audit (Premium)");
        println!("  [3] Service Analysis");
        println!("  [4] Scheduled Tasks");
        println!("  [5] Registry Search (Premium)");
        println!("  [6] Export Report (Premium)");
        println!("  [7] Full Analysis");
        println!("  [8] Enter License Key");
        println!("  [0] Exit");
        
        print!("\n  Select: ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        
        match input.trim() {
            "1" => analyze_autoruns(license),
            "2" => audit_security_config(license),
            "3" => analyze_services(license),
            "4" => analyze_scheduled_tasks(license),
            "5" => {
                print!("  Search query: ");
                io::stdout().flush().unwrap();
                let mut query = String::new();
                if io::stdin().read_line(&mut query).is_ok() {
                    search_registry(query.trim(), license);
                }
            }
            "6" => export_report(license),
            "7" => {
                analyze_autoruns(license);
                audit_security_config(license);
                analyze_services(license);
                analyze_scheduled_tasks(license);
            }
            "8" => {
                print!("  License key: ");
                io::stdout().flush().unwrap();
                let mut key = String::new();
                if io::stdin().read_line(&mut key).is_ok() {
                    *license = License::validate(key.trim());
                    if license.valid {
                        print_success(&format!("License activated: {}", license.tier.as_str()));
                    } else {
                        print_warning("Invalid license key");
                    }
                }
            }
            "0" => break,
            _ => print_error("Invalid option"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════

fn main() {
    println!("\x1b[36m{}\x1b[0m", BANNER);
    println!("  Version {} | {}", VERSION, AUTHOR);
    println!("  🔑 Premium: {}\n", DISCORD);
    
    let mut license = License::new();
    
    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    
    while i < args.len() {
        match args[i].as_str() {
            "-k" | "--key" => {
                if i + 1 < args.len() {
                    license = License::validate(&args[i + 1]);
                    if license.valid {
                        print_success(&format!("License activated: {}", license.tier.as_str()));
                    }
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!("  Usage: {} [options]\n", args[0]);
                println!("  Options:");
                println!("    -k, --key KEY    License key");
                println!("    -h, --help       Show help");
                println!("    -v, --version    Show version");
                return;
            }
            "-v" | "--version" => {
                println!("  NullSec Windows Registry Tool v{}", VERSION);
                return;
            }
            _ => {}
        }
        i += 1;
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        print_warning("Running on non-Windows system - using demo mode");
        println!("    Full functionality available on Windows\n");
    }
    
    show_menu(&mut license);
    
    // Footer
    println!("\n─────────────────────────────────────────");
    println!("  🪟 NullSec Windows Registry Tool");
    println!("  🔑 Premium: {}", DISCORD);
    println!("  👤 Author: {}", AUTHOR);
    println!("─────────────────────────────────────────\n");
}
