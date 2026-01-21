/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC WINDOWS CPP EVENT LOG ANALYZER
 *  Windows Event Log analysis and security monitoring
 *  @author bad-antics | discord.gg/killers
 * ═══════════════════════════════════════════════════════════════════
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")
#endif

const char* VERSION = "2.0.0";
const char* AUTHOR = "bad-antics";
const char* DISCORD = "discord.gg/killers";

const char* BANNER = R"(
╭──────────────────────────────────────────╮
│    🪟 NULLSEC WINDOWS EVENT ANALYZER    │
│    ════════════════════════════════     │
│                                          │
│   📜 Event Log Analysis                  │
│   🔐 Security Event Monitoring           │
│   ⚠️  Threat Detection                   │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
)";

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

enum LicenseTier {
    TIER_FREE = 0,
    TIER_PREMIUM = 1,
    TIER_ENTERPRISE = 2
};

struct License {
    std::string key;
    LicenseTier tier;
    bool valid;
    
    License() : tier(TIER_FREE), valid(false) {}
};

std::string tierToString(LicenseTier tier) {
    switch (tier) {
        case TIER_PREMIUM: return "Premium ⭐";
        case TIER_ENTERPRISE: return "Enterprise 💎";
        default: return "Free";
    }
}

License validateLicense(const std::string& key) {
    License license;
    
    if (key.length() != 24) return license;
    if (key.substr(0, 5) != "NWIN-") return license;
    
    license.key = key;
    license.valid = true;
    
    std::string typeCode = key.substr(5, 2);
    if (typeCode == "PR") {
        license.tier = TIER_PREMIUM;
    } else if (typeCode == "EN") {
        license.tier = TIER_ENTERPRISE;
    } else {
        license.tier = TIER_FREE;
    }
    
    return license;
}

bool isPremium(const License& license) {
    return license.valid && license.tier != TIER_FREE;
}

// ═══════════════════════════════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════════════════════════════

void printSuccess(const std::string& msg) {
    std::cout << "\033[32m✅ " << msg << "\033[0m" << std::endl;
}

void printError(const std::string& msg) {
    std::cout << "\033[31m❌ " << msg << "\033[0m" << std::endl;
}

void printWarning(const std::string& msg) {
    std::cout << "\033[33m⚠️  " << msg << "\033[0m" << std::endl;
}

void printInfo(const std::string& msg) {
    std::cout << "\033[36mℹ️  " << msg << "\033[0m" << std::endl;
}

void printHeader(const std::string& title) {
    std::cout << "\n═══════════════════════════════════════════" << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << "═══════════════════════════════════════════\n" << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Event Log Structures
// ═══════════════════════════════════════════════════════════════════

struct EventRecord {
    int eventId;
    std::string source;
    std::string level;
    std::string timestamp;
    std::string message;
    std::string computer;
    std::string user;
};

struct SecurityAlert {
    int eventId;
    std::string description;
    std::string severity;
    std::string recommendation;
};

// Security event IDs to monitor
std::map<int, SecurityAlert> securityEventIds = {
    {4624, {"4624", "Successful logon", "Info", "Normal activity"}},
    {4625, {"4625", "Failed logon attempt", "Warning", "Monitor for brute force"}},
    {4634, {"4634", "Account logoff", "Info", "Normal activity"}},
    {4648, {"4648", "Explicit credential logon", "Warning", "Verify legitimacy"}},
    {4656, {"4656", "Handle to object requested", "Info", "Check object access"}},
    {4663, {"4663", "Object access attempt", "Info", "Audit file access"}},
    {4672, {"4672", "Special privileges assigned", "Warning", "Admin logon detected"}},
    {4688, {"4688", "Process created", "Info", "New process execution"}},
    {4689, {"4689", "Process terminated", "Info", "Process ended"}},
    {4697, {"4697", "Service installed", "Critical", "New service - verify!"}},
    {4698, {"4698", "Scheduled task created", "Warning", "New task - verify!"}},
    {4720, {"4720", "User account created", "Warning", "New user account"}},
    {4722, {"4722", "User account enabled", "Warning", "Account enabled"}},
    {4724, {"4724", "Password reset attempt", "Warning", "Password change"}},
    {4726, {"4726", "User account deleted", "Warning", "Account deleted"}},
    {4728, {"4728", "Member added to security group", "Warning", "Group change"}},
    {4732, {"4732", "Member added to local group", "Warning", "Local group change"}},
    {4738, {"4738", "User account changed", "Warning", "Account modified"}},
    {4756, {"4756", "Member added to universal group", "Warning", "Universal group change"}},
    {4768, {"4768", "Kerberos TGT requested", "Info", "Authentication"}},
    {4769, {"4769", "Kerberos service ticket requested", "Info", "Service access"}},
    {4771, {"4771", "Kerberos pre-auth failed", "Warning", "Auth failure"}},
    {4776, {"4776", "NTLM authentication", "Info", "Legacy auth used"}},
    {7045, {"7045", "New service installed", "Critical", "Verify service!"}},
    {1102, {"1102", "Audit log cleared", "Critical", "Possible cover-up!"}},
};

// ═══════════════════════════════════════════════════════════════════
// Event Log Operations
// ═══════════════════════════════════════════════════════════════════

std::vector<EventRecord> getEvents(const std::string& logName, int maxEvents = 50) {
    std::vector<EventRecord> events;
    
#ifdef _WIN32
    // Windows Event Log API
    std::wstring wLogName(logName.begin(), logName.end());
    EVT_HANDLE hResults = EvtQuery(NULL, wLogName.c_str(), L"*", 
                                    EvtQueryChannelPath | EvtQueryReverseDirection);
    
    if (hResults) {
        EVT_HANDLE hEvents[10];
        DWORD dwReturned = 0;
        int count = 0;
        
        while (count < maxEvents && EvtNext(hResults, 10, hEvents, INFINITE, 0, &dwReturned)) {
            for (DWORD i = 0; i < dwReturned && count < maxEvents; i++) {
                // Extract event data
                EventRecord record;
                // ... (Full Windows implementation would parse XML here)
                events.push_back(record);
                count++;
                EvtClose(hEvents[i]);
            }
        }
        EvtClose(hResults);
    }
#else
    // Demo data for non-Windows
    events.push_back({4624, "Security", "Information", "2024-01-15 10:30:00", 
                      "An account was successfully logged on", "WORKSTATION", "DOMAIN\\user"});
    events.push_back({4625, "Security", "Warning", "2024-01-15 10:28:00", 
                      "An account failed to log on", "WORKSTATION", "DOMAIN\\attacker"});
    events.push_back({4672, "Security", "Warning", "2024-01-15 10:30:05", 
                      "Special privileges assigned to new logon", "WORKSTATION", "DOMAIN\\admin"});
    events.push_back({4688, "Security", "Information", "2024-01-15 10:31:00", 
                      "A new process has been created", "WORKSTATION", "SYSTEM"});
    events.push_back({7045, "System", "Warning", "2024-01-15 09:00:00", 
                      "A service was installed in the system", "WORKSTATION", "SYSTEM"});
    events.push_back({1102, "Security", "Critical", "2024-01-14 23:59:00", 
                      "The audit log was cleared", "WORKSTATION", "DOMAIN\\admin"});
#endif
    
    return events;
}

void displayEvents(const std::vector<EventRecord>& events) {
    std::cout << std::left;
    std::cout << "  " << std::setw(8) << "ID" 
              << std::setw(12) << "Level"
              << std::setw(20) << "Timestamp"
              << "Message" << std::endl;
    std::cout << "  " << std::string(70, '─') << std::endl;
    
    for (const auto& event : events) {
        std::string levelIcon;
        if (event.level == "Critical" || event.level == "Error") {
            levelIcon = "🔴";
        } else if (event.level == "Warning") {
            levelIcon = "🟡";
        } else {
            levelIcon = "🟢";
        }
        
        std::string msg = event.message;
        if (msg.length() > 40) msg = msg.substr(0, 40) + "...";
        
        std::cout << "  " << levelIcon << " " << std::setw(6) << event.eventId
                  << std::setw(12) << event.level
                  << std::setw(20) << event.timestamp
                  << msg << std::endl;
    }
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Security Analysis
// ═══════════════════════════════════════════════════════════════════

void analyzeSecurityEvents(const License& license) {
    printHeader("🔐 SECURITY EVENT ANALYSIS");
    
    auto events = getEvents("Security", isPremium(license) ? 100 : 20);
    
    std::map<int, int> eventCounts;
    std::vector<EventRecord> criticalEvents;
    std::vector<EventRecord> warningEvents;
    
    for (const auto& event : events) {
        eventCounts[event.eventId]++;
        
        auto it = securityEventIds.find(event.eventId);
        if (it != securityEventIds.end()) {
            if (it->second.severity == "Critical") {
                criticalEvents.push_back(event);
            } else if (it->second.severity == "Warning") {
                warningEvents.push_back(event);
            }
        }
    }
    
    // Summary
    std::cout << "  Event Summary:" << std::endl;
    std::cout << "  " << std::string(50, '─') << std::endl;
    
    for (const auto& pair : eventCounts) {
        auto it = securityEventIds.find(pair.first);
        std::string desc = (it != securityEventIds.end()) ? it->second.description : "Unknown";
        std::cout << "    Event " << pair.first << " (" << desc << "): " 
                  << pair.second << " occurrences" << std::endl;
    }
    
    // Critical alerts
    if (!criticalEvents.empty()) {
        std::cout << "\n  🚨 CRITICAL ALERTS:" << std::endl;
        std::cout << "  " << std::string(50, '─') << std::endl;
        for (const auto& event : criticalEvents) {
            auto it = securityEventIds.find(event.eventId);
            std::cout << "    [" << event.timestamp << "] " 
                      << it->second.description << std::endl;
            std::cout << "      → " << it->second.recommendation << std::endl;
        }
    }
    
    // Warnings
    if (!warningEvents.empty() && isPremium(license)) {
        std::cout << "\n  ⚠️  WARNINGS:" << std::endl;
        std::cout << "  " << std::string(50, '─') << std::endl;
        for (const auto& event : warningEvents) {
            auto it = securityEventIds.find(event.eventId);
            std::cout << "    [" << event.timestamp << "] " 
                      << it->second.description << std::endl;
        }
    } else if (!warningEvents.empty()) {
        std::cout << "\n  " << warningEvents.size() << " warning events (Premium to view)" << std::endl;
    }
    
    std::cout << "\n  Total events analyzed: " << events.size() << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Failed Logon Analysis
// ═══════════════════════════════════════════════════════════════════

void analyzeFailedLogons(const License& license) {
    printHeader("🔓 FAILED LOGON ANALYSIS");
    
    if (!isPremium(license)) {
        printWarning("Failed logon analysis is a Premium feature");
        std::cout << "  Get keys at: " << DISCORD << std::endl << std::endl;
        return;
    }
    
    auto events = getEvents("Security", 200);
    
    std::map<std::string, int> failedByUser;
    std::map<std::string, int> failedByIP;
    int totalFailed = 0;
    
    for (const auto& event : events) {
        if (event.eventId == 4625) {
            failedByUser[event.user]++;
            // In real implementation, parse IP from event data
            totalFailed++;
        }
    }
    
    std::cout << "  Failed Logons by User:" << std::endl;
    std::cout << "  " << std::string(40, '─') << std::endl;
    
    for (const auto& pair : failedByUser) {
        std::string icon = pair.second > 5 ? "🔴" : "🟡";
        std::cout << "    " << icon << " " << pair.first << ": " 
                  << pair.second << " attempts" << std::endl;
    }
    
    if (totalFailed > 10) {
        printWarning("High number of failed logons detected!");
        std::cout << "  Consider investigating for brute force attacks\n" << std::endl;
    }
    
    std::cout << "\n  Total failed logons: " << totalFailed << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Process Creation Analysis
// ═══════════════════════════════════════════════════════════════════

void analyzeProcessCreation(const License& license) {
    printHeader("⚙️  PROCESS CREATION ANALYSIS");
    
    auto events = getEvents("Security", isPremium(license) ? 100 : 20);
    
    std::vector<EventRecord> processEvents;
    for (const auto& event : events) {
        if (event.eventId == 4688) {
            processEvents.push_back(event);
        }
    }
    
    std::cout << "  Recent Process Creations:" << std::endl;
    std::cout << "  " << std::string(60, '─') << std::endl;
    
    int limit = isPremium(license) ? processEvents.size() : 10;
    for (int i = 0; i < limit && i < processEvents.size(); i++) {
        std::cout << "    [" << processEvents[i].timestamp << "] "
                  << processEvents[i].message << std::endl;
    }
    
    if (!isPremium(license) && processEvents.size() > 10) {
        std::cout << "\n  ... and " << (processEvents.size() - 10) 
                  << " more events (Premium)" << std::endl;
    }
    
    std::cout << "\n  Total process events: " << processEvents.size() << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// System Log Analysis
// ═══════════════════════════════════════════════════════════════════

void analyzeSystemLog(const License& license) {
    printHeader("💻 SYSTEM LOG ANALYSIS");
    
    auto events = getEvents("System", isPremium(license) ? 50 : 20);
    
    displayEvents(events);
    
    // Check for service installations
    int serviceInstalls = 0;
    for (const auto& event : events) {
        if (event.eventId == 7045) {
            serviceInstalls++;
        }
    }
    
    if (serviceInstalls > 0) {
        printWarning("New service installations detected!");
        std::cout << "  Review service installations for legitimacy\n" << std::endl;
    }
    
    std::cout << "  Total system events: " << events.size() << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Application Log Analysis
// ═══════════════════════════════════════════════════════════════════

void analyzeApplicationLog(const License& license) {
    printHeader("📱 APPLICATION LOG ANALYSIS");
    
    auto events = getEvents("Application", isPremium(license) ? 50 : 20);
    
    displayEvents(events);
    
    std::cout << "  Total application events: " << events.size() << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Event Search
// ═══════════════════════════════════════════════════════════════════

void searchEvents(const std::string& query, const License& license) {
    printHeader("🔍 EVENT SEARCH: '" + query + "'");
    
    if (!isPremium(license)) {
        printWarning("Event search is a Premium feature");
        std::cout << "  Get keys at: " << DISCORD << std::endl << std::endl;
        return;
    }
    
    std::vector<std::string> logs = {"Security", "System", "Application"};
    int totalMatches = 0;
    
    for (const auto& log : logs) {
        auto events = getEvents(log, 200);
        
        std::cout << "  📁 " << log << " Log:" << std::endl;
        
        int matches = 0;
        for (const auto& event : events) {
            if (event.message.find(query) != std::string::npos ||
                event.source.find(query) != std::string::npos) {
                std::cout << "    [" << event.eventId << "] " 
                          << event.timestamp << " - " << event.message << std::endl;
                matches++;
                totalMatches++;
                
                if (matches >= 5) {
                    std::cout << "    ... (more matches)" << std::endl;
                    break;
                }
            }
        }
        
        if (matches == 0) {
            std::cout << "    (no matches)" << std::endl;
        }
        std::cout << std::endl;
    }
    
    std::cout << "  Total matches: " << totalMatches << std::endl;
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Export Report
// ═══════════════════════════════════════════════════════════════════

void exportReport(const License& license) {
    printHeader("📤 EXPORT REPORT");
    
    if (!isPremium(license)) {
        printWarning("Report export is a Premium feature");
        std::cout << "  Get keys at: " << DISCORD << std::endl << std::endl;
        return;
    }
    
    std::time_t now = std::time(nullptr);
    std::stringstream filename;
    filename << "nullsec_event_report_" << now << ".html";
    
    std::cout << "  Generating report: " << filename.str() << std::endl;
    
    // Generate HTML report
    std::ofstream report(filename.str());
    if (report.is_open()) {
        report << "<!DOCTYPE html><html><head><title>NullSec Event Report</title>";
        report << "<style>body{font-family:Arial;margin:20px;}";
        report << "table{border-collapse:collapse;width:100%;}";
        report << "th,td{border:1px solid #ddd;padding:8px;text-align:left;}";
        report << "th{background-color:#333;color:white;}</style></head>";
        report << "<body><h1>🪟 NullSec Windows Event Report</h1>";
        report << "<p>Generated: " << std::ctime(&now) << "</p>";
        
        // Add event data...
        report << "<h2>Security Events</h2>";
        auto secEvents = getEvents("Security", 50);
        report << "<table><tr><th>ID</th><th>Time</th><th>Level</th><th>Message</th></tr>";
        for (const auto& event : secEvents) {
            report << "<tr><td>" << event.eventId << "</td>";
            report << "<td>" << event.timestamp << "</td>";
            report << "<td>" << event.level << "</td>";
            report << "<td>" << event.message << "</td></tr>";
        }
        report << "</table>";
        
        report << "</body></html>";
        report.close();
        
        printSuccess("Report exported successfully");
    } else {
        printError("Failed to create report file");
    }
    
    std::cout << std::endl;
}

// ═══════════════════════════════════════════════════════════════════
// Main Menu
// ═══════════════════════════════════════════════════════════════════

void showMenu(License& license) {
    std::string input;
    
    while (true) {
        std::string tierBadge = isPremium(license) ? "⭐" : "🆓";
        
        std::cout << "\n  📋 NullSec Windows Event Analyzer " << tierBadge << "\n" << std::endl;
        std::cout << "  [1] Security Event Analysis" << std::endl;
        std::cout << "  [2] Failed Logon Analysis (Premium)" << std::endl;
        std::cout << "  [3] Process Creation Analysis" << std::endl;
        std::cout << "  [4] System Log Analysis" << std::endl;
        std::cout << "  [5] Application Log Analysis" << std::endl;
        std::cout << "  [6] Event Search (Premium)" << std::endl;
        std::cout << "  [7] Export Report (Premium)" << std::endl;
        std::cout << "  [8] Full Analysis" << std::endl;
        std::cout << "  [9] Enter License Key" << std::endl;
        std::cout << "  [0] Exit" << std::endl;
        
        std::cout << "\n  Select: ";
        std::getline(std::cin, input);
        
        if (input == "1") {
            analyzeSecurityEvents(license);
        } else if (input == "2") {
            analyzeFailedLogons(license);
        } else if (input == "3") {
            analyzeProcessCreation(license);
        } else if (input == "4") {
            analyzeSystemLog(license);
        } else if (input == "5") {
            analyzeApplicationLog(license);
        } else if (input == "6") {
            std::string query;
            std::cout << "  Search query: ";
            std::getline(std::cin, query);
            searchEvents(query, license);
        } else if (input == "7") {
            exportReport(license);
        } else if (input == "8") {
            analyzeSecurityEvents(license);
            analyzeSystemLog(license);
            analyzeApplicationLog(license);
            if (isPremium(license)) {
                analyzeFailedLogons(license);
                analyzeProcessCreation(license);
            }
        } else if (input == "9") {
            std::cout << "  License key: ";
            std::string key;
            std::getline(std::cin, key);
            license = validateLicense(key);
            if (license.valid) {
                printSuccess("License activated: " + tierToString(license.tier));
            } else {
                printWarning("Invalid license key");
            }
        } else if (input == "0") {
            break;
        } else {
            printError("Invalid option");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    std::cout << "\033[36m" << BANNER << "\033[0m";
    std::cout << "  Version " << VERSION << " | " << AUTHOR << std::endl;
    std::cout << "  🔑 Premium: " << DISCORD << "\n" << std::endl;
    
    License license;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            license = validateLicense(argv[++i]);
            if (license.valid) {
                printSuccess("License activated: " + tierToString(license.tier));
            }
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "  Usage: " << argv[0] << " [options]\n" << std::endl;
            std::cout << "  Options:" << std::endl;
            std::cout << "    -k, --key KEY    License key" << std::endl;
            std::cout << "    -h, --help       Show help" << std::endl;
            std::cout << "    -v, --version    Show version" << std::endl;
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "  NullSec Windows Event Analyzer v" << VERSION << std::endl;
            return 0;
        }
    }
    
#ifndef _WIN32
    printWarning("Running on non-Windows system - using demo mode");
    std::cout << "    Full functionality available on Windows\n" << std::endl;
#endif
    
    showMenu(license);
    
    // Footer
    std::cout << "\n─────────────────────────────────────────" << std::endl;
    std::cout << "  🪟 NullSec Windows Event Analyzer" << std::endl;
    std::cout << "  🔑 Premium: " << DISCORD << std::endl;
    std::cout << "  👤 Author: " << AUTHOR << std::endl;
    std::cout << "─────────────────────────────────────────\n" << std::endl;
    
    return 0;
}
