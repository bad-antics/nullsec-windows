// ═══════════════════════════════════════════════════════════════════
//  NULLSEC Windows AMSI Bypass & Memory Scanner
//  Advanced anti-malware interface bypass and memory analysis
//  @author bad-antics | discord.gg/killers
// ═══════════════════════════════════════════════════════════════════
//
//  Compile: cl /EHsc /Fe:amsi_scanner.exe amsi_scanner.cpp
//           advapi32.lib amsi.lib psapi.lib

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <amsi.h>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#define VERSION "2.0.0"
#define AUTHOR "bad-antics"
#define DISCORD "discord.gg/killers"

const char* BANNER = R"(
╭──────────────────────────────────────────╮
│     🪟 NULLSEC AMSI & MEMORY SCANNER    │
│     ═══════════════════════════════════ │
│                                          │
│   🔓 AMSI Status Analysis                │
│   🔍 Memory Pattern Scanning             │
│   🛡️  Detection Evasion Research          │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
)";

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

enum LicenseTier {
    LICENSE_FREE = 0,
    LICENSE_PREMIUM = 1,
    LICENSE_ENTERPRISE = 2
};

struct License {
    char key[25];
    LicenseTier tier;
    bool valid;
};

License g_license = { "", LICENSE_FREE, false };

bool validateLicense(const char* key) {
    if (!key || strlen(key) != 24) return false;
    if (strncmp(key, "NWIN-", 5) != 0) return false;
    
    strncpy_s(g_license.key, sizeof(g_license.key), key, 24);
    g_license.valid = true;
    
    char typeCode[3] = { key[5], key[6], '\0' };
    if (strcmp(typeCode, "PR") == 0) {
        g_license.tier = LICENSE_PREMIUM;
    } else if (strcmp(typeCode, "EN") == 0) {
        g_license.tier = LICENSE_ENTERPRISE;
    } else {
        g_license.tier = LICENSE_FREE;
    }
    
    return true;
}

bool isPremium() {
    return g_license.valid && g_license.tier != LICENSE_FREE;
}

const char* getTierName() {
    switch (g_license.tier) {
        case LICENSE_PREMIUM: return "Premium *";
        case LICENSE_ENTERPRISE: return "Enterprise $";
        default: return "Free";
    }
}

// ═══════════════════════════════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════════════════════════════

void setColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void resetColor() {
    setColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void printSuccess(const char* msg) {
    setColor(FOREGROUND_GREEN);
    printf("[+] %s\n", msg);
    resetColor();
}

void printError(const char* msg) {
    setColor(FOREGROUND_RED);
    printf("[-] %s\n", msg);
    resetColor();
}

void printWarning(const char* msg) {
    setColor(FOREGROUND_RED | FOREGROUND_GREEN);
    printf("[!] %s\n", msg);
    resetColor();
}

void printInfo(const char* msg) {
    setColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    printf("[*] %s\n", msg);
    resetColor();
}

void printHeader(const char* title) {
    printf("\n");
    printf("================================================\n");
    printf("  %s\n", title);
    printf("================================================\n\n");
}

// ═══════════════════════════════════════════════════════════════════
// AMSI Analysis
// ═══════════════════════════════════════════════════════════════════

struct AMSIStatus {
    bool amsiLoaded;
    bool amsiEnabled;
    PVOID amsiBaseAddr;
    SIZE_T amsiSize;
    bool scanInterfacePatched;
    std::vector<std::string> findings;
};

// Check if AMSI DLL is loaded
bool isAMSILoaded(AMSIStatus& status) {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (hAmsi) {
        status.amsiLoaded = true;
        status.amsiBaseAddr = hAmsi;
        
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hAmsi, &modInfo, sizeof(modInfo))) {
            status.amsiSize = modInfo.SizeOfImage;
        }
        return true;
    }
    status.amsiLoaded = false;
    return false;
}

// Check AmsiScanBuffer for common bypass patterns
bool checkAMSIBypass(AMSIStatus& status) {
    if (!status.amsiLoaded) return false;
    
    HMODULE hAmsi = (HMODULE)status.amsiBaseAddr;
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    
    if (!pAmsiScanBuffer) {
        status.findings.push_back("AmsiScanBuffer not found - unusual");
        return false;
    }
    
    // Check first bytes for common bypass patterns
    BYTE* funcBytes = (BYTE*)pAmsiScanBuffer;
    
    // Pattern 1: mov eax, 0x80070057 (E_INVALIDARG bypass)
    // Bytes: B8 57 00 07 80
    if (funcBytes[0] == 0xB8 && funcBytes[1] == 0x57 && 
        funcBytes[2] == 0x00 && funcBytes[3] == 0x07 && funcBytes[4] == 0x80) {
        status.scanInterfacePatched = true;
        status.findings.push_back("CRITICAL: AmsiScanBuffer patched (E_INVALIDARG bypass)");
        return true;
    }
    
    // Pattern 2: xor eax, eax; ret (return 0 bypass)
    // Bytes: 31 C0 C3 or 33 C0 C3
    if ((funcBytes[0] == 0x31 || funcBytes[0] == 0x33) && 
        funcBytes[1] == 0xC0 && funcBytes[2] == 0xC3) {
        status.scanInterfacePatched = true;
        status.findings.push_back("CRITICAL: AmsiScanBuffer patched (return 0 bypass)");
        return true;
    }
    
    // Pattern 3: ret (immediate return)
    if (funcBytes[0] == 0xC3) {
        status.scanInterfacePatched = true;
        status.findings.push_back("CRITICAL: AmsiScanBuffer patched (immediate ret)");
        return true;
    }
    
    // Pattern 4: mov eax, 1; ret (AMSI_RESULT_CLEAN)
    // Bytes: B8 01 00 00 00 C3
    if (funcBytes[0] == 0xB8 && funcBytes[1] == 0x01 && 
        funcBytes[2] == 0x00 && funcBytes[3] == 0x00 && 
        funcBytes[4] == 0x00 && funcBytes[5] == 0xC3) {
        status.scanInterfacePatched = true;
        status.findings.push_back("CRITICAL: AmsiScanBuffer patched (return CLEAN)");
        return true;
    }
    
    status.scanInterfacePatched = false;
    return false;
}

// Check AMSI context
void checkAMSIContext(AMSIStatus& status) {
    HAMSICONTEXT amsiContext = NULL;
    HRESULT hr = AmsiInitialize(L"NullSecScanner", &amsiContext);
    
    if (SUCCEEDED(hr) && amsiContext) {
        status.amsiEnabled = true;
        
        // Try to scan a test string
        HAMSISESSION amsiSession = NULL;
        hr = AmsiOpenSession(amsiContext, &amsiSession);
        
        if (SUCCEEDED(hr) && amsiSession) {
            AMSI_RESULT result;
            const char* testString = "AMSI Test String";
            
            hr = AmsiScanBuffer(
                amsiContext, 
                (PVOID)testString, 
                strlen(testString),
                L"test",
                amsiSession,
                &result
            );
            
            if (FAILED(hr)) {
                status.findings.push_back("AmsiScanBuffer returned failure - may be disabled");
            } else if (result == AMSI_RESULT_NOT_DETECTED) {
                status.findings.push_back("AMSI scan returned clean result");
            }
            
            AmsiCloseSession(amsiContext, amsiSession);
        }
        
        AmsiUninitialize(amsiContext);
    } else {
        status.amsiEnabled = false;
        status.findings.push_back("AMSI initialization failed - may be disabled");
    }
}

AMSIStatus analyzeAMSI() {
    AMSIStatus status = { false, false, NULL, 0, false, {} };
    
    printInfo("Checking AMSI status...");
    
    isAMSILoaded(status);
    if (status.amsiLoaded) {
        char msg[128];
        sprintf_s(msg, "AMSI.dll loaded at 0x%p (Size: %zu bytes)", 
                  status.amsiBaseAddr, status.amsiSize);
        printInfo(msg);
        
        checkAMSIBypass(status);
        checkAMSIContext(status);
    } else {
        // Try to load AMSI
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (hAmsi) {
            status.amsiLoaded = true;
            status.amsiBaseAddr = hAmsi;
            printInfo("AMSI.dll loaded on demand");
            checkAMSIBypass(status);
            checkAMSIContext(status);
        } else {
            status.findings.push_back("AMSI.dll not available on this system");
        }
    }
    
    return status;
}

// ═══════════════════════════════════════════════════════════════════
// Memory Scanner
// ═══════════════════════════════════════════════════════════════════

struct MemoryFinding {
    DWORD pid;
    std::string processName;
    PVOID address;
    SIZE_T size;
    std::string description;
    std::string severity;
};

std::vector<MemoryFinding> g_memoryFindings;

// Scan process memory for suspicious patterns
void scanProcessMemory(DWORD pid, const char* processName) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    PVOID addr = si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // Check for RWX memory (highly suspicious)
            if (mbi.State == MEM_COMMIT && 
                mbi.Protect == PAGE_EXECUTE_READWRITE) {
                
                MemoryFinding finding;
                finding.pid = pid;
                finding.processName = processName;
                finding.address = mbi.BaseAddress;
                finding.size = mbi.RegionSize;
                finding.description = "RWX memory region detected";
                finding.severity = "Critical";
                g_memoryFindings.push_back(finding);
            }
            
            // Check for executable anonymous memory
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE) && 
                mbi.Type == MEM_PRIVATE) {
                
                // Premium: Read and analyze the memory content
                if (isPremium() && mbi.RegionSize < 1024 * 1024) {
                    BYTE* buffer = new BYTE[mbi.RegionSize];
                    SIZE_T bytesRead;
                    
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, 
                                         mbi.RegionSize, &bytesRead)) {
                        // Look for shellcode patterns
                        // Common x86/x64 shellcode signatures
                        
                        // NOP sled
                        int nopCount = 0;
                        for (SIZE_T i = 0; i < bytesRead - 16; i++) {
                            if (buffer[i] == 0x90) nopCount++;
                            else nopCount = 0;
                            
                            if (nopCount > 16) {
                                MemoryFinding finding;
                                finding.pid = pid;
                                finding.processName = processName;
                                finding.address = (PVOID)((BYTE*)mbi.BaseAddress + i - nopCount);
                                finding.size = mbi.RegionSize;
                                finding.description = "NOP sled detected (potential shellcode)";
                                finding.severity = "High";
                                g_memoryFindings.push_back(finding);
                                break;
                            }
                        }
                    }
                    
                    delete[] buffer;
                }
            }
            
            addr = (PVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
        } else {
            addr = (PVOID)((BYTE*)addr + 0x1000);
        }
    }
    
    CloseHandle(hProcess);
}

void scanAllProcesses() {
    printInfo("Scanning process memory...");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printError("Failed to create process snapshot");
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    int scanned = 0;
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Skip system processes
            if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) continue;
            
            char processName[MAX_PATH];
            wcstombs(processName, pe32.szExeFile, MAX_PATH);
            
            scanProcessMemory(pe32.th32ProcessID, processName);
            scanned++;
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    char msg[64];
    sprintf_s(msg, "Scanned %d processes", scanned);
    printSuccess(msg);
}

// ═══════════════════════════════════════════════════════════════════
// Report
// ═══════════════════════════════════════════════════════════════════

void printReport(const AMSIStatus& amsiStatus) {
    printHeader("AMSI STATUS");
    
    printf("  AMSI Loaded:    %s\n", amsiStatus.amsiLoaded ? "Yes" : "No");
    if (amsiStatus.amsiLoaded) {
        printf("  Base Address:   0x%p\n", amsiStatus.amsiBaseAddr);
        printf("  Module Size:    %zu bytes\n", amsiStatus.amsiSize);
    }
    printf("  AMSI Enabled:   %s\n", amsiStatus.amsiEnabled ? "Yes" : "No");
    printf("  Interface Patched: %s\n", amsiStatus.scanInterfacePatched ? "YES (BYPASSED)" : "No");
    
    if (!amsiStatus.findings.empty()) {
        printf("\n  Findings:\n");
        for (const auto& finding : amsiStatus.findings) {
            if (finding.find("CRITICAL") != std::string::npos) {
                setColor(FOREGROUND_RED);
            } else {
                setColor(FOREGROUND_RED | FOREGROUND_GREEN);
            }
            printf("    - %s\n", finding.c_str());
            resetColor();
        }
    }
    
    if (!g_memoryFindings.empty()) {
        printHeader("MEMORY FINDINGS");
        
        for (const auto& finding : g_memoryFindings) {
            const char* icon;
            WORD color;
            
            if (finding.severity == "Critical") {
                icon = "[CRIT]";
                color = FOREGROUND_RED;
            } else if (finding.severity == "High") {
                icon = "[HIGH]";
                color = FOREGROUND_RED | FOREGROUND_GREEN;
            } else {
                icon = "[MED]";
                color = FOREGROUND_GREEN;
            }
            
            setColor(color);
            printf("  %s %s\n", icon, finding.description.c_str());
            resetColor();
            printf("         Process: %s (PID: %lu)\n", finding.processName.c_str(), finding.pid);
            printf("         Address: 0x%p (Size: %zu)\n", finding.address, finding.size);
            printf("\n");
        }
    } else {
        printHeader("MEMORY FINDINGS");
        printSuccess("No suspicious memory regions found");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Interactive Mode
// ═══════════════════════════════════════════════════════════════════

void interactiveMode() {
    char input[256];
    
    while (true) {
        printf("\n  NullSec AMSI & Memory Scanner [%s]\n\n", getTierName());
        printf("  [1] Analyze AMSI Status\n");
        printf("  [2] Scan Process Memory\n");
        printf("  [3] Full System Scan\n");
        printf("  [4] Enter License Key\n");
        printf("  [0] Exit\n");
        
        printf("\n  Select: ");
        if (!fgets(input, sizeof(input), stdin)) break;
        
        int choice = atoi(input);
        
        switch (choice) {
            case 1: {
                AMSIStatus status = analyzeAMSI();
                printReport(status);
                break;
            }
            case 2: {
                printf("  PID: ");
                if (fgets(input, sizeof(input), stdin)) {
                    DWORD pid = atoi(input);
                    if (pid > 0) {
                        g_memoryFindings.clear();
                        scanProcessMemory(pid, "Target");
                        AMSIStatus emptyStatus = {};
                        printReport(emptyStatus);
                    }
                }
                break;
            }
            case 3: {
                g_memoryFindings.clear();
                AMSIStatus status = analyzeAMSI();
                scanAllProcesses();
                printReport(status);
                break;
            }
            case 4: {
                printf("  License key: ");
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\n")] = 0;  // Remove newline
                    if (validateLicense(input)) {
                        printSuccess("License activated");
                    } else {
                        printWarning("Invalid license key");
                    }
                }
                break;
            }
            case 0:
                return;
            default:
                printError("Invalid option");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    setColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    printf("%s", BANNER);
    resetColor();
    printf("  Version %s | %s\n", VERSION, AUTHOR);
    printf("  Premium: %s\n\n", DISCORD);
    
    // Parse arguments
    bool autoScan = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            if (validateLicense(argv[++i])) {
                char msg[100];
                sprintf_s(msg, "License activated: %s", getTierName());
                printSuccess(msg);
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--scan") == 0) {
            autoScan = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -k KEY     License key\n");
            printf("  -s         Auto scan (non-interactive)\n");
            printf("  -h         Show this help\n");
            return 0;
        }
    }
    
    if (autoScan) {
        g_memoryFindings.clear();
        AMSIStatus status = analyzeAMSI();
        scanAllProcesses();
        printReport(status);
    } else {
        interactiveMode();
    }
    
    printf("\n-----------------------------------------\n");
    printf("  NullSec AMSI & Memory Scanner\n");
    printf("  Premium: %s\n", DISCORD);
    printf("  Author: %s\n", AUTHOR);
    printf("-----------------------------------------\n\n");
    
    return 0;
}
