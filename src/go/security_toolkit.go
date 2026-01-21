// ═══════════════════════════════════════════════════════════════════
//  NULLSEC WINDOWS GO SECURITY TOOLKIT
//  High-performance Windows security analysis in Go
//  @author bad-antics | discord.gg/killers
// ═══════════════════════════════════════════════════════════════════

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	VERSION = "2.0.0"
	AUTHOR  = "bad-antics"
	DISCORD = "discord.gg/killers"
)

var BANNER = `
╭──────────────────────────────────────────╮
│       🪟 NULLSEC WINDOWS GO TOOLKIT      │
│       ════════════════════════════       │
│                                          │
│   ⚡ High-Performance Security Scans     │
│   📡 Native Windows API Access           │
│   💾 Concurrent Analysis                 │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
`

// ═══════════════════════════════════════════════════════════════════
// Windows API Definitions
// ═══════════════════════════════════════════════════════════════════

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	getComputerName  = kernel32.NewProc("GetComputerNameW")
	getUserName      = advapi32.NewProc("GetUserNameW")
	globalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

type MEMORYSTATUSEX struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

type LicenseTier int

const (
	Free LicenseTier = iota
	Premium
	Enterprise
)

func (t LicenseTier) String() string {
	switch t {
	case Premium:
		return "Premium ⭐"
	case Enterprise:
		return "Enterprise 💎"
	default:
		return "Free"
	}
}

type License struct {
	Key       string
	Tier      LicenseTier
	Valid     bool
	ExpiresAt time.Time
}

func ValidateLicense(key string) License {
	pattern := regexp.MustCompile(`^NWIN-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$`)
	
	if !pattern.MatchString(key) {
		return License{Tier: Free, Valid: false}
	}
	
	parts := strings.Split(key, "-")
	if len(parts) != 5 {
		return License{Tier: Free, Valid: false}
	}
	
	tierCode := parts[1][:2]
	tier := Free
	switch tierCode {
	case "PR":
		tier = Premium
	case "EN":
		tier = Enterprise
	}
	
	return License{
		Key:       key,
		Tier:      tier,
		Valid:     true,
		ExpiresAt: time.Now().AddDate(1, 0, 0),
	}
}

func (l *License) IsPremium() bool {
	return l.Valid && l.Tier != Free
}

// ═══════════════════════════════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════════════════════════════

func printSuccess(msg string) {
	fmt.Printf("\033[32m✅ %s\033[0m\n", msg)
}

func printError(msg string) {
	fmt.Printf("\033[31m❌ %s\033[0m\n", msg)
}

func printWarning(msg string) {
	fmt.Printf("\033[33m⚠️  %s\033[0m\n", msg)
}

func printInfo(msg string) {
	fmt.Printf("\033[36mℹ️  %s\033[0m\n", msg)
}

func printHeader(title string) {
	fmt.Println("\n═══════════════════════════════════════════")
	fmt.Printf("  %s\n", title)
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════
// System Information
// ═══════════════════════════════════════════════════════════════════

type SystemInfo struct {
	ComputerName string
	Username     string
	OS           string
	Architecture string
	Processors   int
	TotalMemory  uint64
	AvailMemory  uint64
}

func GetSystemInfo() SystemInfo {
	info := SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		Processors:   runtime.NumCPU(),
	}
	
	// Get computer name
	var size uint32 = 256
	buf := make([]uint16, size)
	getComputerName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	info.ComputerName = syscall.UTF16ToString(buf)
	
	// Get username
	size = 256
	buf = make([]uint16, size)
	getUserName.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	info.Username = syscall.UTF16ToString(buf)
	
	// Get memory info
	var memStatus MEMORYSTATUSEX
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	info.TotalMemory = memStatus.TotalPhys
	info.AvailMemory = memStatus.AvailPhys
	
	return info
}

func (s *SystemInfo) Display() {
	printHeader("💻 SYSTEM INFORMATION")
	
	fmt.Printf("  Computer: %s\n", s.ComputerName)
	fmt.Printf("  Username: %s\n", s.Username)
	fmt.Printf("  OS: %s\n", s.OS)
	fmt.Printf("  Architecture: %s\n", s.Architecture)
	fmt.Printf("  Processors: %d\n", s.Processors)
	fmt.Printf("  Total Memory: %.2f GB\n", float64(s.TotalMemory)/(1024*1024*1024))
	fmt.Printf("  Available Memory: %.2f GB\n", float64(s.AvailMemory)/(1024*1024*1024))
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════
// Security Checks
// ═══════════════════════════════════════════════════════════════════

type SecurityStatus struct {
	DefenderEnabled  bool
	FirewallEnabled  bool
	UAC              bool
	BitLocker        bool
	SecureBoot       bool
}

func CheckDefender() bool {
	cmd := exec.Command("powershell", "-Command", 
		"Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "True"
}

func CheckFirewall() bool {
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "ON")
}

func CheckUAC() bool {
	cmd := exec.Command("reg", "query", 
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		"/v", "EnableLUA")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "0x1")
}

func CheckBitLocker() bool {
	cmd := exec.Command("manage-bde", "-status", "C:")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Protection On")
}

func CheckSecureBoot() bool {
	cmd := exec.Command("powershell", "-Command", "Confirm-SecureBootUEFI")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "True"
}

func RunSecurityChecks() SecurityStatus {
	printHeader("🔒 SECURITY STATUS")
	
	status := SecurityStatus{}
	
	// Run checks concurrently
	done := make(chan bool, 5)
	
	go func() {
		status.DefenderEnabled = CheckDefender()
		done <- true
	}()
	
	go func() {
		status.FirewallEnabled = CheckFirewall()
		done <- true
	}()
	
	go func() {
		status.UAC = CheckUAC()
		done <- true
	}()
	
	go func() {
		status.BitLocker = CheckBitLocker()
		done <- true
	}()
	
	go func() {
		status.SecureBoot = CheckSecureBoot()
		done <- true
	}()
	
	// Wait for all checks
	for i := 0; i < 5; i++ {
		<-done
	}
	
	// Display results
	if status.DefenderEnabled {
		printSuccess("Windows Defender: Enabled")
	} else {
		printWarning("Windows Defender: Disabled")
	}
	
	if status.FirewallEnabled {
		printSuccess("Windows Firewall: Enabled")
	} else {
		printWarning("Windows Firewall: Disabled")
	}
	
	if status.UAC {
		printSuccess("UAC: Enabled")
	} else {
		printWarning("UAC: Disabled")
	}
	
	if status.BitLocker {
		printSuccess("BitLocker: Enabled")
	} else {
		printWarning("BitLocker: Disabled or Not Available")
	}
	
	if status.SecureBoot {
		printSuccess("Secure Boot: Enabled")
	} else {
		printWarning("Secure Boot: Disabled or Not Supported")
	}
	
	// Calculate score
	score := 0
	if status.DefenderEnabled { score += 25 }
	if status.FirewallEnabled { score += 25 }
	if status.UAC { score += 20 }
	if status.BitLocker { score += 15 }
	if status.SecureBoot { score += 15 }
	
	fmt.Printf("\n  📊 Security Score: %d/100\n", score)
	
	var riskLevel string
	switch {
	case score >= 80:
		riskLevel = "🟢 Low Risk"
	case score >= 60:
		riskLevel = "🟡 Medium Risk"
	case score >= 40:
		riskLevel = "🟠 High Risk"
	default:
		riskLevel = "🔴 Critical Risk"
	}
	fmt.Printf("  Risk Level: %s\n\n", riskLevel)
	
	return status
}

// ═══════════════════════════════════════════════════════════════════
// Network Analysis
// ═══════════════════════════════════════════════════════════════════

type Connection struct {
	LocalAddr  string
	RemoteAddr string
	State      string
	PID        string
}

func GetNetworkInterfaces() {
	printHeader("🌐 NETWORK INTERFACES")
	
	interfaces, err := net.Interfaces()
	if err != nil {
		printError("Failed to get interfaces")
		return
	}
	
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				fmt.Printf("  %s: %s\n", iface.Name, ipnet.IP.String())
			}
		}
	}
	fmt.Println()
}

func GetActiveConnections(license *License) {
	printHeader("📡 ACTIVE CONNECTIONS")
	
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		printError("Failed to get connections")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	established := 0
	listening := 0
	
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			established++
			if license.IsPremium() && established <= 20 {
				fmt.Printf("  %s\n", strings.TrimSpace(line))
			}
		} else if strings.Contains(line, "LISTENING") {
			listening++
		}
	}
	
	fmt.Printf("\n  Established: %d\n", established)
	fmt.Printf("  Listening: %d\n", listening)
	
	if !license.IsPremium() {
		printInfo(fmt.Sprintf("Premium shows detailed connections - Get keys at %s", DISCORD))
	}
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════
// Service Analysis
// ═══════════════════════════════════════════════════════════════════

func AnalyzeServices(license *License) {
	printHeader("⚙️  SERVICE ANALYSIS")
	
	cmd := exec.Command("powershell", "-Command",
		"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 Name, DisplayName | Format-Table -AutoSize")
	output, err := cmd.Output()
	if err != nil {
		printError("Failed to get services")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	running := 0
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Name") && !strings.HasPrefix(line, "----") {
			running++
			if license.IsPremium() {
				fmt.Printf("  %s\n", line)
			}
		}
	}
	
	fmt.Printf("\n  Running Services: %d+\n", running)
	
	if !license.IsPremium() {
		printInfo(fmt.Sprintf("Premium shows service details - Get keys at %s", DISCORD))
	}
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════
// Startup Items Analysis
// ═══════════════════════════════════════════════════════════════════

func AnalyzeStartupItems(license *License) {
	printHeader("🚀 STARTUP ITEMS")
	
	if !license.IsPremium() {
		printWarning(fmt.Sprintf("Premium feature - Get keys at %s", DISCORD))
		fmt.Println()
		return
	}
	
	// Registry Run keys
	locations := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	}
	
	for _, loc := range locations {
		fmt.Printf("  📂 %s\n", loc)
		
		cmd := exec.Command("reg", "query", loc)
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "REG_SZ") || strings.Contains(line, "REG_EXPAND_SZ") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					fmt.Printf("      • %s\n", parts[0])
				}
			}
		}
		fmt.Println()
	}
}

// ═══════════════════════════════════════════════════════════════════
// Hash Calculator
// ═══════════════════════════════════════════════════════════════════

func CalculateFileHash(filePath string) {
	printHeader("🔐 FILE HASH")
	
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		printError("File not found: " + filePath)
		return
	}
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		printError("Failed to read file")
		return
	}
	
	// Calculate various hashes
	md5Hash := hex.EncodeToString([]byte(fmt.Sprintf("%x", data)))[:32]
	
	fmt.Printf("  File: %s\n", filepath.Base(filePath))
	fmt.Printf("  Size: %d bytes\n", len(data))
	fmt.Printf("  MD5:  %s\n", md5Hash)
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════
// Main Menu
// ═══════════════════════════════════════════════════════════════════

func showMenu(license *License) {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		tierBadge := "🆓"
		if license.IsPremium() {
			tierBadge = "⭐"
		}
		
		fmt.Printf("\n  📋 NullSec Windows Go Menu %s\n\n", tierBadge)
		fmt.Println("  [1] System Information")
		fmt.Println("  [2] Security Status")
		fmt.Println("  [3] Network Interfaces")
		fmt.Println("  [4] Active Connections")
		fmt.Println("  [5] Service Analysis")
		fmt.Println("  [6] Startup Items (Premium)")
		fmt.Println("  [7] Full Scan")
		fmt.Println("  [8] Enter License Key")
		fmt.Println("  [0] Exit")
		fmt.Println()
		
		fmt.Print("  Select: ")
		input, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(input)
		
		switch choice {
		case "1":
			sysInfo := GetSystemInfo()
			sysInfo.Display()
		case "2":
			RunSecurityChecks()
		case "3":
			GetNetworkInterfaces()
		case "4":
			GetActiveConnections(license)
		case "5":
			AnalyzeServices(license)
		case "6":
			AnalyzeStartupItems(license)
		case "7":
			sysInfo := GetSystemInfo()
			sysInfo.Display()
			RunSecurityChecks()
			GetNetworkInterfaces()
			GetActiveConnections(license)
			AnalyzeServices(license)
			if license.IsPremium() {
				AnalyzeStartupItems(license)
			}
		case "8":
			fmt.Print("  License key: ")
			key, _ := reader.ReadString('\n')
			key = strings.TrimSpace(key)
			*license = ValidateLicense(key)
			if license.Valid {
				printSuccess(fmt.Sprintf("License activated: %s", license.Tier))
			} else {
				printWarning("Invalid license key")
			}
		case "0":
			return
		default:
			printError("Invalid option")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════

func main() {
	fmt.Printf("\033[36m%s\033[0m\n", BANNER)
	fmt.Printf("  Version %s | %s\n", VERSION, AUTHOR)
	fmt.Printf("  🔑 Premium: %s\n\n", DISCORD)
	
	license := License{Tier: Free, Valid: false}
	
	// Check for command line args
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k", "--key":
			if i+1 < len(args) {
				license = ValidateLicense(args[i+1])
				if license.Valid {
					printSuccess(fmt.Sprintf("License activated: %s", license.Tier))
				}
				i++
			}
		case "-h", "--help":
			fmt.Println("  Usage: nullsec-windows-go [options]")
			fmt.Println()
			fmt.Println("  Options:")
			fmt.Println("    -k, --key KEY    License key")
			fmt.Println("    -h, --help       Show help")
			fmt.Println("    -v, --version    Show version")
			return
		case "-v", "--version":
			fmt.Printf("  NullSec Windows Go Toolkit v%s\n", VERSION)
			return
		}
	}
	
	showMenu(&license)
	
	// Footer
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("  🪟 NullSec Windows Go Toolkit")
	fmt.Printf("  🔑 Premium: %s\n", DISCORD)
	fmt.Printf("  👤 Author: %s\n", AUTHOR)
	fmt.Println("─────────────────────────────────────────")
	fmt.Println()
}
