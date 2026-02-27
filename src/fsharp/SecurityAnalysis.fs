// NullSec Windows F# Security Analysis
// Functional security analysis tools
// @author bad-antics
// @twitter x.com/AnonAntics

module NullSecWindows.FSharp.SecurityAnalysis

open System
open System.IO
open System.Net
open System.Net.NetworkInformation
open System.ServiceProcess
open System.Diagnostics
open Microsoft.Win32

let VERSION = "2.0.0"
let AUTHOR = "bad-antics"
let DISCORD = "x.com/AnonAntics"

let BANNER = """
╭──────────────────────────────────────────╮
│       🪟 NULLSEC WINDOWS F# TOOLS        │
│       ════════════════════════════       │
│                                          │
│   🔧 Functional Security Analysis        │
│   📡 Type-Safe Security Scanning         │
│   💾 Immutable Data Structures           │
│                                          │
│            bad-antics | NullSec         │
╰──────────────────────────────────────────╯
"""

// ═══════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════

type LicenseTier = Free | Premium | Enterprise

type License = {
    Key: string
    Tier: LicenseTier
    Valid: bool
}

let validateLicense (key: string) : License =
    let defaultLicense = { Key = ""; Tier = Free; Valid = false }
    
    if String.IsNullOrEmpty(key) || key.Length <> 24 || not (key.StartsWith("NWIN-")) then
        defaultLicense
    else
        let parts = key.Split('-')
        if parts.Length <> 5 then
            defaultLicense
        else
            let tierCode = parts.[1].Substring(0, min 2 parts.[1].Length)
            let tier = 
                match tierCode with
                | "PR" -> Premium
                | "EN" -> Enterprise
                | _ -> Free
            { Key = key; Tier = tier; Valid = true }

let isPremium (license: License) =
    license.Valid && license.Tier <> Free

// ═══════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════

let printSuccess msg = printfn "\x1b[32m✅ %s\x1b[0m" msg
let printError msg = printfn "\x1b[31m❌ %s\x1b[0m" msg
let printWarning msg = printfn "\x1b[33m⚠️  %s\x1b[0m" msg
let printInfo msg = printfn "\x1b[34mℹ️  %s\x1b[0m" msg
let printCyan msg = printfn "\x1b[36m%s\x1b[0m" msg

// ═══════════════════════════════════════════
// Type Definitions
// ═══════════════════════════════════════════

type SecurityStatus = Enabled | Disabled | Unknown

type FirewallProfile = {
    Name: string
    Enabled: bool
    DefaultInbound: string
    DefaultOutbound: string
}

type ServiceInfo = {
    Name: string
    DisplayName: string
    Status: string
    StartType: string
}

type NetworkConnection = {
    LocalAddress: string
    LocalPort: int
    RemoteAddress: string
    RemotePort: int
    State: string
    ProcessId: int
}

type RegistrySecurityItem = {
    Path: string
    Name: string
    Value: obj
    Risk: string
}

// ═══════════════════════════════════════════
// Registry Analysis
// ═══════════════════════════════════════════

let getRegistryValue path name =
    try
        use key = Registry.LocalMachine.OpenSubKey(path)
        if key <> null then
            Some (key.GetValue(name))
        else
            None
    with _ -> None

let checkUACEnabled () =
    match getRegistryValue @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" with
    | Some value -> 
        match value with
        | :? int as i -> i = 1
        | _ -> false
    | None -> false

let checkSecureBootEnabled () =
    match getRegistryValue @"SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled" with
    | Some value ->
        match value with
        | :? int as i -> i = 1
        | _ -> false
    | None -> false

let getAutoRunItems () =
    let paths = [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    
    paths
    |> List.collect (fun path ->
        try
            use key = Registry.LocalMachine.OpenSubKey(path)
            if key <> null then
                key.GetValueNames()
                |> Array.toList
                |> List.map (fun name ->
                    { Path = path
                      Name = name
                      Value = key.GetValue(name)
                      Risk = "Low" })
            else
                []
        with _ -> [])

// ═══════════════════════════════════════════
// Service Analysis
// ═══════════════════════════════════════════

let getServices () =
    ServiceController.GetServices()
    |> Array.toList
    |> List.map (fun svc ->
        { Name = svc.ServiceName
          DisplayName = svc.DisplayName
          Status = svc.Status.ToString()
          StartType = "Unknown" }) // Would need WMI for start type

let getRunningServices () =
    getServices ()
    |> List.filter (fun s -> s.Status = "Running")

let getStoppedServices () =
    getServices ()
    |> List.filter (fun s -> s.Status = "Stopped")

let analyzeServices () =
    printfn "\n⚙️  Service Analysis:\n"
    
    let services = getServices ()
    let running = getRunningServices ()
    let stopped = getStoppedServices ()
    
    printfn "  Total Services: %d" services.Length
    printfn "  Running: %d" running.Length
    printfn "  Stopped: %d" stopped.Length
    
    // Potentially suspicious services (non-Microsoft)
    let suspicious = 
        running
        |> List.filter (fun s -> 
            not (s.DisplayName.Contains("Windows")) &&
            not (s.DisplayName.Contains("Microsoft")))
        |> List.take (min 10 running.Length)
    
    if not (List.isEmpty suspicious) then
        printfn "\n  📋 Non-Microsoft running services:"
        suspicious |> List.iter (fun s ->
            printfn "      • %s" s.DisplayName)
    
    services

// ═══════════════════════════════════════════
// Network Analysis
// ═══════════════════════════════════════════

let getNetworkInterfaces () =
    NetworkInterface.GetAllNetworkInterfaces()
    |> Array.filter (fun ni -> ni.OperationalStatus = OperationalStatus.Up)
    |> Array.choose (fun ni ->
        let props = ni.GetIPProperties()
        let ipv4 = 
            props.UnicastAddresses
            |> Seq.tryFind (fun a -> a.Address.AddressFamily = Sockets.AddressFamily.InterNetwork)
        match ipv4 with
        | Some addr -> Some (ni.Name, addr.Address.ToString())
        | None -> None)
    |> Array.toList

let getActiveConnections () =
    let props = IPGlobalProperties.GetIPGlobalProperties()
    props.GetActiveTcpConnections()
    |> Array.toList
    |> List.map (fun conn ->
        { LocalAddress = conn.LocalEndPoint.Address.ToString()
          LocalPort = conn.LocalEndPoint.Port
          RemoteAddress = conn.RemoteEndPoint.Address.ToString()
          RemotePort = conn.RemoteEndPoint.Port
          State = conn.State.ToString()
          ProcessId = 0 }) // TCP info doesn't have PID directly

let analyzeNetwork () =
    printfn "\n🌐 Network Analysis:\n"
    
    printfn "  Network Interfaces:"
    getNetworkInterfaces ()
    |> List.iter (fun (name, ip) ->
        printfn "    %s: %s" name ip)
    
    let connections = 
        getActiveConnections ()
        |> List.filter (fun c -> c.State = "Established")
    
    printfn "\n  Established Connections: %d" connections.Length
    
    connections
    |> List.take (min 20 connections.Length)
    |> List.iter (fun c ->
        printfn "    %s:%d → %s:%d" c.LocalAddress c.LocalPort c.RemoteAddress c.RemotePort)
    
    connections

// ═══════════════════════════════════════════
// Security Assessment
// ═══════════════════════════════════════════

type SecurityAssessment = {
    UACEnabled: bool
    SecureBootEnabled: bool
    AutoRunCount: int
    SuspiciousServices: int
    EstablishedConnections: int
    OverallScore: int
}

let performSecurityAssessment () =
    printfn "\n🔒 Security Assessment:\n"
    
    let uacEnabled = checkUACEnabled ()
    let secureBootEnabled = checkSecureBootEnabled ()
    let autoRuns = getAutoRunItems ()
    let services = getRunningServices ()
    let connections = getActiveConnections () |> List.filter (fun c -> c.State = "Established")
    
    // Calculate score (simplified)
    let mutable score = 100
    
    if not uacEnabled then
        score <- score - 20
        printWarning "UAC is disabled"
    else
        printSuccess "UAC is enabled"
    
    if not secureBootEnabled then
        score <- score - 15
        printWarning "Secure Boot is disabled or not available"
    else
        printSuccess "Secure Boot is enabled"
    
    if autoRuns.Length > 20 then
        score <- score - 10
        printWarning (sprintf "High number of startup items: %d" autoRuns.Length)
    else
        printSuccess (sprintf "Startup items: %d" autoRuns.Length)
    
    printfn ""
    printfn "  📊 Security Score: %d/100" score
    
    let riskLevel = 
        match score with
        | s when s >= 80 -> "🟢 Low Risk"
        | s when s >= 60 -> "🟡 Medium Risk"
        | s when s >= 40 -> "🟠 High Risk"
        | _ -> "🔴 Critical Risk"
    
    printfn "  Risk Level: %s" riskLevel
    
    { UACEnabled = uacEnabled
      SecureBootEnabled = secureBootEnabled
      AutoRunCount = autoRuns.Length
      SuspiciousServices = 0
      EstablishedConnections = connections.Length
      OverallScore = score }

// ═══════════════════════════════════════════
// File System Analysis
// ═══════════════════════════════════════════

let getRecentFiles (path: string) (count: int) =
    try
        Directory.GetFiles(path, "*.*", SearchOption.TopDirectoryOnly)
        |> Array.map (fun f -> FileInfo(f))
        |> Array.sortByDescending (fun f -> f.LastWriteTime)
        |> Array.take (min count (Directory.GetFiles(path).Length))
        |> Array.toList
    with _ -> []

let analyzeRecentDownloads () =
    printfn "\n📥 Recent Downloads:\n"
    
    let downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
    
    let recentFiles = getRecentFiles downloadsPath 20
    
    if List.isEmpty recentFiles then
        printfn "  No recent downloads found"
    else
        recentFiles
        |> List.iter (fun f ->
            printfn "  • %s" f.Name
            printfn "    Modified: %s" (f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
            printfn "    Size: %d bytes" f.Length)
    
    recentFiles

// ═══════════════════════════════════════════
// Main Menu
// ═══════════════════════════════════════════

let showMenu (license: License) =
    printCyan BANNER
    
    let tierBadge = 
        match license.Tier with
        | Premium -> "⭐"
        | Enterprise -> "💎"
        | Free -> "🆓"
    
    let rec menuLoop () =
        printfn "\n📋 NullSec F# Menu %s\n" tierBadge
        printfn "  [1] Security Assessment"
        printfn "  [2] Service Analysis"
        printfn "  [3] Network Analysis"
        printfn "  [4] Registry Security"
        printfn "  [5] Recent Downloads"
        printfn "  [0] Exit"
        printfn ""
        
        printf "Select: "
        let input = Console.ReadLine()
        
        match input with
        | "1" -> 
            performSecurityAssessment () |> ignore
            menuLoop ()
        | "2" -> 
            analyzeServices () |> ignore
            menuLoop ()
        | "3" -> 
            analyzeNetwork () |> ignore
            menuLoop ()
        | "4" ->
            printfn "\n🔑 Registry Security Items:\n"
            let items = getAutoRunItems ()
            items |> List.iter (fun item ->
                printfn "  • %s: %A" item.Name item.Value)
            menuLoop ()
        | "5" ->
            analyzeRecentDownloads () |> ignore
            menuLoop ()
        | "0" -> ()
        | _ ->
            printError "Invalid option"
            menuLoop ()
    
    menuLoop ()
    
    printfn "\n─────────────────────────────────────────"
    printfn "🪟 NullSec Windows F# Tools"
    printfn "🔑 Premium: x.com/AnonAntics"
    printfn "🐦 GitHub: bad-antics"
    printfn "─────────────────────────────────────────\n"

// Entry point
[<EntryPoint>]
let main args =
    let mutable license = { Key = ""; Tier = Free; Valid = false }
    
    let rec parseArgs = function
        | "-k" :: key :: rest | "--key" :: key :: rest ->
            license <- validateLicense key
            printInfo (sprintf "License tier: %A" license.Tier)
            parseArgs rest
        | "-h" :: _ | "--help" :: _ ->
            printfn "NullSec Windows F# Tools v%s" VERSION
            printfn "%s | %s\n" AUTHOR DISCORD
            printfn "Usage: nullsec-fsharp [options]\n"
            printfn "Options:"
            printfn "  -k, --key KEY    License key"
            printfn "  -h, --help       Show help"
            printfn "  -v, --version    Show version"
            1
        | "-v" :: _ | "--version" :: _ ->
            printfn "NullSec Windows F# Tools v%s" VERSION
            0
        | _ :: rest -> parseArgs rest
        | [] -> 
            showMenu license
            0
    
    parseArgs (Array.toList args)
