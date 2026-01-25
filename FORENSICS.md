# Windows Forensics Guide

## Overview
Windows forensic analysis techniques and artifact collection.

## Filesystem Artifacts

### User Activity
- Recent files
- Jump lists
- Shellbags
- Prefetch

### Program Execution
- Prefetch files
- Shimcache
- Amcache
- UserAssist

### File System
- MFT analysis
- USN journal
- $I30 indexes
- Deleted files

## Registry Forensics

### System Hives
- SYSTEM
- SOFTWARE
- SECURITY
- SAM

### User Hives
- NTUSER.DAT
- UsrClass.dat

### Key Artifacts
- MRU lists
- Run keys
- Services
- USB history

## Event Logs

### Security Events
- Logon events
- Object access
- Policy changes
- Account management

### System Events
- Service events
- Errors
- Warnings

## Memory Forensics

### Acquisition
- Live memory
- Hibernation file
- Pagefile
- Crash dumps

### Analysis
- Process listing
- Network connections
- Injected code
- Credentials

## Timeline Analysis
- Event correlation
- Activity reconstruction
- Gap identification

## Tools
- Volatility
- Autopsy
- KAPE
- RegRipper

## Legal Notice
For authorized forensic analysis.
