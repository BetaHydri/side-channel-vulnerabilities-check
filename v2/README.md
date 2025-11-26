# Side-Channel Vulnerability Mitigation Tool v2.1.0

Enterprise-grade PowerShell tool for assessing and managing Windows side-channel vulnerability mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs) with comprehensive hardware detection and intelligent scoring.

## 🎯 What's New in v2.1.0

### Major Enhancements
- **✨ Simplified Mode Structure** - Dedicated modes replace parameter combinations
- **🛡️ Comprehensive Coverage** - 24 mitigations (100% parity with v1)
- **🔍 Hardware Detection** - Automatic detection of UEFI, Secure Boot, TPM 2.0, VT-x, IOMMU
- **📊 Intelligent Scoring** - Excludes prerequisites and N/A items from security score
- **💾 Advanced Backup System** - Dedicated Backup and Restore modes
- **👁️ WhatIf Support** - Preview all changes before applying
- **🎨 Enhanced Visual Output** - Block-based progress bar with Unicode icons (█░)
- **🖥️ Platform-Aware** - Automatically adapts to Physical/Hyper-V/VMware environments
- **🔧 PS 5.1 & 7.x Compatible** - Runtime Unicode generation for cross-version compatibility

### Version Comparison

| Feature | v1 (Legacy) | v2.1.0 (Current) |
|---------|-------------|------------------|
| Mitigations Covered | 28 checks | 24 checks (streamlined) |
| Architecture | Monolithic | Modular functions |
| Hardware Detection | Basic | Comprehensive (5 prerequisites) |
| Scoring | All-inclusive | Intelligent (excludes N/A) |
| Modes | Assess/Apply/Revert | 5 dedicated modes |
| Backup System | Auto-backup only | Dedicated management |
| WhatIf Support | ❌ No | ✅ Yes |
| PowerShell Support | 5.1+ | 5.1 & 7.x (optimized) |
| Unicode Rendering | BOM-dependent | Runtime generation |

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7.x
- Administrator privileges
- Execution policy allowing script execution

**Note:** v2.1.0 uses runtime Unicode generation for full compatibility across PowerShell versions without requiring UTF-8 BOM encoding.

```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Basic Usage

```powershell
# 1. Assessment (default mode)
.\SideChannel_Check_v2.ps1

# 2. Apply mitigations interactively
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# 3. Preview changes first (recommended)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# 4. Revert to most recent backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# 5. Restore from specific backup
.\SideChannel_Check_v2.ps1 -Mode Restore
```

## 📋 Available Modes

### 1. **Assess** (Default)
Evaluate current security posture without making changes.

```powershell
# Standard assessment
.\SideChannel_Check_v2.ps1

# With detailed educational output
.\SideChannel_Check_v2.ps1 -ShowDetails

# Export results to CSV
.\SideChannel_Check_v2.ps1 -ExportPath "security_assessment.csv"
```

**Output:**
- Platform Information (CPU, OS, Hypervisor status)
- Hardware Prerequisites Status (5 checks)
- Security Mitigations Status (19 mitigations)
- Enhanced Visual Security Score Bar with block characters (█░)
- Color-coded recommendations with emoji indicators
- Detailed mitigation table with impact assessment

**Detailed Output** (`-ShowDetails` flag):
When using `-ShowDetails`, each mitigation displays comprehensive educational information:
- **CVE Numbers** - Associated vulnerability identifiers
- **Description** - What the mitigation protects against
- **Runtime Status** - Actual kernel-level protection state
- **Registry Status** - Configured values
- **Impact** - Performance implications (Low/Medium/High)
- **Recommendations** - Actions needed (if any)

Example detailed output:
```
• Speculative Store Bypass Disable [Protected]
  CVE:          CVE-2018-3639
  Description:  Prevents Speculative Store Bypass (Variant 4) attacks
  Runtime:      Active
  Registry:     Enabled
  Impact:       Low
```

### 2. **ApplyInteractive**
Interactively select and apply security mitigations with two selection modes.

```powershell
# Interactive application
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# Preview changes first (recommended)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf
```

**Selection Modes:**
- **[R] Recommended** - Shows only actionable/recommended mitigations (default)
- **[A] All Mitigations** - Shows all 24+ available mitigations for selective hardening

**Recommended Workflow:**
1. Run detailed assessment: `.\SideChannel_Check_v2.ps1 -ShowDetails`
2. Review CVEs, descriptions, impacts, and recommendations
3. Use ApplyInteractive with mode [A] to selectively enable mitigations
4. Make informed decisions based on your security requirements

**Features:**
- ✅ Automatic backup creation before changes
- ✅ Interactive selection (individual, ranges, or all)
- ✅ Two view modes: Recommended only or All mitigations
- ✅ WhatIf preview support
- ✅ Impact warnings and current status display
- ✅ System restart notification

**Selection Syntax:**
- `1,3,5` - Apply specific mitigations
- `1-4` - Apply range of mitigations
- `all` - Apply all shown mitigations
- `critical` - Apply only critical mitigations
- `Q` - Quit without changes

### 3. **RevertInteractive**
Restore most recent backup configuration.

```powershell
# Revert to last backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# Preview revert operation
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf
```

**Features:**
- ✅ Shows backup metadata (timestamp, computer, user)
- ✅ Confirmation prompt before reverting
- ✅ WhatIf preview of changes
- ✅ Detailed restore summary

### 4. **Backup**
Create a backup of current mitigation settings.

```powershell
# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup

# Preview backup operation
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf
```

**Backup Contents:**
- Timestamp (ISO 8601 format)
- Computer name
- User name
- All mitigation registry values (24 settings)

**Backup Location:** `.\Backups\Backup_YYYYMMDD_HHMMSS.json`

### 5. **Restore**
Browse and restore from any available backup with selective restoration.

```powershell
# Interactive restore
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**Restore Options:**
- **[A] All mitigations** - Restore complete backup (all settings)
- **[S] Select individual** - Choose specific mitigations to restore
- **[Q] Cancel** - Exit without changes

**Features:**
- ✅ Lists all available backups with age and metadata
- ✅ Shows backup details (computer, user, timestamp, mitigation count)
- ✅ Interactive backup selection
- ✅ Selective restoration - restore only what you need
- ✅ Full or partial restore support
- ✅ WhatIf preview available
- ✅ Intelligent filtering - skips hardware-only items (TPM, CPU features)
- ✅ Clean restore summary with success/skipped counts

**Restore Summary Example:**
```
Successfully restored: 21
Skipped (hardware-only): 3
```

**Use Cases:**
- Restore entire configuration after testing
- Selectively restore specific mitigations
- Recover from misconfiguration
- Rollback individual settings while keeping others

**Note:** Hardware-only features (TPM 2.0, CPU Virtualization, IOMMU/VT-d) are firmware/BIOS settings and cannot be restored from registry backups. These are automatically skipped during restore operations.

---

## 🔍 Comprehensive Assessment Output

### Sample Output - v2.1.0

```
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

[Debug] Detecting platform type...
[Info] Platform detected: HyperVHost
[Debug] Detecting hardware security features...
[Success] Hardware detection complete
[Debug] Initializing kernel runtime state detection...
[Success] Kernel runtime state detection: Operational

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)
[Info] Starting mitigation assessment...
[Success] Assessment complete: 24 mitigations evaluated

--- Security Assessment Summary ---
Total Mitigations Evaluated:  19
Protected:                    19 (100%)

Security Score: [████████████████████████████████████████] 100%
Security Level: Excellent

--- Hardware Prerequisites ---
Prerequisites Enabled: 5 / 5

--- Mitigation Status ---
Mitigation                                    Status               Action Needed             Impact
--------------------------------------------  -------------------  ------------------------  ---------
Speculative Store Bypass Disable             Protected           No                       Low
SSBD Feature Mask                            Protected           No                       Low
Branch Target Injection Mitigation           Protected           No                       Low
Kernel VA Shadow (Meltdown Protection)       Protected           No                       Medium
Enhanced IBRS                                Protected           No                       Low
Intel TSX Disable                            Protected           No                       Low
L1 Terminal Fault Mitigation                 Protected           No                       High
MDS Mitigation (ZombieLoad)                  Protected           No                       Medium
TSX Asynchronous Abort Mitigation            Protected           No                       Medium
Hardware Security Mitigations                Protected           No                       Low
SBDR/SBDS Mitigation                         Protected           No                       Low
SRBDS Update Mitigation                      Protected           No                       Low
DRPW Mitigation                              Protected           No                       Low
Exception Chain Validation                   Protected           No                       Low
Supervisor Mode Access Prevention            Protected           No                       Low
Virtualization Based Security                Protected           No                       Low
Hypervisor-protected Code Integrity          Protected           No                       Low
Credential Guard                             Protected           No                       Low
Hyper-V Core Scheduler                       Protected           No                       Medium
UEFI Firmware                                Active              No                       None
Secure Boot                                  Protected           No                       None
TPM 2.0                                      Protected           No                       None
CPU Virtualization (VT-x/AMD-V)              Protected           No                       None
IOMMU/VT-d Support                           Protected           No                       None

✓ All critical mitigations are properly configured!
```

**Note:** The security score bar uses filled blocks (█) for protected mitigations and light blocks (░) for unprotected ones, providing a clear visual representation. The bar is color-coded: Green (≥90%), Cyan (≥75%), Yellow (≥50%), Red (<50%).

### Detailed Status Explanation

**Mitigation Status Values:**
- **Protected** - Mitigation is properly configured and active
- **Vulnerable** - Mitigation is not configured or disabled
- **Not Applicable** - Hardware doesn't support this mitigation
- **Unknown** - Status cannot be determined

**Prerequisite Status Values:**
- **Protected** - Feature is enabled and active (Secure Boot, TPM, VT-x, IOMMU)
- **Active** - Feature is present and working (UEFI)
- **Vulnerable** - Feature is supported but not enabled (e.g., Secure Boot capable but disabled)
- **Missing** - Feature is not available on this hardware

### Sample Output - ApplyInteractive Mode

```
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

=== Interactive Mitigation Application ===
Select mitigations to apply (or 'all' for recommended, 'critical' for critical only)

[1] L1 Terminal Fault Mitigation
    High performance impact; primarily for multi-tenant virtualization environments
    Impact: High | CVE: CVE-2018-3620

[2] MDS Mitigation (ZombieLoad)
    Protects against MDS attacks
    Impact: Medium | CVE: CVE-2018-12130

Enter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): 2

You have selected 1 mitigation(s):
  • MDS Mitigation (ZombieLoad)

A backup will be created before applying changes.
Do you want to proceed? (Y/N): Y

[INFO] Creating configuration backup...
[SUCCESS] Backup created: C:\...\Backups\Backup_20251126_153045.json

Applying mitigations...
[INFO] Applying: MDS Mitigation (ZombieLoad)
[SUCCESS] Applied: MDS Mitigation (ZombieLoad)

=== Summary ===
Successfully applied: 1
Backup saved: C:\...\Backups\Backup_20251126_153045.json

⚠ A system restart is required for changes to take effect.
```

### Sample Output - WhatIf Mode

```
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

=== Interactive Mitigation Application ===
[WhatIf Mode] Changes will be previewed but not applied

Select mitigations to apply (or 'all' for recommended, 'critical' for critical only)

[1] MDS Mitigation (ZombieLoad)
    Protects against MDS attacks
    Impact: Medium | CVE: CVE-2018-12130

Enter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): 1

You have selected 1 mitigation(s):
  • MDS Mitigation (ZombieLoad)

=== WhatIf: Changes Preview ===
The following changes would be made:

[MDS] MDS Mitigation (ZombieLoad)
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: MDSMitigationLevel
  New Value: 1
  Impact: Medium

WhatIf Summary:
Total changes that would be made: 1
Backup would be created: Yes
System restart would be required: Yes
```

### Sample Output - Backup Mode

```
.\SideChannel_Check_v2.ps1 -Mode Backup

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

[Debug] Detecting platform type...
[Info] Platform detected: HyperVHost
[Debug] Detecting hardware security features...
[Success] Hardware detection complete
[Debug] Initializing kernel runtime state detection...
[Success] Kernel runtime state detection: Operational

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

=== Create Configuration Backup ===

Creating backup of current mitigation settings...

✓ Backup created successfully!
Location: C:\...\Backups\Backup_20251126_201040.json

Backup Details:
Timestamp:   2025-11-26T20:10:40
Computer:    JANTIEDE-STUDIO
User:        jantiede
Mitigations: 21
```

**Backup with WhatIf Preview:**
```
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf

=== Create Configuration Backup ===

[WhatIf Mode] Would create backup of current mitigation settings...

Backup would include:
Computer:    JANTIEDE-STUDIO
User:        jantiede
Mitigations: 21

Would save to: C:\...\Backups\Backup_<timestamp>.json
```

### Sample Output - Restore Mode

```
.\SideChannel_Check_v2.ps1 -Mode Restore

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

=== Available Backups ===

[1] Backup_20251126_153622.json
    Computer: WORKSTATION01
    User: Administrator
    Created: 2025-11-26 15:36:22 (5m ago)
    Mitigations: 19

[2] Backup_20251126_143022.json
    Computer: WORKSTATION01
    User: Administrator
    Created: 2025-11-26 14:30:22 (1h ago)
    Mitigations: 19

Enter backup number to restore (or 'q' to quit): 1

=== Restore Preview ===
This will restore configuration from: 2025-11-26 15:36:22

Changes that will be made:
  [+] Restore: SSBD - Value: 72
  [+] Restore: SSBD Mask - Value: 3
  [+] Restore: BTI - Value: 0
  ... (16 more changes)

Total changes: 19
System restart required: Yes

Do you want to proceed? (Y/N): Y

[INFO] Restoring configuration from 2025-11-26T15:36:22...
[INFO] Restored: Speculative Store Bypass Disable
[INFO] Restored: SSBD Feature Mask
... (17 more)

=== Restore Summary ===
Successfully restored: 21
Skipped (hardware-only): 3

✓ Configuration restored.
⚠ A system restart is required for changes to take effect.
```

**Note:** Hardware-only features like TPM 2.0, CPU Virtualization, and IOMMU are automatically skipped as they are firmware/BIOS settings, not registry values.

### Sample Output - RevertInteractive Mode

```
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

--- Platform Information ---
Type:        HyperVHost
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

=== Revert to Most Recent Backup ===

Found most recent backup:
Timestamp: 2025-11-26T20:25:50
Computer:  JANTIEDE-STUDIO
User:      jantiede

Do you want to restore this backup? (Y/N): Y

[Info] Restoring configuration from 2025-11-26T20:25:50
[Info] Restored: Speculative Store Bypass Disable
[Info] Restored: SSBD Feature Mask
[Info] Restored: Branch Target Injection Mitigation
... (18 more)

=== Restore Summary ===
Successfully restored: 21
Skipped (hardware-only): 3

✓ Configuration restored.
⚠ A system restart is required.
```

### Sample Output - CSV Export

```
.\SideChannel_Check_v2.ps1 -ExportPath "security_assessment.csv"

================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.0
================================================================================

[Assessment runs normally...]

✓ Assessment exported successfully to: security_assessment.csv
```

**CSV Content Preview:**
```csv
Id,Name,CVE,Category,RegistryStatus,RuntimeStatus,OverallStatus,ActionNeeded,Impact,Description,Recommendation
SSBD,"Speculative Store Bypass Disable",CVE-2018-3639,Critical,Enabled,Active,Protected,No,Low,"Prevents Speculative Store Bypass attacks","Enable to protect against speculative execution vulnerabilities"
KVAS,"Kernel VA Shadow (Meltdown Protection)",CVE-2017-5754,Critical,Enabled,Active,Protected,No,Medium,"Page table isolation to prevent Meltdown attacks","Critical for Meltdown protection; modern CPUs have hardware immunity"
...
```

---

## 🛡️ Mitigation Coverage

### Critical Mitigations (6)
- **SSBD** (Speculative Store Bypass Disable) - CVE-2018-3639
- **SSBD Mask** (Required companion setting)
- **BTI** (Branch Target Injection) - CVE-2017-5715 (Spectre v2)
- **KVAS** (Kernel VA Shadow) - CVE-2017-5754 (Meltdown)
- **Enhanced IBRS** - Hardware Spectre v2 protection
- **Hardware Security Mitigations** - Core CPU protections

### Recommended Mitigations (8)
- **TSX Disable** - Prevents TAA vulnerabilities
- **MDS** (Microarchitectural Data Sampling) - CVE-2018-12130
- **TAA** (TSX Asynchronous Abort) - CVE-2019-11135
- **SBDR/SBDS** - CVE-2022-21123, CVE-2022-21125
- **SRBDS** - CVE-2022-21127
- **DRPW** - CVE-2022-21166
- **Exception Chain Validation** - SEH protection
- **SMAP** (Supervisor Mode Access Prevention)

### Optional Mitigations (5)
- **L1TF** (L1 Terminal Fault) - High performance impact
- **VBS** (Virtualization Based Security) - Requires hardware
- **HVCI** (Hypervisor-protected Code Integrity) - Requires VBS
- **Credential Guard** - Requires VBS + TPM
- **Hyper-V Core Scheduler** - For Hyper-V hosts

### Hardware Prerequisites (5)
- **UEFI Firmware** - Required for modern security
- **Secure Boot** - Boot integrity protection
- **TPM 2.0** - Hardware cryptographic security
- **CPU Virtualization (VT-x/AMD-V)** - For Hyper-V and VBS
- **IOMMU/VT-d** - DMA protection and HVCI optimization

---

## 🧪 Testing & Validation

### Automated Test Script

Save as `Test-SideChannelTool.ps1`:

```powershell
#Requires -RunAsAdministrator

Write-Host "=== Side-Channel Tool v2 Test Suite ===" -ForegroundColor Cyan

# Test 1: Basic Assessment
Write-Host "`n[Test 1] Basic Assessment..." -ForegroundColor Yellow
try {
    $result = & ".\SideChannel_Check_v2.ps1" 2>&1
    Write-Host "✅ PASS: Assessment completed" -ForegroundColor Green
} catch {
    Write-Host "❌ FAIL: Assessment failed - $_" -ForegroundColor Red
}

# Test 2: WhatIf Mode
Write-Host "`n[Test 2] WhatIf Mode..." -ForegroundColor Yellow
try {
    $result = & ".\SideChannel_Check_v2.ps1" -Mode ApplyInteractive -WhatIf 2>&1
    if ($result -match "WhatIf") {
        Write-Host "✅ PASS: WhatIf mode working" -ForegroundColor Green
    } else {
        Write-Host "⚠️  WARN: WhatIf indicator not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ FAIL: WhatIf test failed - $_" -ForegroundColor Red
}

# Test 3: Backup Creation
Write-Host "`n[Test 3] Backup Creation..." -ForegroundColor Yellow
try {
    $backupsBefore = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
    & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
    $backupsAfter = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
    
    if ($backupsAfter -gt $backupsBefore) {
        Write-Host "✅ PASS: Backup created successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ FAIL: Backup not created" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: Backup test failed - $_" -ForegroundColor Red
}

# Test 4: CSV Export
Write-Host "`n[Test 4] CSV Export..." -ForegroundColor Yellow
$testCsvPath = ".\test_export.csv"
try {
    & ".\SideChannel_Check_v2.ps1" -ExportPath $testCsvPath | Out-Null
    
    if (Test-Path $testCsvPath) {
        $csv = Import-Csv $testCsvPath
        if ($csv.Count -gt 0) {
            Write-Host "✅ PASS: CSV export successful ($($csv.Count) rows)" -ForegroundColor Green
        } else {
            Write-Host "❌ FAIL: CSV is empty" -ForegroundColor Red
        }
        Remove-Item $testCsvPath -Force
    } else {
        Write-Host "❌ FAIL: CSV file not created" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: CSV export test failed - $_" -ForegroundColor Red
}

# Test 5: WhatIf - No Changes Made
Write-Host "`n[Test 5] WhatIf Safety Check..." -ForegroundColor Yellow
try {
    $backupsBefore = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
    & ".\SideChannel_Check_v2.ps1" -Mode Backup -WhatIf | Out-Null
    $backupsAfter = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
    
    if ($backupsAfter -eq $backupsBefore) {
        Write-Host "✅ PASS: WhatIf prevented changes" -ForegroundColor Green
    } else {
        Write-Host "❌ FAIL: WhatIf did not prevent changes" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ FAIL: WhatIf safety test failed - $_" -ForegroundColor Red
}

# Test 6: Restore Mode Browse
Write-Host "`n[Test 6] Restore Mode..." -ForegroundColor Yellow
try {
    # Create a test backup first
    & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
    
    # Attempt to browse (won't actually restore without selection)
    $result = & ".\SideChannel_Check_v2.ps1" -Mode Restore 2>&1
    
    if ($result -match "available backup") {
        Write-Host "✅ PASS: Restore mode lists backups" -ForegroundColor Green
    } else {
        Write-Host "⚠️  WARN: No backups found or unexpected output" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ FAIL: Restore mode test failed - $_" -ForegroundColor Red
}

Write-Host "`n=== Test Suite Complete ===" -ForegroundColor Cyan
```

### Manual Test Scenarios

#### Test 1: Basic Assessment
```powershell
.\SideChannel_Check_v2.ps1

# Expected: 
# ✅ No errors or exceptions
# ✅ Security score displayed (0-100%)
# ✅ All mitigations evaluated
# ✅ Prerequisites shown separately
```

#### Test 2: WhatIf Preview
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# Expected:
# ✅ No registry changes made
# ✅ Preview of all selected changes displayed
# ✅ "WhatIf Mode" clearly indicated
```

#### Test 3: Interactive Apply
```powershell
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive
# Select: 1,2

# Expected:
# ✅ Backup created before changes
# ✅ Only selected mitigations applied
# ✅ Success/failure count displayed
# ✅ System restart warning shown
```

#### Test 4: Backup & Restore
```powershell
# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup

# Browse backups
.\SideChannel_Check_v2.ps1 -Mode Restore

# Expected:
# ✅ Backup file created in .\Backups\
# ✅ All backups listed with timestamps
# ✅ Age calculation correct (e.g., "2h ago")
```

#### Test 5: WhatIf with Revert
```powershell
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf

# Expected:
# ✅ Lists latest backup
# ✅ Shows all changes that would be made
# ✅ No actual restore performed
```

---

## 📊 Performance Considerations

### Low Impact (<5% performance loss)
- SSBD, BTI, Enhanced IBRS, TSX Disable
- SBDR/SBDS, SRBDS, DRPW
- Exception Chain Validation, SMAP

### Medium Impact (5-15% performance loss)
- KVAS (Kernel VA Shadow / Meltdown)
- MDS (Microarchitectural Data Sampling)
- TAA (TSX Asynchronous Abort)
- Hyper-V Core Scheduler

### High Impact (15%+ performance loss)
- L1TF (L1 Terminal Fault)
- **⚠️ Test in non-production first!**

---

## 🔒 Security Best Practices

### Recommended Workflow

1. **Assessment** → `.\SideChannel_Check_v2.ps1`
2. **Planning** → `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf`
3. **Backup** → `.\SideChannel_Check_v2.ps1 -Mode Backup`
4. **Apply** → `.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive`
5. **Validate** → Restart system, re-run assessment
6. **Rollback** → `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` (if issues)

### Enterprise Deployment

```powershell
# Assess multiple systems
$computers = @("SERVER01", "SERVER02")
$computers | ForEach-Object {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        & "C:\Scripts\SideChannel_Check_v2.ps1" -ExportPath "C:\Reports\$env:COMPUTERNAME.csv"
    }
}
```

---

## 🐛 Troubleshooting

### Access Denied
```powershell
# Solution: Run as Administrator
Start-Process powershell -Verb RunAs
```

### Backups not found
```powershell
# Check backup directory
Test-Path ".\Backups\"
Get-ChildItem ".\Backups\Backup_*.json"
```

### Export fails
```powershell
# Create export directory
$exportDir = Split-Path $ExportPath -Parent
New-Item -ItemType Directory -Path $exportDir -Force
```

### WhatIf not working
```powershell
# Verify PowerShell supports ShouldProcess
Get-Help about_Functions_CmdletBindingAttribute
```

### Unicode characters not displaying correctly
**Solution:** v2.1.0 uses runtime Unicode generation for full compatibility.

The script automatically generates Unicode characters (✓, ✗, ⚠, █, ░) at runtime using `[System.Char]::ConvertFromUtf32()`, ensuring consistent display across PowerShell 5.1 and 7.x without requiring specific file encoding.

**No action needed** - this is handled automatically by the `Get-StatusIcon` function.

---

## ⚠️ Important Warnings

- ⚠️ **Always use -WhatIf first**
- ⚠️ **System restart required** after changes
- ⚠️ **Create backups** before modifications
- ⚠️ **Test in non-production** first

---

## 📝 Changelog

### v2.1.0 (2025-11-26)
- ✨ Enhanced interactive modes with selective apply & restore
  * **ApplyInteractive**: Choice between [R]ecommended (actionable only) or [A]ll mitigations view
  * **Restore**: Support for [A]ll (complete) or [S]elective (individual) restoration
  * Supports informed decision-making workflow after detailed assessment
- 🔧 Fixed restore mode warnings and improved reliability
  * Intelligent filtering of hardware-only items (TPM 2.0, CPU Virtualization, IOMMU/VT-d)
  * Clean restore summary: "Successfully restored: 21, Skipped (hardware-only): 3"
  * No more "Cannot bind argument to parameter 'Path'" warnings
- 🔧 Added parameter validation for incompatible combinations
  * ShowDetails warns when used with non-applicable modes (only works with Assess/ApplyInteractive)
- 🎨 Enhanced visual output with Unicode block characters (█░)
  * Security score bar: `[████████████████████████████████████████] 100%`
  * Runtime Unicode generation for PowerShell 5.1 & 7.x compatibility
- 📊 Intelligent security scoring system
  * Excludes N/A items and prerequisites from score calculation
  * Focuses on actual configurable mitigations
- 🛡️ Comprehensive hardware detection (5 prerequisites)
- 💾 Dedicated Backup and Restore modes with JSON-based storage
- ✨ WhatIf support for all modification modes
- 🐛 Fixed PowerShell 5.1 compatibility issues (array handling, DateTime parsing)

### v2.0.0 (2025-11-20)
- 🎉 Initial v2 release
- Modular function-based architecture
- PowerShell 5.1 & 7.x compatibility
- Runtime kernel detection
- Interactive modes
- Automatic backup creation
- JSON-based restore system

---

## 📄 License

MIT License

---

## 👤 Author

**Jan Tiedemann**
- GitHub: [@BetaHydri](https://github.com/BetaHydri)

---

**Version:** 2.1.0  
**Last Updated:** 2025-11-26  
**PowerShell:** 5.1, 7.x  
**Platform:** Windows 10/11, Server 2016+
