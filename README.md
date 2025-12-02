# Side-Channel Vulnerability Mitigation Tool v2.1.7

Enterprise-grade PowerShell tool for assessing and managing Windows side-channel vulnerability mitigations (Spectre, Meltdown, L1TF, MDS, and related CVEs) with comprehensive hardware detection and intelligent scoring.

## 🎯 Features

### Critical Fixes (v2.1.7)
- **🔧 CRITICAL BUG FIX** - Corrected all kernel API flag bitmasks (v2.1.6 had completely wrong values)
- **✅ KVAS Detection Fixed** - Now correctly shows "Not Needed (HW Immune)" for Meltdown-immune CPUs (Tiger Lake, Ice Lake, etc.)
- **🎯 Microsoft Alignment** - All flag detection now matches Microsoft's SpeculationControl module exactly

### Major Enhancements (v2.1.6)
- **🔬 Hardware-Based Detection** - Reads flags2 from Windows kernel API for SBDR/FBSDP/PSDP
- **🎯 Microsoft SpeculationControl Alignment** - Detection logic matches Microsoft's official module
- **🛡️ Comprehensive Coverage** - 31 mitigations (added FBSDP) + 5 hardware prerequisites
- **✨ Simplified Mode Structure** - Dedicated modes replace parameter combinations
- **🎯 Selective Apply & Restore** - Choose [R]ecommended or [A]ll mitigations; restore [A]ll or [S]elective items
- **🔍 Hardware Detection** - Automatic detection of UEFI, Secure Boot, TPM 2.0, VT-x, IOMMU
- **📊 Intelligent Scoring** - Visual security score bar (█░) with smart filtering
- **💾 Advanced Backup System** - Selective restoration with hardware-only filtering
- **👁️ WhatIf Support** - Preview all changes before applying
- **🎨 Enhanced Visual Output** - Block characters, educational detailed view
- **🖥️ Platform-Aware** - Automatically adapts to Physical/Hyper-V/VMware environments
- **🔧 PS 5.1 & 7.x Compatible** - Runtime Unicode generation for cross-version compatibility

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7.x
- Administrator privileges
- Execution policy allowing script execution

```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

> **⚠️ Virtual Machine Users:** If running on a VM, the **hypervisor host must also have mitigations enabled**
> and restarted before CPU-specific features (PSDP, Retbleed, MMIO) will work in the guest VM.
> See [`HYPERVISOR_CONFIGURATION.md`](HYPERVISOR_CONFIGURATION.md) for complete setup instructions.

### Basic Usage

```powershell
# 1. Assessment (default mode) - Check current security status
.\SideChannel_Check_v2.ps1

# 2. Detailed educational view - Learn about CVEs and impacts
.\SideChannel_Check_v2.ps1 -ShowDetails

# 3. Apply mitigations interactively - Harden your system (auto-backup created)
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive

# 4. Preview changes first - See what will change before applying
.\SideChannel_Check_v2.ps1 -Mode ApplyInteractive -WhatIf

# 5. Quick undo - Revert to most recent backup instantly
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# 6. Advanced recovery - Browse backups, restore selectively
.\SideChannel_Check_v2.ps1 -Mode Restore

# 7. Manual backup - Create checkpoint before risky changes
.\SideChannel_Check_v2.ps1 -Mode Backup
```

**When to use which mode:**
- **Assess** → Checking security status, generating reports
- **ShowDetails** → Learning about vulnerabilities and recommendations
- **ApplyInteractive** → Hardening system (backup auto-created)
- **RevertInteractive** → Undo recent changes quickly
- **Restore** → Need older backup or selective restore
- **Backup** → Creating manual checkpoint (optional, ApplyInteractive auto-creates one)

---

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

# Combine assessment with CSV export
.\SideChannel_Check_v2.ps1 -ShowDetails -ExportPath "detailed_report.csv"
```

**Parameters:**
- **`-ExportPath`** - Export assessment results table to CSV (mitigation status, recommendations)
- **`-ShowDetails`** - Show detailed educational information (CVEs, descriptions, impacts)
- **`-LogPath`** - Optional: Custom log file location (default: `.\Logs\SideChannelCheck_<timestamp>.log`)

**Note:** The log file contains execution details (what the script did), while ExportPath creates a CSV of your security assessment data (what mitigations are enabled/disabled). Most users only need `-ExportPath` for reporting.

**Output:**
- Platform Information (CPU, OS, Hypervisor status)
- Hardware Security Features (Firmware, Secure Boot, TPM, VT-x, IOMMU, VBS/HVCI capability)
- Hardware Prerequisites Status (5 checks)
- Security Mitigations Status (19 mitigations)
- Enhanced Visual Security Score Bar with block characters (█░)
- Color-coded recommendations with emoji indicators
- Detailed mitigation table with impact assessment

**Hardware Security Features Display:**
The platform information section now includes comprehensive hardware capability detection:
- **Firmware** - UEFI (green) or Legacy BIOS (yellow)
- **Secure Boot** - Enabled (green), Capable but Disabled (yellow), or Not Supported (red)
- **TPM** - Present with version (green) or Not Detected (red)
- **VT-x/AMD-V** - CPU virtualization status (green enabled, red disabled)
- **IOMMU/VT-d** - I/O memory management detection (green detected, red not detected)
- **VBS Capable** - Hardware prerequisites met for Virtualization Based Security (green yes, red no with hints)
- **HVCI Capable** - Hardware prerequisites met for Hypervisor-protected Code Integrity

Color coding helps quickly identify missing security prerequisites and provides contextual hints for missing requirements (e.g., "Requires: UEFI" when VBS is not capable).

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
  URL:          https://nvd.nist.gov/vuln/detail/CVE-2018-3639
  Description:  Prevents Speculative Store Bypass (Variant 4) attacks
  Runtime:      ✓ Active
  Registry:     Enabled
  Impact:       Low

• UEFI Firmware [Active]
  CVE:          Boot Security Prerequisite
  URL:          https://uefi.org/specifications
  Required For: Secure Boot, VBS, HVCI, Credential Guard
  Description:  UEFI firmware mode (required for Secure Boot and modern security)
  Runtime:      ✓ Active
  Impact:       None

• TPM 2.0 [Protected]
  CVE:          Hardware Cryptographic Security
  Required For: BitLocker, VBS, Credential Guard, Windows Hello
  Description:  Trusted Platform Module for hardware-based cryptography
  Runtime:      ✓ Active (2.0)
  Impact:       None
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
3. **Create manual backup:** `.\SideChannel_Check_v2.ps1 -Mode Backup` (recommended before any changes)
4. Use ApplyInteractive with mode [A] to selectively enable mitigations
5. Make informed decisions based on your security requirements
6. Restart system to activate changes
7. **If needed, restore from backup:** `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` or `-Mode Restore`

**Features:**
- ✅ Automatic backup creation before changes (ApplyInteractive mode)
- ✅ Manual backup recommended for safety before starting remediation
- ✅ Interactive selection (individual, ranges, or all)
- ✅ Two view modes: Recommended only or All mitigations
- ✅ WhatIf preview support
- ✅ Impact warnings and current status display
- ✅ System restart notification

**Selection Syntax:**
- `1,3,5` - Apply specific mitigations (comma-separated)
- `1-4` - Apply range of mitigations
- `2-4,6-8,10` - Apply multiple ranges and individual items
- `all` - Apply all shown mitigations
- `critical` - Apply only critical mitigations
- `Q` - Quit without changes

**Examples:**
```
Your selection: 1,3,5        # Selects items 1, 3, and 5
Your selection: 2-4          # Selects items 2, 3, and 4
Your selection: 1-3,5,7-9    # Selects items 1, 2, 3, 5, 7, 8, and 9
Your selection: all          # Selects all items
Your selection: critical     # Selects only critical items
```

### 3. **RevertInteractive**
**Quick undo:** Instantly revert to your most recent backup.

```powershell
# Revert to last backup
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive

# Preview revert operation
.\SideChannel_Check_v2.ps1 -Mode RevertInteractive -WhatIf
```

**When to use:**
- ✅ You just applied changes and want to undo them quickly
- ✅ System is unstable after applying mitigations
- ✅ Simple one-step rollback to last known good state

**Features:**
- ✅ Automatically finds your most recent backup
- ✅ Complete restore only (all settings from that backup)
- ✅ Shows backup metadata (timestamp, computer, user)
- ✅ Confirmation prompt before reverting
- ✅ WhatIf preview of changes
- ✅ Detailed restore summary

**What it does:** No browsing, no selection - just instant rollback to your latest backup.

### 4. **Backup**
**Manual snapshot:** Create a backup before making changes or for safekeeping.

```powershell
# Create backup
.\SideChannel_Check_v2.ps1 -Mode Backup

# Preview backup operation
.\SideChannel_Check_v2.ps1 -Mode Backup -WhatIf
```

**When to use:**
- ✅ Before testing changes in production
- ✅ Creating a checkpoint before major configuration updates
- ✅ Scheduled backups for compliance/audit purposes
- ✅ Want to create multiple backup points to compare later

**Backup Contents:**
- Timestamp (ISO 8601 format)
- Computer name
- User name
- All mitigation registry values (24 settings)

**Backup Location:** `.\Backups\Backup_YYYYMMDD_HHMMSS.json`

**Note:** ApplyInteractive mode **automatically creates a backup** before applying changes, so manual backup is optional in that workflow.

### 5. **Restore**
**Advanced recovery:** Browse all backups and choose what to restore (selective or complete).

```powershell
# Interactive restore
.\SideChannel_Check_v2.ps1 -Mode Restore
```

**When to use:**
- ✅ Need to restore from an older backup (not just the latest)
- ✅ Want to restore only specific mitigations, not everything
- ✅ Comparing multiple backups before deciding which to restore
- ✅ Recovering from older configuration states
- ✅ Granular recovery (cherry-pick individual settings)

**Restore Options:**
- **[A] All mitigations** - Restore complete backup (all settings)
- **[S] Select individual** - Choose specific mitigations to restore (granular recovery)
- **[Q] Cancel** - Exit without changes

**Selection Syntax (when selecting individual mitigations):**
- `1,3,5` - Restore specific mitigations (comma-separated)
- `1-4` - Restore range of mitigations
- `2-4,6-8,10` - Restore multiple ranges and individual items
- `all` - Restore all mitigations from selected backup
- `Q` - Cancel restore operation

**Examples:**
```
Enter numbers: 1,3,5        # Restores items 1, 3, and 5
Enter numbers: 2-4          # Restores items 2, 3, and 4
Enter numbers: 1-3,5,7-9    # Restores items 1, 2, 3, 5, 7, 8, and 9
Enter numbers: all          # Restores all items
```

**Difference from RevertInteractive:**
- **RevertInteractive** = Quick undo to latest backup (one command, no choices)
- **Restore** = Browse all backups, choose which one, choose what to restore (flexible)

**Features:**
- ✅ Lists all available backups with age and metadata
- ✅ Shows backup details (computer, user, timestamp, mitigation count)
- ✅ Interactive backup selection (choose from any backup, not just latest)
- ✅ Selective restoration with flexible range notation
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

### Sample Output - v2.1.1

```
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
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

--- Hardware Security Features ---
Firmware:    UEFI
Secure Boot: Enabled
TPM:         Present (2.0)
VT-x/AMD-V:  Enabled
IOMMU/VT-d:  Detected
VBS Capable: Yes
HVCI Capable:Yes
[Info] Starting mitigation assessment...
[Success] Assessment complete: 30 mitigations evaluated

--- Security Assessment Summary ---
Total Mitigations Evaluated:  23
Protected:                    23 (100%)

Security Score: [████████████████████████████████████████] 100%
Security Level: Excellent

--- Hardware Prerequisites ---
Prerequisites Enabled: 5 / 5

--- Mitigation Status ---

Note: Use -ShowDetails flag to see the enhanced 7-column detailed table with CVE, Platform, Impact, and Required For columns.

Simple Table (default view):
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

Detailed Table (with -ShowDetails flag):
Mitigation                     Category     Status       CVE                       Platform     Impact   Required For
-----------------------------  -----------  -----------  ------------------------  -----------  -------  -----------------------------------
Speculative Store Bypass Di... Critical     Protected    CVE-2018-3639             All          Low      -
SSBD Feature Mask              Critical     Protected    CVE-2018-3639             All          Low      -
Branch Target Injection Mit... Critical     Protected    CVE-2017-5715 (Spectre... All          Low      -
Kernel VA Shadow (Meltdown ... Critical     Protected    CVE-2017-5754 (Meltdow... All          Medium   -
Virtualization Based Security  Optional     Protected    Kernel Isolation          All          Low      HVCI, Credential Guard
UEFI Firmware                  Prerequisite Active       Boot Security Prerequi... All          None     Secure Boot, VBS, HVCI, Credent...
Secure Boot                    Prerequisite Protected    Boot Malware Protection   All          None     VBS, HVCI, Credential Guard
TPM 2.0                        Prerequisite Protected    Hardware Cryptographic... All          None     BitLocker, VBS, Credential Guar...
CPU Virtualization (VT-x/AM... Prerequisite Protected    Virtualization Prerequ... All          None     Hyper-V, VBS, HVCI, Credential ...
IOMMU/VT-d Support             Prerequisite Protected    DMA Protection            All          None     HVCI, VBS (full isolation), Ker...

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
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
================================================================================

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
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
================================================================================

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
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
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
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
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
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
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
  Side-Channel Vulnerability Mitigation Tool - Version 2.1.1
================================================================================

[Assessment runs normally...]

✓ Assessment exported successfully to: security_assessment.csv
```

**CSV Features:**
- **18 columns** with complete, untruncated data
- **Semicolon (;) delimiter** to avoid conflicts with comma-separated dependency lists
- **Full PrerequisiteFor lists** (e.g., "Secure Boot, VBS, HVCI, Credential Guard")
- **All URL references** for external documentation
- **Platform information** (All/Physical/HyperVHost/etc.)
- **Compatible with both PowerShell 5.1 and 7+**

**CSV Content Preview:**
```csv
Id;Name;Category;Status;RegistryStatus;RuntimeStatus;ActionNeeded;CVE;Platform;Impact;PrerequisiteFor;CurrentValue;ExpectedValue;Description;Recommendation;RegistryPath;RegistryName;URL
SSBD;Speculative Store Bypass Disable;Critical;Protected;Enabled;Active;No;CVE-2018-3639;All;Low;-;72;72;Prevents Speculative Store Bypass (Variant 4) attacks;Enable to protect against speculative execution vulnerabilities;HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management;FeatureSettingsOverride;https://nvd.nist.gov/vuln/detail/CVE-2018-3639
VBS;Virtualization Based Security;Optional;Protected;Enabled;N/A;No;Kernel Isolation;All;Low;HVCI, Credential Guard;1;1;Hardware-based security isolation using virtualization;Enable for enhanced kernel isolation (requires hardware support);HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard;EnableVirtualizationBasedSecurity;https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs
UEFI;UEFI Firmware;Prerequisite;Active;N/A;Active;No;Boot Security Prerequisite;All;None;Secure Boot, VBS, HVCI, Credential Guard;True;;UEFI firmware mode (required for Secure Boot and modern security);UEFI mode required for Secure Boot, VBS, and HVCI;HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State;UEFISecureBootEnabled;https://uefi.org/specifications
...
```

**Note:** The CSV uses semicolons (;) as delimiters instead of commas to preserve comma-separated lists in the PrerequisiteFor column and other fields. This ensures data integrity when importing into Excel or other CSV tools.

---

## 🛡️ Mitigation Coverage

### Critical Mitigations (6)
- **SSBD** (Speculative Store Bypass Disable) - CVE-2018-3639
- **SSBD Mask** (Required companion setting)
- **BTI** (Branch Target Injection) - CVE-2017-5715 (Spectre v2)
- **KVAS** (Kernel VA Shadow) - CVE-2017-5754 (Meltdown)
- **Enhanced IBRS** - Hardware Spectre v2 protection
- **Hardware Security Mitigations** - Core CPU protections

### Recommended Mitigations (11)
- **TSX Disable** - Prevents TAA vulnerabilities
- **MDS** (Microarchitectural Data Sampling) - CVE-2018-12130
- **TAA** (TSX Asynchronous Abort) - CVE-2019-11135
- **SBDR/SBDS** - CVE-2022-21123, CVE-2022-21125
- **SRBDS** - CVE-2022-21127
- **DRPW** - CVE-2022-21166
- **PSDP** (Predictive Store Forwarding Disable) - CVE-2022-0001, CVE-2022-0002
- **Retbleed** - CVE-2022-29900, CVE-2022-29901
- **MMIO Stale Data** - Processor MMIO vulnerabilities
- **Exception Chain Validation** - SEH protection
- **SMAP** (Supervisor Mode Access Prevention)

### Optional Mitigations (6)
- **L1TF** (L1 Terminal Fault) - High performance impact
- **VBS** (Virtualization Based Security) - Requires hardware
- **HVCI** (Hypervisor-protected Code Integrity) - Requires VBS
- **Credential Guard** - Requires VBS + TPM
- **Hyper-V Core Scheduler** - For Hyper-V hosts
- **Disable SMT/Hyperthreading** - Maximum security (very high performance cost)

### Hardware Prerequisites (5)
- **UEFI Firmware** - Required for modern security
- **Secure Boot** - Boot integrity protection
- **TPM 2.0** - Hardware cryptographic security
- **CPU Virtualization (VT-x/AMD-V)** - For Hyper-V and VBS
- **IOMMU/VT-d** - DMA protection and HVCI optimization

---

## 🧪 Testing & Validation

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
6. **Restore** → `.\SideChannel_Check_v2.ps1 -Mode RevertInteractive` (latest) or `-Mode Restore` (browse backups)

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
**Solution:** v2.1.2 uses runtime Unicode generation for full compatibility.

The script automatically generates Unicode characters (✓, ✗, ⚠, █, ░) at runtime using `[System.Char]::ConvertFromUtf32()`, ensuring consistent display across PowerShell 5.1 and 7.x without requiring specific file encoding.

**No action needed** - this is handled automatically by the `Get-StatusIcon` function.

### MitigationOptions showing as "Not Configured" after reboot
**Symptom:** The "Hardware Security Mitigations" mitigation shows as "Not Configured" or "Disabled" after system restart, even though it was properly applied.

**Cause:** Windows converts the `MitigationOptions` registry value from `REG_QWORD` to `REG_BINARY` after reboot. Older versions of the script couldn't read REG_BINARY format.

**Solution:** v2.1.2+ automatically handles REG_BINARY conversion. The script now:
- Detects when `MitigationOptions` is stored as a byte array (REG_BINARY)
- Converts the 8-byte array to `uint64` using `[BitConverter]::ToUInt64()`
- Performs correct bitwise comparison to verify the mitigation flag is set

**No action needed** - upgrade to v2.1.2 or later. The detection works correctly both before and after system restart.

**Technical Details:**
```powershell
# Before reboot: REG_QWORD (direct uint64 comparison)
# After reboot: REG_BINARY (converted from byte[] to uint64)
```

---

## ⚠️ Important Warnings

- ⚠️ **Always use -WhatIf first**
- ⚠️ **System restart required** after changes
- ⚠️ **Create backups** before modifications
- ⚠️ **Test in non-production** first

---

## 📝 Changelog

### v2.1.5 (2025-12-02)
- 📚 **Enhanced VM configuration guidance**
  * Added hypervisor prerequisite notes to SBDR, SRBDS, and DRPW mitigations
  * All CPU-specific mitigations now clearly indicate VM requirements
  * Clarifies why Microsoft's SpeculationControl module may show "Windows OS support: False" on VMs
  * Comprehensive guidance: PSDP, Retbleed, MMIO, SBDR, SRBDS, DRPW all require host-level configuration
  * Helps administrators understand VM limitations and proper deployment sequence

### v2.1.4 (2025-12-02)
- 🐛 **Enhanced OS compatibility for hardware detection**
  * Removed dependency on `Get-WindowsOptionalFeature` which causes errors on Windows Server and some client builds
  * Improved VT-x/AMD-V detection using multiple fallback methods (registry, WMI, hypervisor presence)
  * Better compatibility across Windows 10/11 client and Windows Server 2016-2025
  * Fixes "Class not registered" errors on both client and server operating systems

### v2.1.3 (2025-12-02)
- 🐛 **Fixed Hyper-V detection on Windows 11 25H2**
  * Replaced `Get-WindowsOptionalFeature` with multi-method detection to prevent "Class not registered" errors
  * Added fallback detection using Hyper-V service, registry checks, and Win32_ComputerSystem
  * Improves reliability across different Windows 11 builds and configurations

### v2.1.2 (2025-12-02)
- 🐛 **Critical Fix: REG_BINARY detection for MitigationOptions**
  * Fixed detection failure after system reboot when Windows converts MitigationOptions to REG_BINARY
  * Added automatic byte array to uint64 conversion in Compare-MitigationValue function
  * Handles both REG_QWORD (pre-reboot) and REG_BINARY (post-reboot) registry formats
  * Supports 8-byte (uint64) and 4-byte (uint32) binary conversions
  * Hardware Security Mitigations now correctly detected in all scenarios
- 📖 **Documentation updates**
  * Added troubleshooting section for MitigationOptions REG_BINARY issue
  * Included technical details about registry type conversion behavior

### v2.1.1 (2025-12-01)
- 📚 **Enhanced Runtime Status Guide**
  * Updated from 4 to 5 comprehensive state descriptions in Bullets format
  * Added "Active / Active (method)" - covers Enhanced IBRS, Retpoline variants
  * Added "Supported" - for L1TF and similar hardware features
  * Added "N/A" - when no runtime detection available
  * Consolidated "Not Needed (HW Immune)" entry
  * Guide now accurately reflects all possible states from 24 side-channel checks
- 🐛 **Fixed recommendation syntax**
  * Changed from `-Mode Apply -Interactive` to `-Mode ApplyInteractive`
  * Updated line 1718 in Show-Recommendations function
- 📖 **Documentation updates**
  * Updated all sample outputs to reflect v2.1.1
  * Enhanced Runtime Status Guide descriptions for clarity

### v2.1.0 (2025-11-26)
- ✨ Enhanced interactive modes with selective apply & restore
  * **ApplyInteractive**: Choice between [R]ecommended (actionable only) or [A]ll mitigations view
  * **Restore**: Support for [A]ll (complete) or [S]elective (individual) restoration
  * Supports informed decision-making workflow after detailed assessment
- 📚 **Comprehensive URL references for all mitigations**
  * 22 authoritative URLs added (NVD, Microsoft Learn, Intel, AMD, TCG, UEFI)
  * External documentation links in ShowDetails bullet-point view
  * References to official CVE databases, vendor security advisories, and standards
- 📊 **Enhanced detailed table with 7 columns**
  * Added **CVE** column with descriptive names (e.g., "CVE-2017-5715 (Spectre v2)")
  * Added **Platform** column showing applicability (All/Physical/HyperVHost/etc.)
  * Added **Impact** column for performance assessment (Low/Medium/High)
  * Added **Required For** column showing dependency relationships
  * Smart truncation at 35 characters with "..." for long entries
  * Both ANSI (PowerShell 7+) and fallback (PowerShell 5.1) implementations
- 🔗 **Dependency mapping with PrerequisiteFor property**
  * Hardware prerequisites show what they enable:
    - UEFI → Secure Boot, VBS, HVCI, Credential Guard
    - Secure Boot → VBS, HVCI, Credential Guard
    - TPM 2.0 → BitLocker, VBS, Credential Guard, Windows Hello
    - CPU Virtualization → Hyper-V, VBS, HVCI, Credential Guard
    - IOMMU/VT-d → HVCI, VBS (full isolation), Kernel DMA Protection
  * Security features show their dependents:
    - VBS → HVCI, Credential Guard
  * Displayed in both detailed table (truncated) and bullet-point view (full)
- 🎨 **Improved CVE presentation**
  * CVE numbers now include descriptive context in definitions
  * Examples: "CVE-2017-5715 (Spectre v2)", "CVE-2018-12130 (ZombieLoad)"
  * Clearer vulnerability identification in reports and exports
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

## 📦 Legacy Version (v1.x)

The original v1.x version has been archived and is available in `archive/v1/` for reference. It is no longer actively maintained but remains available for compatibility with existing workflows.

**To use v1 (archived):**
```powershell
cd archive\v1
.\SideChannel_Check.ps1
```

**Note:** v1 is feature-complete but does not include the enhanced features of v2.1.0 (selective restore, runtime Unicode generation, intelligent scoring, etc.). New deployments should use v2.1.0.

---

## 📄 License

MIT License

---

## 👤 Author

**Jan Tiedemann**
- GitHub: [@BetaHydri](https://github.com/BetaHydri)

---

## 📖 External Resources & Technical Documentation

### Official Vendor Documentation

#### Microsoft Security Guidance
- **[KB4073119: Windows Client Guidance for IT Pros](https://support.microsoft.com/en-us/topic/kb4073119-protect-against-speculative-execution-side-channel-vulnerabilities-in-windows-client-systems-6dd25de0-4d8e-4f7c-8a89-ddc88e3e8853)** - Primary reference for this tool
- **[Windows Kernel CVE Mitigations](https://msrc.microsoft.com/update-guide/vulnerability)** - Microsoft Security Response Center
- **[Virtualization-Based Security (VBS)](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs)** - Hardware requirements and implementation
- **[Hypervisor-Protected Code Integrity (HVCI)](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard)** - Memory integrity protection
- **[Credential Guard Deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)** - Enterprise credential protection
- **[Windows Defender Application Control](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control)** - Code integrity policies

#### Intel Security Advisories
- **[Spectre & Meltdown (CVE-2017-5753/5715/5754)](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/overview.html)** - Original side-channel vulnerabilities
- **[Retpoline: Branch Target Injection Mitigation](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html)** - Software mitigation technique
- **[L1 Terminal Fault (L1TF) - CVE-2018-3620/3646](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/l1-terminal-fault.html)** - L1 cache attacks
- **[Microarchitectural Data Sampling (MDS)](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/microarchitectural-data-sampling.html)** - Multiple CVEs (2018-11091 through 12130)
- **[TAA - CVE-2019-11135](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/intel-tsx-asynchronous-abort.html)** - TSX Asynchronous Abort
- **[Enhanced IBRS](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/indirect-branch-restricted-speculation.html)** - Hardware-based Spectre v2 mitigation
- **[Intel VT-x and VT-d](https://www.intel.com/content/www/us/en/virtualization/virtualization-technology/intel-virtualization-technology.html)** - Virtualization and IOMMU technology

#### AMD Security Documentation
- **[AMD Product Security](https://www.amd.com/en/resources/product-security.html)** - Security bulletins and advisories
- **[AMD-V (SVM) Technology](https://www.amd.com/en/technologies/virtualization-solutions)** - AMD Virtualization
- **[AMD Secure Encrypted Virtualization (SEV)](https://www.amd.com/en/developer/sev.html)** - VM memory encryption
- **[Spectre/Meltdown AMD Guidance](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1000.html)** - AMD-specific mitigations
- **[IOMMU (AMD-Vi) Specification](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/48882_IOMMU.pdf)** - AMD I/O Memory Management Unit

### CVE Databases & Tracking

#### NIST National Vulnerability Database
- **[CVE-2017-5753 (Spectre Variant 1)](https://nvd.nist.gov/vuln/detail/CVE-2017-5753)** - Bounds check bypass
- **[CVE-2017-5715 (Spectre Variant 2)](https://nvd.nist.gov/vuln/detail/CVE-2017-5715)** - Branch target injection
- **[CVE-2017-5754 (Meltdown)](https://nvd.nist.gov/vuln/detail/CVE-2017-5754)** - Rogue data cache load
- **[CVE-2018-3620 (L1TF)](https://nvd.nist.gov/vuln/detail/CVE-2018-3620)** - L1 Terminal Fault - OS/SMM
- **[CVE-2018-3646 (L1TF-VMM)](https://nvd.nist.gov/vuln/detail/CVE-2018-3646)** - L1 Terminal Fault - VMM
- **[CVE-2018-11091 (MDSUM)](https://nvd.nist.gov/vuln/detail/CVE-2018-11091)** - Microarchitectural Data Sampling Uncacheable Memory
- **[CVE-2018-12126 (MFBDS)](https://nvd.nist.gov/vuln/detail/CVE-2018-12126)** - Microarchitectural Fill Buffer Data Sampling
- **[CVE-2018-12127 (MLPDS)](https://nvd.nist.gov/vuln/detail/CVE-2018-12127)** - Microarchitectural Load Port Data Sampling
- **[CVE-2018-12130 (MSBDS)](https://nvd.nist.gov/vuln/detail/CVE-2018-12130)** - Microarchitectural Store Buffer Data Sampling
- **[CVE-2019-11135 (TAA)](https://nvd.nist.gov/vuln/detail/CVE-2019-11135)** - TSX Asynchronous Abort
- **[CVE-2022-0001 (BHI)](https://nvd.nist.gov/vuln/detail/CVE-2022-0001)** - Branch History Injection
- **[CVE-2022-0002 (BHI)](https://nvd.nist.gov/vuln/detail/CVE-2022-0002)** - Intra-Mode Branch Target Injection
- **[CVE-2022-21123 (SBDR)](https://nvd.nist.gov/vuln/detail/CVE-2022-21123)** - Shared Buffers Data Read
- **[CVE-2022-21125 (SBDS)](https://nvd.nist.gov/vuln/detail/CVE-2022-21125)** - Shared Buffers Data Sampling
- **[CVE-2022-21127 (SRBDS)](https://nvd.nist.gov/vuln/detail/CVE-2022-21127)** - Special Register Buffer Data Sampling
- **[CVE-2022-21166 (DRPW)](https://nvd.nist.gov/vuln/detail/CVE-2022-21166)** - Device Register Partial Write
- **[CVE-2022-29900 (Retbleed)](https://nvd.nist.gov/vuln/detail/CVE-2022-29900)** - Return Instruction Speculation (AMD)
- **[CVE-2022-29901 (Retbleed)](https://nvd.nist.gov/vuln/detail/CVE-2022-29901)** - Return Instruction Speculation (Intel)

### Research Papers & Technical Analysis

#### Academic Research
- **[Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)** - Original Spectre paper (Kocher et al.)
- **[Meltdown: Reading Kernel Memory from User Space](https://meltdownattack.com/meltdown.pdf)** - Original Meltdown paper (Lipp et al.)
- **[Foreshadow: L1 Terminal Fault](https://foreshadowattack.eu/)** - L1TF attack website and papers
- **[ZombieLoad: MDS Attacks](https://zombieloadattack.com/)** - MDS vulnerability research
- **[RIDL: Rogue In-Flight Data Load](https://mdsattacks.com/)** - Additional MDS research

#### Performance Impact Studies
- **[Microsoft: Mitigations Performance Impact](https://techcommunity.microsoft.com/t5/windows-kernel-internals-blog/understanding-the-performance-impact-of-spectre-and-meltdown/ba-p/295062)** - Real-world performance analysis
- **[Red Hat: Speculative Execution Exploit Performance Impact](https://access.redhat.com/articles/3311301)** - Enterprise impact assessment
- **[VMware: Side-Channel Aware Scheduler](https://kb.vmware.com/s/article/55806)** - Hypervisor-level mitigations

### Virtualization Platform Security

#### VMware ESXi/vSphere
- **[VMware Security Advisories](https://www.vmware.com/security/advisories.html)** - vSphere security bulletins
- **[VMSA-2018-0004: Spectre/Meltdown](https://www.vmware.com/security/advisories/VMSA-2018-0004.html)** - VMware response
- **[Side-Channel Aware Scheduler (SCAS)](https://kb.vmware.com/s/article/55806)** - ESXi scheduler hardening

##### VMware VM Configuration for Hardware Prerequisites
When running as a VMware guest, the tool provides GUI-based instructions to enable missing hardware prerequisites:

- **Secure Boot**: Power off VM → Edit Settings → VM Options → Boot Options → Enable Secure Boot (requires EFI firmware)
- **TPM 2.0 (vTPM)**: Power off VM → Edit Settings → Add New Device → Trusted Platform Module → Add
- **CPU Virtualization**: Power off VM → Edit Settings → CPU → Enable 'Expose hardware assisted virtualization to the guest OS'
- **IOMMU**: Power off VM → Edit Settings → VM Options → Advanced → Enable 'Enable IOMMU'

**Note**: These settings require the VM to be powered off and may require ESXi/vSphere host-level configuration.
- **[ESXi Patch Tracker](https://esxi-patches.v-front.de/)** - Community patch database

#### Microsoft Hyper-V
- **[Hyper-V Security Documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-security)** - Official hardening guide
- **[Hyper-V Core Scheduler](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types)** - SMT security improvements
- **[Shielded VMs](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms)** - Hardware-based VM isolation
- **[Nested Virtualization Security](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization)** - Nested VM considerations

##### ⚠️ CRITICAL: Virtual Machine Configuration Requirements

**For CPU-specific mitigations (PSDP, Retbleed, MMIO, Enhanced IBRS) to work in VMs:**

1. **The Hyper-V/ESXi host MUST have these mitigations enabled and active first**
2. The hypervisor host must be **restarted** after applying mitigations
3. Only then can the hypervisor expose these CPU features to guest VMs
4. VM processor compatibility mode must be disabled (Hyper-V) or CPUID masking removed (VMware)

**Registry settings alone in the VM are insufficient** - the physical CPU features must be active on the host first.

**Complete Configuration Guide:** See [HYPERVISOR_CONFIGURATION.md](HYPERVISOR_CONFIGURATION.md) for detailed step-by-step instructions for:
- Hyper-V host configuration
- VMware ESXi/Workstation configuration
- VM processor settings
- Verification procedures

## Troubleshooting

### Why do SBDR/PSDP show as "Vulnerable" even though registry values are set?

**Symptom:** Your tool shows SBDR, FBSDP, or PSDP as "Vulnerable" despite registry values being set to `1`.

**Root Cause:** These mitigations require **hardware support** and **microcode updates**. Setting registry values alone is insufficient.

**Detection Logic (v2.1.6+):**
- The tool reads **flags2** from the Windows kernel API (NtQuerySystemInformation)
- Checks if hardware is protected via bits: SBDR (0x01), FBSDP (0x02), PSDP (0x04)
- Checks if mitigation is **actually active** via FBClear bit (0x08)
- **Registry values alone don't enable protection if hardware doesn't support the feature**

**This aligns with Microsoft's SpeculationControl module v1.0.19**, which also reports these as "False" when:
1. Hardware is vulnerable (flags2 bit = 0)
2. FBClear mitigation is not enabled (flags2 bit 0x08 = 0)

**Solution:**
```powershell
# Compare with Microsoft's official tool
Get-SpeculationControlSettings

# Check for missing microcode updates
Get-HotFix | Where-Object { $_.Description -match 'Update' } | Sort-Object InstalledOn -Descending | Select-Object -First 10

# Install latest Windows Updates and CPU microcode
Windows Update → Check for updates → Install all available updates
# Or use Windows Update Catalog for specific CPU microcode package
```

**Why this happens:**
- **Intel CPUs**: May need microcode updates from Windows Update or BIOS updates
- **Older CPUs**: Some CPUs don't support these newer mitigations (hardware limitation)
- **Virtual Machines**: Host must have mitigations enabled first (see HYPERVISOR_CONFIGURATION.md)
- **AMD/ARM CPUs**: Automatically marked as "Hardware Immune" (Intel-specific vulnerabilities)

**Verification:**
If Microsoft's `Get-SpeculationControlSettings` also shows "Windows OS support is enabled: **False**", then your hardware genuinely doesn't support these features or is missing required updates.

### Why does my security score differ from Microsoft's SpeculationControl module?

**This tool (v2.1.6+):**
- Performs **hardware-based detection** using Windows kernel APIs
- Checks if mitigations are **actually active** in the kernel
- Aligns detection logic with Microsoft's SpeculationControl module
- Shows 30 mitigations including prerequisites (UEFI, Secure Boot, TPM)

**Microsoft SpeculationControl:**
- Focuses on CPU speculation vulnerabilities only (10-15 mitigations)
- Does not include VBS, HVCI, Credential Guard
- Uses same kernel API detection (NtQuerySystemInformation)

**Both tools should agree on CPU mitigations (BTI, KVAS, MDS, SBDR, FBSDP, PSDP)**. If they differ, please report an issue.

##### Hyper-V VM Configuration for Hardware Prerequisites
When running as a Hyper-V guest, the tool provides PowerShell commands to enable missing hardware prerequisites:

- **Secure Boot**: `Set-VMFirmware -VMName '<vmname>' -EnableSecureBoot On` (requires Generation 2 VM)
- **TPM 2.0**: `Enable-VMTPM -VMName '<vmname>'` (requires Generation 2 VM and Key Protector)
- **CPU Virtualization**: `Set-VMProcessor -VMName '<vmname>' -ExposeVirtualizationExtensions $true`
- **IOMMU**: Automatically available for Generation 2 VMs with nested virtualization enabled

### Tools & Validation

#### Microsoft Official Tools
- **[SpeculationControl PowerShell Module](https://www.powershellgallery.com/packages/SpeculationControl)** - Microsoft's assessment tool
- **[Device Guard Readiness Tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)** - VBS/HVCI validation
- **[Windows Update Catalog](https://www.catalog.update.microsoft.com/)** - Microcode and patch downloads

#### Third-Party Validation Tools
- **[CPU-Z](https://www.cpuid.com/softwares/cpu-z.html)** - CPU feature detection
- **[HWiNFO](https://www.hwinfo.com/)** - Detailed hardware information
- **[InSpectre](https://www.grc.com/inspectre.htm)** - Steve Gibson's Spectre/Meltdown checker (retired)

### Compliance & Standards

#### Industry Standards
- **[CIS Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)** - Security configuration baselines
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Risk management guidelines
- **[PCI DSS Requirements](https://www.pcisecuritystandards.org/)** - Payment card industry security

#### Government Guidance
- **[NSA Cybersecurity Advisories](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/)** - U.S. government recommendations
- **[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Critical vulnerability tracking

### Additional Learning Resources

#### Video Tutorials & Conferences
- **[Black Hat: Spectre & Meltdown Presentations](https://www.blackhat.com/)** - Security conference talks
- **[Microsoft Ignite: Windows Security Sessions](https://ignite.microsoft.com/)** - Enterprise security guidance
- **[DEF CON: Side-Channel Attack Research](https://www.defcon.org/)** - Cutting-edge security research

#### Community Resources
- **[/r/sysadmin - Windows Security](https://www.reddit.com/r/sysadmin/)** - IT professional community
- **[TechNet Forums (Archive)](https://social.technet.microsoft.com/Forums/)** - Microsoft community support
- **[Spiceworks Community](https://community.spiceworks.com/)** - IT Q&A and troubleshooting

### How to Use These Resources

1. **Start with Microsoft KB4073119** - Primary reference for Windows mitigation implementation
2. **Check your CPU vendor** (Intel/AMD) - Read vendor-specific guidance for your hardware
3. **Review CVE details** - Understand the specific vulnerabilities affecting your systems
4. **Assess performance impact** - Use Microsoft/Red Hat studies to plan mitigation deployment
5. **Validate with tools** - Cross-reference this script with Microsoft's SpeculationControl module
6. **Stay updated** - Subscribe to vendor security advisories for new vulnerabilities

---

**Version:** 2.1.7  
**Last Updated:** 2025-12-02  
**PowerShell:** 5.1, 7.x  
**Platform:** Windows 10/11, Server 2016+
