# Side-Channel Vulnerability Configuration Checker

A comprehensive PowerShell tool for checking, applying, and reverting Windows side-channel vulnerability mitigations with **runtime kernel-level verification** and VMware ESXi/Hyper-V integration.

## 🎯 What This Tool Does

- **Checks** your system for side-channel vulnerability protections (Spectre, Meltdown, L1TF, MDS, TAA)
- **Verifies runtime state** using NtQuerySystemInformation API (same as Microsoft's SpeculationControl module)
- **Compares** registry configuration vs actual kernel-level protection state
- **Detects** when reboots are required or Group Policy overrides are active
- **Applies** missing security mitigations with interactive selection
- **Reverts** problematic mitigations causing performance issues  
- **Provides VMware ESXi** host security configuration guidance
- **Exports results** to CSV for compliance reporting

## ✨ What Makes This Tool Unique

### Runtime State Verification (NEW!)
Unlike registry-only tools, this script queries the **actual Windows kernel** to verify what mitigations are **currently active**:

- ✅ **NtQuerySystemInformation API** - Same method used by Microsoft's official SpeculationControl module
- ✅ **30+ Runtime Flags** - Detects Spectre v2 (BTI, Retpoline, Enhanced IBRS), Spectre v4 (SSBD), MDS, TAA, L1TF, and more
- ✅ **Integrated Table Display** - Shows Registry Status AND Kernel Runtime side-by-side for each mitigation
- ✅ **Discrepancy Detection** - Identifies when configuration differs from active state with clear explanations
- ✅ **"Which to Trust" Guidance** - Explicitly tells users whether to trust registry or runtime state
- ✅ **Reboot Detection** - Warns when registry changes haven't taken effect yet (⚠ Pending status)
- ✅ **Hardware Immunity Detection** - Detects CPUs with built-in protection (e.g., RDCL for Meltdown, MDS immunity)
- ✅ **Smart Recommendations** - Only suggests mitigations that aren't already active in kernel runtime
- ✅ **Enhanced IBRS Awareness** - Clearly indicates when hardware protection supersedes software mitigations
- ✅ **PowerShell 5.1+ Compatible** - Works on Windows Server 2016+ without upgrades

### Example Runtime Detection Output
```
[Runtime State Detection Active]

🛡  SOFTWARE MITIGATIONS
============================================================

Mitigation Name                        Registry Status Kernel Runtime Impact
---------------                        --------------- -------------- ------
Speculative Store Bypass Disable       ✓ Enabled       ✓ Active       Minimal performance impact
Branch Target Injection Mitigation     ✓ Enabled       ✓ Active       Minimal performance impact
Kernel VA Shadow (Meltdown Protection) ✓ Enabled       ✓ Immune       Medium performance impact
MDS Mitigation                         ✗ Not Set       ⚠ Active       MODERATE-HIGH impact
Enhanced IBRS                          ✓ Enabled       ✓ Active       Minimal performance impact

  ⚠ DISCREPANCY DETECTED - Registry says 'Not Set' but Kernel shows 'Active'
  ℹ TRUST: Kernel Runtime (authoritative) - Protection IS currently active
  ℹ Likely causes:
     1. Windows enabled it by default (modern Windows behavior)
     2. Group Policy or security baseline enforcing the setting
     3. CPU has hardware-level immunity (no registry config needed)
  ℹ Status: PROTECTED - No action needed (protection is working)

Category Score: 10/12 enabled (83.3%)

ℹ KERNEL RUNTIME STATE - WHICH TO TRUST?
  ⭐ ALWAYS TRUST: Kernel Runtime (shows actual protection status)
  Registry Status: What you configured (may not be active yet)
  Kernel Runtime: What's ACTUALLY running in the kernel (authoritative)

  Runtime Status Meanings:
  ✓ Active - Protection is running (you are protected)
  ✗ Inactive - Protection is NOT running (you are vulnerable)
  ⚠ Pending - Registry says 'Enabled' but kernel is NOT active (check compatibility)
  ⚠ Active - Registry says 'Not Set' but kernel IS active (Windows default/policy)
  ✓ Immune - CPU has hardware immunity (no software mitigation needed)
  ✓ Not Needed - Hardware protection (Enhanced IBRS) supersedes software mitigation
  ✓ Retpoline - Software mitigation active (older CPUs without Enhanced IBRS)
```

### Comparison with Microsoft's SpeculationControl Module

| Feature | Microsoft SpeculationControl | This Tool |
|---------|------------------------------|-----------|
| Runtime kernel state verification | ✅ | ✅ |
| Registry configuration checking | ❌ | ✅ |
| **Registry vs Runtime comparison** | ❌ | ✅ **UNIQUE** |
| **Reboot required detection** | ❌ | ✅ **UNIQUE** |
| **Actionable remediation** | ❌ | ✅ **UNIQUE** |
| **Apply/Revert operations** | ❌ | ✅ **UNIQUE** |
| **Hardware prerequisites validation** | ❌ | ✅ **UNIQUE** |
| **Dependency matrix** | ❌ | ✅ **UNIQUE** |
| **Interactive mitigation selection** | ❌ | ✅ **UNIQUE** |
| **VMware ESXi integration** | ❌ | ✅ **UNIQUE** |
| **CSV export for compliance** | ❌ | ✅ **UNIQUE** |
| Retpoline detection | ✅ | ✅ |
| Enhanced IBRS detection | ✅ | ✅ |
| MBClear/FBClear detection | ✅ | ✅ |
| CPU vulnerability database | ✅ | ✅ |

**Bottom line**: This tool provides everything Microsoft's SpeculationControl does, **plus** actionable remediation and configuration management.

## 🚀 Quick Start

### Basic Security Check
```powershell
.\SideChannel_Check.ps1
```

### Apply Security Mitigations
```powershell
# Interactive selection (recommended)
.\SideChannel_Check.ps1 -Apply -Interactive

# Preview changes first
.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf
```

### Remove Problematic Mitigations
```powershell
# Safe revert with preview
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# Revert specific mitigations
.\SideChannel_Check.ps1 -Revert -Interactive
```

## 🖥️ Execution Order for Virtualized Environments

### **Step 1: Secure the Hypervisor Host FIRST** 🏗️

**For VMware ESXi:**
```powershell
# Get ESXi configuration commands from Windows VM
.\SideChannel_Check.ps1 -ShowVMwareHostSecurity
```

**Apply on ESXi host (SSH/console):**
```bash
# Enable Side-Channel Aware Scheduler
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

# Enable L1TF protection  
esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true

# Enable MDS protection
esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false
```

**For Hyper-V Host:**
```powershell
# Run on Hyper-V host system
.\SideChannel_Check.ps1 -Apply -Interactive
```

### **Step 2: Secure Guest VMs SECOND** 🖥️

**Run inside each Windows VM:**
```powershell
# 1. Check current security status
.\SideChannel_Check.ps1

# 2. Apply guest-level mitigations
.\SideChannel_Check.ps1 -Apply -Interactive

# 3. Export compliance report
.\SideChannel_Check.ps1 -ExportPath "VM_Security_Report.csv"
```

### **Step 3: Performance Optimization (If Needed)** ⚡

```powershell
# If performance issues occur, selectively revert mitigations:
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
.\SideChannel_Check.ps1 -Revert -Interactive
```

## 📊 Sample Output

### Basic Security Assessment
```
=== Side-Channel Vulnerability Configuration Check ===
Based on Microsoft KB4073119 + Extended Modern CVE Coverage

📊 MODE: ASSESSMENT ONLY
No system changes will be made. Running in read-only analysis mode.

System Information:
CPU: 11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS: Microsoft Windows 11 Enterprise Build 26200
Architecture: 64-bit

Virtualization Environment:
Running in VM: No
Hyper-V Status: Enabled
VBS Status: Running
HVCI Status: Enforced

Checking Side-Channel Vulnerability Mitigations...

[Runtime State Detection Active]
Speculative Store Bypass Disable              : ✓ ENABLED (Value: 72)
SSBD Feature Mask                             : ✓ ENABLED (Value: 3)
Branch Target Injection Mitigation            : ✓ ENABLED (Value: 0)
Kernel VA Shadow (Meltdown Protection)        : ✓ ENABLED (Value: 1)
Hardware Security Mitigations                 : ✓ ENABLED (Value: 0x2000000000000100)
Supervisor Mode Access Prevention             : ✓ ENABLED (Value: 1)
Intel TSX Disable                             : ✓ ENABLED (Value: 1)
Enhanced IBRS                                 : ✓ ENABLED (Value: 1)

Checking Additional CVE Mitigations (Performance Impact Warning)...
L1TF Mitigation                               : ✗ NOT SET
MDS Mitigation                                : ✗ NOT SET
CVE-2019-11135 Mitigation                     : ✓ ENABLED (Value: 1)
SBDR/SBDS Mitigation                          : ✓ ENABLED (Value: 1)
SRBDS Update Mitigation                       : ✓ ENABLED (Value: 1)
DRPW Mitigation                               : ✓ ENABLED (Value: 1)

=== Side-Channel Vulnerability Mitigation Status ===

🛡  SOFTWARE MITIGATIONS
============================================================

Mitigation Name                        Registry Status Kernel Runtime Impact
---------------                        --------------- -------------- ------
Speculative Store Bypass Disable       ✓ Enabled       ✓ Active       Minimal performance impact
SSBD Feature Mask                      ✓ Enabled       -              Works in conjunction with
                                                                      FeatureSettingsOverride
Branch Target Injection Mitigation     ✓ Enabled       ✓ Active       Minimal performance impact
Kernel VA Shadow (Meltdown Protection) ✓ Enabled       ✓ Immune       Medium performance impact
Intel TSX Disable                      ✓ Enabled       -              May affect applications using TSX
Enhanced IBRS                          ✓ Enabled       ✓ Active       Minimal performance impact
L1TF Mitigation                        ✗ Not Set       -              HIGH - May require disabling
                                                                      hyperthreading
MDS Mitigation                         ✗ Not Set       ⚠ Active       MODERATE-HIGH - 3-8% performance
                                                                      impact
CVE-2019-11135 Mitigation              ✓ Enabled       -              MODERATE - Application-dependent
SBDR/SBDS Mitigation                   ✓ Enabled       -              LOW-MODERATE - Varies by CPU
SRBDS Update Mitigation                ✓ Enabled       -              LOW - Minimal impact
DRPW Mitigation                        ✓ Enabled       -              LOW - Minimal impact


  ⚠ DISCREPANCY DETECTED - Registry says 'Not Set' but Kernel shows 'Active'
  ℹ TRUST: Kernel Runtime (authoritative) - Protection IS currently active
  ℹ Likely causes:
     1. Windows enabled it by default (modern Windows behavior)
     2. Group Policy or security baseline enforcing the setting
     3. CPU has hardware-level immunity (no registry config needed)
  ℹ Status: PROTECTED - No action needed (protection is working)

Category Score: 11/12 enabled (91.7%)

🔒 SECURITY FEATURES
============================================================

Mitigation Name                     Registry Status Kernel Runtime Impact
---------------                     --------------- -------------- ------
Hardware Security Mitigations       ✓ Enabled       -              Hardware-dependent, modern CPUs better
Exception Chain Validation          ✓ Enabled       -              Prevents SEH exploitation
Supervisor Mode Access Prevention   ✓ Enabled       -              Improves memory corruption resistance
Windows Defender Exploit Guard ASLR ✗ Not Set       -              Improves memory corruption resistance
Credential Guard                    ✓ Enabled       -              Requires VBS, may affect apps

Category Score: 4/5 enabled (80%)

🔧 HARDWARE PREREQUISITES
============================================================

Mitigation Name                         Registry Status      Kernel Runtime Impact
---------------                         ---------------      -------------- ------
UEFI Firmware (not Legacy BIOS)         UEFI Firmware Active -              Required for Secure Boot, VBS
Secure Boot                             ✓ Enabled            -              Essential for VBS, prevents boot malware
TPM 2.0 (Trusted Platform Module)       TPM 2.0 Enabled      -              Required for Credential Guard, BitLocker
CPU Virtualization Support (VT-x/AMD-V) Enabled and Active   -              Essential for Hyper-V, VBS
IOMU/VT-d Support                       ✓ Enabled            -              Provides DMA isolation, required for HVCI

Category Score: 5/5 enabled (100%)

⚙ OTHER MITIGATIONS
============================================================

Mitigation Name                            Registry Status Kernel Runtime Impact
---------------                            --------------- -------------- ------
Retpoline Support                          Information     ✓ Not Needed   Compiler and application dependent
Virtualization Based Security (VBS)        ✓ Enabled       -              Requires UEFI, Secure Boot
Hypervisor-protected Code Integrity (HVCI) ✓ Enabled       -              May cause driver compatibility issues
Hyper-V Core Scheduler                     ✓ Enabled       -              No action needed - already optimized
Nested Virtualization Security             ✓ Enabled       -              Enables nested hypervisors in VMs

Category Score: 4/5 enabled (80%)

[>>] OVERALL SECURITY SUMMARY
============================================================
Overall Mitigation Score: 86.4%
Security Level: [████████░░] 19/22 enabled

ℹ KERNEL RUNTIME STATE - WHICH TO TRUST?
  ⭐ ALWAYS TRUST: Kernel Runtime (shows actual protection status)
  Registry Status: What you configured (may not be active yet)
  Kernel Runtime: What's ACTUALLY running in the kernel (authoritative)

  Runtime Status Meanings:
  ✓ Active - Protection is running (you are protected)
  ✗ Inactive - Protection is NOT running (you are vulnerable)
  ⚠ Pending - Registry says 'Enabled' but kernel is NOT active (check compatibility)
  ⚠ Active - Registry says 'Not Set' but kernel IS active (Windows default/policy)
  ✓ Immune - CPU has hardware immunity (no software mitigation needed)
  ✓ Not Needed - Hardware protection (Enhanced IBRS) supersedes software mitigation
  ✓ Retpoline - Software mitigation active (older CPUs without Enhanced IBRS)

=== Recommendations ===
The following mitigations should be configured:
- L1TF Mitigation: Enable L1TF protection. WARNING: High performance impact
- Windows Defender Exploit Guard ASLR: Enable ASLR force relocate images

Note: MDS Mitigation is NOT recommended because it's already active in the kernel runtime.

To apply these configurations automatically, run:
.\SideChannel_Check.ps1 -Apply

For interactive selection (recommended):
.\SideChannel_Check.ps1 -Apply -Interactive
```

### Interactive Apply Session
```
=== Interactive Mitigation Selection ===
WhatIf Mode: Changes will be previewed but not applied

The following mitigations are not configured and can be enabled:
Use numbers to select (e.g., 1,3,4 or 1-3 or all for all mitigations):
Enter 0 to apply no mitigations and exit:

  [1] L1TF Mitigation (Impact: HIGH)
      L1 Terminal Fault protection for Intel CPUs
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\L1TFMitigationLevel
      WARNING: High performance impact in virtualized environments

  [2] MDS Mitigation (Impact: MODERATE) 
      Microarchitectural Data Sampling protection
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MDSMitigationLevel
      Performance impact: 3-8%

  [3] Windows Defender ASLR (Impact: LOW)
      Enhanced memory protection against exploitation
      Registry: HKLM:\SOFTWARE\Microsoft\Windows Defender\...\ASLR_ForceRelocateImages

Enter your selection: 2,3

=== WhatIf Preview ===
The following changes would be made:

[2] MDS Mitigation
  Registry Path: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
  Registry Name: MDSMitigationLevel
  New Value: 1
  Value Type: DWORD

[3] Windows Defender ASLR
  Registry Path: HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Exploit Protection\System
  Registry Name: ASLR_ForceRelocateImages
  New Value: 1
  Value Type: DWORD

WhatIf Summary:
Total changes that would be made: 2
System restart would be required: Yes

To apply these changes, run without -WhatIf switch
```

### VMware ESXi Security Guide Output
```
=== VMware ESXi Host Security Configuration Guide ===
ESXi/vSphere Security Hardening for Side-Channel Vulnerability Protection

[*] CRITICAL ESXi HOST SETTINGS:

1. Side-Channel Aware Scheduler (SCAS):
   # Enable Side-Channel Aware Scheduler (ESXi 6.7 U2+)
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigation -i true
   esxcli system settings advanced set -o /VMkernel/Boot/hyperthreadingMitigationIntraVM -i true

2. L1 Terminal Fault (L1TF) Protection:
   # Enable L1D cache flush for VMs
   esxcli system settings advanced set -o /VMkernel/Boot/mitigateL1TF -i true
   esxcli system settings advanced set -o /VMkernel/Boot/runToCompletionOnly -i true

3. MDS/TAA Microcode Mitigations:
   # Enable CPU microcode updates
   esxcli system settings advanced set -o /VMkernel/Boot/ignoreMsrLoad -i false

[*] VM-LEVEL CONFIGURATION:

VM Hardware Requirements:
   - VM Hardware Version: 14+ (required for CPU security features)
   - CPU Configuration: Enable 'Expose hardware assisted virtualization'
   - Memory: Enable 'Reserve all guest memory' for critical VMs

VM Advanced Parameters (.vmx file):
   # Disable vulnerable features
   vmx.allowNonVPID = "FALSE"
   vmx.allowVpid = "TRUE"

   # Enable security features
   vpmc.enable = "TRUE"
   featMask.vm.hv.capable = "Min:1"

[*] PERFORMANCE IMPACT SUMMARY:

Mitigation                    Impact    Recommendation
---------                    ------    --------------
Side-Channel Aware Scheduler  2-5%     Enable for multi-tenant environments
L1TF Protection              5-15%     Critical for untrusted VMs
Full Hyperthreading Disable 20-40%    Only for highest security requirements
MDS Mitigation               3-8%      Enable for Intel hosts
VM Memory Reservation        0%        For critical security workloads (uses more host memory)

IMPORTANT: Test performance impact in non-production environment first!
Some mitigations may significantly impact performance.
```

### Revert Session Example
```
=== Mitigation Revert Mode ===
⚠️  WARNING: Reverting mitigations will REDUCE your system's security!

Available mitigations to revert:
Use numbers to select (e.g., 1,3 or 1-2 or 'all'):
Enter 0 to revert no mitigations and exit:

  [1] Intel TSX Disable (Impact: Application-dependent)
      Re-enable Intel TSX (Transactional Synchronization Extensions)
      Security Risk: Medium - May expose TSX-related vulnerabilities
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableTsx

  [2] Hardware Security Mitigations (Impact: Variable)
      Reset CPU-level security mitigations to default
      Security Risk: High - Removes multiple CPU security features
      Registry: HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\MitigationOptions

  [3] VMware Nested Virtualization (Information Only) (Impact: High)
      VMware nested virtualization detected - requires ESXi host configuration
      Security Risk: Info - Cannot be controlled from Windows guest. Requires ESXi host access.
      VMware: VT-x/AMD-V Passthrough

Enter your selection: 1

Are you sure you want to REMOVE these security protections? (yes/no): yes

=== Mitigation Revert Operation ===
Processing: Intel TSX Disable
  + Reverted: Intel TSX Disable = 0

Revert Results:
Successfully reverted: 1/1

[!] IMPORTANT: A system restart may be required for changes to take effect.
```

## 🔄 Tool Comparison

This tool complements Microsoft's official assessment tool:

| Feature | This Tool | Microsoft SpeculationControl |
|---------|-----------|-------------------------------|
| **CVE Coverage** | ✅ KB4073119 + Extended CVE Coverage (2018-2023) | ✅ Complete (2017-2023) |
| **Virtualization** | ✅ VMware/Hyper-V/Nested Detection & Integration | ❌ None |
| **Auto-Configuration** | ✅ `-Apply` with Interactive Mode | ❌ Assessment only |
| **Revert Functionality** | ✅ **Interactive Revert with WhatIf** | ❌ None |
| **Performance Warnings** | ✅ **L1TF/MDS Impact Warnings** | ⚠️ Basic |
| **CPU-Specific Filtering** | ✅ **Intel/AMD Automatic Detection** | ⚠️ Basic |
| **Categorized Scoring** | ✅ **Software/Security/Hardware Categories** | ⚠️ Combined |
| **Enterprise Features** | ✅ CSV Export, Interactive, WhatIf | ⚠️ Basic text |
| **OS Version-Awareness** | ✅ Automatic | ⚠️ Basic |
| **Hardware Analysis** | ⚠️ Registry-based + Hardware Detection | ✅ Native APIs |

**Recommended Usage:**
```powershell
# Use both tools for comprehensive assessment
.\SideChannel_Check.ps1                    # This tool - configuration management
Install-Module SpeculationControl          # Microsoft tool - detailed analysis
Get-SpeculationControlSettings              # Hardware-level verification
```

## 🏢 Enterprise Workflows

### New VM Deployment
```powershell
# 1. Assess baseline security
.\SideChannel_Check.ps1

# 2. Apply mitigations selectively  
.\SideChannel_Check.ps1 -Apply -Interactive

# 3. Document configuration
.\SideChannel_Check.ps1 -ExportPath "VM_$(hostname)_Security.csv"
```

### Performance Troubleshooting
```powershell
# 1. Identify problematic mitigations
.\SideChannel_Check.ps1 -Detailed

# 2. Preview removal impact
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf

# 3. Selectively remove mitigations
.\SideChannel_Check.ps1 -Revert -Interactive

# 4. Verify performance improvement
.\SideChannel_Check.ps1
```

### Security Audit
```powershell
# Complete environment assessment
.\SideChannel_Check.ps1 -Detailed -ShowVMwareHostSecurity -ExportPath "Security_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv"
```

### Large VM Fleet Management

#### VMware vSphere/ESXi Environments (PowerCLI)
```powershell
# Requires: VMware PowerCLI module
# Install-Module -Name VMware.PowerCLI -Scope CurrentUser

# Connect to vCenter
Connect-VIServer -Server vcenter.company.com

# Get all powered-on Windows VMs
$VMs = Get-VM | Where-Object {$_.PowerState -eq "PoweredOn" -and $_.Guest.OSFullName -like "*Windows*"}

# Create reports directory
New-Item -ItemType Directory -Path "Reports" -Force | Out-Null

foreach ($VM in $VMs) {
    Write-Host "Assessing VM: $($VM.Name)" -ForegroundColor Cyan
    $Result = Invoke-VMScript -VM $VM -ScriptText "& 'C:\Path\To\SideChannel_Check.ps1'" -GuestUser $GuestCred
    $Result.ScriptOutput | Out-File "Reports\$($VM.Name)_Security.txt"
}

Disconnect-VIServer -Confirm:$false
```

#### Microsoft Hyper-V Environments
```powershell
# Get all running Windows VMs on Hyper-V host
$VMs = Get-VM | Where-Object {$_.State -eq "Running"}

# Create reports directory
New-Item -ItemType Directory -Path "Reports" -Force | Out-Null

foreach ($VM in $VMs) {
    Write-Host "Assessing VM: $($VM.Name)" -ForegroundColor Cyan
    
    # Copy script to VM (requires guest integration services)
    Copy-VMFile -Name $VM.Name -SourcePath ".\SideChannel_Check.ps1" `
                -DestinationPath "C:\Temp\SideChannel_Check.ps1" `
                -FileSource Host -CreateFullPath
    
    # Execute script in VM (requires PSRemoting or guest credentials)
    $Session = New-PSSession -VMName $VM.Name -Credential $GuestCred
    $Result = Invoke-Command -Session $Session -ScriptBlock {
        & "C:\Temp\SideChannel_Check.ps1"
    }
    $Result | Out-File "Reports\$($VM.Name)_Security.txt"
    Remove-PSSession $Session
}
```

#### Generic Remote Management (Any Platform)
```powershell
# Works with any Windows VM accessible via PowerShell Remoting
$VMHosts = @(
    "vm-web-01.domain.com",
    "vm-db-01.domain.com",
    "vm-app-01.domain.com"
)

# Create reports directory
New-Item -ItemType Directory -Path "Reports" -Force | Out-Null

$Credential = Get-Credential -Message "Enter VM Administrator credentials"

foreach ($VMHost in $VMHosts) {
    Write-Host "Assessing: $VMHost" -ForegroundColor Cyan
    
    try {
        $Session = New-PSSession -ComputerName $VMHost -Credential $Credential
        
        # Copy script to remote VM
        Copy-Item -Path ".\SideChannel_Check.ps1" `
                  -Destination "C:\Temp\" `
                  -ToSession $Session
        
        # Execute and capture output
        $Result = Invoke-Command -Session $Session -ScriptBlock {
            & "C:\Temp\SideChannel_Check.ps1"
        }
        
        $Result | Out-File "Reports\$($VMHost.Split('.')[0])_Security.txt"
        Remove-PSSession $Session
        
        Write-Host "  ✓ Complete" -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
    }
}
```

## ⚠️ Important Warnings

### **CRITICAL Performance Considerations:**
- **L1TF & MDS mitigations** may require disabling hyperthreading/SMT
- **Test in non-production first** - some mitigations have high performance impact
- **VMware environments** require both host AND guest configuration
- **Backup registry** or create system restore point before making changes

### **Security vs Performance Balance:**
```powershell
# Apply low-impact mitigations first (recommended approach)
.\SideChannel_Check.ps1 -Apply -Interactive
# Select: Low-impact mitigations (typically 1,4,7,9)

# Apply medium-impact after testing performance
# Select: Medium-impact mitigations (typically 2,5,8)

# Apply high-impact mitigations in maintenance window
# Select: High-impact mitigations (typically 3,6,10)
```

### **Revert Safety:**
- Always use `-WhatIf` first to preview changes
- Revert mode requires `-Interactive` for safety - this is intentional
- Some mitigations cannot be reverted if they're OS/hardware enforced
- Always restart system after reverting mitigations for changes to take effect

## 🛠️ Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1+** (fully compatible with Windows Server defaults)
- **Administrator privileges** required
- **System restart** required after applying changes

### Detection Capabilities

**Registry-Based Detection** (Always Available):
- Checks configured mitigation policy in Windows registry
- Shows what *should* be applied after reboot
- Displayed in "Registry Status" column

**Runtime Kernel-Level Detection** (Recommended):
- Uses NtQuerySystemInformation Win32 API (same as Microsoft SpeculationControl)
- Shows what mitigations are *actually active* right now in the kernel
- Displayed in "Kernel Runtime" column alongside registry status
- Automatically enabled on Windows 10/11 and Server 2016+
- Falls back gracefully to registry-only mode if API unavailable

### Integrated Table Display with Discrepancy Detection

The tool shows **both** registry and runtime state side-by-side in a single table:

```
Mitigation Name                        Registry Status Kernel Runtime Impact
---------------                        --------------- -------------- ------
Branch Target Injection Mitigation     ✓ Enabled       ✓ Active       Minimal impact
Kernel VA Shadow (Meltdown Protection) ✓ Enabled       ⚠ Pending      Medium impact
MDS Mitigation                         ✗ Not Set       ⚠ Active       MODERATE impact
```

**When discrepancies are detected**, the tool provides clear guidance:

**Scenario 1: Registry Enabled but Runtime Inactive (⚠ Pending)**
```
  ⚠ DISCREPANCY DETECTED - Registry says 'Enabled' but Kernel shows 'Inactive'
  ℹ TRUST: Kernel Runtime (authoritative) - Protection is NOT currently active
  ℹ Possible causes:
     1. Windows may have overridden the setting (Group Policy, security baseline)
     2. CPU/hardware doesn't support this mitigation
     3. Conflicting registry settings preventing activation
  ℹ Action: Review with 'Get-SpeculationControlSettings' for hardware capability check
```

**Scenario 2: Registry Not Set but Runtime Active (⚠ Active yellow)**
```
  ⚠ DISCREPANCY DETECTED - Registry says 'Not Set' but Kernel shows 'Active'
  ℹ TRUST: Kernel Runtime (authoritative) - Protection IS currently active
  ℹ Likely causes:
     1. Windows enabled it by default (modern Windows behavior)
     2. Group Policy or security baseline enforcing the setting
     3. CPU has hardware-level immunity (no registry config needed)
  ℹ Status: PROTECTED - No action needed (protection is working)
```

### Which State to Trust?

**⭐ ALWAYS TRUST: Kernel Runtime** - This shows actual active protection

- **Registry Status**: What you configured (may not be active yet)
- **Kernel Runtime**: What's ACTUALLY running in the kernel (authoritative)

This integrated dual-detection ensures you know:
1. What you've configured (registry)
2. What's currently active (kernel runtime)
3. Whether there are discrepancies requiring attention
4. Clear guidance on which state represents reality

## 📋 Command Reference

| Command | Purpose |
|---------|---------|
| `.\SideChannel_Check.ps1` | Basic security assessment |
| `.\SideChannel_Check.ps1 -Detailed` | Comprehensive analysis with registry paths |
| `.\SideChannel_Check.ps1 -Apply -Interactive` | Apply selected mitigations interactively |
| `.\SideChannel_Check.ps1 -Apply -Interactive -WhatIf` | Preview changes before applying |
| `.\SideChannel_Check.ps1 -Revert -Interactive` | Remove specific mitigations |
| `.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf` | Preview what would be reverted |
| `.\SideChannel_Check.ps1 -ShowVMwareHostSecurity` | VMware ESXi security guide |
| `.\SideChannel_Check.ps1 -ExportPath "report.csv"` | Export results to CSV |

## 🔍 Troubleshooting

**Access Denied:** Run PowerShell as Administrator

**Performance Issues:** Use revert functionality to remove problematic mitigations:
```powershell
.\SideChannel_Check.ps1 -Revert -Interactive -WhatIf
.\SideChannel_Check.ps1 -Revert -Interactive
```

**VMware Issues:** Ensure both ESXi host AND Windows guest are configured properly

**Registry Errors:** Use `-WhatIf` to preview changes before applying

**Interactive Selection Issues:**
- Use ranges like "1-3" (no spaces around dash)
- Use 'all' (lowercase) to select all mitigations
- Use '0' to exit without changes

## 📊 Security Feature Dependency Matrix

The script includes an **intelligent dependency matrix** that analyzes your hardware capabilities and shows which security features are available with or without specific hardware requirements.

### Feature Overview

| Security Feature | Strict Hardware Required | Software Fallback Available | Impact Without Hardware |
|-----------------|-------------------------|----------------------------|------------------------|
| **Secure Boot** | UEFI firmware + Secure Boot capability | ❌ No | Bootloader attacks possible, rootkit persistence |
| **TPM 2.0** | Trusted Platform Module 2.0 chip | ⚠️ Partial (BitLocker with password/USB) | Reduced cryptographic key security, vulnerable to physical attacks |
| **VBS** (Virtualization Based Security) | CPU virtualization (VT-x/AMD-V) + SLAT/EPT | ✅ Yes (software mode) | Weaker kernel isolation, reduced protection |
| **HVCI** (Hypervisor-protected Code Integrity) | CPU virtualization + IOMMU (VT-d/AMD-Vi) | ✅ Yes (compatible mode) | Less driver protection, higher performance impact |
| **Credential Guard** | VBS + TPM 2.0 (recommended) | ✅ Yes (VBS without TPM) | Less secure credential storage, mimikatz risk |
| **BitLocker** Drive Encryption | TPM 2.0 (recommended) | ✅ Yes (password/USB key) | Vulnerable to physical attacks, evil maid attacks |
| **DRTM** (Dynamic Root of Trust) | Intel TXT / AMD Secure Startup | ❌ No | Vulnerable to bootkit persistence, firmware attacks |
| **Kernel DMA Protection** | IOMMU with pre-boot support | ❌ No | DMA attacks via Thunderbolt/USB4/FireWire possible |
| **Hardware Stack Protection** | Intel CET / AMD Shadow Stack | ❌ No | ROP/JOP attacks easier to execute |
| **Microsoft Pluton** | Integrated Pluton security processor | N/A (optional enhancement) | Falls back to discrete TPM (still secure) |

### Matrix Display in Script Output

The script displays a **real-time analysis** of your system's security capabilities:

```
╔═══════════════════════════════════════════════════════════════════════════╗
║          SECURITY FEATURE DEPENDENCY MATRIX                               ║
╠═══════════════════════════════════════════════════════════════════════════╣

FEATURE                                  FALLBACK   HARDWARE REQUIREMENT
────────────────────────────────────────────────────────────────────────────
Secure Boot                              [✗ No ]    UEFI firmware with Secure Boot capability
TPM 2.0                                  [~ Part]   Trusted Platform Module 2.0 chip
VBS (Virtualization Based Security)      [✓ Yes]    CPU virtualization (VT-x/AMD-V) + SLAT/EPT
HVCI (Hypervisor-protected Code Integrity) [✓ Yes] CPU virtualization + IOMMU (VT-d/AMD-Vi)
Credential Guard                         [✓ Yes]    VBS + TPM 2.0 (recommended)
BitLocker Drive Encryption               [✓ Yes]    TPM 2.0 (recommended)
DRTM (Dynamic Root of Trust)             [✗ No ]    Intel TXT or AMD Secure Startup
Kernel DMA Protection                    [✗ No ]    IOMMU (VT-d/AMD-Vi) with pre-boot protection
Hardware Stack Protection                [✗ No ]    Intel CET or AMD Shadow Stack
Microsoft Pluton                         [  N/A ]   Integrated Pluton security processor

╔═══════════════════════════════════════════════════════════════════════════╗
║          YOUR SYSTEM CAPABILITIES                                         ║
╠═══════════════════════════════════════════════════════════════════════════╣

Hardware Features Detected:
  Secure Boot:      ✓ Enabled
  TPM 2.0:          ✓ Present & Ready (Version 2.0)
  Virtualization:   ✓ Enabled (Intel VT-x / AMD-V active)
  IOMMU (VT-d/Vi):  ✗ Not Detected

Security Features Status:
  VBS:              ✓ Running
  HVCI:             ⚠️  Compatible Mode (IOMMU not available)
  Credential Guard: ✓ Enabled
  Kernel DMA Prot:  ✗ Not Available (IOMMU required)

╔═══════════════════════════════════════════════════════════════════════════╗
║          RECOMMENDATIONS FOR YOUR SYSTEM                                  ║
╠═══════════════════════════════════════════════════════════════════════════╣

  ⚠️  IOMMU (VT-d/AMD-Vi) not detected or disabled
      Impact: HVCI running in compatible mode (reduced protection + higher overhead)
      Action: Enable VT-d (Intel) or AMD-Vi in BIOS/UEFI settings
      Benefit: Full DMA protection + optimized HVCI performance

  ℹ️  All critical security features are active
      Your system has strong baseline protection despite missing IOMMU
```

### Fallback Symbol Legend

The script uses intelligent symbols to show fallback availability:

- **[✓ Yes]** - Full software fallback available (feature works without hardware)
- **[~ Part]** - Partial fallback available (reduced security/functionality)
- **[✗ No ]** - No fallback (hardware absolutely required)
- **[ N/A ]** - Not applicable (optional enhancement feature)

### Key Insights

**✅ Good News:**
- Most critical Windows security features have software fallbacks
- VBS, HVCI, Credential Guard, and BitLocker work on older hardware
- Missing IOMMU doesn't prevent security - it reduces optimization

**⚠️ Performance Trade-offs:**
- Software fallbacks may have higher CPU overhead
- HVCI without IOMMU uses "compatible mode" (more performance impact)
- BitLocker without TPM requires password/USB key (user friction)

**❌ Hardware-Only Features:**
- DRTM (Intel TXT/AMD Secure Startup) - absolute hardware requirement
- Kernel DMA Protection - needs IOMMU with pre-boot support
- Hardware Stack Protection - Intel CET or AMD Shadow Stack CPUs

**📊 Intelligent Analysis:**
- The script detects your actual hardware configuration
- Provides specific recommendations based on what's missing
- Explains real-world security impact, not just technical specs
- Helps prioritize BIOS settings or hardware upgrades

### Use Cases

**System Purchase Planning:**
```powershell
# Check if new hardware meets security requirements
.\SideChannel_Check.ps1
# Review dependency matrix - identify missing hardware features
```

**BIOS Configuration:**
```powershell
# After enabling VT-d/AMD-Vi in BIOS
.\SideChannel_Check.ps1
# Verify IOMMU detection and HVCI mode upgrade
```

**Security Audit:**
```powershell
# Understand security posture and hardware dependencies
.\SideChannel_Check.ps1 -Detailed
# Export matrix data for compliance documentation
```

**Upgrade Justification:**
```powershell
# Show management the security benefit of enabling IOMMU
.\SideChannel_Check.ps1
# Matrix shows: "HVCI Compatible Mode → Full Protection" upgrade path
```

### Technical Implementation

The dependency matrix in the script:

1. **Detects Hardware Features** (4-tier detection system):
   - UEFI/Legacy BIOS detection
   - TPM 2.0 presence and version
   - CPU virtualization (VT-x/AMD-V) via multiple methods
   - IOMMU (VT-d/AMD-Vi) via VBS, Hyper-V, and registry checks

2. **Analyzes Security Features** (cross-reference):
   - Checks VBS/HVCI/Credential Guard actual status
   - Determines operating mode (full vs compatible vs software)
   - Identifies hardware dependencies for each feature

3. **Provides Contextual Recommendations**:
   - Specific to your detected hardware configuration
   - Prioritized by security impact
   - Includes BIOS setting names and expected benefits

4. **Handles Edge Cases**:
   - Virtualized environments (Hyper-V, VMware, nested)
   - AMD vs Intel CPU differences
   - Windows 10 vs 11 vs Server variations
   - Pre-boot vs runtime security feature availability

This matrix transforms complex Microsoft security documentation into **actionable, system-specific guidance**

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
- **[CVE-2022-21123 (SBDR)](https://nvd.nist.gov/vuln/detail/CVE-2022-21123)** - Shared Buffers Data Read
- **[CVE-2022-21125 (SBDS)](https://nvd.nist.gov/vuln/detail/CVE-2022-21125)** - Shared Buffers Data Sampling
- **[CVE-2022-21127 (SRBDS)](https://nvd.nist.gov/vuln/detail/CVE-2022-21127)** - Special Register Buffer Data Sampling
- **[CVE-2022-21166 (DRPW)](https://nvd.nist.gov/vuln/detail/CVE-2022-21166)** - Device Register Partial Write

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
- **[ESXi Patch Tracker](https://esxi-patches.v-front.de/)** - Community patch database

#### Microsoft Hyper-V
- **[Hyper-V Security Documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-security)** - Official hardening guide
- **[Hyper-V Core Scheduler](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types)** - SMT security improvements
- **[Shielded VMs](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-and-shielded-vms)** - Hardware-based VM isolation
- **[Nested Virtualization Security](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization)** - Nested VM considerations

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

## 📚 Quick Reference

### Covered Vulnerabilities
- **Spectre** (CVE-2017-5753, CVE-2017-5715) - Branch prediction attacks
- **Meltdown** (CVE-2017-5754) - Kernel memory disclosure
- **L1TF** (CVE-2018-3620/3646) - L1 Terminal Fault (HIGH performance impact)
- **MDS** (CVE-2018-11091-12130) - Microarchitectural Data Sampling (MODERATE performance impact)
- **TSX** vulnerabilities - Transactional Synchronization Extensions
- **Modern CVEs** (2019-2023) with performance impact ratings

### Security Categories
- **🛡️ Software Mitigations**: CPU side-channel protections (Spectre, Meltdown, L1TF, MDS, etc.) - **12 mitigations on Intel, 13 on AMD**
- **🔐 Security Features**: Windows security technologies (VBS, HVCI, Credential Guard, ASLR, etc.) - **8 features**
- **🔧 Hardware Prerequisites**: Platform security capabilities (UEFI, TPM 2.0, VT-x/AMD-V, IOMMU) - **6 components**

**Note:** Counts are CPU-specific - AMD systems include SRSO mitigation, Intel systems include TSX and Enhanced IBRS mitigations.

### Selection Syntax
- **Individual**: `1,3,5` - Apply specific mitigations
- **Ranges**: `1-3` - Apply consecutive mitigations  
- **Mixed**: `1,3-5,7` - Combination of individual and ranges
- **All**: `all` - Apply all available mitigations
- **None**: `0` - Exit without applying changes

---

**Version:** 3.0  
**Author:** Jan Tiedemann  
**Compatibility:** Windows 10/11, Server 2016+  
**PowerShell:** 5.1+ (fully compatible with runtime detection)  
**Repository:** [GitHub - BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
