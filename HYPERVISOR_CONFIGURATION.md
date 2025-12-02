# Hypervisor Configuration Guide for CPU Side-Channel Mitigations

## Overview

Modern CPU side-channel mitigations (PSDP, Retbleed, MMIO, Enhanced IBRS, etc.) require specific CPU features to be exposed by the hypervisor to guest virtual machines. Simply setting registry values inside the VM is **not sufficient** - the underlying CPU capabilities must be passed through from the physical host.

This guide explains how to configure Hyper-V and VMware ESXi/Workstation to properly expose CPU security features to VMs.

---

## Table of Contents

1. [Understanding the Problem](#understanding-the-problem)
2. [Hyper-V Configuration](#hyper-v-configuration)
3. [VMware ESXi Configuration](#vmware-esxi-configuration)
4. [VMware Workstation/Player Configuration](#vmware-workstationplayer-configuration)
5. [Verification Steps](#verification-steps)
6. [Troubleshooting](#troubleshooting)

---

## Understanding the Problem

### Why Registry Settings Alone Don't Work in VMs

CPU side-channel mitigations like PSDP (Predictive Store Forwarding Disable) work by leveraging specific CPU microarchitecture features. When you set a registry value like `PredictiveStoreForwardingDisable = 1`, Windows attempts to activate the corresponding CPU feature.

**In a VM environment:**
- The registry setting tells Windows to enable the mitigation
- Windows then attempts to use the CPU feature
- **If the hypervisor doesn't expose that CPU feature, the mitigation cannot activate**
- Microsoft SpeculationControl module checks the **actual kernel runtime state**, not just registry values
- Result: Registry shows "configured", but kernel shows "not enabled"

### Required CPU Features

Different mitigations require different CPU capabilities:

| Mitigation | Required CPU Feature | Intel CPUs | AMD CPUs |
|------------|---------------------|------------|----------|
| **PSDP/BHI** | CPUID Bit for PSFD | 11th Gen+ | Zen 3+ |
| **Retbleed** | Retpoline/IBRS support | Most modern | Zen 2+ |
| **MMIO Stale Data** | FB_CLEAR, VERW | 10th Gen+ | N/A (Intel-specific) |
| **Enhanced IBRS** | IBRS_ALL CPUID bit | 8th Gen+ (some), 10th Gen+ | Zen 3+ |
| **SSBD** | SSBD CPUID bit | Most modern | Zen+ |

**The hypervisor must expose these CPUID bits and MSR (Model-Specific Register) access to the VM.**

---

## Hyper-V Configuration

### Prerequisites

1. **Physical Host Requirements:**
   - Windows Server 2016+ or Windows 10/11 with Hyper-V role
   - Physical CPU with the required security features
   - Latest Windows updates installed (includes microcode updates)
   - Latest Hyper-V integration services

2. **VM Requirements:**
   - **Generation 2 VM** (required for modern security features)
   - Latest Integration Services installed in guest
   - Windows 10/11 or Windows Server 2016+ guest OS

### Step 1: Enable Processor Compatibility Mode (DISABLE IT)

**Critical:** Processor Compatibility mode must be **DISABLED** for CPU security features to pass through.

```powershell
# On Hyper-V Host - Disable processor compatibility (allows real CPU features)
Set-VMProcessor -VMName "YourVMName" -CompatibilityForMigration $false
```

**Why?** Compatibility mode masks CPU-specific features to allow live migration between different CPU models. This blocks security features from being exposed.

### Step 2: Expose Virtualization Extensions (for VBS/HVCI)

If the VM needs to run nested virtualization or VBS/HVCI:

```powershell
# On Hyper-V Host - Expose virtualization extensions to guest
Set-VMProcessor -VMName "YourVMName" -ExposeVirtualizationExtensions $true
```

### Step 3: Configure VM for Generation 2 (if not already)

Generation 2 VMs support UEFI, Secure Boot, and modern security features:

```powershell
# Cannot convert Gen 1 to Gen 2, must create new VM
# When creating VM, select Generation 2

# Enable Secure Boot (recommended)
Set-VMFirmware -VMName "YourVMName" -EnableSecureBoot On
```

### Step 4: Enable vTPM (for Credential Guard, BitLocker)

```powershell
# On Hyper-V Host - Enable vTPM for the VM
# Requires Windows Server 2016+ host and Generation 2 VM
Enable-VMTPM -VMName "YourVMName"

# Or configure key protector first if needed
$Guardian = Get-HgsGuardian -Name "UntrustedGuardian"
$KeyProtector = New-HgsKeyProtector -Owner $Guardian -AllowUntrustedRoot
Set-VMKeyProtector -VMName "YourVMName" -KeyProtector $KeyProtector.RawData
Enable-VMTPM -VMName "YourVMName"
```

### Step 5: Update Hyper-V Host CPU Microcode

Ensure the physical host has the latest CPU microcode (via Windows Update):

```powershell
# On Hyper-V Host - Check for and install updates
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll -AutoReboot
```

### Step 6: Configure Hyper-V Scheduler (Optional, for SMT Security)

For multi-tenant environments, configure Hyper-V Core Scheduler to prevent SMT-based attacks:

```powershell
# On Hyper-V Host - Set Core Scheduler type
# Options: Classic, Core, Root
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" `
    -Name "CoreSchedulerType" -Value 1 -Type DWord

# Restart Hyper-V service
Restart-Service vmms

# Verify scheduler type (requires restart)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-Hypervisor-Operational'; ID=2} -MaxEvents 1 | 
    Select-Object -ExpandProperty Message
```

**Scheduler Types:**
- **0 (Classic)**: Legacy scheduler, no SMT protection
- **1 (Core)**: Recommended for multi-tenant, prevents VMs from sharing SMT threads
- **2 (Root)**: Root partition controls scheduling

### Step 7: Restart VM to Apply Changes

```powershell
# On Hyper-V Host - Restart the VM
Restart-VM -VMName "YourVMName" -Force
```

### Complete Hyper-V Configuration Script

```powershell
#Requires -RunAsAdministrator
# Run on Hyper-V Host

$VMName = "YourDomainController"  # Change to your VM name

Write-Host "Configuring Hyper-V VM for CPU Security Features..." -ForegroundColor Cyan

# 1. Disable processor compatibility to expose real CPU features
Write-Host "Disabling processor compatibility mode..." -ForegroundColor Yellow
Set-VMProcessor -VMName $VMName -CompatibilityForMigration $false

# 2. Expose virtualization extensions (for VBS/HVCI support)
Write-Host "Exposing virtualization extensions..." -ForegroundColor Yellow
Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true

# 3. Verify VM is Generation 2
$VM = Get-VM -Name $VMName
if ($VM.Generation -ne 2) {
    Write-Warning "VM is Generation $($VM.Generation). Generation 2 is required for full security features."
    Write-Warning "Consider migrating to a Generation 2 VM."
}

# 4. Enable Secure Boot (if not already enabled)
Write-Host "Enabling Secure Boot..." -ForegroundColor Yellow
Set-VMFirmware -VMName $VMName -EnableSecureBoot On -ErrorAction SilentlyContinue

# 5. Configure vTPM if needed
Write-Host "Checking vTPM configuration..." -ForegroundColor Yellow
$tpmEnabled = Get-VMSecurity -VMName $VMName | Select-Object -ExpandProperty TpmEnabled
if (-not $tpmEnabled) {
    Write-Host "Enabling vTPM (requires Host Guardian Service or standalone mode)..." -ForegroundColor Yellow
    # Create key protector for standalone mode
    $Guardian = Get-HgsGuardian -Name "UntrustedGuardian" -ErrorAction SilentlyContinue
    if (-not $Guardian) {
        $Guardian = New-HgsGuardian -Name "UntrustedGuardian" -GenerateCertificates
    }
    $KeyProtector = New-HgsKeyProtector -Owner $Guardian -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
    Enable-VMTPM -VMName $VMName
}

# 6. Display current configuration
Write-Host "`nCurrent VM Configuration:" -ForegroundColor Green
$VMProc = Get-VMProcessor -VMName $VMName
$VMFirmware = Get-VMFirmware -VMName $VMName

Write-Host "VM Name: $VMName"
Write-Host "Generation: $($VM.Generation)"
Write-Host "Processor Compatibility: $($VMProc.CompatibilityForMigration)"
Write-Host "Expose Virt Extensions: $($VMProc.ExposeVirtualizationExtensions)"
Write-Host "Secure Boot: $($VMFirmware.SecureBoot)"
Write-Host "vTPM Enabled: $tpmEnabled"

Write-Host "`nConfiguration complete. Restart the VM to apply changes." -ForegroundColor Cyan
Write-Host "After restart, run the SideChannel_Check_v2.ps1 script inside the VM." -ForegroundColor Yellow
```

---

## VMware ESXi Configuration

### Prerequisites

1. **ESXi Host Requirements:**
   - ESXi 6.7 Update 2+ (7.0+ recommended for latest CPU features)
   - Physical CPU with required security features
   - Latest ESXi patches installed
   - VMware Tools installed in guest

2. **VM Requirements:**
   - Hardware Version 14+ (HW 19+ for latest features)
   - EFI firmware (for Secure Boot, vTPM)
   - Windows 10/11 or Windows Server 2016+ guest OS

### Step 1: Update VM Hardware Version

Newer hardware versions expose more CPU features:

**Via vSphere Client:**
1. Power off the VM
2. Right-click VM → Compatibility → Upgrade VM Compatibility
3. Select Hardware Version 19 (ESXi 7.0 U2) or latest available
4. Click OK

**Via PowerCLI:**
```powershell
# Connect to vCenter/ESXi
Connect-VIServer -Server your-vcenter.domain.com

# Upgrade VM hardware version
$VM = Get-VM -Name "YourVMName"
Stop-VM -VM $VM -Confirm:$false
Set-VM -VM $VM -Version v19 -Confirm:$false
```

### Step 2: Configure CPU Settings to Expose Host Features

**Via vSphere Client:**
1. Power off the VM
2. Edit Settings → CPU
3. **Uncheck** "Hide NX/XD flag from guest" (allows DEP)
4. Expand "CPU/MMU Virtualization"
5. Select **"Use hardware-assisted virtualization"** (exposes CPU features)
6. Expand "Hardware Virtualization"
7. **Check** "Expose hardware assisted virtualization to the guest OS" (for nested virt)

**Via VM Configuration File (.vmx):**

Add/modify these parameters in the VM's .vmx file:

```ini
# Expose hardware-assisted virtualization (for VBS/HVCI)
vhv.enable = "TRUE"
vmx.allowNested = "TRUE"

# Expose CPUID bits for modern CPU features
cpuid.8000000A:eax = "1"
cpuid.8000000A:ebx = "1"

# Enable EPT/NPT (required for modern mitigations)
ept.mode = "hardware"
vpmc.enable = "TRUE"

# Expose IBRS/IBPB (Spectre mitigations)
cpuid.7.0.edx.spec_ctrl = "1"
cpuid.7.0.edx.ibrs_ibpb = "1"
cpuid.7.0.edx.stibp = "1"

# Expose SSBD (Speculative Store Bypass Disable)
cpuid.7.0.edx.ssbd = "1"

# Expose Enhanced IBRS
cpuid.7.0.edx.ibrs_all = "1"

# Expose L1D Flush (for L1TF mitigation)
cpuid.7.0.edx.flush_l1d = "1"

# Expose MD_CLEAR (for MDS mitigation)
cpuid.7.0.edx.md_clear = "1"

# Expose FB_CLEAR (for MMIO mitigation - Intel only)
cpuid.7.1.eax.fb_clear = "1"

# Disable CPU/MMU masking (allows real CPU to pass through)
monitor.allowLegacyCPU = "FALSE"
```

**Important:** These settings require the VM to be powered off before editing.

### Step 3: Configure EFI Firmware and Secure Boot

**Via vSphere Client:**
1. Power off the VM
2. Edit Settings → VM Options → Boot Options
3. Firmware: Select **EFI** (not BIOS)
4. Secure Boot: **Enable** (requires EFI firmware)
5. Click OK

**Via .vmx file:**
```ini
# Enable EFI firmware
firmware = "efi"

# Enable Secure Boot
uefi.secureBoot.enabled = "TRUE"
```

### Step 4: Add vTPM to VM

**Via vSphere Client:**
1. Power off the VM
2. Edit Settings → Add New Device → Trusted Platform Module
3. Select TPM 2.0
4. Click Add, then OK

**Via PowerCLI:**
```powershell
# Add vTPM to VM (requires EFI firmware)
$VM = Get-VM -Name "YourVMName"
New-VTPMDevice -VM $VM
```

### Step 5: Configure ESXi Host CPU Microcode

Ensure the ESXi host has the latest CPU microcode:

```bash
# SSH to ESXi host
# Check current microcode version
esxcli hardware cpu cpuid raw -l 1

# Update ESXi (includes microcode updates)
esxcli software profile update -d https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml -p ESXi-7.0U3-latest

# Or apply offline bundle
esxcli software vib install -d /path/to/offline-bundle.zip

# Reboot host
reboot
```

### Step 6: Configure ESXi Side-Channel Mitigations

Configure host-level mitigations that affect VMs:

```bash
# SSH to ESXi host
# View current mitigation settings
vsish -e get /hardware/cpu/specControl

# Enable L1D flush for VMs (L1TF mitigation)
esxcli system settings kernel set -s hypervisorMitigations -v TRUE

# Configure SMT (Hyperthreading) behavior
# Options: default, noSMT, partialSMT
esxcli system settings kernel set -s smtType -v default

# Reboot host to apply
reboot
```

### Step 7: Restart VM and Verify

```powershell
# Via PowerCLI
Start-VM -VM (Get-VM -Name "YourVMName")
```

### Complete VMware ESXi Configuration Script (PowerCLI)

```powershell
#Requires -Modules VMware.VimAutomation.Core

$vCenterServer = "your-vcenter.domain.com"
$VMName = "YourDomainController"

# Connect to vCenter
Write-Host "Connecting to vCenter..." -ForegroundColor Cyan
Connect-VIServer -Server $vCenterServer

$VM = Get-VM -Name $VMName

# 1. Power off VM
Write-Host "Powering off VM..." -ForegroundColor Yellow
Stop-VM -VM $VM -Confirm:$false

# 2. Upgrade hardware version
Write-Host "Upgrading hardware version..." -ForegroundColor Yellow
Set-VM -VM $VM -Version v19 -Confirm:$false

# 3. Configure CPU settings
Write-Host "Configuring CPU settings..." -ForegroundColor Yellow
$VMView = $VM | Get-View
$ConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec

# Expose hardware-assisted virtualization
$ConfigSpec.NestedHVEnabled = $true

# CPU/MMU virtualization mode
$ConfigSpec.CpuHotAddEnabled = $false
$ConfigSpec.CpuHotRemoveEnabled = $false

# Apply CPU configuration
$VMView.ReconfigVM($ConfigSpec)

# 4. Configure advanced settings (CPUID passthrough)
Write-Host "Configuring advanced CPU features..." -ForegroundColor Yellow
New-AdvancedSetting -Entity $VM -Name "vhv.enable" -Value "TRUE" -Confirm:$false -Force
New-AdvancedSetting -Entity $VM -Name "cpuid.7.0.edx.spec_ctrl" -Value "1" -Confirm:$false -Force
New-AdvancedSetting -Entity $VM -Name "cpuid.7.0.edx.ssbd" -Value "1" -Confirm:$false -Force
New-AdvancedSetting -Entity $VM -Name "cpuid.7.0.edx.md_clear" -Value "1" -Confirm:$false -Force

# 5. Configure EFI firmware
Write-Host "Configuring EFI firmware and Secure Boot..." -ForegroundColor Yellow
$ConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
$ConfigSpec.Firmware = "efi"
$ConfigSpec.BootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
$ConfigSpec.BootOptions.EfiSecureBootEnabled = $true
$VMView.ReconfigVM($ConfigSpec)

# 6. Add vTPM (if not present)
Write-Host "Adding vTPM..." -ForegroundColor Yellow
try {
    New-VTPMDevice -VM $VM -ErrorAction Stop
} catch {
    Write-Warning "vTPM may already be present or requires additional configuration: $($_.Exception.Message)"
}

# 7. Start VM
Write-Host "Starting VM..." -ForegroundColor Yellow
Start-VM -VM $VM -Confirm:$false

Write-Host "`nConfiguration complete!" -ForegroundColor Green
Write-Host "After VM boots, log in and run SideChannel_Check_v2.ps1 to verify mitigations." -ForegroundColor Yellow

Disconnect-VIServer -Confirm:$false
```

---

## VMware Workstation/Player Configuration

### Step 1: Update VM Hardware Compatibility

1. Power off the VM
2. VM → Manage → Change Hardware Compatibility
3. Select **Workstation 17.x** or latest
4. Click OK

### Step 2: Edit Virtual Machine Settings

1. Power off the VM
2. Edit Virtual Machine Settings → Processors
3. Virtualization engine:
   - ☑ **Virtualize Intel VT-x/EPT or AMD-V/RVI**
   - ☑ **Virtualize IOMMU (IO memory management unit)**

### Step 3: Manually Edit .vmx File

1. Power off the VM
2. Locate the VM's .vmx file (in the VM directory)
3. Edit with a text editor (Notepad++, VSCode)
4. Add/modify these lines:

```ini
# Enable nested virtualization
vhv.enable = "TRUE"
vmx.allowNested = "TRUE"

# Expose CPU security features
cpuid.7.0.edx.spec_ctrl = "1"
cpuid.7.0.edx.ssbd = "1"
cpuid.7.0.edx.md_clear = "1"
cpuid.7.0.edx.ibrs_all = "1"

# Enable EFI firmware
firmware = "efi"
uefi.secureBoot.enabled = "TRUE"

# Enable vTPM
managedVM.autoAddVTPM = "software"
```

5. Save and close
6. Start the VM

---

## Verification Steps

After configuring the hypervisor and restarting the VM:

### Inside the Windows VM:

1. **Verify CPU Features are Exposed:**

```powershell
# Check CPUID capabilities (requires coreinfo from Sysinternals)
# Download: https://learn.microsoft.com/en-us/sysinternals/downloads/coreinfo

coreinfo.exe -f

# Look for:
# IBRS   - Indirect Branch Restricted Speculation
# IBPB   - Indirect Branch Predictor Barrier
# STIBP  - Single Thread Indirect Branch Predictors
# SSBD   - Speculative Store Bypass Disable
# MD_CLEAR - MDS mitigation
# FB_CLEAR - MMIO mitigation
```

2. **Run Microsoft SpeculationControl Module:**

```powershell
# Install the module
Install-Module SpeculationControl -Force

# Check mitigation status
Get-SpeculationControlSettings

# Expected output should show:
# - Hardware support for mitigations: Present
# - Windows OS support: Enabled
```

3. **Run SideChannel_Check_v2.ps1:**

```powershell
# Navigate to script directory
cd C:\path\to\script

# Run assessment
.\SideChannel_Check_v2.ps1 -Mode Assess

# Check specific mitigation
.\SideChannel_Check_v2.ps1 | Where-Object { $_.Id -eq 'PSDP' } | Format-List
```

Expected results:
- **RegistryStatus**: Enabled
- **RuntimeStatus**: Active (if previously showed "N/A", hypervisor config worked!)
- **OverallStatus**: Protected

4. **Check Event Logs:**

```powershell
# Check for mitigation-related events
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-General'
} -MaxEvents 50 | Where-Object { $_.Message -match 'speculation|mitigation' }
```

---

## Troubleshooting

### Issue: Microsoft SpeculationControl still shows "enabled: False" after configuration

**Possible Causes:**

1. **VM not restarted after hypervisor config:**
   - Solution: Fully shut down and restart the VM (not just reboot)

2. **Physical CPU doesn't support the feature:**
   - Check: Run `coreinfo -f` on the **Hyper-V/ESXi host**
   - Solution: If CPU doesn't support feature, mitigation cannot be enabled

3. **Hypervisor version too old:**
   - Hyper-V: Update to Windows Server 2019+ or Windows 10 1809+
   - ESXi: Update to 6.7 U2+ or 7.0+

4. **Microcode not updated:**
   - Solution: Install latest Windows/ESXi updates on host

5. **Processor Compatibility Mode still enabled (Hyper-V):**
   ```powershell
   Get-VMProcessor -VMName "YourVM" | Select-Object CompatibilityForMigration
   # Should be: False
   ```

6. **CPUID masking active (VMware):**
   - Check .vmx for `cpuid.*.` overrides that might be hiding features
   - Remove any `cpuid.*.hide = "1"` entries

### Issue: vTPM cannot be added

**Hyper-V:**
- Requires Generation 2 VM
- Requires key protector configuration
- Solution: Follow vTPM enable script above

**VMware:**
- Requires EFI firmware (not BIOS)
- Requires hardware version 14+
- Solution: Convert to EFI firmware first

### Issue: Performance degradation after enabling mitigations

**Expected:** CPU side-channel mitigations have performance impact:
- PSDP/Retbleed: ~2-5% impact
- MMIO: ~1-3% impact
- L1TF (full): ~10-30% impact (VMs only)
- Disabling SMT: ~30-50% impact

**Recommendations:**
- Enable only necessary mitigations based on threat model
- For domain controllers: Enable all Critical + Recommended mitigations
- For low-security workloads: Consider selective mitigation
- Test performance before/after in your environment

### Issue: VM won't boot after configuration changes

**Recovery Steps:**

1. Revert firmware to BIOS (if EFI conversion failed)
2. Disable vTPM temporarily
3. Boot to safe mode and review registry changes
4. Restore from Hyper-V/VMware snapshot

---

## Summary

### Key Takeaways:

1. **Registry settings alone are insufficient** - hypervisor must expose CPU features
2. **Generation 2 (Hyper-V) or EFI firmware (VMware)** required for modern security
3. **Disable processor compatibility/masking** to expose real CPU capabilities
4. **Update host and guest** to latest versions for best compatibility
5. **Verify after changes** using SpeculationControl module and SideChannel_Check_v2.ps1

### Quick Reference:

| Hypervisor | Key Setting | Purpose |
|------------|-------------|---------|
| **Hyper-V** | `CompatibilityForMigration = $false` | Expose real CPU features |
| **Hyper-V** | `ExposeVirtualizationExtensions = $true` | Enable VBS/HVCI |
| **VMware** | `vhv.enable = "TRUE"` | Enable nested virtualization |
| **VMware** | `cpuid.*.edx = "1"` | Expose specific CPU features |
| **Both** | Generation 2 / EFI firmware | Modern security prerequisite |
| **Both** | vTPM | Required for Credential Guard, BitLocker |

---

## Additional Resources

- [Microsoft: Hyper-V Security](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types)
- [VMware: Security Hardening Guides](https://docs.vmware.com/en/VMware-vSphere/index.html)
- [Intel: Security Advisories](https://www.intel.com/content/www/us/en/security-center/default.html)
- [AMD: Security Research](https://www.amd.com/en/corporate/product-security)

---

**Document Version:** 1.0  
**Last Updated:** December 2024  
**Compatibility:** Hyper-V (Windows Server 2016+), VMware ESXi 6.7+, VMware Workstation 15+
