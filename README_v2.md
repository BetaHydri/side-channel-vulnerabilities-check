# Side-Channel Vulnerability Mitigation Tool v2.0

## Overview

**Version 2.0** is a complete architectural redesign of the Side-Channel Vulnerability Assessment and Remediation Tool, featuring a modular, class-based architecture for improved maintainability, clearer output, and enhanced functionality.

### Key Improvements Over v1.x

✅ **Modular Architecture**: Clean separation of concerns with dedicated classes for detection, assessment, configuration, and output  
✅ **Simplified Output**: Focused on actionable intelligence, removing confusing technical details from main view  
✅ **Enhanced Platform Detection**: Automatically detects Physical/Hyper-V Host/Guest/VMware scenarios  
✅ **Kernel Runtime Detection**: Direct Windows API integration for authoritative protection status  
✅ **Interactive Apply Mode**: Guided mitigation selection with clear categorization and impact warnings  
✅ **Backup & Revert**: Automatic backup before changes with one-command rollback capability  
✅ **Comprehensive Logging**: Detailed audit trail of all operations  
✅ **Centralized Mitigation Registry**: Single source of truth for all mitigation definitions

---

## Architecture

### Component Overview

```
SideChannel_Check_v2.ps1
│
├── Logger Module
│   └── Centralized logging (console + file)
│
├── KernelRuntimeDetector Class
│   ├── NtQuerySystemInformation API wrapper
│   ├── Real-time kernel mitigation state
│   └── Hardware immunity detection
│
├── PlatformDetector Class
│   ├── Environment detection (Physical/Hyper-V/VMware)
│   ├── CPU and OS information
│   └── Platform-specific filtering
│
├── MitigationDefinition Class
│   └── Structured mitigation metadata
│
├── Mitigation Registry Function
│   └── Centralized definitions (no code duplication)
│
├── AssessmentEngine Class
│   ├── Runs mitigation assessments
│   ├── Compares registry vs runtime state
│   └── Determines action needed
│
├── OutputFormatter Class
│   ├── Platform information display
│   ├── Security assessment summary
│   ├── Simplified mitigation tables
│   └── Actionable recommendations
│
└── ConfigurationManager Class
    ├── Backup creation (JSON format)
    ├── Mitigation application
    └── Configuration revert
```

---

## Usage

### Basic Assessment

```powershell
# Run security assessment (default mode)
.\SideChannel_Check_v2.ps1

# Show detailed technical information
.\SideChannel_Check_v2.ps1 -ShowDetails
```

**Output**: Displays current platform, protection status, and clear recommendations

### Interactive Apply Mode (Recommended)

```powershell
# Apply mitigations with guided selection
.\SideChannel_Check_v2.ps1 -Mode Apply -Interactive
```

**Features**:
- Numbered list of actionable mitigations
- Color-coded priority (Red=Critical, Yellow=Recommended, Cyan=Optional)
- Performance impact warnings
- Automatic backup before changes
- Flexible selection: `1,2,5` or `1-3` or `all` or `critical`

### Export Assessment

```powershell
# Export to CSV for compliance/reporting
.\SideChannel_Check_v2.ps1 -Mode Export -ExportPath ".\Assessment.csv"

# Export with default timestamped filename
.\SideChannel_Check_v2.ps1 -Mode Export
```

**Output**: CSV file with complete mitigation status including registry, runtime state, and recommendations

### Revert Configuration

```powershell
# Restore previous configuration
.\SideChannel_Check_v2.ps1 -Mode Revert
```

**Process**:
1. Displays latest backup information
2. Prompts for confirmation
3. Restores all registry values
4. Logs all changes

---

## Sample Output

### Assessment Mode

```
================================================================================
  Side-Channel Vulnerability Mitigation Tool - Version 2.0.0
================================================================================


--- Platform Information ---
Type:        Physical
CPU:         11th Gen Intel(R) Core(TM) i7-11370H @ 3.30GHz
OS:          Microsoft Windows 11 Enterprise (Build 26200)

--- Security Assessment Summary ---
Total Mitigations Evaluated:  10
Protected:                    7 (70.0%)
Vulnerable:                   3

Security Level: Good

--- Mitigation Status ---
Speculative Store Bypass Disable             Protected       No                   Low       
Branch Target Injection Mitigation           Protected       No                   Low       
Kernel VA Shadow                             Protected       No                   Medium    
Enhanced IBRS                                Protected       No                   Low       
Intel TSX Disable                            Protected       No                   Low       
L1 Terminal Fault Mitigation                 Vulnerable      Yes - Recommended    High      
MDS Mitigation                               Protected       No                   Medium    
TSX Asynchronous Abort Mitigation            Vulnerable      Yes - Recommended    Medium    
Hardware Security Mitigations                Protected       No                   Low       

--- Recommendations ---

🟡 RECOMMENDED - Apply for enhanced security:
   • L1 Terminal Fault Mitigation
     High performance impact; primarily for multi-tenant virtualization environments
   • TSX Asynchronous Abort Mitigation
     Enable if TSX cannot be disabled; moderate performance impact

To apply mitigations, run:
   .\SideChannel_Check_v2.ps1 -Mode Apply -Interactive
```

### Interactive Apply Mode

```
=== Interactive Mitigation Application ===
Select mitigations to apply (or 'all' for automatic selection)

[1] L1 Terminal Fault Mitigation
    High performance impact; primarily for multi-tenant virtualization environments
    Impact: High | CVE: CVE-2018-3620

[2] TSX Asynchronous Abort Mitigation
    Enable if TSX cannot be disabled; moderate performance impact
    Impact: Medium | CVE: CVE-2019-11135

Enter selections (e.g., '1,2,5' or '1-3' or 'all' or 'critical'): 2

You have selected 1 mitigation(s):
  • TSX Asynchronous Abort Mitigation

A backup will be created before applying changes.
Do you want to proceed? (Y/N): Y

[INFO] Creating configuration backup...
[SUCCESS] Backup created: C:\...\Backups\Backup_20251126_143022.json

Applying mitigations...
[INFO] Applying: TSX Asynchronous Abort Mitigation
[SUCCESS] Applied: TSX Asynchronous Abort Mitigation

=== Summary ===
Successfully applied: 1

⚠ A system restart is required for changes to take effect.
```

---

## Mitigation Categories

### Critical (Apply Immediately)
- **Speculative Store Bypass Disable (SSBD)** - CVE-2018-3639
- **Branch Target Injection (BTI)** - CVE-2017-5715 (Spectre v2)
- **Kernel VA Shadow (KVAS)** - CVE-2017-5754 (Meltdown)
- **Enhanced IBRS** - CVE-2017-5715
- **Hardware Security Mitigations** - Core hardware protections

**Impact**: Low to Medium  
**When**: Always enable unless hardware has native immunity

### Recommended (Enhanced Security)
- **Intel TSX Disable** - CVE-2019-11135
- **MDS Mitigation** - CVE-2018-12130 (ZombieLoad)
- **TSX Asynchronous Abort (TAA)** - CVE-2019-11135

**Impact**: Low to Medium  
**When**: Enable for production environments; modern CPUs may have hardware immunity

### Optional (Evaluate Carefully)
- **L1 Terminal Fault (L1TF)** - CVE-2018-3620 (Foreshadow)

**Impact**: High (may require disabling hyperthreading)  
**When**: Multi-tenant virtualization environments, compliance requirements

---

## Platform-Specific Behavior

### Physical Hardware
- All mitigations evaluated
- Focus on core OS and hardware protections
- No hypervisor-specific checks

### Hyper-V Host
- All mitigations evaluated
- Additional focus on L1TF (critical for VM isolation)
- Hypervisor Core Scheduler recommendations

### Hyper-V Guest
- Standard mitigations evaluated
- Host-level mitigations noted as informational
- Guest-specific recommendations

### VMware Guest
- Standard mitigations evaluated
- VMware Tools update recommendations
- Platform-aware filtering

---

## Logging

All operations are logged to:
```
Logs\SideChannelCheck_YYYYMMDD_HHMMSS.log
```

Log levels:
- **INFO**: Operational messages
- **SUCCESS**: Completed actions
- **WARNING**: Non-critical issues
- **ERROR**: Critical failures
- **DEBUG**: Verbose diagnostics (requires `-Verbose`)

---

## Backup & Restore

### Backup Location
```
Backups\Backup_YYYYMMDD_HHMMSS.json
```

### Backup Format
```json
{
  "Timestamp": "2025-11-26T14:30:22",
  "Computer": "WORKSTATION01",
  "User": "Administrator",
  "Mitigations": [
    {
      "Name": "Speculative Store Bypass Disable",
      "RegistryPath": "HKLM:\\SYSTEM\\...",
      "RegistryName": "FeatureSettingsOverride",
      "Value": 72
    }
  ]
}
```

### Restore Process
1. Latest backup is automatically identified
2. User confirms restore operation
3. All registry values are restored to backup state
4. System restart required

---

## Migration from v1.x

### Key Differences

| Feature | v1.x | v2.0 |
|---------|------|------|
| **Architecture** | Monolithic script | Modular classes |
| **Output** | Detailed technical view | Simplified actionable view |
| **Mode Selection** | Multiple switches | Single `-Mode` parameter |
| **Backup** | Manual | Automatic |
| **Revert** | Not available | Built-in |
| **Platform Detection** | Basic | Advanced with filtering |
| **Logging** | Console only | File + Console |

### Migration Steps

1. **Run v1.x assessment** and export current state:
   ```powershell
   .\SideChannel_Check.ps1 -ExportPath ".\v1_state.csv"
   ```

2. **Run v2.0 assessment** to compare:
   ```powershell
   .\SideChannel_Check_v2.ps1 -Mode Export -ExportPath ".\v2_state.csv"
   ```

3. **Apply new mitigations** (if any) using interactive mode:
   ```powershell
   .\SideChannel_Check_v2.ps1 -Mode Apply -Interactive
   ```

### Parameter Mapping

| v1.x Parameter | v2.0 Equivalent |
|----------------|-----------------|
| `-Apply` | `-Mode Apply` |
| `-Interactive` | `-Interactive` (with `-Mode Apply`) |
| `-Detailed` | `-ShowDetails` |
| `-ExportPath` | `-ExportPath` (with `-Mode Export`) |
| `-ShowVMwareHostSecurity` | Automatic based on platform |

---

## Troubleshooting

### Issue: "Kernel runtime detection not available"

**Cause**: Windows API call failed (rare on modern Windows)  
**Impact**: Assessment falls back to registry-only mode  
**Solution**: No action needed; registry status is still accurate

### Issue: "Access denied" errors

**Cause**: Script not running as Administrator  
**Solution**: Right-click PowerShell, "Run as Administrator"

### Issue: Mitigations show "Unknown" status

**Cause**: Registry values not configured (default Windows state)  
**Solution**: Apply recommended mitigations via interactive mode

### Issue: Revert fails

**Cause**: No backup exists or backup file corrupted  
**Solution**: Check `Backups\` folder; re-apply mitigations manually if needed

---

## Advanced Usage

### Custom Log Location

```powershell
.\SideChannel_Check_v2.ps1 -LogPath "C:\Logs\CustomLog.log"
```

### Batch Apply (Future Feature)

```powershell
# Coming soon: Non-interactive apply with config file
.\SideChannel_Check_v2.ps1 -Mode Apply -ConfigFile ".\config.json"
```

### Verbose Debugging

```powershell
.\SideChannel_Check_v2.ps1 -Verbose
```

---

## Requirements

- **PowerShell**: 5.1 or higher
- **Privileges**: Administrator
- **Platform**: Windows 10/11, Windows Server 2016+
- **CPU**: Intel or AMD (platform-specific mitigations auto-detected)

---

## Security Considerations

1. **Always create backups** before applying mitigations (automatic in v2.0)
2. **Test in non-production** first, especially high-impact mitigations
3. **Review performance impact** on critical workloads
4. **Keep logs** for audit and compliance purposes
5. **Restart required** for most mitigations to take effect

---

## Support & Contribution

- **GitHub**: [BetaHydri/side-channel-vulnerabilities-check](https://github.com/BetaHydri/side-channel-vulnerabilities-check)
- **Issues**: Report bugs via GitHub Issues
- **Branch**: `feature/v2-redesign` (development), `main` (stable v1.x)

---

## Changelog

### v2.0.0 (November 2025)

**New Features**:
- Complete architectural redesign with class-based modules
- Simplified, actionable output format
- Interactive apply mode with categorized recommendations
- Automatic backup and revert functionality
- Comprehensive audit logging
- Platform-aware mitigation filtering
- Enhanced kernel runtime detection

**Improvements**:
- Eliminated code duplication with centralized mitigation registry
- Clear separation of concerns (detection, assessment, configuration, output)
- Better error handling and logging
- More intuitive parameter naming

**Breaking Changes**:
- New parameter structure (use `-Mode` instead of multiple switches)
- Different output format (simplified table view)
- CSV export now requires `-Mode Export`

---

## License

Same as v1.x - See main repository LICENSE file

---

## Acknowledgments

Built upon the foundation of v1.x with lessons learned from production deployments and administrator feedback. Special thanks to the security community for ongoing research into side-channel vulnerabilities.
