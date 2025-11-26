# Version 2.0 Changes and Improvements

## Overview
Version 2.0 represents a complete architectural redesign of the Side-Channel Vulnerability Mitigation Tool while maintaining backward compatibility with PowerShell 5.1 and 7.x.

## Branch Structure
- **main**: Stable v1.x with RuntimeStatus enhancements
- **feature/v2-redesign**: New v2.0 with redesigned architecture

## Major Improvements in v2.0

### 1. **Modular Architecture**
- **v1.x**: Monolithic script with nested functions
- **v2.0**: Clean separation of concerns with dedicated functional modules:
  - Logging functions (`Write-Log`, `Initialize-Log`)
  - Runtime detection (`Initialize-RuntimeDetection`, `Get-RuntimeMitigationStatus`)
  - Platform detection (`Initialize-PlatformDetection`, `Test-PlatformApplicability`)
  - Assessment engine (`Invoke-MitigationAssessment`, `Test-Mitigation`)
  - Output formatting (`Show-Header`, `Show-PlatformInfo`, `Show-AssessmentSummary`, etc.)
  - Configuration management (`New-ConfigurationBackup`, `Set-MitigationValue`, `Restore-Configuration`)

### 2. **Simplified User Interface**
- **v1.x**: Complex tables with technical details
- **v2.0**: 
  - Simplified output focused on actionable intelligence
  - Two display modes: Simple (default) and Detailed (-ShowDetails)
  - Color-coded recommendations by priority
  - Clear security level indicator (Excellent/Good/Fair/Poor)

### 3. **Platform-Aware Recommendations**
- **v1.x**: All mitigations shown regardless of environment
- **v2.0**: 
  - Auto-detects platform type: Physical, Hyper-V Host, Hyper-V Guest, VMware
  - Filters mitigations by applicability (e.g., L1TF only for Hyper-V hosts)
  - Targeted recommendations based on environment

### 4. **Interactive Apply Mode**
- **v1.x**: Manual registry editing required
- **v2.0**: 
  - Interactive selection interface
  - Quick options: 'all', 'critical', or specific numbers/ranges
  - Automatic backup before changes
  - Apply confirmation with summary
  - Restart reminder

### 5. **Backup and Revert Functionality**
- **v1.x**: No built-in rollback capability
- **v2.0**: 
  - Automatic JSON backup before applying changes
  - Timestamped backups in `Backups/` directory
  - One-command restore: `-Mode Revert`
  - Backup metadata (timestamp, computer, user)

### 6. **Comprehensive Logging**
- **v1.x**: Console output only
- **v2.0**: 
  - Dual output: console + file
  - Log levels: Info, Success, Warning, Error, Debug
  - Timestamped entries
  - Automatic log directory creation
  - Session metadata in log header

### 7. **Centralized Mitigation Registry**
- **v1.x**: Mitigation details scattered throughout code
- **v2.0**: 
  - Single source of truth: `Get-MitigationDefinitions`
  - Structured metadata (ID, CVE, Category, Impact, Platform, etc.)
  - Easy to maintain and extend
  - No code duplication

### 8. **Enhanced Output Formatting**
```
v1.x Output:
- Complex multi-column tables
- All technical details visible
- No clear action items

v2.0 Output:
- Clean, professional formatting
- Security level at-a-glance
- Categorized recommendations (Critical/Recommended/Optional)
- Platform information displayed
- Simplified table by default, detailed on request
```

## Technical Improvements

### PowerShell Compatibility
- **v1.x**: PowerShell 5.1+
- **v2.0**: PowerShell 5.1 and 7.x tested and verified
- Traditional function-based design (not classes) for maximum compatibility
- Proper array handling with `@()` wrapper for `.Count` operations

### Code Quality
- **v1.x**: ~5,272 lines, some code duplication
- **v2.0**: ~1,020 lines, DRY principles applied
- Better separation of concerns
- Consistent naming conventions
- Comprehensive inline documentation

### Error Handling
- **v1.x**: Basic error handling
- **v2.0**: 
  - Try-catch blocks throughout
  - Graceful degradation when API unavailable
  - Detailed error logging
  - User-friendly error messages

### Performance
- Both versions perform similarly for assessment
- v2.0 has optimized platform detection
- Parallel-ready architecture (future enhancement)

## Feature Comparison Matrix

| Feature | v1.x | v2.0 |
|---------|------|------|
| Assessment | ✓ | ✓ |
| Kernel Runtime Detection | ✓ | ✓ |
| CSV Export | ✓ | ✓ |
| Platform Detection | ✗ | ✓ |
| Interactive Apply | ✗ | ✓ |
| Backup/Revert | ✗ | ✓ |
| Comprehensive Logging | ✗ | ✓ |
| Simplified Output | ✗ | ✓ |
| Detailed Mode | ✓ | ✓ |
| Categorized Recommendations | ✗ | ✓ |
| Security Level Indicator | ✗ | ✓ |
| Modular Architecture | ✗ | ✓ |

## Migration Guide

### For End Users
```powershell
# v1.x Usage
.\SideChannel_Check.ps1 -ExportPath "results.csv"

# v2.0 Equivalent
.\SideChannel_Check_v2.ps1 -Mode Export -ExportPath "results.csv"

# New v2.0 Capabilities
.\SideChannel_Check_v2.ps1 -Mode Apply -Interactive  # Apply mitigations
.\SideChannel_Check_v2.ps1 -Mode Revert              # Rollback changes
.\SideChannel_Check_v2.ps1 -ShowDetails              # Detailed view
```

### Parameter Mapping
| v1.x | v2.0 |
|------|------|
| (default) | -Mode Assess |
| -ExportPath | -Mode Export -ExportPath |
| -Detailed | -ShowDetails |
| N/A | -Mode Apply -Interactive |
| N/A | -Mode Revert |

## Testing Results

### Tested Environments
✓ Windows 11 Enterprise Build 26200  
✓ PowerShell 5.1  
✓ PowerShell 7.x  
✓ Hyper-V Host platform  
✓ 11th Gen Intel Core i7 (with Enhanced IBRS, hardware immunity)  

### Tested Operations
✓ Assessment mode (simplified and detailed)  
✓ Export to CSV  
✓ Interactive apply mode  
✓ Backup creation  
✓ Configuration restore  
✓ Platform detection  
✓ Kernel runtime detection  
✓ Log file creation  

### Known Issues
- Large QWord registry values (>0xFFFFFFFF) in backup restore may require type handling improvement
- Both versions require Administrator privileges
- Both versions require system restart after applying mitigations

## File Structure

### v1.x Branch (main)
```
SideChannel_Check.ps1         # Main script (5,272 lines)
README.md                     # Documentation
```

### v2.0 Branch (feature/v2-redesign)
```
SideChannel_Check_v2.ps1                    # Main script (1,020 lines)
README_v2.md                                # v2 Documentation
V2_CHANGES.md                               # This file
SideChannel_Check_v2_classes_backup.ps1     # Reference (class-based attempt)
Backups/                                     # Auto-created for backups
  Backup_*.json                              # Timestamped backups
Logs/                                        # Auto-created for logs
  SideChannelCheck_*.log                     # Session logs
Config/                                      # Reserved for future use
```

## Development Notes

### Architecture Evolution
1. **Initial Attempt**: Class-based design for clean OOP structure
   - **Issue**: PowerShell 5.1/7.x strict class parsing requirements
   - **Issue**: Type references must exist at parse time
   - **Issue**: Switch statements in methods problematic for return values
   
2. **Final Design**: Function-based modular architecture
   - **Benefit**: Full PS 5.1/7.x compatibility
   - **Benefit**: Familiar PowerShell idioms
   - **Benefit**: Easy to maintain and extend
   - **Benefit**: All design benefits without compatibility issues

### Design Principles Applied
1. **Separation of Concerns**: Each function has single responsibility
2. **DRY (Don't Repeat Yourself)**: Centralized definitions, reusable functions
3. **User-Centric Design**: Focus on actionable intelligence over technical details
4. **Safety First**: Backup before changes, confirmation prompts
5. **Flexibility**: Multiple modes, detailed/simplified views
6. **Maintainability**: Clear structure, comprehensive documentation

## v2.1.0 Enhancements (2025-11-26)

### Documentation & References
- **22 Authoritative URL References**
  - Added URL property to all 22 mitigation definitions (11 CVEs, 6 security features, 5 prerequisites)
  - Sources: NVD (NIST), Microsoft Learn, Intel, AMD, TCG, UEFI Forum
  - Displayed in ShowDetails bullet-point view for educational purposes
  - Examples:
    * CVE-2017-5715: https://nvd.nist.gov/vuln/detail/CVE-2017-5715
    * VBS: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs
    * TPM 2.0: https://trustedcomputinggroup.org/resource/tpm-library-specification/

### Enhanced Detailed Table (7 Columns)
- **New Columns Added**:
  1. **Category** - Prerequisite/Critical/Recommended/Optional (12 chars)
  2. **CVE** - CVE numbers with descriptive names (25 chars, e.g., "CVE-2017-5715 (Spectre v2)")
  3. **Platform** - All/Physical/HyperVHost/etc. (12 chars)
  4. **Impact** - Low/Medium/High performance impact (8 chars)
  5. **Required For** - Dependency mapping (35 chars with auto-truncation)

- **Table Format**:
  ```
  Mitigation                     Category     Status       CVE                       Platform     Impact   Required For
  -----------------------------  -----------  -----------  ------------------------  -----------  -------  -----------------------------------
  Speculative Store Bypass Di... Critical     Protected    CVE-2018-3639             All          Low      -
  Virtualization Based Security  Optional     Protected    Kernel Isolation          All          Low      HVCI, Credential Guard
  UEFI Firmware                  Prerequisite Active       Boot Security Prerequi... All          None     Secure Boot, VBS, HVCI, Credent...
  ```

- **Cross-Version Compatibility**:
  - PowerShell 7+: ANSI escape codes for whole-line coloring
  - PowerShell 5.1: Write-Host with -ForegroundColor fallback
  - Automatic version detection via `$PSVersionTable.PSVersion.Major`

### Dependency Mapping with PrerequisiteFor
- **Hardware Prerequisites** (firmware/BIOS settings):
  * **UEFI** → Secure Boot, VBS, HVCI, Credential Guard
  * **Secure Boot** → VBS, HVCI, Credential Guard
  * **TPM 2.0** → BitLocker, VBS, Credential Guard, Windows Hello
  * **CPU Virtualization (VT-x/AMD-V)** → Hyper-V, VBS, HVCI, Credential Guard
  * **IOMMU/VT-d Support** → HVCI, VBS (full isolation), Kernel DMA Protection

- **Security Features** (software/registry settings):
  * **VBS (Virtualization Based Security)** → HVCI, Credential Guard

- **Display Modes**:
  - **Detailed Table**: Truncated at 20 chars with "..." suffix (compact view)
  - **Bullet-Point View**: Full untruncated list in magenta color (detailed view)
  - **Example**:
    ```
    • UEFI Firmware [Active]
      Required For: Secure Boot, VBS, HVCI, Credential Guard  (magenta color)
    ```

### Improved CVE Presentation
- **CVE Field Enhancements**:
  - Added descriptive context to CVE numbers in `Get-MitigationDefinitions`
  - Examples:
    * "CVE-2017-5715 (Spectre v2)" - Branch Target Injection
    * "CVE-2017-5754 (Meltdown)" - Kernel VA Shadow
    * "CVE-2018-3639" - Speculative Store Bypass Disable
    * "CVE-2018-3620 (Foreshadow)" - L1 Terminal Fault
    * "CVE-2018-12130 (ZombieLoad)" - MDS Mitigation
    * "CVE-2019-11135 (TAA)" - TSX Asynchronous Abort
  - Clearer vulnerability identification for users unfamiliar with CVE numbers

### Implementation Details
- **Safe Property Access**: All URL and PrerequisiteFor access uses `ContainsKey()` checks
- **Show-MitigationTable Refactoring**: Switch-based architecture with three formats:
  * `'Simple'` - 4-column basic table (default mode)
  * `'Detailed'` - 7-column enhanced table (ShowDetails mode)
  * `'Bullets'` - Educational bullet-point view with URLs and full dependencies (ShowDetails mode)
- **Column Width Optimization**: 30, 12, 12, 25, 12, 8, 20 characters for detailed table
- **Color Scheme**: Green (Protected), Red (Vulnerable), Cyan (Active), Gray (Other), Magenta (PrerequisiteFor)

### Testing & Validation
- Tested on PowerShell 7.4.6 and PowerShell 5.1
- Verified ANSI color codes work correctly in PS 7+
- Confirmed fallback coloring works in PS 5.1
- Validated table alignment across both versions
- All 24 mitigations + 5 prerequisites display correctly
- Safe property access prevents errors for items without PrerequisiteFor

## Future Enhancements (Potential)
- [ ] GUI interface option
- [ ] Remote system assessment
- [ ] Scheduled assessments with email reports
- [ ] Group Policy Object (GPO) export
- [ ] Compliance reporting (CIS, STIG, etc.)
- [ ] Automated update checking
- [ ] Custom mitigation profiles
- [ ] Performance impact measurement
- [ ] Export PrerequisiteFor to CSV for documentation
- [ ] Reverse dependency lookup (what depends on a given feature)
- [ ] Dependency graph visualization

## Recommendations

### When to Use v1.x
- Existing scripts/automation depend on v1.x parameter structure
- Prefer monolithic single-file approach
- Only need assessment and export functionality

### When to Use v2.0
- Need interactive mitigation application
- Want backup/revert capability
- Prefer simplified, actionable output
- Managing multiple systems with different platforms
- Need comprehensive audit logging
- Want modern, maintainable architecture

## Conclusion
Version 2.0 represents a significant evolution in functionality, usability, and maintainability while preserving the core assessment capabilities and PowerShell compatibility of v1.x.

The modular architecture, simplified interface, and enhanced safety features (backup/revert) make v2.0 the recommended version for production use, especially in environments where configuration changes need to be applied safely and tracked comprehensively.

---
**Version**: 2.1.0  
**Date**: November 26, 2025  
**Author**: Jan Tiede  
**Branch**: main (merged from feature/v2-redesign)
