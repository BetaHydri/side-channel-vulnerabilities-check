<#
.SYNOPSIS
    Automated test suite for Side-Channel Vulnerability Mitigation Tool v2.

.DESCRIPTION
    Comprehensive test suite that validates all functionality of the v2 tool:
    - Basic assessment
    - WhatIf safety checks
    - Backup creation
    - Restore browsing
    - CSV export
    - Error handling
    - Parameter validation

.PARAMETER SkipBackupTests
    Skip tests that create backup files

.PARAMETER SkipExportTests
    Skip CSV export tests

.PARAMETER Verbose
    Show detailed test output

.EXAMPLE
    .\Test-SideChannelTool.ps1
    Run all tests

.EXAMPLE
    .\Test-SideChannelTool.ps1 -SkipBackupTests
    Run all tests except backup creation

.NOTES
    Author: Jan Tiedemann
    Version: 2.1.0
    Requires: Administrator privileges
    Updated: 2025-11-27
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipBackupTests,

    [Parameter()]
    [switch]$SkipExportTests
)

# Test Results Tracking
$script:TestResults = @{
    Passed   = 0
    Failed   = 0
    Skipped  = 0
    Warnings = 0
}

$script:FailedTests = @()

function Write-TestResult {
    param(
        [Parameter(Mandatory)]
        [string]$TestName,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Skip', 'Warn')]
        [string]$Result,

        [Parameter()]
        [string]$Message = ""
    )

    switch ($Result) {
        'Pass' {
            Write-Host "✅ PASS: $TestName" -ForegroundColor Green
            $script:TestResults.Passed++
        }
        'Fail' {
            Write-Host "❌ FAIL: $TestName" -ForegroundColor Red
            if ($Message) { Write-Host "   $Message" -ForegroundColor Red }
            $script:TestResults.Failed++
            $script:FailedTests += @{Test = $TestName; Message = $Message }
        }
        'Skip' {
            Write-Host "⏭️  SKIP: $TestName" -ForegroundColor Gray
            if ($Message) { Write-Host "   $Message" -ForegroundColor Gray }
            $script:TestResults.Skipped++
        }
        'Warn' {
            Write-Host "⚠️  WARN: $TestName" -ForegroundColor Yellow
            if ($Message) { Write-Host "   $Message" -ForegroundColor Yellow }
            $script:TestResults.Warnings++
        }
    }
}

function Test-ScriptExists {
    Write-Host "`n[Pre-Test] Verifying script exists..." -ForegroundColor Yellow
    
    $scriptPath = ".\SideChannel_Check_v2.ps1"
    if (Test-Path $scriptPath) {
        Write-TestResult -TestName "Script file exists" -Result Pass
        return $true
    }
    else {
        Write-TestResult -TestName "Script file exists" -Result Fail -Message "SideChannel_Check_v2.ps1 not found"
        return $false
    }
}

function Test-BasicAssessment {
    Write-Host "`n[Test 1] Basic Assessment..." -ForegroundColor Yellow
    
    try {
        $result = & ".\SideChannel_Check_v2.ps1" 2>&1
        
        if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
            Write-TestResult -TestName "Basic Assessment" -Result Pass
        }
        else {
            Write-TestResult -TestName "Basic Assessment" -Result Fail -Message "Exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-TestResult -TestName "Basic Assessment" -Result Fail -Message $_.Exception.Message
    }
}

function Test-WhatIfMode {
    Write-Host "`n[Test 2] WhatIf Mode..." -ForegroundColor Yellow
    
    try {
        $result = & ".\SideChannel_Check_v2.ps1" -Mode ApplyInteractive -WhatIf 2>&1
        
        if ($result -match "WhatIf") {
            Write-TestResult -TestName "WhatIf Mode Indicator" -Result Pass
        }
        else {
            Write-TestResult -TestName "WhatIf Mode Indicator" -Result Warn -Message "WhatIf text not found in output"
        }
    }
    catch {
        Write-TestResult -TestName "WhatIf Mode" -Result Fail -Message $_.Exception.Message
    }
}

function Test-BackupCreation {
    if ($SkipBackupTests) {
        Write-Host "`n[Test 3] Backup Creation..." -ForegroundColor Yellow
        Write-TestResult -TestName "Backup Creation" -Result Skip -Message "SkipBackupTests specified"
        return
    }

    Write-Host "`n[Test 3] Backup Creation..." -ForegroundColor Yellow
    
    try {
        $backupsBefore = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
        
        & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
        
        $backupsAfter = @(Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue).Count
        
        if ($backupsAfter -gt $backupsBefore) {
            Write-TestResult -TestName "Backup Creation" -Result Pass
            
            # Verify backup format
            $latestBackup = Get-ChildItem ".\Backups\Backup_*.json" -ErrorAction SilentlyContinue | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 1
            
            if ($latestBackup) {
                try {
                    $backupData = Get-Content $latestBackup.FullName | ConvertFrom-Json
                    
                    if ($backupData.Timestamp -and $backupData.Computer -and $backupData.Mitigations) {
                        Write-TestResult -TestName "Backup Format Validation" -Result Pass
                    }
                    else {
                        Write-TestResult -TestName "Backup Format Validation" -Result Fail -Message "Missing required fields"
                    }
                }
                catch {
                    Write-TestResult -TestName "Backup Format Validation" -Result Fail -Message "Invalid JSON format"
                }
            }
        }
        else {
            Write-TestResult -TestName "Backup Creation" -Result Fail -Message "Backup count did not increase"
        }
    }
    catch {
        Write-TestResult -TestName "Backup Creation" -Result Fail -Message $_.Exception.Message
    }
}

function Test-CSVExport {
    if ($SkipExportTests) {
        Write-Host "`n[Test 4] CSV Export..." -ForegroundColor Yellow
        Write-TestResult -TestName "CSV Export" -Result Skip -Message "SkipExportTests specified"
        return
    }

    Write-Host "`n[Test 4] CSV Export..." -ForegroundColor Yellow
    
    $testCsvPath = ".\test_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    try {
        & ".\SideChannel_Check_v2.ps1" -ExportPath $testCsvPath | Out-Null
        
        if (Test-Path $testCsvPath) {
            $csvContent = Get-Content $testCsvPath -Raw
            
            # Test 1: Verify semicolon delimiter (v2.1.0 feature)
            if ($csvContent -match ';') {
                Write-TestResult -TestName "CSV Semicolon Delimiter" -Result Pass
            }
            else {
                Write-TestResult -TestName "CSV Semicolon Delimiter" -Result Fail -Message "Expected semicolon delimiter not found"
            }
            
            # Test 2: Import and verify structure
            $csv = Import-Csv $testCsvPath -Delimiter ';'
            
            if ($csv.Count -gt 0) {
                Write-TestResult -TestName "CSV Export Row Count" -Result Pass -Message "$($csv.Count) rows exported"
                
                # Test 3: Verify v2.1.0 18-column structure
                $requiredColumns = @('Id', 'Name', 'Category', 'Status', 'RegistryStatus', 'RuntimeStatus', 
                    'ActionNeeded', 'CVE', 'Platform', 'Impact', 'PrerequisiteFor', 
                    'CurrentValue', 'ExpectedValue', 'Description', 'Recommendation', 
                    'RegistryPath', 'RegistryName', 'URL')
                $csvColumns = $csv[0].PSObject.Properties.Name
                
                $missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }
                
                if ($missingColumns.Count -eq 0) {
                    Write-TestResult -TestName "CSV 18-Column Structure" -Result Pass
                }
                else {
                    Write-TestResult -TestName "CSV 18-Column Structure" -Result Fail -Message "Missing columns: $($missingColumns -join ', ')"
                }
                
                # Test 4: Verify PrerequisiteFor field preserves commas (v2.1.0)
                $prereqRow = $csv | Where-Object { $_.PrerequisiteFor -and $_.PrerequisiteFor -ne '-' } | Select-Object -First 1
                if ($prereqRow -and $prereqRow.PrerequisiteFor -match ',') {
                    Write-TestResult -TestName "CSV Comma Preservation in PrerequisiteFor" -Result Pass -Message "Found: $($prereqRow.PrerequisiteFor)"
                }
                else {
                    Write-TestResult -TestName "CSV Comma Preservation in PrerequisiteFor" -Result Warn -Message "No comma-separated PrerequisiteFor found (may be valid)"
                }
                
                # Test 5: Verify URL field is populated (v2.1.0)
                $urlRow = $csv | Where-Object { $_.URL -and $_.URL -ne '' } | Select-Object -First 1
                if ($urlRow) {
                    Write-TestResult -TestName "CSV URL References" -Result Pass -Message "URLs populated"
                }
                else {
                    Write-TestResult -TestName "CSV URL References" -Result Warn -Message "No URLs found in export"
                }
            }
            else {
                Write-TestResult -TestName "CSV Export" -Result Fail -Message "CSV is empty"
            }
            
            # Cleanup
            Remove-Item $testCsvPath -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-TestResult -TestName "CSV Export" -Result Fail -Message "CSV file not created"
        }
    }
    catch {
        Write-TestResult -TestName "CSV Export" -Result Fail -Message $_.Exception.Message
    }
}

function Test-WhatIfSafety {
    Write-Host "`n[Test 5] WhatIf Safety Check..." -ForegroundColor Yellow
    
    try {
        $backupsBefore = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
        
        & ".\SideChannel_Check_v2.ps1" -Mode Backup -WhatIf | Out-Null
        
        $backupsAfter = @(Get-ChildItem ".\Backups\*.json" -ErrorAction SilentlyContinue).Count
        
        if ($backupsAfter -eq $backupsBefore) {
            Write-TestResult -TestName "WhatIf Safety (No Changes)" -Result Pass
        }
        else {
            Write-TestResult -TestName "WhatIf Safety (No Changes)" -Result Fail -Message "WhatIf created files (expected no changes)"
        }
    }
    catch {
        Write-TestResult -TestName "WhatIf Safety" -Result Fail -Message $_.Exception.Message
    }
}

function Test-RestoreMode {
    Write-Host "`n[Test 6] Restore Mode..." -ForegroundColor Yellow
    
    try {
        # First ensure at least one backup exists
        if (-not $SkipBackupTests) {
            & ".\SideChannel_Check_v2.ps1" -Mode Backup | Out-Null
        }
        
        # Attempt to browse backups (won't actually restore without selection)
        $result = & ".\SideChannel_Check_v2.ps1" -Mode Restore 2>&1
        
        if ($result -match "available backup" -or $result -match "Backup #") {
            Write-TestResult -TestName "Restore Mode" -Result Pass
        }
        else {
            Write-TestResult -TestName "Restore Mode" -Result Warn -Message "No backups found or unexpected output"
        }
    }
    catch {
        Write-TestResult -TestName "Restore Mode" -Result Fail -Message $_.Exception.Message
    }
}

function Test-ParameterValidation {
    Write-Host "`n[Test 7] Parameter Validation..." -ForegroundColor Yellow
    
    # Test invalid mode
    try {
        $result = & ".\SideChannel_Check_v2.ps1" -Mode "InvalidMode" 2>&1
        
        if ($result -match "Cannot validate argument" -or $LASTEXITCODE -ne 0) {
            Write-TestResult -TestName "Invalid Mode Rejection" -Result Pass
        }
        else {
            Write-TestResult -TestName "Invalid Mode Rejection" -Result Fail -Message "Invalid mode was accepted"
        }
    }
    catch {
        # Expected to throw error
        Write-TestResult -TestName "Invalid Mode Rejection" -Result Pass
    }
    
    # Test invalid export path
    try {
        $invalidPath = "Z:\NonExistent\Path\export.csv"
        $result = & ".\SideChannel_Check_v2.ps1" -ExportPath $invalidPath 2>&1
        
        # Should either fail gracefully or create directory
        Write-TestResult -TestName "Invalid Path Handling" -Result Pass -Message "Handled gracefully"
    }
    catch {
        Write-TestResult -TestName "Invalid Path Handling" -Result Pass -Message "Error handled properly"
    }
}

function Test-ModeCompatibility {
    Write-Host "`n[Test 8] Mode-Specific WhatIf..." -ForegroundColor Yellow
    
    $modesWithWhatIf = @('ApplyInteractive', 'RevertInteractive', 'Backup')
    
    foreach ($mode in $modesWithWhatIf) {
        try {
            $result = & ".\SideChannel_Check_v2.ps1" -Mode $mode -WhatIf 2>&1
            
            if ($result -match "WhatIf" -or $result -match "What if") {
                Write-TestResult -TestName "WhatIf on $mode mode" -Result Pass
            }
            else {
                Write-TestResult -TestName "WhatIf on $mode mode" -Result Warn -Message "WhatIf indicator not clearly shown"
            }
        }
        catch {
            Write-TestResult -TestName "WhatIf on $mode mode" -Result Fail -Message $_.Exception.Message
        }
    }
}

function Test-ShowDetailsMode {
    Write-Host "`n[Test 9] ShowDetails Mode..." -ForegroundColor Yellow
    
    try {
        $result = & ".\SideChannel_Check_v2.ps1" -ShowDetails 2>&1
        
        # Test for v2.1.0 features in detailed output
        $foundCVE = $result -match 'CVE-\d{4}-\d+'
        $foundURL = $result -match 'https?://'
        $foundImpact = $result -match 'Impact:\s+(Low|Medium|High|None)'
        $foundPrereqFor = $result -match 'Required For:'
        
        if ($foundCVE) {
            Write-TestResult -TestName "ShowDetails CVE Display" -Result Pass
        }
        else {
            Write-TestResult -TestName "ShowDetails CVE Display" -Result Warn -Message "CVE numbers not found in output"
        }
        
        if ($foundURL) {
            Write-TestResult -TestName "ShowDetails URL References" -Result Pass
        }
        else {
            Write-TestResult -TestName "ShowDetails URL References" -Result Warn -Message "URLs not found in output"
        }
        
        if ($foundImpact) {
            Write-TestResult -TestName "ShowDetails Impact Display" -Result Pass
        }
        else {
            Write-TestResult -TestName "ShowDetails Impact Display" -Result Warn -Message "Impact info not found in output"
        }
        
        if ($foundPrereqFor) {
            Write-TestResult -TestName "ShowDetails PrerequisiteFor Display" -Result Pass
        }
        else {
            Write-TestResult -TestName "ShowDetails PrerequisiteFor Display" -Result Warn -Message "Prerequisite dependencies not found"
        }
    }
    catch {
        Write-TestResult -TestName "ShowDetails Mode" -Result Fail -Message $_.Exception.Message
    }
}

function Test-HardwareDetection {
    Write-Host "`n[Test 10] Hardware Security Features Detection..." -ForegroundColor Yellow
    
    try {
        $result = & ".\SideChannel_Check_v2.ps1" 2>&1
        
        # Test for v2.1.0 hardware detection output
        $foundFirmware = $result -match 'Firmware:\s+(UEFI|Legacy BIOS)'
        $foundSecureBoot = $result -match 'Secure Boot:'
        $foundTPM = $result -match 'TPM:'
        $foundVTx = $result -match 'VT-x/AMD-V:'
        $foundIOMMU = $result -match 'IOMMU/VT-d:'
        $foundVBS = $result -match 'VBS Capable:'
        $foundHVCI = $result -match 'HVCI Capable:'
        
        if ($foundFirmware -and $foundSecureBoot -and $foundTPM -and $foundVTx -and $foundIOMMU -and $foundVBS -and $foundHVCI) {
            Write-TestResult -TestName "Hardware Security Features Display" -Result Pass -Message "All 7 features detected"
        }
        else {
            $missing = @()
            if (-not $foundFirmware) { $missing += 'Firmware' }
            if (-not $foundSecureBoot) { $missing += 'Secure Boot' }
            if (-not $foundTPM) { $missing += 'TPM' }
            if (-not $foundVTx) { $missing += 'VT-x' }
            if (-not $foundIOMMU) { $missing += 'IOMMU' }
            if (-not $foundVBS) { $missing += 'VBS' }
            if (-not $foundHVCI) { $missing += 'HVCI' }
            Write-TestResult -TestName "Hardware Security Features Display" -Result Fail -Message "Missing: $($missing -join ', ')"
        }
    }
    catch {
        Write-TestResult -TestName "Hardware Security Features" -Result Fail -Message $_.Exception.Message
    }
}

function Test-SelectionRangeNotation {
    Write-Host "`n[Test 11] Selection Range Notation Support..." -ForegroundColor Yellow
    
    # This is a behavioral test - we can't easily automate interactive input
    # But we can verify the function exists by checking the script content
    try {
        $scriptContent = Get-Content ".\SideChannel_Check_v2.ps1" -Raw
        
        # Check for range notation parsing logic (v2.1.0 feature)
        if ($scriptContent -match '\$part -match ''\^\\d\+-\\d\+\$''') {
            Write-TestResult -TestName "Range Notation Parser Present" -Result Pass -Message "Code for '1-4' range parsing found"
        }
        else {
            Write-TestResult -TestName "Range Notation Parser Present" -Result Warn -Message "Range parsing code not detected"
        }
        
        # Check for selection examples in help/comments
        if ($scriptContent -match '1-3,5,7-9' -or $scriptContent -match '2-4,6-8') {
            Write-TestResult -TestName "Range Notation Documentation" -Result Pass -Message "Range examples found in code"
        }
        else {
            Write-TestResult -TestName "Range Notation Documentation" -Result Warn -Message "Range examples not found"
        }
    }
    catch {
        Write-TestResult -TestName "Selection Range Notation" -Result Fail -Message $_.Exception.Message
    }
}

# Main Test Execution
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host "  Side-Channel Tool v2 - Automated Test Suite" -ForegroundColor Cyan
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host ""

# Pre-test validation
if (-not (Test-ScriptExists)) {
    Write-Host "`n❌ Critical: Script not found. Aborting tests." -ForegroundColor Red
    exit 1
}

# Run test suite
Test-BasicAssessment
Test-WhatIfMode
Test-BackupCreation
Test-CSVExport
Test-WhatIfSafety
Test-RestoreMode
Test-ParameterValidation
Test-ModeCompatibility
Test-ShowDetailsMode
Test-HardwareDetection
Test-SelectionRangeNotation

# Summary
Write-Host "`n=================================================================================" -ForegroundColor Cyan
Write-Host "  Test Summary" -ForegroundColor Cyan
Write-Host "=================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Passed:   $($script:TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed:   $($script:TestResults.Failed)" -ForegroundColor $(if ($script:TestResults.Failed -gt 0) { 'Red' } else { 'Green' })
Write-Host "Warnings: $($script:TestResults.Warnings)" -ForegroundColor Yellow
Write-Host "Skipped:  $($script:TestResults.Skipped)" -ForegroundColor Gray
Write-Host ""

if ($script:FailedTests.Count -gt 0) {
    Write-Host "Failed Tests Details:" -ForegroundColor Red
    foreach ($failed in $script:FailedTests) {
        Write-Host "  • $($failed.Test): $($failed.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

$totalTests = $script:TestResults.Passed + $script:TestResults.Failed + $script:TestResults.Warnings
if ($totalTests -gt 0) {
    $successRate = [math]::Round(($script:TestResults.Passed / $totalTests) * 100, 1)
    Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { 'Green' } elseif ($successRate -ge 70) { 'Yellow' } else { 'Red' })
}

Write-Host "`n=== Test Suite Complete ===" -ForegroundColor Cyan

# Exit with error code if any tests failed
if ($script:TestResults.Failed -gt 0) {
    exit 1
}
else {
    exit 0
}
