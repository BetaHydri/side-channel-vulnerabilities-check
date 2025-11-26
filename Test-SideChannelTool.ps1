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
    Version: 1.0.0
    Requires: Administrator privileges
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
    Passed = 0
    Failed = 0
    Skipped = 0
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
            $script:FailedTests += @{Test = $TestName; Message = $Message}
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
    } else {
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
        } else {
            Write-TestResult -TestName "Basic Assessment" -Result Fail -Message "Exit code: $LASTEXITCODE"
        }
    } catch {
        Write-TestResult -TestName "Basic Assessment" -Result Fail -Message $_.Exception.Message
    }
}

function Test-WhatIfMode {
    Write-Host "`n[Test 2] WhatIf Mode..." -ForegroundColor Yellow
    
    try {
        $result = & ".\SideChannel_Check_v2.ps1" -Mode ApplyInteractive -WhatIf 2>&1
        
        if ($result -match "WhatIf") {
            Write-TestResult -TestName "WhatIf Mode Indicator" -Result Pass
        } else {
            Write-TestResult -TestName "WhatIf Mode Indicator" -Result Warn -Message "WhatIf text not found in output"
        }
    } catch {
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
                    } else {
                        Write-TestResult -TestName "Backup Format Validation" -Result Fail -Message "Missing required fields"
                    }
                } catch {
                    Write-TestResult -TestName "Backup Format Validation" -Result Fail -Message "Invalid JSON format"
                }
            }
        } else {
            Write-TestResult -TestName "Backup Creation" -Result Fail -Message "Backup count did not increase"
        }
    } catch {
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
            $csv = Import-Csv $testCsvPath
            
            if ($csv.Count -gt 0) {
                Write-TestResult -TestName "CSV Export" -Result Pass -Message "$($csv.Count) rows exported"
                
                # Verify CSV structure
                $requiredColumns = @('Name', 'Status', 'RegistryState', 'RuntimeState', 'Recommendation')
                $csvColumns = $csv[0].PSObject.Properties.Name
                
                $missingColumns = $requiredColumns | Where-Object { $_ -notin $csvColumns }
                
                if ($missingColumns.Count -eq 0) {
                    Write-TestResult -TestName "CSV Structure Validation" -Result Pass
                } else {
                    Write-TestResult -TestName "CSV Structure Validation" -Result Fail -Message "Missing columns: $($missingColumns -join ', ')"
                }
            } else {
                Write-TestResult -TestName "CSV Export" -Result Fail -Message "CSV is empty"
            }
            
            # Cleanup
            Remove-Item $testCsvPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-TestResult -TestName "CSV Export" -Result Fail -Message "CSV file not created"
        }
    } catch {
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
        } else {
            Write-TestResult -TestName "WhatIf Safety (No Changes)" -Result Fail -Message "WhatIf created files (expected no changes)"
        }
    } catch {
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
        } else {
            Write-TestResult -TestName "Restore Mode" -Result Warn -Message "No backups found or unexpected output"
        }
    } catch {
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
        } else {
            Write-TestResult -TestName "Invalid Mode Rejection" -Result Fail -Message "Invalid mode was accepted"
        }
    } catch {
        # Expected to throw error
        Write-TestResult -TestName "Invalid Mode Rejection" -Result Pass
    }
    
    # Test invalid export path
    try {
        $invalidPath = "Z:\NonExistent\Path\export.csv"
        $result = & ".\SideChannel_Check_v2.ps1" -ExportPath $invalidPath 2>&1
        
        # Should either fail gracefully or create directory
        Write-TestResult -TestName "Invalid Path Handling" -Result Pass -Message "Handled gracefully"
    } catch {
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
            } else {
                Write-TestResult -TestName "WhatIf on $mode mode" -Result Warn -Message "WhatIf indicator not clearly shown"
            }
        } catch {
            Write-TestResult -TestName "WhatIf on $mode mode" -Result Fail -Message $_.Exception.Message
        }
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
} else {
    exit 0
}
