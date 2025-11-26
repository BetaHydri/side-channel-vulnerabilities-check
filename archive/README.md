# Archived Versions

This directory contains archived versions of the Side-Channel Vulnerability Mitigation Tool that are no longer actively maintained.

## v1.x (Legacy)

The original version of the tool, now archived. This version is stable and production-tested but does not receive new features or updates.

**Location:** `v1/`

**Status:** Archived (No longer actively maintained)

**Last Updated:** November 2025

### Why was v1 archived?

Version 2.1.0 represents a complete redesign with:
- Enhanced features and capabilities
- Better user experience
- Modern PowerShell practices
- Comprehensive testing suite
- Active maintenance and updates

### When to use v1?

Use the archived v1 version only if:
- You have existing automation scripts dependent on v1's specific behavior
- You need to reference historical configurations
- You are troubleshooting legacy deployments

### Migration to v2

We strongly recommend migrating to v2.1.0 for:
- Latest security features
- Better hardware detection
- Interactive modes with selective apply/restore
- WhatIf preview support
- Ongoing support and updates

**Migration Path:**
1. Export current v1 state: `.\SideChannel_Check.ps1 -ExportPath "v1_baseline.csv"`
2. Run v2 assessment: `.\SideChannel_Check_v2.ps1 -ShowDetails`
3. Use v2's interactive mode to apply changes incrementally
4. Leverage v2's backup/restore features for safe testing

---

**For the latest version, please use the main repository tools.**
