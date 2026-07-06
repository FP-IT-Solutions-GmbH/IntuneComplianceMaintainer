# IntuneComplianceMaintainer

Automatically maintain Microsoft Intune Compliance and App Protection policies with the latest supported minimum OS versions, ensuring device access is restricted based on up-to-date device security.

> **This is a locally patched version.** See [Changes in This Version](#changes-in-this-version-local-fixes) below for exactly what was changed compared to the original script from [SkipToTheEndpoint/IntuneComplianceMaintainer](https://github.com/SkipToTheEndpoint/IntuneComplianceMaintainer), and [Issues Found in the Original](#issues-found-in-the-original-script--docs) for problems identified in the upstream version.

## Changes in This Version (Local Fixes)

Three issues were found and fixed while testing the original script (v2.0, 2026-07-01) against a real tenant with a `AppRegCert`-based App Registration on a customer VM:

### 1. Fixed: `AppRegCert` authentication failed with "Unable to find type" error

**Problem:** The original `Get-GraphToken` function built the JWT client assertion using `[System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]` and `[System.IdentityModel.Tokens.X509SigningCredentials]`. Neither type is loaded by default in Windows PowerShell 5.1, and modern versions of the underlying NuGet package no longer expose `X509SigningCredentials` in that namespace at all — so even manually installing the package did not resolve the error.

**Fix:** The `AppRegCert` branch of `Get-GraphToken` now builds the JWT manually using only built-in .NET cryptography (`System.Security.Cryptography`), with no external assembly dependency:
- Header/payload are JSON-encoded and Base64URL-encoded by hand
- The assertion is signed via `RSACertificateExtensions.GetRSAPrivateKey($cert).SignData(...)` (RS256 / PKCS1)
- The resulting `client_assertion` is sent to the token endpoint exactly as before

No configuration changes are needed — `$AuthMode = "AppRegCert"`, `$TenantId`, `$ClientId`, and `$CertThumbprint` work exactly as documented. The certificate still needs to be in `Cert:\CurrentUser\My` (this was already correctly documented in the original Prerequisites section).

### 2. Fixed: App Protection policies using "Warn" instead of "Block" were invisible to the script

**Problem:** iOS/Android App Protection conditional-launch rules for minimum OS version can be configured with either action:
- **Block access** → Graph field `minimumRequiredOsVersion`
- **Warn** → Graph field `minimumWarningOsVersion`

The original script only ever read and wrote `minimumRequiredOsVersion`. A policy configured only with the "Warn" action (a common, less disruptive rollout choice) showed an empty `Current` value and was never actually updated, even though the script reported a result row for it.

**Fix:**
- `Get-AppProtectionPolicyInfo` now also reads `minimumWarningOsVersion` into a new `CurrentWarning` property
- `Update-AppProtectionPolicy` now detects which field(s) are actually configured on each policy and updates only those — a policy with only "Warn" configured gets `minimumWarningOsVersion` updated; a policy with only "Block" configured gets `minimumRequiredOsVersion` updated; a policy with both configured gets both updated. **Neither field is added to a policy that didn't already have it** — the fix does not silently turn on blocking where only a warning previously existed, or vice versa.
- A new `NoData` result is returned if a policy has neither field configured at all.

### 3. Renamed: `Current` → `CurrentRequired` for clarity

**Problem:** With the addition of `CurrentWarning`, the original `Current` property name became ambiguous — it specifically means the *Block* value, not "whichever value happens to be set".

**Fix:** Renamed throughout the script (result objects, console `[RESULT]` log line, and the final summary table) to `CurrentRequired`, matching the Graph field name `minimumRequiredOsVersion`. The summary table's column list is now specified explicitly (`Format-Table -Property ...`) rather than relying on automatic schema detection — the original approach silently dropped the `CurrentWarning` column whenever the *first* row in the result set happened to be a Compliance policy (which never has that property), regardless of whether later App Protection rows had a value.

## Issues Found in the Original Script / Docs

These were not fixed (no code change made) but are worth being aware of:

- **Version number mismatch:** the script header comment states `Version: v2.0, Release Date: 2026-07-01`, while the README's Version History section only lists up to `v1.2 (2026-07-01)`. The documented feature set (Android multi-version support, patch level enforcement, etc.) matches v1.2 — it's unclear what changed in v2.0, since it isn't documented anywhere.
- **`$WindowsAllowNewerBuilds` default mismatch:** the README's example configuration snippet shows `$WindowsAllowNewerBuilds = $true` with the comment "Allow devices on newer builds (e.g. Preview Updates)", but the actual script default is `$false`. Worth double-checking which value you actually want before relying on the README example verbatim.
- **No mention of the `AppRegCert` assembly dependency:** the original Prerequisites section lists Graph permissions and modules for Managed Identity / Key Vault, but never mentions that the original (unpatched) certificate-auth code path required `System.IdentityModel.Tokens.Jwt` to already be loaded in the session — which isn't guaranteed on a plain Windows Server/VM outside Azure Automation. This is now moot with the fix above, but would have caused the same failure for any user following the documented setup steps exactly.
- **No mention of `minimumWarningOsVersion` anywhere in the original docs:** the "How It Works" and "Output" sections describe App Protection updates purely in terms of `minimumRequiredOsVersion`. Given "Warn" is a completely standard, commonly used conditional-launch action in Intune, this looks like an oversight rather than an intentional scope limitation — worth flagging to the upstream author.

---

## Overview

IntuneComplianceMaintainer is a PowerShell automation script that keeps your Intune compliance and app-protection policies up-to-date with the latest OS version requirements across all major platforms. By leveraging the [endoflife.date API](https://endoflife.date/docs/api/v1/) and [Microsoft Graph Windows Update Catalog](https://learn.microsoft.com/en-us/graph/api/windowsupdates-catalog-list-entries?view=graph-rest-beta&tabs=http) data sources, it ensures your organisation maintains security posture while respecting configurable cadence periods for gradual rollout.

## Features

- **Multi-Platform Support**: iOS, iPadOS, macOS, Android, and Windows
- **Dual Policy Types**: Updates both compliance and app-protection policies
- **Warn and Block Support** *(local fix)*: App Protection minimum OS version is tracked and updated independently for both the "Warn" (`minimumWarningOsVersion`) and "Block" (`minimumRequiredOsVersion`) conditional-launch actions
- **Flexible Authentication**: Supports Managed Identity (Azure Automation), App Registration with Certificate (now dependency-free, see fixes above), or App Registration with Secret (including Azure Key Vault integration)
- **Cadence Control**: Configurable delay between update release and policy enforcement to account for update rollout schedule, with optional force-apply override
- **Android Patch Level**: Enforces minimum Android security patch level alongside OS version; targets the oldest maintained Android version for `osMinimumVersion` (so any supported release passes) and derives the monthly patch date from Android's patch schedule (1st of each month)
- **Windows Advanced Options**: Support for specific build numbers, update classifications, version ranges, and selectable app-protection target build (lowest by default)
- **Safety Features**: Optional downgrade protection and dry-run mode (downgrade check covers OS version, warning version, and patch level independently)
- **Retry Logic**: Built-in retry mechanism for API resilience
- **Comprehensive Logging**: Verbose logging with detailed result output

## Prerequisites

- PowerShell 5.1 or later
- Microsoft Graph API permissions:
  - `DeviceManagementConfiguration.ReadWrite.All` (for Compliance policies)
  - `DeviceManagementApps.ReadWrite.All` (for App Protection policies)
  - `WindowsUpdates.ReadWrite.All` (for Windows Update Catalog queries — only needed if automating Windows)
- For Managed Identity authentication: `Az.Accounts` module (pre-installed in Azure Automation)
- For Key Vault integration: `Az.KeyVault` module and appropriate Key Vault access
- For certificate authentication: certificate installed in `Cert:\CurrentUser\My` store (private key required); **no external assembly needed** — the JWT is built with built-in .NET crypto (local fix)

## Configuration

### Authentication Settings

#### Managed Identity
```powershell
$AuthMode = "ManagedIdentity"
$TenantId = "your-tenant-id"
$UserAssignedClientId = "" # optional
```

#### App Registration with Certificate
```powershell
$AuthMode = "AppRegCert"
$TenantId = "your-tenant-id"
$ClientId = "your-client-id"
$CertThumbprint = "certificate-thumbprint"
```

#### App Registration with Secret
```powershell
$AuthMode = "AppRegSecret"
$TenantId = "your-tenant-id"
$ClientId = "your-client-id"
$ClientSecret = "your-client-secret"

# Optional: Use Key Vault
$KeyVaultName = "your-keyvault-name"
$KeyVaultSecretName = "your-secret-name"
```

### Environment Configuration

```powershell
$CadenceDays = 14

$CompliancePolicies = @{
  iOS     = @("policy-guid-1", "policy-guid-2")
  iPadOS  = @("policy-guid-3")
  macOS   = @()
  Android = @("policy-guid-4")
  Windows = @("policy-guid-5")
}

$AppProtectionPolicies = @{
  iOS     = @("policy-guid-6")
  iPadOS  = @()
  Android = @("policy-guid-7")
  Windows = @("policy-guid-8")
}
```

### Safety Settings

```powershell
$AllowDowngrade = $false
$DryRun         = $true
$ForceApply     = $false
```

## Usage

1. Configure authentication and policy IDs in the script
2. Run with `$DryRun = $true` first and review the output
3. Set `$DryRun = $false` for a production run

Even with `$DryRun = $false`, no change is made until `EffectiveDate` (release date + `$CadenceDays`) has passed — use `$ForceApply = $true` temporarily to test the write path before that date, then set it back to `$false` for production.

## Output

```
[RESULT][iOS/Compliance]    test:     action=NotEffectiveYet; currentRequired=23.5; target=26.5.2; ...
[RESULT][iOS/AppProtection] test_123: action=NotEffectiveYet; currentRequired=23.4; currentWarning=22.4; target=26.5.2; ...

Platform Type          Setting        Name     CurrentRequired CurrentWarning Target ... Action          ...
-------- ----          -------        ----     --------------- -------------- ------ --- ------          ---
iOS      Compliance    MinimumVersion test     23.5                           26.5.2 ... NotEffectiveYet ...
iOS      AppProtection MinimumVersion test_123 23.4            22.4           26.5.2 ... NotEffectiveYet ...
```

## Action Types

- **Updated**: Policy was successfully updated
- **WouldUpdate**: Policy would be updated (dry-run mode)
- **Skipped**: Current version(s) meet or exceed target (downgrade protection)
- **NotEffectiveYet**: Cadence period hasn't elapsed
- **NoData**: No version data available (or, for App Protection, neither `minimumRequiredOsVersion` nor `minimumWarningOsVersion` is configured on the policy)
- **Error**: Update failed (see error details in output)

## Security Considerations

- Store secrets in Azure Key Vault when using `AppRegSecret` mode
- Prefer certificate authentication over secrets for non-Azure-Automation scenarios (longer validity, private key never leaves the machine)
- Use Managed Identity for Azure Automation scenarios
- Apply least-privilege Graph API permissions
- Review audit logs for policy changes
- Test in a non-production environment first

## License

Use at your own discretion. Review and test thoroughly before production deployment.

## Disclaimer

This script modifies production Intune policies. Always test in a non-production environment and use dry-run mode before live deployment. Neither the original author nor the author of these local fixes assumes any liability for unintended changes or impacts to your environment.
