# IntuneComplianceMaintainer

Keeps Microsoft Intune Compliance and App Protection minimum-OS-version requirements current for Apple platforms (iOS, iPadOS, macOS), and reports/notifies on device-level non-compliance.

Maintained by FP-IT-Solutions GmbH. Originally based on [SkipToTheEndpoint/IntuneComplianceMaintainer](https://github.com/SkipToTheEndpoint/IntuneComplianceMaintainer); substantially rewritten (see [Changelog](#changelog-vs-upstream) below) — Android and Windows support removed, Warn-field support added, device-level compliance reporting and per-user email notification added, split cadence for Warn vs. Block, and several reliability fixes.

## Overview

The script is organized into three independently switchable blocks:

1. **Policy Maintenance** (`$RunPolicyMaintenance`) — reads the current minimum OS version from your Compliance and App Protection policies, checks the latest publicly available OS version via [endoflife.date](https://endoflife.date/docs/api/v1/), and — once the configured cadence period has elapsed — updates the policy. The only block that writes to Intune, and only when `$DryRun` is `$false`.
2. **Device Compliance Report** (`$CheckDeviceCompliance`) — read-only. Lists every device evaluated against the configured policies, compares installed vs. required version, and saves a CSV **and** a self-contained, sortable/filterable HTML report to `$DeviceComplianceReportPath`.
3. **User Notification Email** (`$SendUserNotificationEmail`) — sends one individual email per non-compliant device to its owner. Requires Block 2's data. Never sends a real email while `$DryRun` is `$true` — it only logs what it would send.

`$DryRun = $true` disables **all** side effects at once: no policy writes (Block 1) and no emails sent (Block 3). Block 2 is always read-only regardless of `$DryRun`.

## Supported platforms

- **iOS** — Compliance and App Protection
- **iPadOS** — Compliance and App Protection
- **macOS** — Compliance only (Intune has no App Protection support for macOS)

Android and Windows are intentionally not supported by this fork.

## Prerequisites

- PowerShell 5.1 or later (Windows PowerShell or PowerShell 7)
- An Entra ID App Registration (or an Azure Automation Managed Identity) with the following **Application permissions** (admin-consented) on Microsoft Graph:

| Permission | Needed for |
|---|---|
| `DeviceManagementConfiguration.ReadWrite.All` | Reading/writing Compliance policies |
| `DeviceManagementApps.ReadWrite.All` | Reading/writing App Protection policies |
| `DeviceManagementManagedDevices.Read.All` | Reading installed OS version per device (Block 2) |
| `Mail.Send` | Sending notification emails (Block 3 only) |
| `User.Read.All` | Resolving the real primary SMTP address for the device owner (Block 3 only) |

If you use `Mail.Send`, restrict the App Registration to a single sending mailbox with an Exchange Online **Application Access Policy** — otherwise the app can send as *any* mailbox in the tenant:

```powershell
New-ApplicationAccessPolicy -AppId "<client-id>" `
    -PolicyScopeGroupId "intune-automation@yourtenant.com" `
    -AccessRight RestrictAccess `
    -Description "Restrict to the automation mailbox"
```

For certificate authentication, the certificate must be installed with its private key in `Cert:\CurrentUser\My` — of whichever Windows account actually runs the script (careful with scheduled tasks running under a service account).

## Configuration

### Authentication

```powershell
# ManagedIdentity | AppRegCert | AppRegSecret
$AuthMode              = "AppRegCert"
$TenantId              = "<tenant-id>"
$ClientId              = "<client-id>"
$CertThumbprint        = "<thumbprint>"          # AppRegCert only
$ClientSecret          = "<secret>"              # AppRegSecret only
$UserAssignedClientId  = ""                      # ManagedIdentity, optional
$KeyVaultName          = ""                      # AppRegSecret, optional
$KeyVaultSecretName    = ""                       # AppRegSecret, optional
```

### Policies and cadence

```powershell
# Compliance + App Protection "Block" cadence
$CadenceDays        = 30
# App Protection "Warn" cadence — typically shorter, so users get warned well before
# the stricter Block deadline. Not used for Compliance policies (no separate Warn field there).
$CadenceDaysWarning = 14

$CompliancePolicies = @{ iOS = @(); iPadOS = @(); macOS = @() }
$AppProtectionPolicies = @{ iOS = @(); iPadOS = @() }

$AllowDowngrade = $false
$DryRun         = $true
$ForceApply     = $false   # bypasses cadence, applies to both Warn and Block deadlines
```

### Block switches

```powershell
$RunPolicyMaintenance = $true

$CheckDeviceCompliance             = $false
$CompareAgainstLatestPublicVersion = $false   # fallback to latest public OS version if a policy has no minimum configured
$ShowDeviceComplianceList          = $false   # also print the device table to console
$DeviceComplianceReportPath        = "C:\Reports"

$SendUserNotificationEmail = $false           # requires $CheckDeviceCompliance = $true
$EmailSenderAddress        = "<sender-mailbox@yourtenant.onmicrosoft.com>"
```

## How it works

### Block 1 — Policy Maintenance

For each configured platform, the script fetches the latest OS version and release date from endoflife.date, then computes two independent deadlines from that release date:

- `WarningEffectiveDate = ReleaseDate + $CadenceDaysWarning`
- `RequiredEffectiveDate = ReleaseDate + $CadenceDays`

Each App Protection policy's `minimumWarningOsVersion` (Warn) and `minimumRequiredOsVersion` (Block) fields are then evaluated **independently** against their own deadline. A policy can end up with only the Warn field updated in a given run while Block is not yet due — this is expected, and shows up as `Updated (nur Warn - Block noch nicht faellig)` (or the reverse) rather than a plain `Updated`. Only fields that are already configured on the policy are ever touched — the script never turns on Block where only Warn existed, or vice versa.

Compliance policies only have the single `osMinimumVersion` field and use `$CadenceDays` only.

### Block 2 — Device Compliance Report

- **Compliance policies**: uses the documented Graph endpoint `/deviceManagement/deviceCompliancePolicies/{id}/deviceStatuses` for the device list, then correlates each entry by ID to `/deviceManagement/managedDevices/{id}` for the installed OS version, device model, and last sync time. This ID correlation is a widely used community pattern, not explicitly documented by Microsoft — verify in Graph Explorer if results look off for your tenant.
- **App Protection policies**: the simple per-policy device-status endpoint is not reliably available across tenants. Instead, this uses the asynchronous **Intune Reports export API** (`/deviceManagement/reports/exportJobs`, report `MAMAppProtectionStatus`): create the export job, poll until complete, download the ZIP, extract, and parse. Despite Microsoft's own documentation stating this report has "no filters," it does include a `Policy` column with the policy's display name, which the script uses to attribute rows to the correct policy.
- Output: `IntuneDeviceComplianceReport_<timestamp>.csv` and a matching `.html` file with click-to-sort columns, a per-column text filter row, and non-compliant rows highlighted in red — fully self-contained (no external JS/CSS, works offline).

### Block 3 — User Notification Email

Reuses Block 2's device list, filters to `Compliant = "No"` rows with a resolvable user, looks up each user's real primary SMTP address via `/users/{upn}` (falls back to the UPN if the lookup fails — UPN and primary email are not always the same, e.g. with an on-prem `.local` UPN suffix), and sends one individual email per device via `/users/{sender}/sendMail`. The email's stated deadline (`$CadenceDays` vs. `$CadenceDaysWarning`) automatically matches whichever rule (Warn or Block) triggered the notification.

## Known limitations

- The `MAMAppProtectionStatus` report schema was determined empirically (Microsoft's public documentation doesn't list exact column names) — if your tenant returns different column names, the script's keyword-based lookup (`Get-PropertyValueLike`) may not find the expected field. Check the `[INFO]` diagnostic log lines (report row count, column names, and any "no match" warnings) if device data comes back empty.
- Apple device model values (e.g. `iPhone12,1`) are Apple's internal identifiers, not human-readable names — there's no official API mapping these to marketing names (e.g. "iPhone 11").
- Windows PowerShell 5.1's `Invoke-RestMethod`/`Invoke-WebRequest` mis-decode UTF-8 as ISO-8859-1 for JSON responses without an explicit charset (mangling German umlauts/ß). Worked around via a raw `HttpWebRequest`-based `Invoke-GraphGet` wrapper for GET calls. If a display name still looks wrong even under PowerShell 7 (which doesn't have this bug), the value is very likely genuinely corrupted in the stored Intune object itself (e.g. from an earlier tool with the same bug) — check directly in the Intune portal.

## Troubleshooting

**"Unable to find type [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]"** — this only affects the *original* upstream script; this fork builds the JWT client assertion manually with built-in .NET crypto (`System.Security.Cryptography`), no external assembly needed.

**"AADSTS7000215: Invalid client secret provided"** — you've entered the Secret **ID** (a plain GUID) instead of the Secret **Value** from Entra ID → Certificates & secrets. The value is only shown once, right after creating the secret.

**Certificate not found** — must be in `Cert:\CurrentUser\My` of the account actually running the script (not `Cert:\LocalMachine\My`), with its private key.

## Changelog vs. upstream

- Removed Android and Windows support entirely (iOS/iPadOS/macOS only)
- Added support for the App Protection "Warn" field (`minimumWarningOsVersion`), independent from "Block" (`minimumRequiredOsVersion`) — previously only Block was read/written
- Split cadence: separate, shorter cadence for Warn vs. Block
- Renamed `Current` → `CurrentRequired` for clarity now that `CurrentWarning` exists
- Fixed `AppRegCert` authentication: rebuilt without the `System.IdentityModel.Tokens.Jwt` dependency
- Fixed a redundant duplicate API call to endoflife.date for App Protection cadence checks (reuses the Compliance check's result)
- Fixed Windows PowerShell 5.1 UTF-8 mangling via a custom `Invoke-GraphGet` wrapper
- Added device-level compliance reporting (Block 2), including CSV and filterable/sortable HTML output, device model, and last-sync timestamp
- Added per-user individual email notification for non-compliant devices (Block 3), fully `$DryRun`-safe
- Fixed a property-lookup priority bug that could pick a display name instead of an email address when building notification recipients

## Disclaimer

This script modifies production Intune policies and can send email on your organization's behalf. Always test with `$DryRun = $true` first, in a non-production environment if possible. Neither the original upstream author nor FP-IT-Solutions GmbH assumes any liability for unintended changes or impacts to your environment.
