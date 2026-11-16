<#
.SYNOPSIS
  Grant Microsoft Graph API permissions to an Azure Automation Account's managed identity.

.DESCRIPTION
  This script grants the required Graph API application permissions to a managed identity
  so it can run IntuneComplianceMaintainer (this fork: iOS/iPadOS/macOS only) - updating
  Intune Compliance and App Protection policies (Block 1), reading device-level OS version
  for the compliance report (Block 2), and sending user notification emails (Block 3).

  "Mail.Send" and "User.Read.All" (only needed for Block 3, email notifications) are granted
  only with -IncludeMailPermissions - least privilege by default.

  Only service principals of type "ManagedIdentity" are considered, and exactly one must match
  the given name. Display names are not unique: without these checks, an app registration
  someone else created with the same name could receive the permissions.

.PARAMETER IncludeMailPermissions
  Also grant Mail.Send and User.Read.All (Block 3). Restrict Mail.Send afterwards with an
  Exchange Online Application Access Policy (see NOTES).

.NOTES
  Run this script with an account that has:
  - the Privileged Role Administrator or Global Administrator role in Entra ID
  The Graph session requests Application.Read.All and AppRoleAssignment.ReadWrite.All.

  You must have the Microsoft.Graph PowerShell module installed:
  Install-Module Microsoft.Graph -Scope CurrentUser -Force

  If you use Mail.Send, also restrict the managed identity to a single sending mailbox via
  an Exchange Online Application Access Policy - otherwise it can send as ANY mailbox in the
  tenant:
    New-ApplicationAccessPolicy -AppId "<managed-identity-app-id>" `
      -PolicyScopeGroupId "intune-automation@yourtenant.com" `
      -AccessRight RestrictAccess `
      -Description "Restrict to the automation mailbox"

.EXAMPLE
  # For system-assigned managed identity
  .\Grant-ManagedIdentityGraphPermissions.ps1 -TenantId "your-tenant-id" -ManagedIdentityDisplayName "AutomationAccountName"

  # For user-assigned managed identity
  .\Grant-ManagedIdentityGraphPermissions.ps1 -TenantId "your-tenant-id" -ManagedIdentityDisplayName "YourManagedIdentityName"

  # Including the permissions for email notifications (Block 3)
  .\Grant-ManagedIdentityGraphPermissions.ps1 -TenantId "your-tenant-id" -ManagedIdentityDisplayName "AutomationAccountName" -IncludeMailPermissions
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$TenantId,

  [Parameter(Mandatory=$true)]
  [string]$ManagedIdentityDisplayName,

  [switch]$IncludeMailPermissions
)

# Connect to Microsoft Graph. Reading service principals and assigning app roles needs no
# Application.ReadWrite.All.
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# Get the managed identity service principal - only managed identities, exactly one match.
# Single quotes in the name are doubled for the OData filter.
Write-Host "Finding managed identity: $ManagedIdentityDisplayName" -ForegroundColor Cyan
$escapedName = $ManagedIdentityDisplayName -replace "'", "''"
$candidates = @(Get-MgServicePrincipal -Filter "displayName eq '$escapedName'" -All -ErrorAction Stop |
  Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" })
if ($candidates.Count -eq 0) {
  throw "No managed identity named '$ManagedIdentityDisplayName' found. For system-assigned identities, use the Automation Account name (and make sure the identity is enabled)."
}
if ($candidates.Count -gt 1) {
  throw "$($candidates.Count) managed identities are named '$ManagedIdentityDisplayName' (ObjectIds: $(($candidates | ForEach-Object Id) -join ', ')). Rename one or grant the permissions manually."
}
$managedIdentity = $candidates[0]
Write-Host "  Found: $($managedIdentity.DisplayName) (ObjectId: $($managedIdentity.Id))" -ForegroundColor Green
# For a system-assigned identity, AlternativeNames contains the Azure resource ID - lets you
# double-check it is the right Automation Account / VM.
if ($managedIdentity.AlternativeNames) {
  Write-Host "  Resource: $(($managedIdentity.AlternativeNames | Where-Object { $_ -like '/subscriptions/*' }) -join ', ')" -ForegroundColor Green
}

# Get Microsoft Graph service principal
Write-Host "Finding Microsoft Graph service principal..." -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
Write-Host "  Found: $($graphSp.DisplayName)" -ForegroundColor Green

# Define required permissions
# - DeviceManagementConfiguration.ReadWrite.All : Block 1, Compliance policies
# - DeviceManagementApps.ReadWrite.All          : Block 1, App Protection policies
# - DeviceManagementManagedDevices.Read.All     : Block 2, installed OS version per device
# - Mail.Send                                   : Block 3, notification emails (only with -IncludeMailPermissions)
# - User.Read.All                               : Block 3, resolving the device owner's mail address (only with -IncludeMailPermissions)
# NOTE: WindowsUpdates.ReadWrite.All was removed - this fork no longer supports Windows/Android.
$requiredPermissions = @(
  "DeviceManagementConfiguration.ReadWrite.All",
  "DeviceManagementApps.ReadWrite.All",
  "DeviceManagementManagedDevices.Read.All"
)
if ($IncludeMailPermissions) {
  $requiredPermissions += "Mail.Send", "User.Read.All"
  Write-Host "Including Mail.Send and User.Read.All. Restrict Mail.Send with an Exchange Online Application Access Policy afterwards (see NOTES)." -ForegroundColor Yellow
}

Write-Host "`nGranting Graph API permissions..." -ForegroundColor Cyan
foreach ($permissionName in $requiredPermissions) {
  # Find the app role (permission) by value
  $appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq $permissionName }
  if (-not $appRole) {
    Write-Warning "Permission '$permissionName' not found in Graph API app roles"
    continue
  }
  
  # Check if permission is already assigned
  $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentity.Id |
    Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphSp.Id }
  
  if ($existingAssignment) {
    Write-Host "  [SKIP] $permissionName - already assigned" -ForegroundColor Yellow
    continue
  }
  
  # Grant the permission
  try {
    $assignment = New-MgServicePrincipalAppRoleAssignment `
      -ServicePrincipalId $managedIdentity.Id `
      -PrincipalId $managedIdentity.Id `
      -ResourceId $graphSp.Id `
      -AppRoleId $appRole.Id `
      -ErrorAction Stop
    
    Write-Host "  [SUCCESS] $permissionName - granted" -ForegroundColor Green
  }
  catch {
    Write-Host "  [ERROR] $permissionName - failed: $($_.Exception.Message)" -ForegroundColor Red
  }
}

Write-Host "`nPermission grant complete!" -ForegroundColor Green
Write-Host "The managed identity can now access Microsoft Graph API with the granted permissions." -ForegroundColor Cyan
Write-Host "`nNote: Permissions may take a few minutes to fully propagate." -ForegroundColor Yellow

Disconnect-MgGraph
