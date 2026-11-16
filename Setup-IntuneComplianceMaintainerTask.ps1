<#
.SYNOPSIS
  Creates a Windows Scheduled Task that runs IntuneComplianceMaintainer.ps1 unattended, once
  daily, via the logging wrapper (Invoke-IntuneComplianceMaintainerWithLogging.ps1).

.DESCRIPTION
  Two run modes are supported:

  1. "Run whether user is logged on or not" under a specific account (default). This is the
     simplest option if you already have your AppRegCert certificate installed under that
     account's Cert:\CurrentUser\My - e.g. your own admin account, since that's where you
     installed and tested the certificate earlier. Requires a password (prompted via
     Get-Credential, or pass -Credential) because Windows needs to store logon credentials to
     run the task without an interactive session.

  2. -RunAsSystem: runs under the built-in SYSTEM account, no password needed. Only use this if
     either:
       - AuthMode is "AppRegSecret" (no certificate involved), or
       - AuthMode is "AppRegCert" AND you have specifically installed the certificate into the
         SYSTEM account's own certificate store (not your own - SYSTEM has a separate profile;
         installing a cert while logged in as yourself does NOT put it there for SYSTEM).
     For most AppRegCert setups tested interactively as an admin user, mode 1 is the right
     choice.

.PARAMETER ScriptPath
  Full path to IntuneComplianceMaintainer.ps1.

.PARAMETER WrapperScriptPath
  Full path to Invoke-IntuneComplianceMaintainerWithLogging.ps1. Defaults to the same folder
  as this setup script.

.PARAMETER LogDirectory
  Folder the wrapper writes log files to. Default: C:\Logs\IntuneComplianceMaintainer

.PARAMETER TaskName
  Name of the scheduled task. Default: IntuneComplianceMaintainer

.PARAMETER TriggerTime
  Daily run time, 24h format "HH:mm". Default: 06:00

.PARAMETER Credential
  Account to run the task as ("Run whether user is logged on or not"). If omitted (and
  -RunAsSystem is not specified), you will be prompted via Get-Credential.

.PARAMETER RunAsSystem
  Run under the built-in SYSTEM account instead of a specific user. See DESCRIPTION above for
  when this is (and isn't) appropriate.

.EXAMPLE
  # Prompts for the account to run as - simplest option for an AppRegCert setup tested under
  # your own admin account
  .\Setup-IntuneComplianceMaintainerTask.ps1 -ScriptPath "C:\Skripte\IntuneComplianceMaintainer.ps1"

.EXAMPLE
  # AppRegSecret setup, no certificate involved, runs as SYSTEM
  .\Setup-IntuneComplianceMaintainerTask.ps1 -ScriptPath "C:\Skripte\IntuneComplianceMaintainer.ps1" -RunAsSystem

.EXAMPLE
  # Explicit credential, custom time and log folder
  $cred = Get-Credential -UserName "CONTOSO\svc-intune-automation"
  .\Setup-IntuneComplianceMaintainerTask.ps1 -ScriptPath "C:\Skripte\IntuneComplianceMaintainer.ps1" -Credential $cred -TriggerTime "05:30" -LogDirectory "D:\Logs"
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$ScriptPath,

  [string]$WrapperScriptPath = (Join-Path $PSScriptRoot "Invoke-IntuneComplianceMaintainerWithLogging.ps1"),

  [string]$LogDirectory = "C:\Logs\IntuneComplianceMaintainer",

  [string]$TaskName = "IntuneComplianceMaintainer",

  [string]$TriggerTime = "06:00",

  [System.Management.Automation.PSCredential]$Credential,

  [switch]$RunAsSystem
)

#Requires -RunAsAdministrator

if (-not (Test-Path -Path $ScriptPath)) {
  throw "Main script not found: $ScriptPath"
}
if (-not (Test-Path -Path $WrapperScriptPath)) {
  throw "Logging wrapper script not found: $WrapperScriptPath (expected next to this setup script, or pass -WrapperScriptPath explicitly)"
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "IntuneComplianceMaintainer - Scheduled Task Setup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Script:    $ScriptPath"
Write-Host "Wrapper:   $WrapperScriptPath"
Write-Host "Log dir:   $LogDirectory"
Write-Host "Task name: $TaskName"
Write-Host "Time:      $TriggerTime daily"
Write-Host "Run as:    $(if ($RunAsSystem) { 'SYSTEM' } else { 'specific user account' })"
Write-Host "=========================================" -ForegroundColor Cyan

# Build the action: powershell.exe running the logging wrapper, which in turn runs the main
# script and captures its output. -ExecutionPolicy Bypass only affects this one process, not
# the machine-wide policy.
$powershellPath = (Get-Command powershell.exe).Source
$argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$WrapperScriptPath`" -ScriptPath `"$ScriptPath`" -LogDirectory `"$LogDirectory`""

$action = New-ScheduledTaskAction -Execute $powershellPath -Argument $argumentList

$triggerDateTime = [datetime]::ParseExact($TriggerTime, "HH:mm", $null)
$trigger = New-ScheduledTaskTrigger -Daily -At $triggerDateTime

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -DontStopOnIdleEnd `
  -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 10) `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Write-Host "A task named '$TaskName' already exists - removing it first so this run replaces it cleanly." -ForegroundColor Yellow
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if ($RunAsSystem) {
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
}
else {
  if (-not $Credential) {
    Write-Host "`nEnter the credentials of the account this task should run as." -ForegroundColor Cyan
    Write-Host "(This must be an account where the AppRegCert certificate - if used - is installed" -ForegroundColor Cyan
    Write-Host " in Cert:\CurrentUser\My, e.g. the account you tested the script under interactively.)" -ForegroundColor Cyan
    $Credential = Get-Credential -Message "Account to run IntuneComplianceMaintainer as"
  }

  # "Run whether user is logged on or not" requires the password to be provided directly to
  # Register-ScheduledTask (not just a PSCredential object) - Windows needs to store it to be
  # able to log the account on non-interactively.
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password `
    -RunLevel Highest | Out-Null
}

Write-Host "`n[OK] Scheduled task '$TaskName' created successfully." -ForegroundColor Green
Write-Host "It will run daily at $TriggerTime. Logs will be written to: $LogDirectory" -ForegroundColor Green

Write-Host "`nTo test it immediately instead of waiting for the schedule, run:" -ForegroundColor Cyan
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host "Then check its result with:" -ForegroundColor Cyan
Write-Host "  Get-ScheduledTaskInfo -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host "(LastTaskResult 0 = success; a non-zero value means the wrapper or main script threw" -ForegroundColor Cyan
Write-Host " an error - check the newest log file in $LogDirectory for details.)" -ForegroundColor Cyan
