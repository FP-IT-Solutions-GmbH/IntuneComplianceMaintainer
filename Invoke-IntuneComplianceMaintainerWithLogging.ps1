<#
.SYNOPSIS
  Runs IntuneComplianceMaintainer.ps1 and captures its console output to a timestamped log
  file. Intended to be called by the Windows Scheduled Task created by
  Setup-IntuneComplianceMaintainerTask.ps1 - a scheduled task has no visible console, so
  without this wrapper all Write-Output/Write-Host output from the main script would simply
  be lost.

.PARAMETER ScriptPath
  Full path to IntuneComplianceMaintainer.ps1.

.PARAMETER LogDirectory
  Folder log files are written to. Created automatically if it doesn't exist.

.PARAMETER RetentionDays
  Log files older than this are deleted at the start of each run. Default 30.

.EXAMPLE
  .\Invoke-IntuneComplianceMaintainerWithLogging.ps1 -ScriptPath "C:\Skripte\IntuneComplianceMaintainer.ps1" -LogDirectory "C:\Logs\IntuneComplianceMaintainer"
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$ScriptPath,

  [Parameter(Mandatory = $true)]
  [string]$LogDirectory,

  [int]$RetentionDays = 30
)

if (-not (Test-Path -Path $ScriptPath)) {
  throw "Script not found: $ScriptPath"
}

if (-not (Test-Path -Path $LogDirectory)) {
  New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

# Clean up old logs before this run, so the log folder doesn't grow unbounded over months of
# unattended daily runs.
Get-ChildItem -Path $LogDirectory -Filter "IntuneComplianceMaintainer_*.log" -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } |
  Remove-Item -Force -ErrorAction SilentlyContinue

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$logFile = Join-Path $LogDirectory "IntuneComplianceMaintainer_$timestamp.log"

try {
  # *> redirects all output streams (Output, Warning, Error, Verbose, Debug, Information) into
  # the log file, so nothing the main script writes gets silently dropped when run unattended.
  & $ScriptPath *> $logFile
  $exitNote = "Completed"
}
catch {
  "UNHANDLED EXCEPTION: $($_.Exception.Message)`n$($_.ScriptStackTrace)" | Out-File -FilePath $logFile -Append -Encoding UTF8
  $exitNote = "Failed"
}

# A one-line summary appended at the very end makes it fast to spot success/failure without
# opening the full log - e.g. when skimming the log folder after not having checked in for a
# few days.
"[$timestamp] $exitNote - see above for full output." | Out-File -FilePath $logFile -Append -Encoding UTF8

if ($exitNote -eq "Failed") {
  exit 1
}
