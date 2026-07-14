<#
.SYNOPSIS
  Maintains Intune Compliance and App Protection minimum-OS-version settings for Apple platforms
  (iOS, iPadOS, macOS), based on endoflife.date data, and reports/notifies on device-level
  non-compliance.
 
  Supported auth methods:
    - Managed Identity
    - App Registration with Certificate
    - App Registration with Secret (optionally from Key Vault)
 
  Supported platforms:
    - iOS (Compliance and App Protection)
    - iPadOS (Compliance and App Protection)
    - macOS (Compliance only - App Protection is not available for macOS in Intune)
 
  The script is organized into three independently switchable blocks:
    1. Policy Maintenance ($RunPolicyMaintenance)  - keeps the configured minimum OS version
       current, respecting cadence. This is the only block that writes to Intune, and only
       when $DryRun is $false.
    2. Device Compliance Report ($CheckDeviceCompliance) - read-only. Lists every device
       evaluated against the configured policies, compares installed vs. required version,
       and saves a CSV report to $DeviceComplianceReportPath.
    3. User Notification Email ($SendUserNotificationEmail) - sends one individual email per
       non-compliant device to its owner. Requires block 2's data. Never sends a real email
       while $DryRun is $true - it only logs what would be sent.
 
.NOTES
  Based on the original IntuneComplianceMaintainer by James Robinson | SkipToTheEndpoint
  (https://skiptotheendpoint.co.uk / https://stte.me/automatecompliance), with local
  modifications: Android/Windows support removed, Warn-field support added, device-level
  compliance reporting and per-user email notification added. See README for full changelog.
#>
 
# --------------------------- Authentication ---------------------------
# Auth mode: ManagedIdentity | AppRegCert | AppRegSecret
$AuthMode              = "<auth-mode>"
$TenantId              = "<tenant-id>"
$ClientId              = "<client-id-if-AppReg>"
$CertThumbprint        = "<thumb-if-AppRegCert>"
$ClientSecret          = "<secret-if-AppRegSecret>"
 
# Optional: clientId of user-assigned managed identity
$UserAssignedClientId  = ""
 
# Optional Key Vault lookups (leave blank to skip)
$KeyVaultName          = ""
$KeyVaultSecretName    = ""
 
# --------------------------- Environment Configuration ---------------------------
# Cadence: days after update release before enforcing.
# - Applies to Compliance policies (single osMinimumVersion field).
# - Applies to App Protection's "Zugriff blockieren" field (minimumRequiredOsVersion).
$CadenceDays           = 30
 
# Separate, typically shorter cadence for App Protection's "Warnung" field
# (minimumWarningOsVersion). Lets you warn users well before the stricter block cadence kicks
# in, e.g. warn after 14 days, block only after 30 days. Not used for Compliance policies,
# since those have no separate warning field.
$CadenceDaysWarning    = 14
 
# Policy IDs to maintain (per platform). Leave an array empty to skip that platform.
$CompliancePolicies = @{
  iOS     = @()
  iPadOS  = @()
  macOS   = @()
}
$AppProtectionPolicies = @{
  iOS     = @()
  iPadOS  = @()
}

# --------------------------- Safety ---------------------------
# Allow lowering an existing minimum (if set)? Default false
$AllowDowngrade        = $false

# Dry run: no policy writes AND no emails are actually sent - both blocks only log what they
# would do. Always test with this set to $true first.
$DryRun                = $true

# Force apply even if cadence/effective date not reached (Block 1 only)
$ForceApply            = $false

# --------------------------- Block 1: Policy Maintenance ---------------------------
# Master switch for reading the configured minimum version, checking the latest public OS
# version, and - once the cadence period has elapsed - updating the policy. Writes only occur
# if this is $true AND $DryRun is $false.
$RunPolicyMaintenance = $true

# --------------------------- Block 2: Device Compliance Report ---------------------------
# Master switch. Read-only - never writes to Intune, runs independently of $DryRun.
$CheckDeviceCompliance = $true

# Only relevant if $CheckDeviceCompliance is $true: if a policy has no minimum OS version
# configured at all, fall back to comparing devices against the latest publicly available OS
# version (from endoflife.date) instead of skipping the policy.
$CompareAgainstLatestPublicVersion = $false

# Also print the device compliance table to the console (in addition to saving the CSV file).
$ShowDeviceComplianceList = $true

# Local folder the CSV report is saved to. A timestamped filename is generated automatically,
# e.g. IntuneDeviceComplianceReport_2026-07-06_155900.csv
$DeviceComplianceReportPath = "C:\Reports"

# --------------------------- Block 3: User Notification Email ---------------------------
# Master switch. Requires $CheckDeviceCompliance to also be $true (Block 3 reuses Block 2's
# device list rather than fetching it again). Sends ONE individual email per non-compliant
# device to its owner - never a bulk/collective email.
# While $DryRun is $true, no email is actually sent - the script only logs what it would send.
$SendUserNotificationEmail = $false

# Mailbox the notification is sent from. Must be a mailbox the App Registration is allowed to
# send as (see Mail.Send permission + Exchange Online Application Access Policy in the README).
$EmailSenderAddress = "<sender-mailbox@yourtenant.onmicrosoft.com>"

# --------------------------- Script Variables ---------------------------
# Platform slugs (endoflife.date API product names)
$EolProducts = @{
  iOS     = "iOS"
  iPadOS  = "iPadOS"
  macOS   = "macOS"
}

# Retry policy
$RetryCount            = 3
$RetryDelaySeconds     = 3

# Enable verbose console logging
$VerboseLogging        = $true

# --------------------------- Helpers ---------------------------
function Get-GraphToken {
  param([string]$TenantId,[string]$ClientId,[string]$AuthMode,[string]$CertThumbprint,[string]$ClientSecret)
  $resourceScope = "https://graph.microsoft.com/.default"
  switch ($AuthMode) {
    "ManagedIdentity" {
      # Azure Automation managed identity authentication
      try {
        Import-Module Az.Accounts -ErrorAction Stop

        $connectParams = @{ Identity = $true; ErrorAction = 'Stop' }
        if ($UserAssignedClientId) {
          $connectParams["AccountId"] = $UserAssignedClientId
        }

        $null = Connect-AzAccount @connectParams
        $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/" -ErrorAction Stop

        if (-not $tokenObj -or -not $tokenObj.Token) {
          throw "Get-AzAccessToken returned no token"
        }

        $token = [System.Net.NetworkCredential]::new('', $tokenObj.Token).Password
      } catch {
        $errMsg = $_.Exception.Message
        throw "Managed Identity authentication failed: $errMsg. Ensure managed identity is enabled on the Automation Account and has the required Graph API permissions."
      }
    }
    "AppRegCert" {
      # Builds the JWT client assertion manually using only built-in .NET crypto
      # (System.Security.Cryptography), avoiding a dependency on the
      # System.IdentityModel.Tokens.Jwt assembly, which is not loaded by default in
      # Windows PowerShell 5.1 and whose newer NuGet versions no longer expose
      # X509SigningCredentials.
      $cert = Get-Item "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction Stop
      if (-not $cert.HasPrivateKey) {
        throw "Certificate $CertThumbprint was found but has no private key, or is not present in Cert:\CurrentUser\My."
      }

      function script:ConvertTo-Base64UrlInternal([byte[]]$Bytes) {
        [Convert]::ToBase64String($Bytes) -replace '\+','-' -replace '/','_' -replace '='
      }

      $nowUtc = [DateTimeOffset]::UtcNow
      $expUtc = $nowUtc.AddMinutes(10)
      $x5t    = ConvertTo-Base64UrlInternal $cert.GetCertHash()

      $jwtHeader = @{ alg = "RS256"; typ = "JWT"; x5t = $x5t } | ConvertTo-Json -Compress
      $jwtPayload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $nowUtc.ToUnixTimeSeconds()
        exp = $expUtc.ToUnixTimeSeconds()
      } | ConvertTo-Json -Compress

      $headerEncoded  = ConvertTo-Base64UrlInternal ([System.Text.Encoding]::UTF8.GetBytes($jwtHeader))
      $payloadEncoded = ConvertTo-Base64UrlInternal ([System.Text.Encoding]::UTF8.GetBytes($jwtPayload))
      $unsignedToken  = "$headerEncoded.$payloadEncoded"

      $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
      if (-not $rsa) {
        throw "Could not obtain an RSA private key from certificate $CertThumbprint."
      }
      $signatureBytes = $rsa.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($unsignedToken),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
      )
      $assertion = "$unsignedToken.$(ConvertTo-Base64UrlInternal $signatureBytes)"

      $body = @{
        client_id             = $ClientId
        scope                 = $resourceScope
        client_assertion      = $assertion
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        grant_type            = "client_credentials"
      }
      $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded").access_token
    }
    "AppRegSecret" {
      if ($KeyVaultName -and $KeyVaultSecretName) {
        $ClientSecret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName -AsPlainText)
      }
      $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $resourceScope
        grant_type    = "client_credentials"
      }
      $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType "application/x-www-form-urlencoded").access_token
    }
    default { throw "Unsupported AuthMode $AuthMode" }
  }
  return $token
}

function Invoke-WithRetry {
  param([scriptblock]$Script,[int]$RetryCount,[int]$DelaySeconds)
  for ($i=0; $i -le $RetryCount; $i++) {
    try { return & $Script }
    catch {
      if ($i -eq $RetryCount) { throw }
      Start-Sleep -Seconds $DelaySeconds
    }
  }
}

function Invoke-GraphGet {
  # Windows PowerShell 5.1's Invoke-RestMethod/Invoke-WebRequest can mis-decode UTF-8 JSON
  # responses as ISO-8859-1 (mangling German umlauts/ß, e.g. "Außendienst" -> "AuÃŸendienst"),
  # and working around this via Invoke-WebRequest's Content/RawContentStream properties proved
  # inconsistent in practice. This instead uses a raw System.Net.HttpWebRequest and explicitly
  # decodes the response stream as UTF-8 via StreamReader, sidestepping PowerShell's own
  # encoding heuristics entirely. Only used under Windows PowerShell (Desktop edition) -
  # PowerShell 7 (Core) does not have this bug.
  param([string]$Uri,[hashtable]$Headers)
  if ($PSVersionTable.PSEdition -ne "Desktop") {
    return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
  }

  $request = [System.Net.HttpWebRequest]::Create($Uri)
  $request.Method = "GET"
  $request.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
  foreach ($key in $Headers.Keys) {
    switch ($key) {
      "Authorization" { $request.Headers.Add("Authorization", $Headers[$key]) }
      "Content-Type"  { $request.ContentType = $Headers[$key] }
      default         { $request.Headers.Add($key, $Headers[$key]) }
    }
  }

  try {
    $response = $request.GetResponse()
  } catch [System.Net.WebException] {
    if ($_.Exception.Response) {
      $errStream = $_.Exception.Response.GetResponseStream()
      $errReader = New-Object System.IO.StreamReader($errStream, [System.Text.Encoding]::UTF8)
      $errBody = $errReader.ReadToEnd()
      $errReader.Close()
      throw "Graph GET $Uri failed: $errBody"
    }
    throw
  }

  $stream = $response.GetResponseStream()
  $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
  $json = $reader.ReadToEnd()
  $reader.Close()
  $response.Close()
  if (-not $json) { return $null }
  return $json | ConvertFrom-Json
}

function Write-Log {
  param([string]$Message,[string]$Level="INFO")
  if (-not $VerboseLogging) { return }
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts][$Level] $Message"
}

function Write-ResultLog {
  param([psobject]$Row)
  if (-not $VerboseLogging) { return }
  $effective = $null
  if ($Row.PSObject.Properties.Name -contains "EffectiveDate") { $effective = $Row.EffectiveDate }
  $warnEffective = $null
  if ($Row.PSObject.Properties.Name -contains "WarningEffectiveDate") { $warnEffective = $Row.WarningEffectiveDate }
  $reqEffective = $null
  if ($Row.PSObject.Properties.Name -contains "RequiredEffectiveDate") { $reqEffective = $Row.RequiredEffectiveDate }
  $release = $null
  if ($Row.PSObject.Properties.Name -contains "ReleaseDate") { $release = $Row.ReleaseDate }
  $errorMsg = $null
  if ($Row.PSObject.Properties.Name -contains "Error") { $errorMsg = $Row.Error }
  $effText = if ($effective) { "; effective=$effective" } else { "" }
  $effText += if ($warnEffective) { "; warnEffective=$warnEffective" } else { "" }
  $effText += if ($reqEffective) { "; requiredEffective=$reqEffective" } else { "" }
  $relText = if ($release) { "; release=$release" } else { "" }
  $errorText = if ($errorMsg) { "; error=$errorMsg" } else { "" }
  $currentWarning = $null
  if ($Row.PSObject.Properties.Name -contains "CurrentWarning") { $currentWarning = $Row.CurrentWarning }
  $warningText = if ($currentWarning) { "; currentWarning=$currentWarning" } else { "" }
  Write-Host "[RESULT][$($Row.Platform)/$($Row.Type)] $($Row.Name): action=$($Row.Action); currentRequired=$($Row.CurrentRequired)$warningText; target=$($Row.Target)$relText$effText$errorText"
}

function Get-CompliancePolicyInfo {
  param([string]$Token,[string]$PolicyId)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  $currentOs = $null
  if ($policy.PSObject.Properties.Name -contains "osMinimumVersion") {
    $currentOs = $policy.osMinimumVersion
  }
  return [pscustomobject]@{Name=$policy.displayName;CurrentRequired=$currentOs}
}

function Get-AppProtectionPolicyInfo {
  param([string]$Token,[string]$PolicyId,[string]$Platform)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  $current = $policy.minimumRequiredOsVersion
  if (-not $current -and ($policy.PSObject.Properties.Name -contains "minimumRequiredOSVersion")) {
    $current = $policy.minimumRequiredOSVersion
  }
  if (-not $current -and ($policy.PSObject.Properties.Name -contains "minimumRequiredOperatingSystem")) {
    $current = $policy.minimumRequiredOperatingSystem
  }

  # Warning-level minimum OS version (Conditional launch action = "Warn"), independent from the
  # Required/Block field above. A policy can have either, both, or neither configured.
  $currentWarning = $policy.minimumWarningOsVersion
  if (-not $currentWarning -and ($policy.PSObject.Properties.Name -contains "minimumWarningOSVersion")) {
    $currentWarning = $policy.minimumWarningOSVersion
  }

  return [pscustomobject]@{Name=$policy.displayName;CurrentRequired=$current;CurrentWarning=$currentWarning}
}

function Get-LatestOsVersion {
  param([string]$ProductSlug,[int]$CadenceDays)
  $url = "https://endoflife.date/api/v1/products/$ProductSlug/releases/latest"
  $res = Invoke-RestMethod -Uri $url -Method Get
  $release = $res.result
  $targetVersion = if ($release.latest.name) { $release.latest.name } else { $release.name }
  # Use the date of the latest patch/hotfix release to drive cadence; fall back to major release date if missing.
  $dateSource = $release.latest.date
  if (-not $dateSource) { $dateSource = $release.releaseDate }
  $releaseDate = [datetime]::Parse($dateSource)
  $effectiveDate = $releaseDate.AddDays($CadenceDays)
  return [pscustomobject]@{
    Version       = $targetVersion
    ReleaseDate   = $releaseDate
    EffectiveDate = $effectiveDate
  }
}

function Update-CompliancePolicy {
  param([string]$Token,[string]$PolicyId,[string]$TargetVersion,[bool]$DryRun,[bool]$AllowDowngrade,[string]$Platform,[datetime]$ReleaseDate)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  $name = $policy.displayName
  $current = $policy.osMinimumVersion
  $osUpToDate = $current -and ([version]$current -ge [version]$TargetVersion)
  if (-not $AllowDowngrade -and $osUpToDate) {
    return [pscustomobject]@{Platform=$Platform;Type="Compliance";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Skipped"}
  }
  if ($DryRun) {
    return [pscustomobject]@{Platform=$Platform;Type="Compliance";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="WouldUpdate"}
  }
  try {
    $body = @{
      "@odata.type"      = $policy.'@odata.type'
      "osMinimumVersion" = "$TargetVersion"
    }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return [pscustomobject]@{Platform=$Platform;Type="Compliance";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Updated"}
  }
  catch {
    $errMsg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = $_.ErrorDetails.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = $_.Exception.Response.Content }
    return [pscustomobject]@{Platform=$Platform;Type="Compliance";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;Target=$TargetVersion;ReleaseDate=$ReleaseDate;Action="Error";Error=$errMsg}
  }
}

function Update-AppProtectionPolicy {
  # Evaluates the "Warn" (minimumWarningOsVersion) and "Zugriff blockieren"
  # (minimumRequiredOsVersion) fields independently, each against its own cadence deadline.
  # A policy can end up with only one of the two fields updated in a given run (e.g. Warn
  # becomes due after 14 days, Required/Block only after 30 days) - this is expected, not an
  # error. Only fields already configured on the policy are ever touched (see comment below).
  param(
    [string]$Token,[string]$PolicyId,[string]$TargetVersion,[bool]$DryRun,[bool]$AllowDowngrade,
    [string]$Platform,[datetime]$ReleaseDate,[datetime]$WarningEffectiveDate,[datetime]$RequiredEffectiveDate,
    [bool]$ForceApply,[datetime]$Now
  )
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  $name = $policy.displayName
  $current = $policy.minimumRequiredOsVersion
  $currentWarning = $policy.minimumWarningOsVersion

  # Only touch whichever field(s) are already configured on the policy. This avoids silently
  # turning on "Block" (minimumRequiredOsVersion) on a policy that was only ever configured with
  # "Warn" (minimumWarningOsVersion), or vice versa - the admin's chosen conditional-launch action
  # is preserved, only the version number is kept current.
  $hasRequired = [bool]$current
  $hasWarning  = [bool]$currentWarning

  $baseRow = @{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;CurrentWarning=$currentWarning;Target=$TargetVersion;ReleaseDate=$ReleaseDate;WarningEffectiveDate=$WarningEffectiveDate;RequiredEffectiveDate=$RequiredEffectiveDate}

  if (-not $hasRequired -and -not $hasWarning) {
    return [pscustomobject]($baseRow + @{Action="NoData"})
  }

  $requiredUpToDate = -not $hasRequired -or ([version]$current -ge [version]$TargetVersion)
  $warningUpToDate  = -not $hasWarning -or ([version]$currentWarning -ge [version]$TargetVersion)

  $requiredEligible = $ForceApply -or ($Now -ge $RequiredEffectiveDate)
  $warningEligible  = $ForceApply -or ($Now -ge $WarningEffectiveDate)

  $willUpdateRequired = $hasRequired -and $requiredEligible -and ($AllowDowngrade -or -not $requiredUpToDate)
  $willUpdateWarning  = $hasWarning  -and $warningEligible  -and ($AllowDowngrade -or -not $warningUpToDate)

  if (-not $willUpdateRequired -and -not $willUpdateWarning) {
    $pendingCadence = ($hasRequired -and -not $requiredEligible -and -not $requiredUpToDate) -or ($hasWarning -and -not $warningEligible -and -not $warningUpToDate)
    $action = if ($pendingCadence) { "NotEffectiveYet" } else { "Skipped" }
    return [pscustomobject]($baseRow + @{Action=$action})
  }

  $partial = $willUpdateRequired -ne $willUpdateWarning  # exactly one of the two fields is due, the other isn't yet
  $partialNote = if ($partial) {
    if ($willUpdateWarning) { " (nur Warn - Block noch nicht faellig)" } else { " (nur Block - Warn bereits aktuell/nicht konfiguriert)" }
  } else { "" }

  if ($DryRun) {
    return [pscustomobject]($baseRow + @{Action="WouldUpdate$partialNote"})
  }

  try {
    $body = @{}
    if ($willUpdateRequired) { $body["minimumRequiredOsVersion"] = $TargetVersion }
    if ($willUpdateWarning)  { $body["minimumWarningOsVersion"]  = $TargetVersion }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return [pscustomobject]($baseRow + @{Action="Updated$partialNote"})
  }
  catch {
    $errMsg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $errMsg = $_.ErrorDetails.Message }
    elseif ($_.Exception.Response -and $_.Exception.Response.Content) { $errMsg = $_.Exception.Response.Content }
    return [pscustomobject]($baseRow + @{Action="Error";Error=$errMsg})
  }
}

# --------------------------- Device-Level Compliance Check Helpers ---------------------------
function Convert-ToComparableVersion {
  # Normalizes OS version strings so they can be cast to [version] for comparison.
  # Handles things [version] can't: iOS RapidSecurityResponse suffixes (e.g. "26.5.2.a"),
  # or any non-numeric trailing characters, by stripping everything except digits and dots
  # and keeping at most 4 numeric segments (Major.Minor.Build.Revision).
  param([string]$VersionString)
  if (-not $VersionString) { return $null }
  $clean = ($VersionString -replace '[^\d\.]', '')
  $parts = @($clean.Split('.') | Where-Object { $_ -ne '' } | Select-Object -First 4)
  if ($parts.Count -eq 0) { return $null }
  if ($parts.Count -eq 1) { $parts += '0' }
  return ($parts -join '.')
}

function Get-PropertyValueLike {
  # Looks up a property on a report row case-insensitively by keyword, since the exact column
  # names returned by the Intune Reports export API aren't consistently documented character-for-
  # character. $Keywords is treated as a priority list: every property is checked against the
  # FIRST keyword before falling back to the second, etc. - so a caller can pass e.g.
  # @("Email","User") and reliably get the Email column even if a "User" (display name) column
  # happens to appear earlier in the object.
  param([psobject]$Object,[string[]]$Keywords)
  if (-not $Object) { return $null }
  foreach ($kw in $Keywords) {
    foreach ($prop in $Object.PSObject.Properties) {
      if ($prop.Name -like "*$kw*") { return $prop.Value }
    }
  }
  return $null
}

function Invoke-IntuneReportExport {
  # Runs the full Intune Reports export workflow: create the export job, poll until it
  # completes, download the resulting ZIP, extract it, and parse the JSON payload.
  #
  # This is the only reliable way to get device/user-level App Protection status - the simple
  # synchronous "/iosManagedAppProtections('{id}')/deviceStatuses" endpoint used in an earlier
  # version of this script is not consistently available across tenants.
  #
  # IMPORTANT CAVEAT: the "MAMAppProtectionStatus" report is user/app-centric, not tied to a
  # specific App Protection policy ID - Microsoft's own documentation lists "no filters" for
  # this report. That means this function returns ALL protected app instances tenant-wide; the
  # caller is responsible for filtering by platform, and results cannot be attributed to one
  # specific policy when multiple App Protection policies target the same platform.
  param([string]$Token,[string]$ReportName,[int]$PollIntervalSeconds = 5,[int]$MaxPollAttempts = 24)
  $headers = @{Authorization = "Bearer $Token"; "Content-Type" = "application/json"}
  $createUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
  $createBody = @{ reportName = $ReportName; format = "json" } | ConvertTo-Json

  $job = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
    Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -Body $createBody
  }

  $jobId = $job.id
  $statusUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$jobId')"
  $attempts = 0
  while ($job.status -ne "completed" -and $attempts -lt $MaxPollAttempts) {
    Start-Sleep -Seconds $PollIntervalSeconds
    $job = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-GraphGet -Uri $statusUri -Headers @{Authorization = "Bearer $Token"}
    }
    $attempts++
  }
  if ($job.status -ne "completed" -or -not $job.url) {
    throw "Report export '$ReportName' did not complete in time (last status: $($job.status))"
  }

  $tempZip = [System.IO.Path]::GetTempFileName() + ".zip"
  Invoke-WebRequest -Uri $job.url -OutFile $tempZip -UseBasicParsing

  $tempExtractDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
  New-Item -Path $tempExtractDir -ItemType Directory -Force | Out-Null
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $tempExtractDir)

  # If the archive contains more than one JSON file (e.g. a small metadata file alongside the
  # actual data payload), the largest one is almost certainly the real per-row data.
  $jsonFiles = @(Get-ChildItem -Path $tempExtractDir -Filter "*.json" -Recurse | Sort-Object Length -Descending)
  if ($jsonFiles.Count -gt 1) {
    Write-Log "Export archive for '$ReportName' contains $($jsonFiles.Count) JSON files: $(($jsonFiles | ForEach-Object { "$($_.Name) ($($_.Length) bytes)" }) -join '; ') - using the largest." "INFO"
  }
  $jsonFile = $jsonFiles | Select-Object -First 1
  if (-not $jsonFile) {
    throw "No JSON file found in the exported '$ReportName' report archive."
  }
  $content = Get-Content -Path $jsonFile.FullName -Raw -Encoding UTF8
  $data = $content | ConvertFrom-Json

  Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue

  # Intune report exports commonly return a tabular "columns"/"values" structure rather than an
  # array of named objects - transform it into pscustomobjects so downstream code (which looks
  # up fields by property name) works regardless of which shape a given report returns.
  Write-Log "Report '$ReportName' payload top-level properties: $(($data.PSObject.Properties.Name) -join ', ')" "INFO"
  if ($data.PSObject.Properties.Name -contains "columns" -and $data.PSObject.Properties.Name -contains "values") {
    $columnNames = @($data.columns | ForEach-Object {
      if ($_.PSObject.Properties.Name -contains "name") { $_.name } else { $_ }
    })
    Write-Log "Report '$ReportName' columns ($($columnNames.Count)): $($columnNames -join ', ')" "INFO"
    if ($data.values.Count -gt 0) {
      $firstRow = $data.values[0]
      $firstRowType = if ($null -ne $firstRow) { $firstRow.GetType().FullName } else { "(null)" }
      Write-Log "Report '$ReportName' first values row type: $firstRowType" "INFO"

      # Some reports return "values" as already-keyed objects (e.g. {"User": "...", ...}) despite
      # also providing a "columns" array; others genuinely return raw arrays that need zipping
      # with "columns" by position. Detect which shape this is and handle both.
      if ($firstRow -is [System.Management.Automation.PSCustomObject]) {
        return @($data.values)
      }
    }
    $rows = @()
    foreach ($valueRow in @($data.values)) {
      $obj = [ordered]@{}
      for ($i = 0; $i -lt $columnNames.Count -and $i -lt $valueRow.Count; $i++) {
        $obj[$columnNames[$i]] = $valueRow[$i]
      }
      $rows += [pscustomobject]$obj
    }
    return $rows
  }

  return $data
}

$script:MamReportCache = $null
$script:MamReportError = $null

function Get-AppProtectionDeviceRows {
  # Returns device/user rows for a given platform from the (tenant-wide, non-policy-specific)
  # MAMAppProtectionStatus report, compared against $RequiredVersion. The report is fetched
  # once and cached for the rest of the script run, since it isn't policy-specific anyway.
  param([string]$Token,[string]$Platform,[string]$RequiredVersion,[string]$PolicyName,[string]$RuleType,[string]$PolicyId)

  if (-not $RequiredVersion) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="AppProtection";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(n/a)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion="(none)";Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  if (-not $script:MamReportCache -and -not $script:MamReportError) {
    try {
      $script:MamReportCache = @(Invoke-IntuneReportExport -Token $Token -ReportName "MAMAppProtectionStatus")
      Write-Log "MAMAppProtectionStatus report returned $($script:MamReportCache.Count) total row(s)" "INFO"
      if ($script:MamReportCache.Count -gt 0) {
        $sampleProps = ($script:MamReportCache[0].PSObject.Properties.Name) -join ", "
        Write-Log "MAMAppProtectionStatus row properties: $sampleProps" "INFO"
      }
    } catch {
      $script:MamReportError = $_.Exception.Message
    }
  }

  if ($script:MamReportError) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="AppProtection";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(unavailable)";UserPrincipalName="(unavailable)";InstalledVersion="(unavailable)";RequiredVersion=$RequiredVersion;Compliant="Error: MAMAppProtectionStatus report failed - $script:MamReportError";LastSync=$null;DeviceModel=$null})
  }

  $platformRows = @($script:MamReportCache | Where-Object {
    $p = Get-PropertyValueLike -Object $_ -Keywords @("Platform")
    $p -and ($p -like "*$Platform*")
  })

  if ($platformRows.Count -eq 0) {
    $distinctPlatforms = @($script:MamReportCache | ForEach-Object { Get-PropertyValueLike -Object $_ -Keywords @("Platform") } | Where-Object { $_ } | Select-Object -Unique)
    if ($distinctPlatforms.Count -gt 0) {
      Write-Log "No rows matched platform '$Platform'. Platform values found in report: $($distinctPlatforms -join ', ')" "INFO"
    } else {
      Write-Log "No rows matched platform '$Platform', and no 'Platform'-like property was found on any row at all - the report schema may differ from what this script expects. Check the logged row properties above." "INFO"
    }
    return @([pscustomobject]@{Platform=$Platform;PolicyType="AppProtection";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(none reported)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion=$RequiredVersion;Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  # The report includes a "Policy" column with the policy's display name, so rows can be
  # attributed to this specific policy rather than showing every platform row for every policy.
  $policyRows = @($platformRows | Where-Object {
    $p = Get-PropertyValueLike -Object $_ -Keywords @("Policy")
    $p -and ($p.Trim() -ieq $PolicyName.Trim())
  })

  if ($policyRows.Count -eq 0) {
    $distinctPolicies = @($platformRows | ForEach-Object { Get-PropertyValueLike -Object $_ -Keywords @("Policy") } | Where-Object { $_ } | Select-Object -Unique)
    Write-Log "No rows matched policy '$PolicyName' on platform '$Platform'. Policy values found for this platform: $($distinctPolicies -join ', ')" "INFO"
    return @([pscustomobject]@{Platform=$Platform;PolicyType="AppProtection";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(none reported)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion=$RequiredVersion;Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  $rows = @()
  foreach ($r in $policyRows) {
    $deviceName = Get-PropertyValueLike -Object $r -Keywords @("DeviceName","Device Name")
    $upn = Get-PropertyValueLike -Object $r -Keywords @("UserPrincipalName","UserEmail","Email","UserName","User")
    $installedVersion = Get-PropertyValueLike -Object $r -Keywords @("PlatformVersion","OSVersion","Platform Version")
    $lastSync = Get-PropertyValueLike -Object $r -Keywords @("LastSync","Last Sync")
    $deviceModel = Get-PropertyValueLike -Object $r -Keywords @("DeviceModel","Device Model")

    $compliant = "Unknown"
    if ($installedVersion) {
      $installedComparable = Convert-ToComparableVersion $installedVersion
      $requiredComparable  = Convert-ToComparableVersion $RequiredVersion
      if ($installedComparable -and $requiredComparable) {
        try {
          $compliant = if ([version]$installedComparable -ge [version]$requiredComparable) { "Yes" } else { "No" }
        } catch {
          $compliant = "Unknown (version format)"
        }
      }
    }

    $rows += [pscustomobject]@{
      Platform          = $Platform
      PolicyType        = "AppProtection"
      RuleType          = $RuleType
      PolicyId          = $PolicyId
      PolicyName        = $PolicyName
      DeviceName        = $deviceName
      UserPrincipalName = $upn
      InstalledVersion  = $installedVersion
      RequiredVersion   = $RequiredVersion
      Compliant         = $compliant
      LastSync          = $lastSync
      DeviceModel       = $deviceModel
    }
  }
  return $rows
}

function Get-DeviceComplianceStatusList {
  # Returns one row per device the Compliance policy is evaluated against, comparing the
  # device's installed OS version to $RequiredVersion. Read-only - makes no changes to Intune.
  #
  # NOTE: uses the documented Graph endpoint
  # /deviceManagement/deviceCompliancePolicies/{id}/deviceStatuses, and correlates each entry to
  # /deviceManagement/managedDevices/{id} (same id) to get the installed osVersion - this ID
  # correlation is a widely used community pattern but is not explicitly documented by Microsoft;
  # verify against Graph Explorer for your tenant if the results look wrong.
  #
  # App Protection policies use Get-AppProtectionDeviceRows instead (see below), since there is
  # no equivalent reliable synchronous per-policy device-status endpoint for those.
  param([string]$Token,[string]$PolicyId,[string]$PolicyName,[string]$RuleType,[string]$Platform,[string]$RequiredVersion)
  $headers = @{Authorization = "Bearer $Token"}
  $rows = @()

  if (-not $RequiredVersion) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(n/a)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion="(none)";Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  try {
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId/deviceStatuses"
    $statusResponse = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  } catch {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(unavailable)";UserPrincipalName="(unavailable)";InstalledVersion="(unavailable)";RequiredVersion=$RequiredVersion;Compliant="Error: device-level status not available for this policy via Graph in this tenant";LastSync=$null;DeviceModel=$null})
  }

  $statusList = @($statusResponse.value)
  if ($statusList.Count -eq 0) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(none assigned/reporting)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion=$RequiredVersion;Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  foreach ($status in $statusList) {
    $deviceName = $status.deviceDisplayName
    $upn = if ($status.userPrincipalName) { $status.userPrincipalName } elseif ($status.userName) { $status.userName } else { $null }
    $installedVersion = $null
    $lastSync = $status.lastReportedDateTime
    $deviceModel = $null

    if ($status.id) {
      try {
        $device = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
          Invoke-GraphGet -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($status.id)" -Headers $headers
        }
        $installedVersion = $device.osVersion
        $deviceModel = $device.model
        if (-not $lastSync -and $device.lastSyncDateTime) { $lastSync = $device.lastSyncDateTime }
      } catch {
        $installedVersion = $null
      }
    }

    $compliant = "Unknown"
    if ($installedVersion) {
      $installedComparable = Convert-ToComparableVersion $installedVersion
      $requiredComparable  = Convert-ToComparableVersion $RequiredVersion
      if ($installedComparable -and $requiredComparable) {
        try {
          $compliant = if ([version]$installedComparable -ge [version]$requiredComparable) { "Yes" } else { "No" }
        } catch {
          $compliant = "Unknown (version format)"
        }
      }
    }

    $rows += [pscustomobject]@{
      Platform          = $Platform
      PolicyType        = "Compliance"
      RuleType          = $RuleType
      PolicyId          = $PolicyId
      PolicyName        = $PolicyName
      DeviceName        = $deviceName
      UserPrincipalName = $upn
      InstalledVersion  = $installedVersion
      RequiredVersion   = $RequiredVersion
      Compliant         = $compliant
      LastSync          = $lastSync
      DeviceModel       = $deviceModel
    }
  }
  return $rows
}

# --------------------------- Email Notification Helpers ---------------------------
function Get-UserMailAddress {
  # Looks up the user's actual primary SMTP address (the "mail" attribute), since
  # userPrincipalName is not guaranteed to match the real email address (e.g. with an
  # on-prem UPN suffix like "@company.local"). Falls back to the UPN if the lookup fails.
  param([string]$Token,[string]$UserPrincipalName)
  if (-not $UserPrincipalName) { return $null }
  $headers = @{Authorization = "Bearer $Token"}
  try {
    $uri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($UserPrincipalName))?`$select=mail,displayName,userPrincipalName"
    $user = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
    $mail = if ($user.mail) { $user.mail } else { $user.userPrincipalName }
    return [pscustomobject]@{ Mail = $mail; DisplayName = $user.displayName }
  } catch {
    return [pscustomobject]@{ Mail = $UserPrincipalName; DisplayName = $UserPrincipalName }
  }
}

function Send-DeviceComplianceNotification {
  # Sends ONE individual email to the device owner. While $DryRun is $true, no email is sent -
  # the intended recipient/subject is logged instead.
  param(
    [string]$Token,[string]$FromAddress,[string]$ToAddress,[string]$DisplayName,
    [string]$DeviceName,[string]$InstalledVersion,[string]$RequiredVersion,
    [string]$PolicyName,[string]$RuleType,[int]$CadenceDays,[int]$CadenceDaysWarning,[bool]$DryRun
  )

  # Use the cadence value that actually applies to this rule type, not a single generic one -
  # Warn and Block/Compliance can have different deadlines since the cadence split was added.
  $relevantCadenceDays = switch ($RuleType) {
    "AppProtection-Warn" { $CadenceDaysWarning }
    default              { $CadenceDays }
  }

  $subject = "Bitte aktualisieren Sie Ihr iOS/iPadOS-Gerät ($DeviceName)"
  $actionText = switch ($RuleType) {
    "AppProtection-Block" { "der Zugriff auf Unternehmens-Apps auf diesem Gerät blockiert wird" }
    "AppProtection-Warn"  { "Sie beim Zugriff auf Unternehmens-Apps eine Warnung erhalten" }
    default               { "das Gerät als nicht konform (non-compliant) eingestuft wird" }
  }

  $body = @"
Hallo $DisplayName,

Ihr Gerät "$DeviceName" hat aktuell die Version $InstalledVersion installiert.
Die Richtlinie "$PolicyName" verlangt mindestens Version $RequiredVersion.

Bitte aktualisieren Sie Ihr Gerät zeitnah, möglichst innerhalb der nächsten $relevantCadenceDays Tage.
Andernfalls kann es sein, dass $actionText.

Mit freundlichen Grüßen
IT-Support
"@

  if ($DryRun) {
    Write-Log "[WouldSend] To: $ToAddress; Subject: $subject" "INFO"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="WouldSend"}
  }

  $headers = @{Authorization = "Bearer $Token"; "Content-Type" = "application/json"}
  $mailPayload = @{
    message = @{
      subject      = $subject
      body         = @{ contentType = "Text"; content = $body }
      toRecipients = @(@{ emailAddress = @{ address = $ToAddress } })
    }
    saveToSentItems = $true
  } | ConvertTo-Json -Depth 6

  try {
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/users/$FromAddress/sendMail" -Headers $headers -Body $mailPayload
    }
    Write-Log "Sent notification to $ToAddress for device $DeviceName" "INFO"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="Sent"}
  } catch {
    $errMsg = $_.Exception.Message
    Write-Log "Failed to send notification to $ToAddress for device $DeviceName - $errMsg" "ERROR"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="Error";Error=$errMsg}
  }
}

function Export-DeviceComplianceHtmlReport {
  # Builds a single self-contained HTML file (no external CSS/JS dependencies, works fully
  # offline) with a sortable, per-column-filterable table. Click a header to sort by that
  # column; type in the filter row to narrow rows by substring match (case-insensitive).
  param([array]$Rows,[string]$Path)

  Add-Type -AssemblyName System.Web

  $columns = @("Platform","PolicyType","RuleType","PolicyName","DeviceName","DeviceModel","UserPrincipalName","InstalledVersion","RequiredVersion","Compliant","LastSync")

  $headerCells = ($columns | ForEach-Object { "<th onclick=`"sortTable($($columns.IndexOf($_)))`">$_ &#x25B4;&#x25BE;</th>" }) -join "`n"
  $filterCells = ($columns | ForEach-Object { "<th><input type=`"text`" oninput=`"filterTable()`" data-col=`"$($columns.IndexOf($_))`" placeholder=`"Filter...`"></th>" }) -join "`n"

  $bodyRows = foreach ($row in $Rows) {
    $cells = foreach ($col in $columns) {
      $val = $row.$col
      $escaped = [System.Web.HttpUtility]::HtmlEncode("$val")
      "<td>$escaped</td>"
    }
    "<tr>$($cells -join '')</tr>"
  }

  $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>Intune Device Compliance Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
  h1 { font-size: 18px; color: #222; }
  .meta { color: #666; margin-bottom: 12px; font-size: 13px; }
  table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; text-align: left; white-space: nowrap; }
  th { background: #2b579a; color: #fff; cursor: pointer; position: sticky; top: 0; user-select: none; }
  th:hover { background: #1e3f73; }
  tr:nth-child(even) td { background: #fafafa; }
  input[type=text] { width: 90%; box-sizing: border-box; font-size: 12px; padding: 2px 4px; }
  .compliant-no { background: #ffe0e0 !important; }
  .compliant-yes { background: #e4f7e4 !important; }
</style>
</head>
<body>
<h1>Intune Device Compliance Report</h1>
<div class="meta">Erstellt: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss") | Zeilen: $($Rows.Count)</div>
<table id="reportTable">
<thead>
<tr>
$headerCells
</tr>
<tr>
$filterCells
</tr>
</thead>
<tbody>
$($bodyRows -join "`n")
</tbody>
</table>
<script>
function filterTable() {
  var table = document.getElementById("reportTable");
  var inputs = table.querySelectorAll('thead tr:nth-child(2) input');
  var filters = [];
  inputs.forEach(function(inp) { filters.push(inp.value.toLowerCase()); });
  var rows = table.tBodies[0].rows;
  for (var i = 0; i < rows.length; i++) {
    var visible = true;
    var cells = rows[i].cells;
    for (var c = 0; c < filters.length; c++) {
      if (filters[c] && cells[c] && cells[c].innerText.toLowerCase().indexOf(filters[c]) === -1) {
        visible = false;
        break;
      }
    }
    rows[i].style.display = visible ? "" : "none";
  }
}
var sortState = {};
function sortTable(colIndex) {
  var table = document.getElementById("reportTable");
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var asc = !sortState[colIndex];
  sortState = {};
  sortState[colIndex] = asc;
  rows.sort(function(a, b) {
    var av = a.cells[colIndex].innerText;
    var bv = b.cells[colIndex].innerText;
    var an = parseFloat(av), bn = parseFloat(bv);
    var cmp;
    if (!isNaN(an) && !isNaN(bn) && av.trim() !== "" && bv.trim() !== "") {
      cmp = an - bn;
    } else {
      cmp = av.localeCompare(bv);
    }
    return asc ? cmp : -cmp;
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}
// Highlight non-compliant rows
(function() {
  var table = document.getElementById("reportTable");
  var complIndex = $($columns.IndexOf("Compliant"));
  var rows = table.tBodies[0].rows;
  for (var i = 0; i < rows.length; i++) {
    var val = rows[i].cells[complIndex].innerText;
    if (val === "No") { rows[i].classList.add("compliant-no"); }
    else if (val === "Yes") { rows[i].classList.add("compliant-yes"); }
  }
})();
</script>
</body>
</html>
"@

  Set-Content -Path $Path -Value $html -Encoding UTF8
}

# --------------------------- Main ---------------------------
Write-Output "========================================="
Write-Output "IntuneComplianceMaintainer Starting"
Write-Output "========================================="
Write-Output "AuthMode: $AuthMode"
Write-Output "DryRun: $DryRun"
Write-Output "CadenceDays: $CadenceDays (Required/Block + Compliance) | CadenceDaysWarning: $CadenceDaysWarning (App Protection Warn)"
Write-Output "RunPolicyMaintenance: $RunPolicyMaintenance | CheckDeviceCompliance: $CheckDeviceCompliance | SendUserNotificationEmail: $SendUserNotificationEmail"
Write-Output "========================================="

Write-Output "[MAIN] Attempting to acquire Graph API token..."
try {
  $token = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -AuthMode $AuthMode -CertThumbprint $CertThumbprint -ClientSecret $ClientSecret
  if (-not $token) { throw "Token acquisition returned empty." }
  Write-Output "[MAIN] Token acquired successfully"
} catch {
  Write-Output "[MAIN][CRITICAL ERROR] Failed to acquire token!"
  Write-Output "[MAIN][ERROR] Exception: $($_.Exception.Message)"
  throw
}

$now = Get-Date

# =========================================================================================
# BLOCK 1: Policy Maintenance
# =========================================================================================
$results = @()

if ($RunPolicyMaintenance) {
  Write-Log "Starting Block 1 (Policy Maintenance): DryRun=$DryRun; AllowDowngrade=$AllowDowngrade; ForceApply=$ForceApply; CadenceDays=$CadenceDays; CadenceDaysWarning=$CadenceDaysWarning" "INFO"

  foreach ($platform in $EolProducts.Keys) {
    $hasCompliance  = $CompliancePolicies[$platform] -and $CompliancePolicies[$platform].Count -gt 0
    $hasAppProtect  = ($platform -ne "macOS") -and $AppProtectionPolicies[$platform] -and $AppProtectionPolicies[$platform].Count -gt 0
    if (-not $hasCompliance -and -not $hasAppProtect) { continue }

    Write-Log "Platform ${platform}: compliance=$($CompliancePolicies[$platform].Count) appProtection=$(if ($platform -eq 'macOS') { 0 } else { $AppProtectionPolicies[$platform].Count })" "INFO"

    $latest = $null
    $notEffectiveCompliance = $false
    if ($hasCompliance) {
      $latest = Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays $CadenceDays
      $notEffectiveCompliance = $now -lt $latest.EffectiveDate
    }

    $appLatest = $null
    $warningEffectiveDate = $null
    $requiredEffectiveDate = $null
    if ($hasAppProtect) {
      # Reuse $latest instead of a second, redundant call to the same endoflife.date endpoint.
      $appLatest = if ($latest) { $latest } else { Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays $CadenceDays }
      $warningEffectiveDate  = $appLatest.ReleaseDate.AddDays($CadenceDaysWarning)
      $requiredEffectiveDate = $appLatest.ReleaseDate.AddDays($CadenceDays)
    }

    foreach ($policyId in $CompliancePolicies[$platform]) {
      if ($notEffectiveCompliance) {
        $info = Get-CompliancePolicyInfo -Token $token -PolicyId $policyId
        if (-not $ForceApply) {
          $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting="MinimumVersion";Name=$info.Name;CurrentRequired=$info.CurrentRequired;Target=$latest.Version;ReleaseDate=$latest.ReleaseDate;Action="NotEffectiveYet";EffectiveDate=$latest.EffectiveDate}
          continue
        }
      }
      $results += Update-CompliancePolicy -Token $token -PolicyId $policyId -TargetVersion $latest.Version -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $latest.ReleaseDate
    }

    if ($platform -eq "macOS") { continue } # No App Protection support for macOS

    foreach ($policyId in $AppProtectionPolicies[$platform]) {
      if (-not $appLatest -or -not $appLatest.ReleaseDate) {
        $results += [pscustomobject]@{Platform=$platform;Type="AppProtection";Setting="MinimumVersion";Name=$policyId;CurrentRequired="(unknown)";Target="(none)";ReleaseDate=$null;Action="NoData";EffectiveDate=$null}
        continue
      }
      # Update-AppProtectionPolicy evaluates the Warn and Required/Block fields against their
      # own cadence deadlines internally, so it's always called directly - no separate
      # "NotEffectiveYet" pre-check here (a policy might be due for Warn but not yet for Block).
      $results += Update-AppProtectionPolicy -Token $token -PolicyId $policyId -TargetVersion $appLatest.Version -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $appLatest.ReleaseDate -WarningEffectiveDate $warningEffectiveDate -RequiredEffectiveDate $requiredEffectiveDate -ForceApply $ForceApply -Now $now
    }
  }

  if ($VerboseLogging) {
    foreach ($row in $results) { Write-ResultLog -Row $row }
    Write-Host ""
  }

  Write-Output "[MAIN] Displaying Block 1 results table..."
  $results | Format-Table -Property Platform,Type,Setting,Name,CurrentRequired,CurrentWarning,Target,ReleaseDate,Action,EffectiveDate,WarningEffectiveDate,RequiredEffectiveDate,Error -AutoSize
} else {
  Write-Log "Block 1 (Policy Maintenance) skipped - RunPolicyMaintenance is false" "INFO"
}

# =========================================================================================
# BLOCK 2: Device Compliance Report
# =========================================================================================
$deviceResults = @()

if ($CheckDeviceCompliance) {
  Write-Output "[MAIN] Running Block 2 (Device Compliance Report)..."
  Write-Log "CompareAgainstLatestPublicVersion=$CompareAgainstLatestPublicVersion" "INFO"

  foreach ($platform in $EolProducts.Keys) {
    $compliancePolicyIds    = $CompliancePolicies[$platform]
    $appProtectionPolicyIds = if ($platform -eq "macOS") { @() } else { $AppProtectionPolicies[$platform] }
    if ((-not $compliancePolicyIds -or $compliancePolicyIds.Count -eq 0) -and (-not $appProtectionPolicyIds -or $appProtectionPolicyIds.Count -eq 0)) { continue }

    $publicLatestVersion = $null
    if ($CompareAgainstLatestPublicVersion) {
      try {
        $publicLatestVersion = (Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays 0).Version
      } catch {
        $publicLatestVersion = $null
      }
    }

    foreach ($policyId in $compliancePolicyIds) {
      try {
        $info = Get-CompliancePolicyInfo -Token $token -PolicyId $policyId
        $ruleVersion = $info.CurrentRequired
        if (-not $ruleVersion -and $CompareAgainstLatestPublicVersion) { $ruleVersion = $publicLatestVersion }
        $deviceResults += Get-DeviceComplianceStatusList -Token $token -PolicyId $policyId -PolicyName $info.Name -RuleType "Compliance" -Platform $platform -RequiredVersion $ruleVersion
      } catch {
        $deviceResults += [pscustomobject]@{Platform=$platform;PolicyType="Compliance";RuleType="Compliance";PolicyId=$policyId;PolicyName=$policyId;DeviceName="(error)";UserPrincipalName="(error)";InstalledVersion="(error)";RequiredVersion="(error)";Compliant="Error: $($_.Exception.Message)";LastSync=$null;DeviceModel=$null}
      }
    }

    foreach ($policyId in $appProtectionPolicyIds) {
      try {
        $info = Get-AppProtectionPolicyInfo -Token $token -PolicyId $policyId -Platform $platform
        # Prefer the Block ("Required") field if configured, else the Warn field.
        if ($info.CurrentRequired) {
          $ruleVersion = $info.CurrentRequired
          $ruleType = "AppProtection-Block"
        } elseif ($info.CurrentWarning) {
          $ruleVersion = $info.CurrentWarning
          $ruleType = "AppProtection-Warn"
        } else {
          $ruleVersion = $null
          $ruleType = "AppProtection"
        }
        if (-not $ruleVersion -and $CompareAgainstLatestPublicVersion) { $ruleVersion = $publicLatestVersion }
        $deviceResults += Get-AppProtectionDeviceRows -Token $token -Platform $platform -RequiredVersion $ruleVersion -PolicyName $info.Name -RuleType $ruleType -PolicyId $policyId
      } catch {
        $deviceResults += [pscustomobject]@{Platform=$platform;PolicyType="AppProtection";RuleType="AppProtection";PolicyId=$policyId;PolicyName=$policyId;DeviceName="(error)";UserPrincipalName="(error)";InstalledVersion="(error)";RequiredVersion="(error)";Compliant="Error: $($_.Exception.Message)";LastSync=$null;DeviceModel=$null}
      }
    }
  }

  if ($ShowDeviceComplianceList) {
    Write-Output "[MAIN] Displaying device-level compliance list..."
    if ($deviceResults.Count -gt 0) {
      $deviceResults | Format-Table -Property Platform,PolicyType,RuleType,PolicyName,DeviceName,UserPrincipalName,InstalledVersion,RequiredVersion,Compliant -AutoSize
    } else {
      Write-Output "[MAIN] No device-level data returned."
    }
  }

  # Save CSV + filterable/sortable HTML report to the local path, regardless of DryRun (this is
  # read-only reporting).
  try {
    if (-not (Test-Path -Path $DeviceComplianceReportPath)) {
      New-Item -Path $DeviceComplianceReportPath -ItemType Directory -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $csvFile  = Join-Path $DeviceComplianceReportPath "IntuneDeviceComplianceReport_$timestamp.csv"
    $htmlFile = Join-Path $DeviceComplianceReportPath "IntuneDeviceComplianceReport_$timestamp.html"
    $deviceResults | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Export-DeviceComplianceHtmlReport -Rows $deviceResults -Path $htmlFile
    Write-Output "[MAIN] Device compliance report saved to: $csvFile"
    Write-Output "[MAIN] Filterable HTML report saved to: $htmlFile"
  } catch {
    Write-Log "Failed to save device compliance report: $($_.Exception.Message)" "ERROR"
  }
} else {
  Write-Log "Block 2 (Device Compliance Report) skipped - CheckDeviceCompliance is false" "INFO"
}

# =========================================================================================
# BLOCK 3: User Notification Email
# =========================================================================================
if ($SendUserNotificationEmail) {
  if (-not $CheckDeviceCompliance) {
    Write-Log "Block 3 (User Notification Email) requires CheckDeviceCompliance to be true - no device data available, skipping." "ERROR"
  } else {
    Write-Output "[MAIN] Running Block 3 (User Notification Email)..."
    $nonCompliant = @($deviceResults | Where-Object { $_.Compliant -eq "No" -and $_.UserPrincipalName -and $_.UserPrincipalName -notlike "(*" })
    Write-Log "Found $($nonCompliant.Count) non-compliant device(s) with a resolvable user to notify" "INFO"

    $emailResults = @()
    foreach ($row in $nonCompliant) {
      $userInfo = Get-UserMailAddress -Token $token -UserPrincipalName $row.UserPrincipalName
      $emailResults += Send-DeviceComplianceNotification -Token $token -FromAddress $EmailSenderAddress -ToAddress $userInfo.Mail -DisplayName $userInfo.DisplayName `
        -DeviceName $row.DeviceName -InstalledVersion $row.InstalledVersion -RequiredVersion $row.RequiredVersion `
        -PolicyName $row.PolicyName -RuleType $row.RuleType -CadenceDays $CadenceDays -CadenceDaysWarning $CadenceDaysWarning -DryRun $DryRun
    }

    Write-Output "[MAIN] Displaying email notification results..."
    if ($emailResults.Count -gt 0) {
      $emailResults | Format-Table -Property To,Subject,Action,Error -AutoSize
    } else {
      Write-Output "[MAIN] No notifications were needed (no non-compliant devices with a resolvable user)."
    }
  }
} else {
  Write-Log "Block 3 (User Notification Email) skipped - SendUserNotificationEmail is false" "INFO"
}

Write-Output "[MAIN] Script completed successfully"
