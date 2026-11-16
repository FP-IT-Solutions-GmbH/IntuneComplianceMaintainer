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

# Persists which OS version is currently being tracked toward the Required/Block deadline, per
# platform, across script runs. Without this, every run only ever looks at "the single latest
# version right now" - if a newer version is released before an older one's own Required cadence
# had elapsed, the older version would simply be skipped entirely, and Warning could end up
# never firing for it. With this state file, when a newer version supersedes the one currently
# being tracked, the previously-tracked version is immediately promoted to the Warning target
# (rather than waiting on its own Warning cadence, which might never complete before being
# superseded again) - so Warning keeps advancing step by step even during frequent release
# periods, while Required keeps counting down from whichever version is currently newest.
# This file is written to regardless of $DryRun (it's just bookkeeping of what was observed,
# not a change to Intune) - only actual policy writes respect $DryRun.
$VersionStateFilePath = "C:\Skripte\IntuneComplianceMaintainer-VersionState.json"

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

# Safety limit: if more devices than this would be notified in one run, Block 3 sends nothing
# at all and logs an error instead. Protects against a mass mailing caused by a wrong target
# version or a misconfiguration. Raise it deliberately if your environment really needs more.
$MaxNotificationsPerRun = 50

# --------------------------- Script Variables ---------------------------
# Platform slugs (endoflife.date API product names)
$EolProducts = @{
  iOS     = "iOS"
  iPadOS  = "iPadOS"
  macOS   = "macOS"
}

# Expected Graph @odata.type of a Compliance policy per platform. Block 1 refuses to write
# into a policy of a different type (protects against a wrong policy ID in the config).
$CompliancePolicyTypes = @{
  iOS     = "#microsoft.graph.iosCompliancePolicy"
  iPadOS  = "#microsoft.graph.iosCompliancePolicy"
  macOS   = "#microsoft.graph.macOSCompliancePolicy"
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
      # Look in the running account's own store first, then in the machine store. The machine
      # store matters when the script runs as SYSTEM (e.g. as a scheduled task): SYSTEM has its
      # own, usually empty, CurrentUser store.
      $cert = $null
      foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        $candidate = Get-Item "$store\$CertThumbprint" -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.HasPrivateKey) { $cert = $candidate; break }
      }
      if (-not $cert) {
        throw "Certificate $CertThumbprint with private key not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My (or the running account cannot access its private key)."
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
        # Get-AzKeyVaultSecret needs an Az session. Reuse an existing one (e.g. Connect-AzAccount
        # done beforehand), otherwise sign in with the managed identity of the Automation
        # Account / VM.
        if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
          $connectParams = @{ Identity = $true; ErrorAction = 'Stop' }
          if ($UserAssignedClientId) { $connectParams["AccountId"] = $UserAssignedClientId }
          $null = Connect-AzAccount @connectParams
        }
        $ClientSecret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName -AsPlainText -ErrorAction Stop)
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

function Get-HttpErrorInfo {
  # Extracts the HTTP status code and a Retry-After delay (seconds) from an error record, for
  # Windows PowerShell 5.1 (WebException), PowerShell 7 (HttpResponseException) and the
  # exceptions thrown by Invoke-GraphGet (status code in Exception.Data). Values are $null when
  # unknown, e.g. for network errors without any HTTP response.
  param($ErrorRecord)
  $ex = $ErrorRecord.Exception
  $status = $null
  $retryAfter = $null
  if ($ex.Data -and $ex.Data.Contains("StatusCode")) { $status = [int]$ex.Data["StatusCode"] }
  if ($ex.Data -and $ex.Data.Contains("RetryAfter")) { $retryAfter = $ex.Data["RetryAfter"] }
  if (-not $status -and $ex.Response) {
    try { $status = [int]$ex.Response.StatusCode } catch { }
    try {
      if ($ex.Response.Headers.RetryAfter -and $ex.Response.Headers.RetryAfter.Delta) {
        $retryAfter = [int]$ex.Response.Headers.RetryAfter.Delta.TotalSeconds
      } elseif ($ex.Response.Headers -and $ex.Response.Headers["Retry-After"]) {
        $retryAfter = [int]$ex.Response.Headers["Retry-After"]
      }
    } catch { }
  }
  return [pscustomobject]@{ StatusCode = $status; RetryAfterSeconds = $retryAfter }
}

function Update-GraphTokenIfNeeded {
  # Graph tokens are valid for roughly 60-90 minutes. Long runs (large tenants, slow report
  # exports) would otherwise fail with 401 halfway through. Re-acquires the token after 45
  # minutes; returns the token to use.
  param([string]$CurrentToken)
  if ($script:TokenAcquiredAt -and ((Get-Date) - $script:TokenAcquiredAt).TotalMinutes -lt 45) { return $CurrentToken }
  Write-Log "Refreshing Graph token (older than 45 minutes)" "INFO"
  $newToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -AuthMode $AuthMode -CertThumbprint $CertThumbprint -ClientSecret $ClientSecret
  if (-not $newToken) { throw "Token refresh returned an empty token." }
  $script:TokenAcquiredAt = Get-Date
  return $newToken
}

function Invoke-WithRetry {
  # Retries transient failures only: network errors without a response, 408, 429 and 5xx.
  # Other 4xx errors (400/403/404 ...) fail immediately - retrying them cannot help and only
  # delays the run. Waits for Retry-After if the server sends it, otherwise backs off
  # exponentially ($DelaySeconds, 2x, 4x ...).
  # -ThrottleOnly: retry only on 429/503, where the server definitely did not process the
  # request. Used for non-idempotent calls like sendMail, where a retry after a timeout could
  # send the same email twice.
  param([scriptblock]$Script,[int]$RetryCount,[int]$DelaySeconds,[switch]$ThrottleOnly)
  for ($i=0; $i -le $RetryCount; $i++) {
    try { return & $Script }
    catch {
      $info = Get-HttpErrorInfo $_
      $code = $info.StatusCode
      $transient = if ($ThrottleOnly) { $code -in 429, 503 } else { (-not $code) -or $code -in 408, 429 -or $code -ge 500 }
      if ($i -eq $RetryCount -or -not $transient) { throw }
      $wait = if ($info.RetryAfterSeconds) { [math]::Min([int]$info.RetryAfterSeconds, 120) } else { $DelaySeconds * [math]::Pow(2, $i) }
      Write-Log "Transient error (HTTP $(if ($code) { $code } else { 'n/a' })), retry $($i + 1)/$RetryCount in $wait s: $($_.Exception.Message)" "WARN"
      Start-Sleep -Seconds $wait
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
    $errResponse = $_.Exception.Response
    if ($errResponse) {
      $errStream = $errResponse.GetResponseStream()
      $errReader = New-Object System.IO.StreamReader($errStream, [System.Text.Encoding]::UTF8)
      $errBody = $errReader.ReadToEnd()
      $errReader.Close()
      # Keep the status code (and Retry-After) on the exception so Invoke-WithRetry can tell
      # transient errors (429/5xx) from permanent ones (404 ...).
      $statusCode = [int]$errResponse.StatusCode
      $ex = New-Object System.Exception("Graph GET $Uri failed (HTTP $statusCode): $errBody")
      $ex.Data["StatusCode"] = $statusCode
      $retryAfterHeader = $errResponse.Headers["Retry-After"]
      if ($retryAfterHeader -match '^\d+$') { $ex.Data["RetryAfter"] = [int]$retryAfterHeader }
      $errResponse.Close()
      throw $ex
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

function Invoke-GraphGetAll {
  # GETs a Graph collection and follows @odata.nextLink until all pages are read. Graph returns
  # large collections in pages; reading only ".value" of the first response silently drops
  # everything after page one.
  param([string]$Uri,[hashtable]$Headers)
  $items = New-Object System.Collections.Generic.List[object]
  $next = $Uri
  $pages = 0
  while ($next) {
    $pageUri = $next
    $page = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $pageUri -Headers $Headers }
    foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
    $next = $page.'@odata.nextLink'
    $pages++
    if ($pages -ge 1000) { throw "Paging aborted after 1000 pages for $Uri" }
  }
  return ,$items.ToArray()
}

$script:LoggedErrorCount = 0

function Write-Log {
  # INFO lines are only shown with $VerboseLogging. WARN and ERROR are always shown, so a
  # problem is never hidden by turning verbose logging off. ERRORs are counted and make the
  # script end with exit code 1 (see end of script).
  param([string]$Message,[ValidateSet("INFO","WARN","ERROR")][string]$Level="INFO")
  if ($Level -eq "ERROR") { $script:LoggedErrorCount++ }
  if ($Level -eq "INFO" -and -not $VerboseLogging) { return }
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  Write-Host "[$ts][$Level] $Message"
}

function Get-ErrorText {
  # Best available error text from a REST error record (Graph error body if present).
  param($ErrorRecord)
  if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { return $ErrorRecord.ErrorDetails.Message }
  if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Content) { return $ErrorRecord.Exception.Response.Content }
  return $ErrorRecord.Exception.Message
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
  # Reads the same two fields Update-AppProtectionPolicy writes, so Block 1 and Block 2 always
  # see the same values. iOS and iPadOS share the iosManagedAppProtections endpoint.
  # (Property access in PowerShell is case-insensitive, so no spelling variants are needed.)
  param([string]$Token,[string]$PolicyId)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId"
  $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
  # Block ("Zugriff blockieren") and Warn ("Warnung") minimum OS versions - a policy can have
  # either, both, or neither configured.
  return [pscustomobject]@{Name=$policy.displayName;CurrentRequired=$policy.minimumRequiredOsVersion;CurrentWarning=$policy.minimumWarningOsVersion}
}

function Get-VersionState {
  # Loads the persisted per-platform version-tracking state. Returns an empty hashtable if the
  # file doesn't exist yet (first run) or can't be read.
  param([string]$Path)
  if (-not (Test-Path -Path $Path)) { return @{} }
  try {
    $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $state = @{}
    foreach ($prop in $raw.PSObject.Properties) {
      # Dates are stored as ISO text in local time (see Save-VersionState). Older files may
      # contain the "\/Date(ms)\/" format, which ConvertFrom-Json turns into a UTC DateTime -
      # converted back to local time so deadlines don't shift by the UTC offset.
      $d = $prop.Value.TargetVersionReleaseDate
      if ($d -is [datetime]) {
        if ($d.Kind -eq [DateTimeKind]::Utc) { $d = $d.ToLocalTime() }
      } else {
        $d = [datetime]::Parse("$d", [System.Globalization.CultureInfo]::InvariantCulture)
      }
      $state[$prop.Name] = @{
        TargetVersion            = $prop.Value.TargetVersion
        TargetVersionReleaseDate = $d
        WarningVersion           = $prop.Value.WarningVersion
      }
    }
    return $state
  } catch {
    Write-Log "Could not read version state file '$Path' ($($_.Exception.Message)) - starting fresh." "ERROR"
    return @{}
  }
}

function Save-VersionState {
  param([hashtable]$State,[string]$Path)
  try {
    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    # Write dates as ISO text ("2026-11-09T00:00:00"), not as DateTime objects: Windows
    # PowerShell 5.1 would serialize them as "\/Date(ms)\/", which reads back as UTC.
    $serializable = [ordered]@{}
    foreach ($key in $State.Keys) {
      $e = $State[$key]
      $serializable[$key] = [ordered]@{
        TargetVersion            = $e.TargetVersion
        TargetVersionReleaseDate = ([datetime]$e.TargetVersionReleaseDate).ToString("yyyy-MM-ddTHH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        WarningVersion           = $e.WarningVersion
      }
    }
    $serializable | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
  } catch {
    Write-Log "Could not save version state file '$Path': $($_.Exception.Message)" "ERROR"
  }
}

function Resolve-CadenceTargets {
  # Decides the actual version string to enforce for Warning and for Required/Block this run
  # (or $null if not yet effective), given the persisted tracking state and the currently
  # latest-known OS version. Mutates $State (the caller is responsible for persisting it).
  #
  # Behaviour:
  # - First time seeing this platform: start tracking the current latest version.
  # - Same latest version as last run: keep counting down from its own release date as usual.
  # - A NEWER version has appeared since last run: the previously-tracked version is promoted
  #   straight to the Warning target (bypassing its own Warning cadence, which may not have had
  #   time to elapse), and tracking resets to the new version for the ongoing Required countdown.
  param([hashtable]$State,[string]$Platform,[psobject]$Latest,[int]$CadenceDays,[int]$CadenceDaysWarning,[datetime]$Now,[bool]$ForceApply)

  $entry = $State[$Platform]
  if ($entry) {
    # Plausibility check against what we tracked so far: endoflife.date is a community data
    # source, and a wrong value would be written into every policy (and never be lowered again
    # with $AllowDowngrade = $false). A jump of more than one major version is refused.
    $trackedMajor = [int](Convert-ToComparableVersion $entry.TargetVersion).Split('.')[0]
    $latestMajor  = [int](Convert-ToComparableVersion $Latest.Version).Split('.')[0]
    if ($latestMajor -gt $trackedMajor + 1) {
      throw "Implausible version from endoflife.date for ${Platform}: $($Latest.Version) (currently tracked: $($entry.TargetVersion)). Refusing to use it. If this is correct, delete the platform's entry in '$VersionStateFilePath'."
    }
  }
  if (-not $entry) {
    $entry = @{ TargetVersion = $Latest.Version; TargetVersionReleaseDate = $Latest.ReleaseDate; WarningVersion = $null }
    $State[$Platform] = $entry
  }
  elseif ((Compare-OsVersion $Latest.Version $entry.TargetVersion) -lt 0) {
    # endoflife.date reports an OLDER version than the one already tracked (data glitch or a
    # pulled release). Never step backwards - keep tracking the known newer version.
    Write-Log "Platform ${Platform}: endoflife.date reports $($Latest.Version), which is older than the tracked $($entry.TargetVersion) - keeping $($entry.TargetVersion)." "WARN"
  }
  elseif ((Compare-OsVersion $Latest.Version $entry.TargetVersion) -gt 0) {
    Write-Log "Platform ${Platform}: newer version detected ($($entry.TargetVersion) -> $($Latest.Version)). Promoting $($entry.TargetVersion) to the Warning target." "INFO"
    $entry.WarningVersion = $entry.TargetVersion
    $entry.TargetVersion = $Latest.Version
    $entry.TargetVersionReleaseDate = $Latest.ReleaseDate
  }

  $warningDeadline  = ([datetime]$entry.TargetVersionReleaseDate).AddDays($CadenceDaysWarning)
  $requiredDeadline = ([datetime]$entry.TargetVersionReleaseDate).AddDays($CadenceDays)

  $requiredTarget = if ($ForceApply -or $Now -ge $requiredDeadline) { $entry.TargetVersion } else { $null }

  # Warning normally tracks the current TargetVersion once ITS OWN Warning cadence elapses. If a
  # newer version superseded the previous one before that could happen, the previous version was
  # promoted (see above) and is used in the meantime. But once the current TargetVersion's own
  # Warning cadence elapses too, it takes over from the promoted value - it's newer/higher and its
  # own time has now come; the promoted value is cleared so future runs behave normally again.
  if ($ForceApply -or $Now -ge $warningDeadline) {
    $warningTarget = $entry.TargetVersion
    $entry.WarningVersion = $null
  } elseif ($entry.WarningVersion) {
    $warningTarget = $entry.WarningVersion
  } else {
    $warningTarget = $null
  }

  return [pscustomobject]@{
    WarningTarget         = $warningTarget
    RequiredTarget        = $requiredTarget
    ReleaseDate            = $entry.TargetVersionReleaseDate
    WarningEffectiveDate   = $warningDeadline
    RequiredEffectiveDate  = $requiredDeadline
  }
}

function Get-LatestOsVersion {
  param([string]$ProductSlug,[int]$CadenceDays)
  $url = "https://endoflife.date/api/v1/products/$ProductSlug/releases/latest"
  $res = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-RestMethod -Uri $url -Method Get }
  $release = $res.result
  $targetVersion = "$(if ($release.latest.name) { $release.latest.name } else { $release.name })".Trim()
  # Use the date of the latest patch/hotfix release to drive cadence; fall back to major release date if missing.
  $dateSource = $release.latest.date
  if (-not $dateSource) { $dateSource = $release.releaseDate }

  # Validate before anything is derived from it - this value ends up in Intune policies.
  if ($targetVersion -notmatch '^\d{1,3}(\.\d{1,4}){0,3}$') {
    throw "endoflife.date returned an unusable version for '$ProductSlug': '$targetVersion'"
  }
  if (-not $dateSource) {
    throw "endoflife.date returned no release date for '$ProductSlug' $targetVersion"
  }
  $releaseDate = if ($dateSource -is [datetime]) { $dateSource } else { [datetime]::Parse("$dateSource", [System.Globalization.CultureInfo]::InvariantCulture) }
  if ($releaseDate -gt (Get-Date).AddDays(1)) {
    throw "endoflife.date returned a release date in the future for '$ProductSlug' $targetVersion ($releaseDate)"
  }
  $effectiveDate = $releaseDate.AddDays($CadenceDays)
  return [pscustomobject]@{
    Version       = $targetVersion
    ReleaseDate   = $releaseDate
    EffectiveDate = $effectiveDate
  }
}

function Update-CompliancePolicy {
  param([string]$Token,[string]$PolicyId,[string]$RequiredTargetVersion,[bool]$DryRun,[bool]$AllowDowngrade,[string]$Platform,[datetime]$ReleaseDate,[datetime]$RequiredEffectiveDate)
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId"
  $name = $PolicyId
  $current = $null
  $row = { param($Action,$ErrorText) [pscustomobject]@{Platform=$Platform;Type="Compliance";Setting="MinimumVersion";Name=$name;CurrentRequired=$current;Target=$RequiredTargetVersion;ReleaseDate=$ReleaseDate;Action=$Action;Error=$ErrorText;RequiredEffectiveDate=$RequiredEffectiveDate} }

  # Everything - including the GET - is inside try, so one broken policy (deleted, wrong ID,
  # no permission) becomes an "Error" row instead of aborting the whole run.
  try {
    $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
    if ($policy.displayName) { $name = $policy.displayName }
    $current = $policy.osMinimumVersion

    # Never write into a policy of another platform (e.g. a Windows policy ID entered under
    # iOS by mistake) - its minimum version would be overwritten with an Apple version.
    $expectedType = $CompliancePolicyTypes[$Platform]
    if ($policy.'@odata.type' -ne $expectedType) {
      return (& $row "Error" "Policy type '$($policy.'@odata.type')' does not match platform $Platform (expected '$expectedType') - not touched. Check the policy ID in `$CompliancePolicies.")
    }

    if (-not $RequiredTargetVersion) { return (& $row "NotEffectiveYet" $null) }

    $cmp = if ($current) { Compare-OsVersion $current $RequiredTargetVersion } else { -1 }
    if ($null -eq $cmp) { return (& $row "Error" "Cannot compare current value '$current' with target '$RequiredTargetVersion'.") }
    # Equal: nothing to do. Higher: only lowered with $AllowDowngrade.
    if ($cmp -eq 0 -or ($cmp -gt 0 -and -not $AllowDowngrade)) { return (& $row "Skipped" $null) }
    if ($DryRun) { return (& $row "WouldUpdate" $null) }

    $body = @{
      "@odata.type"      = $policy.'@odata.type'
      "osMinimumVersion" = "$RequiredTargetVersion"
    }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return (& $row "Updated" $null)
  }
  catch {
    return (& $row "Error" (Get-ErrorText $_))
  }
}

function Update-AppProtectionPolicy {
  # Evaluates the "Warn" (minimumWarningOsVersion) and "Zugriff blockieren"
  # (minimumRequiredOsVersion) fields independently. $WarningTargetVersion and
  # $RequiredTargetVersion are each either a version string (already decided as due by
  # Resolve-CadenceTargets, including any Warning promotion) or $null (not yet effective this
  # run). A policy can end up with only one of the two fields updated in a given run - this is
  # expected, not an error. Only fields already configured on the policy are ever touched.
  param(
    [string]$Token,[string]$PolicyId,[string]$WarningTargetVersion,[string]$RequiredTargetVersion,
    [bool]$DryRun,[bool]$AllowDowngrade,[string]$Platform,[datetime]$ReleaseDate,
    [datetime]$WarningEffectiveDate,[datetime]$RequiredEffectiveDate
  )
  $headers = @{Authorization = "Bearer $Token"}
  $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId"
  $displayTarget = if ($RequiredTargetVersion) { $RequiredTargetVersion } elseif ($WarningTargetVersion) { $WarningTargetVersion } else { $null }
  $baseRow = @{Platform=$Platform;Type="AppProtection";Setting="MinimumVersion";Name=$PolicyId;CurrentRequired=$null;CurrentWarning=$null;Target=$displayTarget;ReleaseDate=$ReleaseDate;WarningEffectiveDate=$WarningEffectiveDate;RequiredEffectiveDate=$RequiredEffectiveDate}

  # Everything - including the GET - is inside try, so one broken policy becomes an "Error"
  # row instead of aborting the whole run.
  try {
    $policy = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $uri -Headers $headers }
    $current = $policy.minimumRequiredOsVersion
    $currentWarning = $policy.minimumWarningOsVersion
    if ($policy.displayName) { $baseRow.Name = $policy.displayName }
    $baseRow.CurrentRequired = $current
    $baseRow.CurrentWarning  = $currentWarning

    # Only touch whichever field(s) are already configured on the policy. This avoids silently
    # turning on "Block" (minimumRequiredOsVersion) on a policy that was only ever configured with
    # "Warn" (minimumWarningOsVersion), or vice versa - the admin's chosen conditional-launch action
    # is preserved, only the version number is kept current.
    $hasRequired = [bool]$current
    $hasWarning  = [bool]$currentWarning

    if (-not $hasRequired -and -not $hasWarning) {
      return [pscustomobject]($baseRow + @{Action="NoData"})
    }

    # Per field: is it due this run (target set), and does the value need to change?
    # Equal values never count as a change; a higher value is only lowered with $AllowDowngrade.
    $fieldPlan = foreach ($f in @(
        @{ Key = "Required"; Has = $hasRequired; Current = $current;        Target = $RequiredTargetVersion },
        @{ Key = "Warning";  Has = $hasWarning;  Current = $currentWarning; Target = $WarningTargetVersion })) {
      $cmp = if ($f.Has -and $f.Target) { Compare-OsVersion $f.Current $f.Target } else { $null }
      if ($f.Has -and $f.Target -and $null -eq $cmp) {
        throw "Cannot compare current $($f.Key) value '$($f.Current)' with target '$($f.Target)'."
      }
      [pscustomobject]@{
        Key     = $f.Key
        Has     = $f.Has
        Pending = $f.Has -and -not $f.Target
        Update  = $f.Has -and $f.Target -and ($cmp -lt 0 -or ($cmp -gt 0 -and $AllowDowngrade))
      }
    }
    $req  = $fieldPlan | Where-Object Key -eq "Required"
    $warn = $fieldPlan | Where-Object Key -eq "Warning"

    if (-not $req.Update -and -not $warn.Update) {
      $action = if ($req.Pending -or $warn.Pending) { "NotEffectiveYet" } else { "Skipped" }
      return [pscustomobject]($baseRow + @{Action=$action})
    }

    # Exactly one field changes: say why the other one doesn't.
    $partialNote = ""
    if ($req.Update -ne $warn.Update) {
      $other = if ($req.Update) { $warn } else { $req }
      $reason = if (-not $other.Has) { "nicht konfiguriert" } elseif ($other.Pending) { "noch nicht faellig" } else { "bereits aktuell" }
      $partialNote = if ($req.Update) { " (nur Block - Warn $reason)" } else { " (nur Warn - Block $reason)" }
    }

    if ($DryRun) {
      return [pscustomobject]($baseRow + @{Action="WouldUpdate$partialNote"})
    }

    $body = @{}
    if ($req.Update)  { $body["minimumRequiredOsVersion"] = $RequiredTargetVersion }
    if ($warn.Update) { $body["minimumWarningOsVersion"]  = $WarningTargetVersion }
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script {
      Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json)
    }
    return [pscustomobject]($baseRow + @{Action="Updated$partialNote"})
  }
  catch {
    return [pscustomobject]($baseRow + @{Action="Error";Error=(Get-ErrorText $_)})
  }
}

# --------------------------- Device-Level Compliance Check Helpers ---------------------------
function Convert-ToComparableVersion {
  # Normalizes OS version strings so they can be cast to [version] for comparison.
  # Takes the FIRST run of dot-separated numbers and ignores everything after it, e.g.
  #   "26.5.2.a"      -> 26.5.2.0  (iOS Rapid Security Response suffix)
  #   "14.1 (23B74)"  -> 14.1.0.0  (macOS build in brackets - must not be glued onto the version)
  #   "iOS 17.4"      -> 17.4.0.0
  #   "18.0-beta1"    -> 18.0.0.0
  #   "17"            -> 17.0.0.0
  # Always pads to 4 segments, because [version]"18.5" is LESS than [version]"18.5.0" in .NET
  # (missing segments count as -1). Returns $null if no number is found.
  param([string]$VersionString)
  if (-not $VersionString) { return $null }
  if ($VersionString -notmatch '\d+(\.\d+){0,3}') { return $null }
  $parts = @($Matches[0].Split('.'))
  while ($parts.Count -lt 4) { $parts += '0' }
  return ($parts -join '.')
}

function Compare-OsVersion {
  # Compares two OS version strings after normalization. Returns -1, 0 or 1 like CompareTo,
  # or $null if either side can't be parsed.
  param([string]$A,[string]$B)
  $na = Convert-ToComparableVersion $A
  $nb = Convert-ToComparableVersion $B
  if (-not $na -or -not $nb) { return $null }
  try { return ([version]$na).CompareTo([version]$nb) } catch { return $null }
}

function Get-VersionComplianceState {
  # "Yes" if $Installed >= $Required, "No" if lower, "Unknown" if either can't be read.
  param([string]$Installed,[string]$Required)
  if (-not $Installed) { return "Unknown" }
  $cmp = Compare-OsVersion $Installed $Required
  if ($null -eq $cmp) { return "Unknown (version format)" }
  if ($cmp -ge 0) { return "Yes" } else { return "No" }
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

  # The export contains user and device data of the whole tenant - the temp files are removed
  # in "finally", so they don't stay behind when download, extraction or parsing fails.
  $tempBase = Join-Path ([System.IO.Path]::GetTempPath()) "IntuneReport_$([guid]::NewGuid())"
  $tempZip = "$tempBase.zip"
  $tempExtractDir = $tempBase
  try {
    Invoke-WebRequest -Uri $job.url -OutFile $tempZip -UseBasicParsing
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
  }
  finally {
    Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue
  }

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
    # foreach-assignment instead of "+=" - the report can have tens of thousands of rows, and
    # "+=" copies the whole array on every row.
    $rows = foreach ($valueRow in @($data.values)) {
      $obj = [ordered]@{}
      for ($i = 0; $i -lt $columnNames.Count -and $i -lt $valueRow.Count; $i++) {
        $obj[$columnNames[$i]] = $valueRow[$i]
      }
      [pscustomobject]$obj
    }
    return @($rows)
  }

  return $data
}

$script:MamReportCache = $null
$script:MamReportError = $null
$script:ManagedDeviceCache = @{}

function Resolve-AppProtectionDeviceRule {
  # Decides which App Protection rule applies to one device, given the policy's Block
  # (minimumRequiredOsVersion) and Warn (minimumWarningOsVersion) values - either may be empty.
  # Block is checked first (stricter consequence). A device that passes Block but is below
  # Warn is reported against the Warn rule - e.g. Block=18.3, Warn=18.5, device on 18.4: the
  # app already shows the warning, so the device must show up as "No" for the Warn rule.
  param([string]$Installed,[string]$BlockVersion,[string]$WarnVersion)
  if ($BlockVersion) {
    $state = Get-VersionComplianceState $Installed $BlockVersion
    if ($state -ne "Yes" -or -not $WarnVersion) {
      return [pscustomobject]@{ RuleType = "AppProtection-Block"; RequiredVersion = $BlockVersion; Compliant = $state }
    }
  }
  $state = Get-VersionComplianceState $Installed $WarnVersion
  return [pscustomobject]@{ RuleType = "AppProtection-Warn"; RequiredVersion = $WarnVersion; Compliant = $state }
}

function Get-AppProtectionDeviceRows {
  # Returns device/user rows for a given platform from the (tenant-wide, non-policy-specific)
  # MAMAppProtectionStatus report, compared against the policy's Block and Warn versions. The
  # report is fetched once and cached for the rest of the script run, since it isn't
  # policy-specific anyway.
  param([string]$Token,[string]$Platform,[string]$BlockVersion,[string]$WarnVersion,[string]$PolicyName,[string]$PolicyId)

  $RuleType = if ($BlockVersion) { "AppProtection-Block" } elseif ($WarnVersion) { "AppProtection-Warn" } else { "AppProtection" }
  $RequiredVersion = if ($BlockVersion) { $BlockVersion } else { $WarnVersion }
  if (-not $RequiredVersion) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="AppProtection";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(n/a)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion="(none)";Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  # $null check instead of "-not": an empty report (@()) is falsy and would otherwise be
  # exported again for every App Protection policy.
  if ($null -eq $script:MamReportCache -and -not $script:MamReportError) {
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

  $rows = foreach ($r in $policyRows) {
    $deviceName = Get-PropertyValueLike -Object $r -Keywords @("DeviceName","Device Name")
    $upn = Get-PropertyValueLike -Object $r -Keywords @("UserPrincipalName","UserEmail","Email","UserName","User")
    $installedVersion = Get-PropertyValueLike -Object $r -Keywords @("PlatformVersion","OSVersion","Platform Version")
    $lastSync = Get-PropertyValueLike -Object $r -Keywords @("LastSync","Last Sync")
    $deviceModel = Get-PropertyValueLike -Object $r -Keywords @("DeviceModel","Device Model")

    $rule = Resolve-AppProtectionDeviceRule -Installed $installedVersion -BlockVersion $BlockVersion -WarnVersion $WarnVersion

    [pscustomobject]@{
      Platform          = $Platform
      PolicyType        = "AppProtection"
      RuleType          = $rule.RuleType
      PolicyId          = $PolicyId
      PolicyName        = $PolicyName
      DeviceName        = $deviceName
      UserPrincipalName = $upn
      InstalledVersion  = $installedVersion
      RequiredVersion   = $rule.RequiredVersion
      Compliant         = $rule.Compliant
      LastSync          = $lastSync
      DeviceModel       = $deviceModel
    }
  }
  return @($rows)
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

  if (-not $RequiredVersion) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(n/a)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion="(none)";Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }

  try {
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId/deviceStatuses"
    $statusList = @(Invoke-GraphGetAll -Uri $uri -Headers $headers)
  } catch {
    $errMsg = $_.Exception.Message
    Write-Log "Could not read device statuses of compliance policy '$PolicyName': $errMsg" "ERROR"
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(unavailable)";UserPrincipalName="(unavailable)";InstalledVersion="(unavailable)";RequiredVersion=$RequiredVersion;Compliant="Error: device statuses not available - $errMsg";LastSync=$null;DeviceModel=$null})
  }

  if ($statusList.Count -eq 0) {
    return @([pscustomobject]@{Platform=$Platform;PolicyType="Compliance";RuleType=$RuleType;PolicyId=$PolicyId;PolicyName=$PolicyName;DeviceName="(none assigned/reporting)";UserPrincipalName="(n/a)";InstalledVersion="(n/a)";RequiredVersion=$RequiredVersion;Compliant="NoData";LastSync=$null;DeviceModel=$null})
  }
  Write-Log "Compliance policy '$PolicyName': $($statusList.Count) device status(es)" "INFO"

  $lookupFailures = 0
  $rows = foreach ($status in $statusList) {
    $deviceName = $status.deviceDisplayName
    $upn = if ($status.userPrincipalName) { $status.userPrincipalName } elseif ($status.userName) { $status.userName } else { $null }
    $installedVersion = $null
    $lastSync = $status.lastReportedDateTime
    $deviceModel = $null
    $lookupFailed = $false

    if ($status.id) {
      # Cached per run: the same device is often evaluated by several policies.
      $device = $script:ManagedDeviceCache[$status.id]
      if (-not $device) {
        try {
          $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($status.id)?`$select=id,osVersion,model,lastSyncDateTime"
          $device = Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -Script { Invoke-GraphGet -Uri $deviceUri -Headers $headers }
          $script:ManagedDeviceCache[$status.id] = $device
        } catch {
          $lookupFailed = $true
          $lookupFailures++
        }
      }
      if ($device) {
        $installedVersion = $device.osVersion
        $deviceModel = $device.model
        if (-not $lastSync -and $device.lastSyncDateTime) { $lastSync = $device.lastSyncDateTime }
      }
    }

    $compliant = if ($lookupFailed) { "Unknown (device lookup failed)" } else { Get-VersionComplianceState $installedVersion $RequiredVersion }

    [pscustomobject]@{
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
  if ($lookupFailures -gt 0) {
    # Not silent: if the device lookup fails for every device (e.g. the deviceStatuses ID does
    # not match the managedDevices ID in this tenant), the report would otherwise just show
    # "Unknown" everywhere and Block 3 would never notify anyone.
    Write-Log "Compliance policy '$PolicyName': device lookup failed for $lookupFailures of $($statusList.Count) device(s) - shown as 'Unknown (device lookup failed)'." "WARN"
  }
  return @($rows)
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
    [string]$DeviceName,[string]$Platform,[string]$InstalledVersion,[string]$RequiredVersion,
    [string]$PolicyName,[string]$RuleType,[bool]$DryRun
  )

  # Block 2 compares devices against the version that is CURRENTLY configured in the policy,
  # so the consequence already applies when this mail is sent. The text therefore describes
  # the current state instead of promising a grace period.
  $platformLabel = if ($Platform -eq "macOS") { "Mac" } elseif ($Platform -eq "iPadOS") { "iPad" } else { "iPhone/iPad" }
  $subject = "Bitte aktualisieren Sie Ihr $platformLabel ($DeviceName)"
  $statusText = switch ($RuleType) {
    "AppProtection-Block" { "Deshalb ist der Zugriff auf Unternehmens-Apps auf diesem Gerät derzeit blockiert." }
    "AppProtection-Warn"  { "Deshalb erhalten Sie beim Öffnen von Unternehmens-Apps eine Warnung. Ohne Update wird der Zugriff zu einem späteren Zeitpunkt blockiert." }
    default               { "Deshalb gilt das Gerät derzeit als nicht konform, und der Zugriff auf Unternehmensdaten kann eingeschränkt sein." }
  }
  $updatePath = if ($Platform -eq "macOS") { "Systemeinstellungen > Allgemein > Softwareupdate" } else { "Einstellungen > Allgemein > Softwareupdate" }

  $body = @"
Hallo $DisplayName,

Ihr Gerät "$DeviceName" hat aktuell die Version $InstalledVersion installiert.
Die Richtlinie "$PolicyName" verlangt mindestens Version $RequiredVersion.
$statusText

Bitte installieren Sie das Update so bald wie möglich ($updatePath).

Mit freundlichen Grüßen
IT-Support
"@

  if ($DryRun) {
    Write-Log "[WouldSend] To: $ToAddress; Subject: $subject" "INFO"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="WouldSend"}
  }

  $mailPayload = @{
    message = @{
      subject      = $subject
      body         = @{ contentType = "Text"; content = $body }
      toRecipients = @(@{ emailAddress = @{ address = $ToAddress } })
    }
    saveToSentItems = $true
  } | ConvertTo-Json -Depth 6

  try {
    # Body as UTF-8 bytes with explicit charset: Windows PowerShell 5.1 (and PowerShell 7 before
    # 7.4) would otherwise send a string body as ISO-8859-1 and mangle umlauts.
    # -ThrottleOnly: sendMail is not idempotent - after a timeout the mail may already be sent,
    # so only 429/503 (request definitely not processed) are retried.
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($mailPayload)
    $sendUri = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($FromAddress))/sendMail"
    Invoke-WithRetry -RetryCount $RetryCount -DelaySeconds $RetryDelaySeconds -ThrottleOnly -Script {
      Invoke-RestMethod -Method Post -Uri $sendUri -Headers @{Authorization = "Bearer $Token"} -ContentType "application/json; charset=utf-8" -Body $payloadBytes
    }
    Write-Log "Sent notification to $ToAddress for device $DeviceName" "INFO"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="Sent"}
  } catch {
    $errMsg = $_.Exception.Message
    Write-Log "Failed to send notification to $ToAddress for device $DeviceName - $errMsg" "ERROR"
    return [pscustomobject]@{To=$ToAddress;Subject=$subject;Action="Error";Error=$errMsg}
  }
}

function ConvertTo-CsvSafeRow {
  # Device and user names are chosen by end users. A value starting with = + - @ (or tab/CR)
  # is evaluated as a formula when the CSV is opened in Excel (e.g. a device named
  # =HYPERLINK(...)). Such values get a leading apostrophe so Excel shows them as text.
  param([psobject]$Row)
  $copy = [ordered]@{}
  foreach ($p in $Row.PSObject.Properties) {
    $v = $p.Value
    if ($v -is [string] -and $v -match '^[=+\-@\t\r]') { $v = "'" + $v }
    $copy[$p.Name] = $v
  }
  return [pscustomobject]$copy
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
// Natural comparison: number runs are compared as numbers, so "18.10" sorts after "18.9" and
// "26.1.1" after "26.1"; ISO dates sort chronologically.
function naturalCompare(a, b) {
  var ax = a.match(/\d+|\D+/g) || [], bx = b.match(/\d+|\D+/g) || [];
  for (var i = 0; i < Math.min(ax.length, bx.length); i++) {
    var an = /^\d/.test(ax[i]), bn = /^\d/.test(bx[i]);
    var c = (an && bn) ? (parseInt(ax[i], 10) - parseInt(bx[i], 10)) : ax[i].localeCompare(bx[i]);
    if (c !== 0) { return c; }
  }
  return ax.length - bx.length;
}
function sortTable(colIndex) {
  var table = document.getElementById("reportTable");
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var asc = !sortState[colIndex];
  sortState = {};
  sortState[colIndex] = asc;
  rows.sort(function(a, b) {
    var cmp = naturalCompare(a.cells[colIndex].innerText.trim(), b.cells[colIndex].innerText.trim());
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
  $script:TokenAcquiredAt = Get-Date
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

  $versionState = Get-VersionState -Path $VersionStateFilePath

  foreach ($platform in $EolProducts.Keys) {
    $hasCompliance  = $CompliancePolicies[$platform] -and $CompliancePolicies[$platform].Count -gt 0
    $hasAppProtect  = ($platform -ne "macOS") -and $AppProtectionPolicies[$platform] -and $AppProtectionPolicies[$platform].Count -gt 0
    if (-not $hasCompliance -and -not $hasAppProtect) { continue }

    Write-Log "Platform ${platform}: compliance=$($CompliancePolicies[$platform].Count) appProtection=$(if ($platform -eq 'macOS') { 0 } else { $AppProtectionPolicies[$platform].Count })" "INFO"

    # A failure here (endoflife.date unreachable, implausible data) only skips this platform:
    # every configured policy gets an "Error" row, and the run continues with the next
    # platform and Blocks 2/3.
    try {
      $latest = Get-LatestOsVersion -ProductSlug $EolProducts[$platform] -CadenceDays $CadenceDays
      $targets = Resolve-CadenceTargets -State $versionState -Platform $platform -Latest $latest -CadenceDays $CadenceDays -CadenceDaysWarning $CadenceDaysWarning -Now $now -ForceApply $ForceApply
    } catch {
      $errMsg = $_.Exception.Message
      Write-Log "Platform ${platform}: could not determine target version - no policy of this platform is changed. $errMsg" "ERROR"
      foreach ($policyId in $CompliancePolicies[$platform]) {
        $results += [pscustomobject]@{Platform=$platform;Type="Compliance";Setting="MinimumVersion";Name=$policyId;Action="Error";Error=$errMsg}
      }
      if ($platform -ne "macOS") {
        foreach ($policyId in $AppProtectionPolicies[$platform]) {
          $results += [pscustomobject]@{Platform=$platform;Type="AppProtection";Setting="MinimumVersion";Name=$policyId;Action="Error";Error=$errMsg}
        }
      }
      continue
    }
    Save-VersionState -State $versionState -Path $VersionStateFilePath

    foreach ($policyId in $CompliancePolicies[$platform]) {
      $token = Update-GraphTokenIfNeeded -CurrentToken $token
      $results += Update-CompliancePolicy -Token $token -PolicyId $policyId -RequiredTargetVersion $targets.RequiredTarget -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $targets.ReleaseDate -RequiredEffectiveDate $targets.RequiredEffectiveDate
    }

    if ($platform -eq "macOS") { continue } # No App Protection support for macOS

    foreach ($policyId in $AppProtectionPolicies[$platform]) {
      $token = Update-GraphTokenIfNeeded -CurrentToken $token
      $results += Update-AppProtectionPolicy -Token $token -PolicyId $policyId -WarningTargetVersion $targets.WarningTarget -RequiredTargetVersion $targets.RequiredTarget -DryRun $DryRun -AllowDowngrade $AllowDowngrade -Platform $platform -ReleaseDate $targets.ReleaseDate -WarningEffectiveDate $targets.WarningEffectiveDate -RequiredEffectiveDate $targets.RequiredEffectiveDate
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
      $token = Update-GraphTokenIfNeeded -CurrentToken $token
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
      $token = Update-GraphTokenIfNeeded -CurrentToken $token
      try {
        $info = Get-AppProtectionPolicyInfo -Token $token -PolicyId $policyId
        # Both rules are evaluated per device (see Resolve-AppProtectionDeviceRule): a device can
        # pass Block and still be below Warn.
        $blockVersion = $info.CurrentRequired
        $warnVersion  = $info.CurrentWarning
        if (-not $blockVersion -and -not $warnVersion -and $CompareAgainstLatestPublicVersion) { $blockVersion = $publicLatestVersion }
        $deviceResults += Get-AppProtectionDeviceRows -Token $token -Platform $platform -BlockVersion $blockVersion -WarnVersion $warnVersion -PolicyName $info.Name -PolicyId $policyId
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
    $deviceResults | ForEach-Object { ConvertTo-CsvSafeRow $_ } | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
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
    $nonCompliantRows = @($deviceResults | Where-Object { $_.Compliant -eq "No" -and $_.UserPrincipalName -and $_.UserPrincipalName -notlike "(*" })

    # One mail per device: the App Protection report has one row per app instance, and the
    # same device can also appear under a Compliance policy. Group by user + device and send
    # only the most serious finding (Block/Compliance before Warn, then the highest required
    # version).
    $severity = @{ "AppProtection-Block" = 0; "Compliance" = 0; "AppProtection-Warn" = 1 }
    $nonCompliant = @($nonCompliantRows |
      Group-Object -Property { "$($_.UserPrincipalName.ToLowerInvariant())|$($_.DeviceName)" } |
      ForEach-Object {
        $_.Group |
          Sort-Object -Property @{ Expression = { if ($severity.ContainsKey($_.RuleType)) { $severity[$_.RuleType] } else { 0 } } },
                                @{ Expression = { [version](Convert-ToComparableVersion $_.RequiredVersion) }; Descending = $true } |
          Select-Object -First 1
      })
    Write-Log "Found $($nonCompliantRows.Count) non-compliant row(s) = $($nonCompliant.Count) device(s) with a resolvable user to notify" "INFO"

    $emailResults = @()
    if ($nonCompliant.Count -gt $MaxNotificationsPerRun) {
      Write-Log "Block 3: $($nonCompliant.Count) devices would be notified, more than `$MaxNotificationsPerRun = $MaxNotificationsPerRun. No email is sent this run - check the report (wrong target version?) and raise the limit deliberately if this is correct." "ERROR"
    } else {
      foreach ($row in $nonCompliant) {
        $token = Update-GraphTokenIfNeeded -CurrentToken $token
        $userInfo = Get-UserMailAddress -Token $token -UserPrincipalName $row.UserPrincipalName
        $emailResults += Send-DeviceComplianceNotification -Token $token -FromAddress $EmailSenderAddress -ToAddress $userInfo.Mail -DisplayName $userInfo.DisplayName `
          -DeviceName $row.DeviceName -Platform $row.Platform -InstalledVersion $row.InstalledVersion -RequiredVersion $row.RequiredVersion `
          -PolicyName $row.PolicyName -RuleType $row.RuleType -DryRun $DryRun
      }
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

# =========================================================================================
# Summary and exit code
# =========================================================================================
# Exit code 1 if anything failed, so a scheduled task / runbook job shows the run as failed
# instead of always "successful". The logging wrapper evaluates this exit code.
if (-not $emailResults) { $emailResults = @() }
$policyErrors = @($results | Where-Object { $_.Action -eq "Error" }).Count
$deviceErrors = @($deviceResults | Where-Object { "$($_.Compliant)" -like "Error*" }).Count
$mailErrors   = @($emailResults | Where-Object { $_.Action -eq "Error" }).Count
$totalErrors  = $policyErrors + $deviceErrors + $mailErrors + $script:LoggedErrorCount

Write-Output "========================================="
Write-Output ("[SUMMARY] Policies: {0} (changed/would change: {1}, errors: {2}) | Device rows: {3} (non-compliant: {4}, errors: {5}) | Emails: {6} (errors: {7}) | Logged errors: {8}" -f `
  $results.Count, @($results | Where-Object { "$($_.Action)" -like "Updated*" -or "$($_.Action)" -like "WouldUpdate*" }).Count, $policyErrors,
  $deviceResults.Count, @($deviceResults | Where-Object { $_.Compliant -eq "No" }).Count, $deviceErrors,
  $emailResults.Count, $mailErrors, $script:LoggedErrorCount)

if ($totalErrors -gt 0) {
  Write-Output "[MAIN] Script completed WITH ERRORS - see the log above."
  exit 1
}
Write-Output "[MAIN] Script completed successfully"
