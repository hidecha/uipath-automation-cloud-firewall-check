<#
.SYNOPSIS
    UiPath Automation Cloud firewall requirement check script.

.DESCRIPTION
    Performs HTTP(S) GET reachability checks from the current environment against
    the list of URLs that must be allowed through the firewall as described in the
    UiPath public documentation (configuring-the-firewall-for-cloud), and writes
    the result to a UTF-8 BOM CSV file.

    Main behavior:
    - Duplicate URLs are checked only once.
    - URLs that contain a wildcard (*) are skipped (the FQDN is not deterministic).
    - wss:// is normalized to https:// and the same port (443) is used for the check.
    - Response time (ms) is measured for every URL.

    Result categories:
    - Pass : HTTP 2xx / 3xx response (network reachability OK).
    - Warn : HTTP 4xx / 5xx response (reached the server but it returned an error).
    - Fail : Timeout / DNS resolution failure / connection refused / SSL/TLS error,
             or HTTP 407 (proxy authentication required - end-to-end not reached).
    - Skip : URL contains a wildcard and cannot be checked directly.

    CSV columns:
        URL / Purpose / Result / ResponseTimeMs / Detail

.PARAMETER OutputPath
    Destination path of the result CSV. When not specified, defaults to
    AutomationCloudFirewall-CheckResult.csv located next to the script.
    When the output file is locked by another process, the script automatically
    falls back to a timestamped filename.

.PARAMETER TimeoutSec
    Connection timeout (seconds) per URL. Default: 15.

.NOTES
    Reference: https://docs.uipath.com/automation-cloud/automation-cloud/latest/admin-guide/configuring-the-firewall-for-cloud
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$TimeoutSec = 15
)

# Fallback for older environments where $PSScriptRoot is not populated.
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDir)) {
    if ($MyInvocation.MyCommand.Path) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $scriptDir = Get-Location | Select-Object -ExpandProperty Path
    }
}

if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $scriptDir "AutomationCloudFirewall-CheckResult.csv"
}

# Force TLS 1.2 for older PowerShell environments.
[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# -------------------------------------------------------------------
# URL / Purpose master list
# Source: UiPath Automation Cloud firewall configuration documentation
# -------------------------------------------------------------------
$urlList = @(
    # Automation Cloud portal
    @{ Url = 'https://account.uipath.com';                Purpose = 'Automation Cloud portal / Basic authentication sign-in' }
    @{ Url = 'https://cloud.uipath.com';                  Purpose = 'Automation Cloud portal / Basic authentication sign-in' }
    @{ Url = 'https://platform-cdn.uipath.com';           Purpose = 'Automation Cloud portal / Basic authentication sign-in' }
    @{ Url = 'https://aadcdn.msftauth.net';               Purpose = 'Automation Cloud portal / Sign in with Microsoft' }
    @{ Url = 'https://login.live.com';                    Purpose = 'Automation Cloud portal / Sign in with Microsoft' }
    @{ Url = 'https://login.microsoftonline.com';         Purpose = 'Automation Cloud portal / Sign in with Microsoft' }
    @{ Url = 'https://accounts.google.com';               Purpose = 'Automation Cloud portal / Sign in with Google' }
    @{ Url = 'https://google.com';                        Purpose = 'Automation Cloud portal / Sign in with Google' }
    @{ Url = 'https://lh3.googleusercontent.com/';        Purpose = 'Automation Cloud portal / Sign in with Google' }
    @{ Url = 'https://www.gstatic.com';                   Purpose = 'Automation Cloud portal / Sign in with Google' }
    @{ Url = 'https://lnkd.demdex.net';                   Purpose = 'Automation Cloud portal / Sign in with LinkedIn' }
    @{ Url = 'https://platform.linkedin.com';             Purpose = 'Automation Cloud portal / Sign in with LinkedIn' }
    @{ Url = 'https://static-exp1.licdn.com';             Purpose = 'Automation Cloud portal / Sign in with LinkedIn' }
    @{ Url = 'https://www.linkedin.com';                  Purpose = 'Automation Cloud portal / Sign in with LinkedIn' }
    @{ Url = '*-signalr.service.signalr.net';             Purpose = 'Automation Cloud portal / UiPath Assistant sign-in' }
    @{ Url = 'https://api.nuget.org';                     Purpose = 'Automation Cloud portal / UiPath Studio sign-in' }
    @{ Url = 'https://gallery.uipath.com';                Purpose = 'Automation Cloud portal / UiPath Studio sign-in' }
    @{ Url = 'https://pkgs.dev.azure.com';                Purpose = 'Automation Cloud portal / UiPath Studio sign-in' }
    @{ Url = 'uipath.eu.auth0.com';                       Purpose = 'Automation Cloud portal / First sign-in and password reset' }
    @{ Url = 'account.uipath.com';                        Purpose = 'Automation Cloud portal / First sign-in and password reset' }
    @{ Url = 'https://use.typekit.net';                   Purpose = 'Automation Cloud portal / Fonts' }
    @{ Url = 'https://fonts.gstatic.com';                 Purpose = 'Automation Cloud portal / Fonts' }
    @{ Url = 'https://s.gravatar.com';                    Purpose = 'Automation Cloud portal / Images' }
    @{ Url = 'https://secure.gravatar.com';               Purpose = 'Automation Cloud portal / Images' }
    @{ Url = 'https://*.wp.com';                          Purpose = 'Automation Cloud portal / Images' }
    @{ Url = 'https://*.googleusercontent.com';           Purpose = 'Automation Cloud portal / Images' }
    @{ Url = 'https://i.ytimg.com';                       Purpose = 'Automation Cloud portal / Images' }
    @{ Url = 'https://fonts.googleapis.com/css';          Purpose = 'Automation Cloud portal / CSS' }
    @{ Url = 'https://p.typekit.net';                     Purpose = 'Automation Cloud portal / CSS' }
    @{ Url = 'https://primer.typekit.net';                Purpose = 'Automation Cloud portal / Scripts' }
    @{ Url = 'http://ctldl.windowsupdate.com';            Purpose = 'Automation Cloud portal / Update services' }
    @{ Url = 'https://autopilot-prd.azureedge.net';       Purpose = 'Automation Cloud portal / Autopilot for Everyone download' }

    # Action Center
    @{ Url = 'https://cloud.uipath.com';                  Purpose = 'Action Center / Authentication' }
    @{ Url = 'https://account.uipath.com/';               Purpose = 'Action Center / Authentication' }
    @{ Url = 'https://uipath-acc-prod.azureedge.net/';    Purpose = 'Action Center / Page navigation' }
    @{ Url = 'https://www.youtube.com/';                  Purpose = 'Action Center / Page navigation' }
    @{ Url = 'https://platform-cdn.uipath.com/';          Purpose = 'Action Center / Page navigation' }
    @{ Url = 'https://fonts.gstatic.com/';                Purpose = 'Action Center / Page navigation' }
    @{ Url = '*.googleapis.com';                          Purpose = 'Action Center / Page navigation' }
    @{ Url = 'https://api.smartling.com/';                Purpose = 'Action Center / Display and assign actions' }
    @{ Url = '*.cloudfront.net';                          Purpose = 'Action Center / Display and assign actions' }
    @{ Url = '*.blob.core.windows.net';                   Purpose = 'Action Center / Storage buckets' }

    # AI Center
    @{ Url = 'https://aifproddataauetraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (Australia)' }
    @{ Url = 'https://aifproddatacactraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (Canada)' }
    @{ Url = 'https://aifproddatawetraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (Europe)' }
    @{ Url = 'https://aifproddatajaetraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (Japan)' }
    @{ Url = 'https://aifproddataseatraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (Singapore)' }
    @{ Url = 'https://aifproddataeustraining.blob.core.windows.net'; Purpose = 'AI Center / File upload (United States)' }
    @{ Url = 'https://bam.eu01.nr-data.net';              Purpose = 'AI Center / App Insights' }
    @{ Url = 'https://eastus-6.in.applicationinsights.azure.com/'; Purpose = 'AI Center / App Insights' }
    @{ Url = 'https://aifprodassets.azureedge.net';       Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://i2.wp.com/cdn.auth0.com';           Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://js-agent.newrelic.com';             Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://d2c7xlmseob604.cloudfront.net';     Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://du-prod-cdn.azureedge.net/';        Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://aifstgassets.azureedge.net';        Purpose = 'AI Center / Static assets' }
    @{ Url = 'https://dc.services.visualstudio.com';      Purpose = 'AI Center / OpenId configuration related' }
    @{ Url = 'https://du-prod-du-eus-signalr.service.signalr.net/'; Purpose = 'AI Center / OpenId configuration related' }
    @{ Url = 'wss://du-prod-du-eus-signalr.service.signalr.net/';   Purpose = 'AI Center / OpenId configuration related' }

    # AI Computer Vision
    @{ Url = 'https://cv.uipath.com';                     Purpose = 'AI Computer Vision / Endpoint' }
    @{ Url = 'https://cv-eu.uipath.com';                  Purpose = 'AI Computer Vision / Endpoint' }
    @{ Url = 'https://cv-us.uipath.com';                  Purpose = 'AI Computer Vision / Endpoint' }
    @{ Url = 'https://cv-delayed.uipath.com';             Purpose = 'AI Computer Vision / Endpoint' }

    # Apps
    @{ Url = 'https://fonts.googleapis.com';              Purpose = 'Apps / Page navigation' }
    @{ Url = 'https://cdnjs.cloudflare.com';              Purpose = 'Apps / Page navigation' }
    @{ Url = 'https://uipath-apps-prd.azureedge.net';     Purpose = 'Apps / Page navigation and app authoring' }
    @{ Url = 'https://govcloud.uipath.us';                Purpose = 'Apps / GovCloud' }
    @{ Url = 'https://uipath-apps-pgov.uipath.us';        Purpose = 'Apps / GovCloud' }
    @{ Url = 'https://usgovvirginia-1.in.applicationinsights.azure.us'; Purpose = 'Apps / GovCloud' }
    @{ Url = '*.trafficmanager.net';                      Purpose = 'Apps / App connection' }
    @{ Url = 'wss://*.uipath.systems';                    Purpose = 'Apps / App connection' }
    @{ Url = 'wss://cloud.uipath.com';                    Purpose = 'Apps / App connection' }

    # Automation Hub
    @{ Url = 'http://*.userpilot.io';                     Purpose = 'Automation Hub / Page navigation' }
    @{ Url = 'https://ah-prod-ts-blue-eu.uipath.com';     Purpose = 'Automation Hub / Page navigation (EU)' }
    @{ Url = 'https://ah-prod-ts-blue-us.uipath.com';     Purpose = 'Automation Hub / Page navigation (US)' }
    @{ Url = 'https://ah-prod-ts-blue-ja.uipath.com';     Purpose = 'Automation Hub / Page navigation (JP)' }
    @{ Url = 'https://ah-prod-ts-blue-au.uipath.com';     Purpose = 'Automation Hub / Page navigation (AU)' }
    @{ Url = 'https://ah-prod-ts-blue-ca.uipath.com';     Purpose = 'Automation Hub / Page navigation (CA)' }
    @{ Url = 'https://ah-prod-ts-blue-sea.uipath.com';    Purpose = 'Automation Hub / Page navigation (SEA)' }
    @{ Url = 'https://ah-prod-ts-blue-uk.uipath.com';     Purpose = 'Automation Hub / Page navigation (UK)' }
    @{ Url = 'https://ah-prod-ts-blue-in.uipath.com';     Purpose = 'Automation Hub / Page navigation (IN)' }
    @{ Url = 'https://ah-gxp-ts-blue-us.uipath.com';      Purpose = 'Automation Hub / Page navigation (GXP US)' }
    @{ Url = 'https://automation-hub.uipath.com';         Purpose = 'Automation Hub / OpenAPI usage' }
    @{ Url = 'http://ah-gxp-openapi-us.uipath.com';       Purpose = 'Automation Hub / OpenAPI usage' }

    # Automation Ops
    @{ Url = 'https://stdadmstgcdn.azureedge.net';        Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://app.vssps.visualstudio.com';        Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://stdadmstgcdn.blob.core.windows.net';Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://nexus.ensighten.com';               Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://content.usage.uipath.com';          Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://data.usage.uipath.com';             Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://i2.wp.com';                         Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://github.com';                        Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://github.githubassets.com';           Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://avatars.githubusercontent.com';     Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://collector.github.com';              Purpose = 'Automation Ops / Page navigation' }
    @{ Url = 'https://api.github.com';                    Purpose = 'Automation Ops / Page navigation' }

    # IXP
    @{ Url = '*.service.signalr.net';                     Purpose = 'IXP / SignalR' }
    @{ Url = 'https://*.in.applicationinsights.azure.com';Purpose = 'IXP / Telemetry' }
    @{ Url = 'https://*.pendo.io';                        Purpose = 'IXP / Pendo' }
    @{ Url = 'https://o486811.ingest.sentry.io';          Purpose = 'IXP / Performance monitoring' }

    # Data Fabric
    @{ Url = '*.cloudapp.azure.com';                      Purpose = 'Data Fabric / Frontend content' }
    @{ Url = '*.visualstudio.com';                        Purpose = 'Data Fabric / Telemetry' }

    # Document Understanding (all wildcards)
    @{ Url = 'https://*.uipath.com';                      Purpose = 'Document Understanding / Basic navigation' }
    @{ Url = 'https://*.azure.com';                       Purpose = 'Document Understanding / Azure related' }
    @{ Url = 'https://*.azureedge.net';                   Purpose = 'Document Understanding / Azure related' }
    @{ Url = 'https://*.azurefd.net';                     Purpose = 'Document Understanding / Azure related' }
    @{ Url = 'https://*.visualstudio.com';                Purpose = 'Document Understanding / Telemetry' }
    @{ Url = 'https://*.service.signalr.net';             Purpose = 'Document Understanding / SignalR' }
    @{ Url = 'https://*.trafficmanager.net';              Purpose = 'Document Understanding / Storage' }
    @{ Url = 'https://*.blob.core.windows.net';           Purpose = 'Document Understanding / Storage' }

    # Insights
    @{ Url = 'https://*.lookercdn.com';                   Purpose = 'Insights / Page navigation' }
    @{ Url = 'https://uipath-insights-statics.azureedge.net/'; Purpose = 'Insights / Page navigation' }
    @{ Url = 'https://*.looker.uipath.com/';              Purpose = 'Insights / Page navigation' }

    # Orchestrator
    @{ Url = 'https://orch-cdn.uipath.com';               Purpose = 'Orchestrator / Basic access' }
    @{ Url = 'https://download.uipath.com';               Purpose = 'Orchestrator / Robot and auto-update' }
    @{ Url = '*.s3.amazonaws.com';                        Purpose = 'Orchestrator / Storage' }

    # Process Mining
    @{ Url = 'https://i1.wp.com';                         Purpose = 'Process Mining / Static assets' }

    # Solutions
    @{ Url = 'api.smartling.com';                         Purpose = 'Solutions / Page navigation' }
    @{ Url = 'use.typekit.net';                           Purpose = 'Solutions / Page navigation' }
    @{ Url = 'p.typekit.net';                             Purpose = 'Solutions / Page navigation' }
    @{ Url = 's.gravatar.com';                            Purpose = 'Solutions / Page navigation' }
    @{ Url = 'i2.wp.com';                                 Purpose = 'Solutions / Page navigation' }
    @{ Url = 'https://sol-cdn.uipath.com';                Purpose = 'Solutions / Page navigation' }
    @{ Url = 'https://solutions.uipath.com';              Purpose = 'Solutions / Page navigation' }

    # Studio Web
    @{ Url = 'wss://*.service.signalr.net';               Purpose = 'Studio Web / SignalR' }
    @{ Url = 'https://*.service.signalr.net';             Purpose = 'Studio Web / SignalR' }
    @{ Url = 'wss://*.trafficmanager.net';                Purpose = 'Studio Web / SignalR' }
    @{ Url = 'https://studio-feedback.azure-api.net';     Purpose = 'Studio Web / UiPath product' }
    @{ Url = 'https://*.typekit.net';                     Purpose = 'Studio Web / Static assets' }
    @{ Url = 'https://*.amazonaws.com';                   Purpose = 'Studio Web / Storage' }

    # Task Mining
    @{ Url = 'dc.applicationinsights.azure.com';          Purpose = 'Task Mining / App Insights' }
    @{ Url = 'dc.applicationinsights.microsoft.com';      Purpose = 'Task Mining / App Insights' }
    @{ Url = 'live.applicationinsights.azure.com';        Purpose = 'Task Mining / App Insights' }
    @{ Url = 'rt.applicationinsights.microsoft.com';      Purpose = 'Task Mining / App Insights' }
    @{ Url = 'rt.services.visualstudio.com';              Purpose = 'Task Mining / App Insights' }
    @{ Url = '*.livediagnostics.monitor.azure.com';       Purpose = 'Task Mining / App Insights' }
    @{ Url = 'i2.wp.com/cdn.auth0.com/avatars';           Purpose = 'Task Mining / Avatars' }
)

# -------------------------------------------------------------------
# URL normalization: fill in scheme, strip trailing slash
# -------------------------------------------------------------------
function Get-NormalizedUrl {
    param([string]$Url)

    $u = $Url.Trim()

    # wss:// -> https:// (reachable on the same port 443 is good enough).
    if ($u -match '^wss://')  { $u = 'https://' + $u.Substring(6) }
    if ($u -match '^ws://')   { $u = 'http://'  + $u.Substring(5) }

    # Default to https:// when no scheme is present.
    if ($u -notmatch '^(https?|wss?)://') { $u = 'https://' + $u }

    # Strip trailing slash when it is the only path segment.
    if ($u -match '^https?://[^/]+/$') { $u = $u.TrimEnd('/') }

    return $u
}

# -------------------------------------------------------------------
# Connection check
# -------------------------------------------------------------------
function Get-HttpStatusFromError {
    <#
        Extracts the HTTP status code (int) from an Invoke-WebRequest failure
        exception. Returns $null if nothing can be recovered.

        Sources considered:
          - Windows PowerShell 5.1 : System.Net.WebException + .Response.StatusCode (HttpStatusCode)
          - PowerShell 7+          : Microsoft.PowerShell.Commands.HttpResponseException + .Response.StatusCode (HttpStatusCode)
          - ErrorRecord properties : .Exception.Response.StatusCode / .Exception.StatusCode
    #>
    param($ErrorRecord)

    $ex = $ErrorRecord.Exception

    # 1) Exception.Response.StatusCode
    try {
        if ($null -ne $ex.Response -and $null -ne $ex.Response.StatusCode) {
            return [int]$ex.Response.StatusCode
        }
    } catch { }

    # 2) Exception.StatusCode (PowerShell 7 HttpResponseException)
    try {
        if ($null -ne $ex.StatusCode) {
            return [int]$ex.StatusCode
        }
    } catch { }

    # 3) Last resort: parse a 3-digit status code out of ErrorDetails.Message.
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message -match '\b([1-5]\d{2})\b') {
        return [int]$Matches[1]
    }

    return $null
}

function Test-UrlConnection {
    param(
        [string]$Url,
        [int]$TimeoutSec = 15
    )

    # Decision rules:
    #   Pass : HTTP 2xx / 3xx response.
    #   Warn : HTTP 4xx / 5xx or similar - response received but with an error status (network reachable).
    #   Fail : Timeout / DNS failure / connection refused / 407 (proxy auth required) etc.
    #
    #  HTTP 407 Proxy Authentication Required is treated as Fail because end-to-end
    #  reachability to the target is not established.

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $resp = Invoke-WebRequest -Uri $Url -Method Get `
                                  -UseBasicParsing -TimeoutSec $TimeoutSec `
                                  -MaximumRedirection 5 -ErrorAction Stop
        $sw.Stop()
        return [PSCustomObject]@{
            Status      = 'Pass'
            Detail      = "HTTP $([int]$resp.StatusCode)"
            ElapsedMs   = [int]$sw.ElapsedMilliseconds
        }
    } catch {
        $sw.Stop()
        $elapsedMs = [int]$sw.ElapsedMilliseconds
        $err  = $_
        $ex   = $err.Exception
        $code = Get-HttpStatusFromError -ErrorRecord $err

        # We received an HTTP status => the server was reached (but 407 is still Fail).
        if ($null -ne $code) {
            if ($code -eq 407) {
                return [PSCustomObject]@{
                    Status    = 'Fail'
                    Detail    = 'HTTP 407 (proxy authentication required)'
                    ElapsedMs = $elapsedMs
                }
            }
            if ($code -ge 200 -and $code -lt 400) {
                return [PSCustomObject]@{ Status = 'Pass'; Detail = "HTTP $code"; ElapsedMs = $elapsedMs }
            }
            return [PSCustomObject]@{
                Status    = 'Warn'
                Detail    = "HTTP $code (reachable / server returned error)"
                ElapsedMs = $elapsedMs
            }
        }

        # System.Net.WebException.Status (PowerShell 5.1)
        if ($ex -is [System.Net.WebException]) {
            switch ($ex.Status) {
                'Timeout'               { return [PSCustomObject]@{ Status = 'Fail'; Detail = "Timeout ($TimeoutSec s)";         ElapsedMs = $elapsedMs } }
                'NameResolutionFailure' { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'DNS resolution failure';          ElapsedMs = $elapsedMs } }
                'ConnectFailure'        { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'Connection failed';               ElapsedMs = $elapsedMs } }
                'TrustFailure'          { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'SSL/TLS trust failure';           ElapsedMs = $elapsedMs } }
                'SecureChannelFailure'  { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'SSL/TLS handshake failure';       ElapsedMs = $elapsedMs } }
            }
        }

        # Pattern-match typical unreachable-network exception messages.
        $msg = "$($ex.Message)"
        if ($msg -match 'timed out|timeout')                                                     { return [PSCustomObject]@{ Status = 'Fail'; Detail = "Timeout ($TimeoutSec s)";    ElapsedMs = $elapsedMs } }
        if ($msg -match 'No such host|name or service not known|Name or service|host is unknown') { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'DNS resolution failure';     ElapsedMs = $elapsedMs } }
        if ($msg -match 'refused')                                                               { return [PSCustomObject]@{ Status = 'Fail'; Detail = 'Connection refused';          ElapsedMs = $elapsedMs } }
        if ($msg -match 'SSL|TLS|certificate')                                                   { return [PSCustomObject]@{ Status = 'Fail'; Detail = "SSL/TLS error: $msg";         ElapsedMs = $elapsedMs } }

        return [PSCustomObject]@{ Status = 'Fail'; Detail = $msg; ElapsedMs = $elapsedMs }
    }
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
Write-Host "Starting UiPath Automation Cloud firewall requirement check." -ForegroundColor Cyan
Write-Host "Output: $OutputPath" -ForegroundColor Cyan
Write-Host ""

$results      = New-Object System.Collections.Generic.List[object]
$checkedUrls  = New-Object System.Collections.Generic.HashSet[string]
$total        = $urlList.Count
$index        = 0

foreach ($item in $urlList) {
    $index++
    $originalUrl = $item.Url
    $purpose     = $item.Purpose

    Write-Progress -Activity "Firewall reachability check" `
                   -Status "$index / $total : $originalUrl" `
                   -PercentComplete (($index / $total) * 100)

    # Skip URLs that contain a wildcard.
    if ($originalUrl -like '*`**') {
        $results.Add([PSCustomObject]@{
            URL            = $originalUrl
            Purpose        = $purpose
            Result         = 'Skip'
            ResponseTimeMs = ''
            Detail         = 'Contains wildcard - not checked directly'
        })
        Write-Host ("[Skip] {0}" -f $originalUrl) -ForegroundColor DarkGray
        continue
    }

    $normalized = Get-NormalizedUrl -Url $originalUrl

    # De-duplicate.
    if (-not $checkedUrls.Add($normalized)) {
        Write-Host ("[Dup ] {0}" -f $originalUrl) -ForegroundColor DarkGray
        continue
    }

    Write-Host ("[Chk ] {0}" -f $normalized) -ForegroundColor Gray -NoNewline
    $r = Test-UrlConnection -Url $normalized -TimeoutSec $TimeoutSec

    $color = switch ($r.Status) {
        'Pass' { 'Green' }
        'Warn' { 'Yellow' }
        'Fail' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("  => {0} ({1}) [{2} ms]" -f $r.Status, $r.Detail, $r.ElapsedMs) -ForegroundColor $color

    $results.Add([PSCustomObject]@{
        URL            = $normalized
        Purpose        = $purpose
        Result         = $r.Status
        ResponseTimeMs = $r.ElapsedMs
        Detail         = $r.Detail
    })
}

Write-Progress -Activity "Firewall reachability check" -Completed

# -------------------------------------------------------------------
# CSV output (UTF-8 BOM so Excel opens it cleanly)
# -------------------------------------------------------------------
$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Always write the CSV as UTF-8 with BOM.
#   - PowerShell 7+ supports -Encoding UTF8BOM.
#   - PowerShell 5.1 writes BOM with -Encoding UTF8.
# To paper over the difference, serialize first then write with .NET UTF8Encoding(true).
$csvText = ($results | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
$utf8Bom  = New-Object System.Text.UTF8Encoding($true)

# .NET uses its own current directory, so resolve to an absolute path first.
$absoluteOutPath = [System.IO.Path]::GetFullPath(
    [System.IO.Path]::Combine((Get-Location).Path, $OutputPath)
)

try {
    [System.IO.File]::WriteAllText($absoluteOutPath, $csvText, $utf8Bom)
} catch {
    Write-Host ""
    Write-Host "Failed to write the output file (it may be open in Excel): $absoluteOutPath" -ForegroundColor Yellow

    # Fall back to a timestamped filename.
    $dir  = [System.IO.Path]::GetDirectoryName($absoluteOutPath)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($absoluteOutPath)
    $ext  = [System.IO.Path]::GetExtension($absoluteOutPath)
    $fallback = Join-Path $dir ("{0}_{1}{2}" -f $base, (Get-Date -Format 'yyyyMMdd_HHmmss'), $ext)

    [System.IO.File]::WriteAllText($fallback, $csvText, $utf8Bom)
    Write-Host "Saved to fallback file instead: $fallback" -ForegroundColor Yellow
    $absoluteOutPath = $fallback
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
Write-Host ("Total : {0}" -f $urlList.Count)
Write-Host ("Output: {0}" -f $results.Count)
Write-Host ("Pass  : {0}" -f (@($results | Where-Object { $_.Result -eq 'Pass' }).Count)) -ForegroundColor Green
Write-Host ("Warn  : {0}" -f (@($results | Where-Object { $_.Result -eq 'Warn' }).Count)) -ForegroundColor Yellow
Write-Host ("Fail  : {0}" -f (@($results | Where-Object { $_.Result -eq 'Fail' }).Count)) -ForegroundColor Red
Write-Host ("Skip  : {0}" -f (@($results | Where-Object { $_.Result -eq 'Skip' }).Count)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "CSV: $absoluteOutPath" -ForegroundColor Green
