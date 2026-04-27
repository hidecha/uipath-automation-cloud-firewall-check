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
             HTTP 407 (proxy authentication required), or HTTP 403 returned by an
             intermediate proxy (the request did not reach the origin server).
    - Skip : URL contains a wildcard and cannot be checked directly.

    403 handling:
    A 403 response identified as originating from an intermediate proxy is
    treated as Fail; a 403 that looks like it came from the origin web server
    is recorded as Warn. Detection is vendor-neutral and uses two layers:
      1) Headers: Via, Proxy-Connection, X-Cache, X-Cache-Lookup, or a Server
         header containing "proxy", "cache", or "gateway".
      2) Body fallback (used when headers are not available, as commonly
         happens with HTTPS CONNECT failures on PowerShell 5.1): the HTML
         error page is matched against generic markers such as the words
         "proxy" / "gateway", phrases like "cache administrator", or the
         classic forward-proxy phrase "requested URL could not be retrieved".

    Proxy authentication:
    When the initial request returns HTTP 407, the request is retried using
    credentials matched to the advertised Proxy-Authenticate scheme:
      - Negotiate / Kerberos / NTLM: the current Windows user's OS credentials
        (Integrated Authentication).
      - Basic: credentials read from a local UiPath proxy configuration file
        (priority 1: C:\ProgramData\UiPath\Shared\proxy.json; priority 2:
        C:\Program Files\UiPath\Studio\uipath.config). Domain is optional -
        when empty, UserName is sent as-is; otherwise both "UserName" and
        "Domain\UserName" forms are tried because proxies differ in which
        form they expect.
    A one-shot raw CONNECT probe is run at startup against the system proxy
    so that the advertised scheme list can be captured even on PowerShell
    5.1, which otherwise hides the Proxy-Authenticate header on HTTPS
    CONNECT failures. When Integrated and Basic are both applicable,
    Integrated is attempted first and Basic is used as a fallback. The
    retry outcome replaces the original 407 result.

    CSV columns:
        URL / Purpose / Result / ResponseTimeMs / Detail

.PARAMETER OutputPath
    Destination path of the result CSV. When not specified, defaults to
    AutomationCloudFirewall-CheckResult.csv located next to the script.
    When the output file is locked by another process, the script automatically
    falls back to a timestamped filename.

.PARAMETER TimeoutSec
    Connection timeout (seconds) per URL. Default: 15.

.PARAMETER DebugProxyAuth
    When specified, prints a per-variant wire-level trace of the raw CONNECT
    request/response used to diagnose proxy authentication. The Base64 token
    in the request is masked (first four and last four characters only) but
    the proxy error page body is echoed to the console. Leave off in routine
    runs; enable only when investigating a 407.

.NOTES
    Reference: https://docs.uipath.com/automation-cloud/automation-cloud/latest/admin-guide/configuring-the-firewall-for-cloud
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$TimeoutSec = 15,
    [switch]$DebugProxyAuth
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

# Make the system proxy use the current Windows user's credentials by default.
# This lets Invoke-WebRequest pass through Kerberos/NTLM proxies transparently
# on PowerShell 5.1, which does not always honor -ProxyUseDefaultCredentials on
# the first attempt. PowerShell 7 generally picks this up as well.
try {
    $defaultProxy = [System.Net.WebRequest]::DefaultWebProxy
    if ($null -ne $defaultProxy) {
        $defaultProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }
} catch { }

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
        Extracts the HTTP status code (int) from an Invoke-WebRequest or
        HttpWebRequest failure exception. Returns $null if nothing can be
        recovered.

        Sources considered:
          - Windows PowerShell 5.1 : System.Net.WebException + .Response.StatusCode (HttpStatusCode)
          - PowerShell 7+          : Microsoft.PowerShell.Commands.HttpResponseException + .Response.StatusCode (HttpStatusCode)
          - InnerException chain   : HttpWebRequest.GetResponse() throws a
                                     MethodInvocationException that wraps the
                                     real System.Net.WebException, so we walk
                                     the chain rather than looking at the
                                     outermost exception only.
          - ErrorRecord / Exception message: last-resort "(407)" pattern match.
    #>
    param($ErrorRecord)

    $seen = 0
    $ex   = $ErrorRecord.Exception
    while ($null -ne $ex -and $seen -lt 10) {
        $seen++

        # Exception.Response.StatusCode (WebException / HttpResponseException)
        try {
            if ($null -ne $ex.Response -and $null -ne $ex.Response.StatusCode) {
                return [int]$ex.Response.StatusCode
            }
        } catch { }

        # Exception.StatusCode (PowerShell 7 HttpResponseException)
        try {
            if ($null -ne $ex.StatusCode) {
                return [int]$ex.StatusCode
            }
        } catch { }

        $ex = $ex.InnerException
    }

    # Fallback 1: ErrorDetails.Message (populated by Invoke-WebRequest).
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message -match '\b([1-5]\d{2})\b') {
        return [int]$Matches[1]
    }

    # Fallback 2: Exception message itself. HttpWebRequest.GetResponse failures
    # produce strings like "The remote server returned an error: (407) Proxy
    # Authentication Required." that carry the code even when .Response is null.
    $msg = [string]$ErrorRecord.Exception.Message
    if ($msg -match '\(([1-5]\d{2})\)') {
        return [int]$Matches[1]
    }

    return $null
}

function Get-ProxyAuthSchemes {
    <#
        Extracts the Proxy-Authenticate header values (scheme list such as
        "Negotiate", "Kerberos", "NTLM", "Basic") from an HTTP 407 response.

        Sources considered:
          - Windows PowerShell 5.1 : System.Net.HttpWebResponse.Headers (WebHeaderCollection)
          - PowerShell 7+          : System.Net.Http.HttpResponseMessage.Headers.ProxyAuthenticate
    #>
    param($ErrorRecord)

    $schemes = New-Object System.Collections.Generic.List[string]

    $resp = $null
    try { $resp = $ErrorRecord.Exception.Response } catch { }
    if ($null -eq $resp) { return $schemes }

    # PowerShell 5.1 path: WebHeaderCollection exposes GetValues("Proxy-Authenticate").
    try {
        $hdrs = $resp.Headers
        if ($hdrs -and $hdrs.GetType().GetMethod('GetValues')) {
            $values = $null
            try { $values = $hdrs.GetValues('Proxy-Authenticate') } catch { }
            if ($values) {
                foreach ($v in $values) {
                    $head = ($v -split '[ ,]')[0]
                    if ($head) { [void]$schemes.Add($head.Trim()) }
                }
                if ($schemes.Count -gt 0) { return $schemes }
            }
        }
    } catch { }

    # PowerShell 7 path: HttpResponseHeaders.ProxyAuthenticate is a collection
    # of AuthenticationHeaderValue, each with a .Scheme.
    try {
        $pa = $resp.Headers.ProxyAuthenticate
        if ($pa) {
            foreach ($v in $pa) {
                if ($v.Scheme) { [void]$schemes.Add([string]$v.Scheme) }
            }
        }
    } catch { }

    return $schemes
}

function Test-ProxySchemeIsIntegrated {
    param($Schemes)
    foreach ($s in $Schemes) {
        if ($s -match '(?i)^(Negotiate|Kerberos|NTLM)$') { return $true }
    }
    return $false
}

function Test-ProxySchemeIsBasic {
    param($Schemes)
    foreach ($s in $Schemes) {
        if ($s -match '(?i)^Basic$') { return $true }
    }
    return $false
}

function Get-UiPathProxyCredentialFromJson {
    <#
        Reads a UiPath proxy.json file (typically located at
        C:\ProgramData\UiPath\Shared\proxy.json) and returns an object with
        UserName / Password / Domain / ProxyAddress, or $null when the file
        does not exist / is unreadable / lacks credentials.

        Schema (as observed in Studio):
          {
            "ScriptAddress": "",
            "ProxyAddress":  "http://host:port",
            "BypassList":    "",
            "BypassLocalAddresses": false,
            "UserName":      "...",
            "Password":      "...",
            "Domain":        ""   // may be empty
          }
    #>
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $raw  = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $json = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }

    if (-not $json) { return $null }
    if ([string]::IsNullOrEmpty([string]$json.UserName)) { return $null }

    return [PSCustomObject]@{
        UserName     = [string]$json.UserName
        Password     = [string]$json.Password
        Domain       = [string]$json.Domain
        ProxyAddress = [string]$json.ProxyAddress
        Source       = $Path
    }
}

function Get-UiPathProxyCredentialFromConfig {
    <#
        Reads a UiPath Studio uipath.config file (typically located at
        C:\Program Files\UiPath\Studio\uipath.config) and returns an object
        with UserName / Password / Domain / ProxyAddress, or $null when the
        file does not exist / cannot be parsed / lacks credentials.

        The credentials live under <webProxySettings> as <add key="..."
        value="..." /> entries. Domain may be absent or empty.
    #>
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        return $null
    }

    $section = $xml.configuration.webProxySettings
    if ($null -eq $section) { return $null }

    $settings = @{}
    foreach ($entry in @($section.add)) {
        if ($entry -and $entry.key) {
            $settings[[string]$entry.key] = [string]$entry.value
        }
    }

    if ([string]::IsNullOrEmpty([string]$settings['UserName'])) { return $null }

    return [PSCustomObject]@{
        UserName     = [string]$settings['UserName']
        Password     = [string]$settings['Password']
        Domain       = [string]$settings['Domain']
        ProxyAddress = [string]$settings['ProxyAddress']
        Source       = $Path
    }
}

$script:UiPathProxyCredentialCache     = $null
$script:UiPathProxyCredentialCacheRead = $false

function Get-UiPathProxyCredential {
    <#
        Loads proxy credentials from local UiPath configuration files in the
        documented priority order:
          1) C:\ProgramData\UiPath\Shared\proxy.json
          2) C:\Program Files\UiPath\Studio\uipath.config

        Returns the first source that supplies a non-empty UserName, or
        $null when nothing is found. The result is cached for the lifetime
        of the script process.

        On first load the outcome is printed to the host (password masked)
        so proxy-auth issues can be diagnosed without guessing whether the
        file was even read.
    #>
    if ($script:UiPathProxyCredentialCacheRead) {
        return $script:UiPathProxyCredentialCache
    }

    $cred = Get-UiPathProxyCredentialFromJson -Path 'C:\ProgramData\UiPath\Shared\proxy.json'
    if ($null -eq $cred) {
        $cred = Get-UiPathProxyCredentialFromConfig -Path 'C:\Program Files\UiPath\Studio\uipath.config'
    }

    if ($null -ne $cred) {
        $domainLabel = if ([string]::IsNullOrEmpty([string]$cred.Domain)) { '(empty)' } else { $cred.Domain }
        $passLabel   = if ([string]::IsNullOrEmpty([string]$cred.Password)) { '(empty)' } else { '***' }
        Write-Host ("[Info] Loaded proxy credentials: Source={0}, UserName={1}, Domain={2}, Password={3}, ProxyAddress={4}" `
                        -f $cred.Source, $cred.UserName, $domainLabel, $passLabel, $cred.ProxyAddress) `
                   -ForegroundColor DarkCyan
    } else {
        Write-Host '[Info] No UiPath proxy credentials found (checked proxy.json then uipath.config).' -ForegroundColor DarkCyan
    }

    $script:UiPathProxyCredentialCache     = $cred
    $script:UiPathProxyCredentialCacheRead = $true
    return $cred
}

function Get-BasicUserNameVariants {
    <#
        Returns the list of UserName strings to try for HTTP Basic proxy
        authentication, in order. Proxies that front Active Directory are
        inconsistent about whether they want the plain sAMAccountName
        (e.g. "user") or the domain-qualified form (e.g. "DOMAIN\user"),
        so when a Domain is present we try both.
    #>
    param($Credential)

    $user   = [string]$Credential.UserName
    $domain = [string]$Credential.Domain

    if ([string]::IsNullOrWhiteSpace($domain)) {
        return ,$user
    }
    return @($user, ("{0}\{1}" -f $domain, $user))
}

function Get-ResponseHeaderValue {
    <#
        Reads a single header value from either a WebHeaderCollection
        (Windows PowerShell 5.1 / HttpWebResponse) or an HttpResponseHeaders
        instance (PowerShell 7+ / HttpResponseMessage).
        Returns a single string with all values joined by ", ", or $null.
    #>
    param($Response, [string]$HeaderName)

    if ($null -eq $Response) { return $null }

    # PowerShell 5.1: WebHeaderCollection.GetValues(string)
    try {
        $hdrs = $Response.Headers
        if ($hdrs -and $hdrs.GetType().GetMethod('GetValues')) {
            $values = $null
            try { $values = $hdrs.GetValues($HeaderName) } catch { }
            if ($values) { return ($values -join ', ') }
        }
    } catch { }

    # PowerShell 7+: HttpResponseHeaders.TryGetValues(string, out IEnumerable<string>)
    try {
        $hdrs = $Response.Headers
        if ($hdrs) {
            $out = $null
            $ok  = $hdrs.TryGetValues($HeaderName, [ref]$out)
            if ($ok -and $out) { return ($out -join ', ') }
        }
    } catch { }

    return $null
}

function Test-ResponseIsFromProxy {
    <#
        Decides whether an HTTP response most likely came from an intermediate
        proxy rather than from the origin web server, based on generic headers
        only (no vendor-specific product names).

        Signals considered:
          - Via (RFC 9110 standard proxy marker)
          - Proxy-Connection (non-standard but widely used)
          - X-Cache / X-Cache-Lookup (common to forward/cache proxies)
          - Server header containing the generic tokens "proxy", "cache",
            or "gateway"
    #>
    param($Response)

    if ($null -eq $Response) { return $false }

    foreach ($name in @('Via', 'Proxy-Connection', 'X-Cache', 'X-Cache-Lookup')) {
        $val = Get-ResponseHeaderValue -Response $Response -HeaderName $name
        if ($val) { return $true }
    }

    $server = Get-ResponseHeaderValue -Response $Response -HeaderName 'Server'
    if ($server -and ($server -match '(?i)\b(proxy|cache|gateway)\b')) { return $true }

    return $false
}

function Get-ErrorResponseBody {
    <#
        Returns the HTTP response body from a failed Invoke-WebRequest call,
        or $null when no body is available. PowerShell exposes the body in
        two different places depending on the failure mode:
          - $_.ErrorDetails.Message            (populated by Invoke-WebRequest)
          - $_.Exception.Response stream       (raw WebResponse stream)
    #>
    param($ErrorRecord)

    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            return [string]$ErrorRecord.ErrorDetails.Message
        }
    } catch { }

    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -ne $resp) {
            $stream = $resp.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                return $reader.ReadToEnd()
            }
        }
    } catch { }

    return $null
}

function Test-BodyIsFromProxy {
    <#
        Looks for generic, vendor-neutral markers in an HTTP error page body
        that suggest it was produced by an intermediate proxy / gateway /
        caching product rather than by an origin web application.

        Markers:
          - the word "proxy" or "gateway"
          - phrases like "cache administrator" / "cache manager" / "cache server"
          - "requested URL could not be retrieved" (classic forward-proxy error)
    #>
    param([string]$Body)

    if ([string]::IsNullOrEmpty($Body)) { return $false }

    if ($Body -match '(?i)\b(proxy|gateway)\b')                       { return $true }
    if ($Body -match '(?i)cache\s+(administrator|manager|server)')    { return $true }
    if ($Body -match '(?i)requested\s+URL\s+could\s+not\s+be\s+retrieved') { return $true }

    return $false
}

function Get-SystemProxyForUrl {
    <#
        Returns the system proxy URL (string) for the target $Url, or $null
        when no proxy is configured or cannot be resolved.
    #>
    param([string]$Url)
    try {
        $proxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($null -eq $proxy) { return $null }
        $target   = [Uri]$Url
        $proxyUri = $proxy.GetProxy($target)
        if ($null -eq $proxyUri) { return $null }
        # GetProxy returns the original URI when no proxy is configured for it.
        if ($proxyUri.AbsoluteUri -eq $target.AbsoluteUri) { return $null }
        return $proxyUri.AbsoluteUri
    } catch {
        return $null
    }
}

function Get-ProxyAuthSchemesFromConnect {
    <#
        Probes the proxy directly at the TCP layer to read the Proxy-Authenticate
        headers from the raw 407 response to an HTTPS CONNECT request.

        Why this exists:
        On PowerShell 5.1, HttpWebRequest/Invoke-WebRequest do NOT surface the
        proxy's WWW-headers when a CONNECT tunnel is refused (the WebException
        carries a blank Response), so we cannot tell whether the proxy wants
        Basic / NTLM / Negotiate. A direct socket probe bypasses that layer
        and lets us read the 407 response headers verbatim.

        Returns a string[] of scheme tokens ("Basic", "NTLM", "Negotiate"...)
        extracted from Proxy-Authenticate, or an empty array on any failure.

        $ProxyUrl is expected to be of the form http(s)://host:port/.
        $TargetUrl provides the CONNECT target (host:port only is used).
    #>
    param(
        [string]$ProxyUrl,
        [string]$TargetUrl,
        [int]$TimeoutSec = 5
    )

    $schemes = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($ProxyUrl))  { return $schemes.ToArray() }
    if ([string]::IsNullOrWhiteSpace($TargetUrl)) { return $schemes.ToArray() }

    try {
        $proxyUri  = [Uri]$ProxyUrl
        $targetUri = [Uri]$TargetUrl
    } catch {
        return $schemes.ToArray()
    }

    $proxyHost = $proxyUri.Host
    $proxyPort = if ($proxyUri.Port -gt 0) { $proxyUri.Port } else { 8080 }
    $tgtHost   = $targetUri.Host
    $tgtPort   = if ($targetUri.Port -gt 0) { $targetUri.Port } else { 443 }

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.SendTimeout    = $TimeoutSec * 1000
        $tcp.ReceiveTimeout = $TimeoutSec * 1000
        $async = $tcp.BeginConnect($proxyHost, $proxyPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)) {
            return $schemes.ToArray()
        }
        $tcp.EndConnect($async)

        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TimeoutSec * 1000
        $stream.WriteTimeout = $TimeoutSec * 1000

        $req = "CONNECT {0}:{1} HTTP/1.1`r`nHost: {0}:{1}`r`nProxy-Connection: close`r`n`r`n" -f $tgtHost, $tgtPort
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        $raw    = New-Object System.Text.StringBuilder
        while ($true) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            if ($line -eq '')    { break }   # End of headers.
            [void]$raw.AppendLine($line)
            if ($line -match '^(?i)Proxy-Authenticate:\s*(.+)$') {
                $head = ($Matches[1] -split '[ ,]')[0]
                if ($head) { [void]$schemes.Add($head.Trim()) }
            }
        }
    } catch {
        # Fall through - return whatever we got (possibly empty).
    } finally {
        try { $tcp.Close() } catch { }
    }

    return $schemes.ToArray()
}

function Invoke-HttpWebRequestBasic {
    <#
        Performs an HTTP GET of $Url through $ProxyUrl using Basic proxy
        authentication. On PS 5.1 / .NET Framework, setting the
        "Proxy-Authorization" header manually is unreliable - the stack
        re-authenticates via Proxy.Credentials during the CONNECT handshake
        and ignores/overwrites the manually set header. The correct pattern
        is:
          - Build a CredentialCache explicitly bound to (proxyUri, "Basic").
          - Attach it to a WebProxy and assign that to HttpWebRequest.Proxy.
        This lets HttpWebRequest respond to the 407 challenge with a proper
        Basic token on the retried CONNECT.
    #>
    param(
        [string]$Url,
        [string]$ProxyUrl,
        [string]$UserName,
        [string]$Password,
        [int]$TimeoutSec
    )

    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method            = 'GET'
    $req.Timeout           = $TimeoutSec * 1000
    $req.ReadWriteTimeout  = $TimeoutSec * 1000
    $req.AllowAutoRedirect = $true
    $req.UserAgent         = 'AC-FW-Check/1.0'

    if ($ProxyUrl) {
        $proxyUri = [Uri]$ProxyUrl
        $netCred  = New-Object System.Net.NetworkCredential($UserName, $Password)
        $cache    = New-Object System.Net.CredentialCache
        $cache.Add($proxyUri, 'Basic', $netCred)

        $proxy = New-Object System.Net.WebProxy($proxyUri, $true)
        $proxy.Credentials = $cache
        $req.Proxy = $proxy
    } else {
        # No system proxy configured - send the header directly.
        $token   = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $UserName, $Password))
        $encoded = [Convert]::ToBase64String($token)
        $req.Headers['Proxy-Authorization'] = "Basic $encoded"
    }

    $resp = $req.GetResponse()   # Throws WebException on HTTP failure; caller handles.
    try {
        return [int]$resp.StatusCode
    } finally {
        $resp.Close()
    }
}

function Invoke-RawConnectBasic {
    <#
        Opens a raw TCP connection to $ProxyUrl, sends a CONNECT request with
        an explicit Basic Proxy-Authorization header, and returns the full
        request/response wire trace as a diagnostic object:

          {
            StatusCode    : 200|407|... (int or $null)
            StatusLine    : "HTTP/1.1 407 Proxy Authentication Required"
            ResponseLines : @("HTTP/1.1 407 ...", "Proxy-Authenticate: Basic ...", ...)
            ResponseBody  : string body after headers (truncated to 1024 chars)
            SentRequest   : the exact bytes sent, with the Basic token masked
            Error         : exception message, or $null on success
          }

        This bypasses HttpWebRequest entirely so we can see *exactly* what the
        proxy says back when it rejects our credentials - useful when Basic is
        advertised but still returns 407.
    #>
    param(
        [string]$ProxyUrl,
        [string]$TargetUrl,
        [string]$UserName,
        [string]$Password,
        [int]$TimeoutSec = 10
    )

    $result = [PSCustomObject]@{
        StatusCode    = $null
        StatusLine    = $null
        ResponseLines = @()
        ResponseBody  = $null
        SentRequest   = $null
        Error         = $null
    }

    try {
        $proxyUri  = [Uri]$ProxyUrl
        $targetUri = [Uri]$TargetUrl
    } catch {
        $result.Error = "Invalid URL: $($_.Exception.Message)"
        return $result
    }

    $proxyHost = $proxyUri.Host
    $proxyPort = if ($proxyUri.Port -gt 0) { $proxyUri.Port } else { 8080 }
    $tgtHost   = $targetUri.Host
    $tgtPort   = if ($targetUri.Port -gt 0) { $targetUri.Port } else { 443 }

    $token   = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $UserName, $Password))
    $encoded = [Convert]::ToBase64String($token)
    $maskedEncoded = if ($encoded.Length -gt 8) { $encoded.Substring(0,4) + '...' + $encoded.Substring($encoded.Length - 4) } else { '***' }

    $req = ("CONNECT {0}:{1} HTTP/1.1`r`n" `
          + "Host: {0}:{1}`r`n" `
          + "Proxy-Authorization: Basic {2}`r`n" `
          + "User-Agent: AC-FW-Check/1.0`r`n" `
          + "Proxy-Connection: close`r`n`r`n") -f $tgtHost, $tgtPort, $encoded

    $result.SentRequest = ($req -replace [regex]::Escape($encoded), $maskedEncoded)

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.SendTimeout    = $TimeoutSec * 1000
        $tcp.ReceiveTimeout = $TimeoutSec * 1000
        $async = $tcp.BeginConnect($proxyHost, $proxyPort, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSec * 1000, $false)) {
            $result.Error = "TCP connect timeout to ${proxyHost}:${proxyPort}"
            return $result
        }
        $tcp.EndConnect($async)

        $stream = $tcp.GetStream()
        $stream.ReadTimeout  = $TimeoutSec * 1000
        $stream.WriteTimeout = $TimeoutSec * 1000

        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        $lines  = New-Object System.Collections.Generic.List[string]

        $first = $reader.ReadLine()
        if ($null -ne $first) {
            $result.StatusLine = $first
            $lines.Add($first)
            if ($first -match '^HTTP/\d\.\d\s+(\d{3})') {
                $result.StatusCode = [int]$Matches[1]
            }
            while ($true) {
                $hdr = $reader.ReadLine()
                if ($null -eq $hdr -or $hdr -eq '') { break }
                $lines.Add($hdr)
            }
        }
        $result.ResponseLines = $lines.ToArray()

        # Read up to 1024 chars of body (proxies usually return a short HTML page).
        $bodyBuf = New-Object char[] 1024
        $readChars = 0
        try { $readChars = $reader.Read($bodyBuf, 0, $bodyBuf.Length) } catch { }
        if ($readChars -gt 0) {
            $result.ResponseBody = (New-Object string($bodyBuf, 0, $readChars)).Trim()
        }
    } catch {
        $result.Error = $_.Exception.Message
    } finally {
        try { $tcp.Close() } catch { }
    }

    return $result
}

function Invoke-ProxyAuthRetry {
    <#
        Retries a GET against $Url through the system proxy, supplying
        credentials according to $Mode:
          - 'Integrated': current Windows user (Negotiate/Kerberos/NTLM) via
                          Invoke-WebRequest -UseDefaultCredentials.
          - 'Basic'     : UserName/Password/Domain loaded from the UiPath
                          proxy configuration files. Sent as an explicit
                          "Proxy-Authorization: Basic ..." header using
                          HttpWebRequest directly (see Invoke-HttpWebRequestBasic
                          for why). When Domain is present, both the plain
                          UserName and "Domain\UserName" forms are tried,
                          because proxy admins configure this inconsistently.
                          Returns $null when no credentials are available on
                          disk so the caller can fall back to the next mode.

        Returns a result object in the same shape as Test-UrlConnection, or
        $null when the mode is not applicable for this environment.
    #>
    param(
        [string]$Url,
        [int]$TimeoutSec,
        [ValidateSet('Integrated','Basic')]
        [string]$Mode,
        [string]$SchemesLabel
    )

    $proxyUrl = Get-SystemProxyForUrl -Url $Url

    if ($Mode -eq 'Integrated') {
        $iwrParams = @{
            Uri                        = $Url
            Method                     = 'Get'
            UseBasicParsing            = $true
            TimeoutSec                 = $TimeoutSec
            MaximumRedirection         = 5
            ErrorAction                = 'Stop'
            UseDefaultCredentials      = $true
            ProxyUseDefaultCredentials = $true
        }
        if ($proxyUrl) { $iwrParams['Proxy'] = $proxyUrl }

        $credLabel = 'OS credentials'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $resp = Invoke-WebRequest @iwrParams
            $sw.Stop()
            return [PSCustomObject]@{
                Status    = 'Pass'
                Detail    = "HTTP $([int]$resp.StatusCode) (proxy auth via $SchemesLabel, $credLabel)"
                ElapsedMs = [int]$sw.ElapsedMilliseconds
            }
        } catch {
            $sw.Stop()
            return ConvertFrom-ProxyRetryException -ErrorRecord $_ `
                                                   -ElapsedMs ([int]$sw.ElapsedMilliseconds) `
                                                   -SchemesLabel $SchemesLabel `
                                                   -CredLabel $credLabel
        }
    }

    # --- Basic mode --------------------------------------------------
    $uiCred = Get-UiPathProxyCredential
    if ($null -eq $uiCred) { return $null }

    $sourceLeaf = Split-Path -Leaf $uiCred.Source
    $variants   = @(Get-BasicUserNameVariants -Credential $uiCred)
    $lastResult = $null
    $index      = 0

    foreach ($userName in $variants) {
        $index++
        $variantLabel = if ($userName -eq [string]$uiCred.UserName) { 'user' } else { 'domain\user' }
        $credLabel    = "UiPath Basic credentials from $sourceLeaf ($variantLabel $index/$($variants.Count): $userName)"

        # Verbose wire-level diagnostic: show exactly what the proxy says back
        # when Basic with this username is offered. We log each username
        # variant once (across the whole run) so the console shows both the
        # "user" and "domain\user" probe without repeating per-URL. This is
        # gated behind -DebugProxyAuth because the request trace includes a
        # (masked but partially visible) Base64 token and the proxy's error
        # page body verbatim.
        if ($script:DebugProxyAuthEnabled -and $script:BasicProbeLoggedVariants.Add($userName)) {
            $probeProxy = $proxyUrl
            if ($probeProxy) {
                $trace = Invoke-RawConnectBasic -ProxyUrl $probeProxy `
                                                -TargetUrl $Url `
                                                -UserName $userName `
                                                -Password ([string]$uiCred.Password) `
                                                -TimeoutSec $TimeoutSec
                Write-Host ""
                Write-Host ("[Debug] Raw CONNECT trace (user={0}) -> {1}" -f $userName, $probeProxy) -ForegroundColor Magenta
                Write-Host "[Debug] --- Request sent (Base64 masked) ---" -ForegroundColor Magenta
                foreach ($ln in ($trace.SentRequest -split "`r`n")) {
                    if ($ln -ne '') { Write-Host ("[Debug] > {0}" -f $ln) -ForegroundColor DarkMagenta }
                }
                Write-Host "[Debug] --- Response ---" -ForegroundColor Magenta
                if ($trace.Error) {
                    Write-Host ("[Debug] ERROR: {0}" -f $trace.Error) -ForegroundColor Red
                } else {
                    foreach ($ln in $trace.ResponseLines) {
                        Write-Host ("[Debug] < {0}" -f $ln) -ForegroundColor DarkMagenta
                    }
                    if ($trace.ResponseBody) {
                        Write-Host "[Debug] --- Response body (truncated 1024) ---" -ForegroundColor Magenta
                        foreach ($ln in ($trace.ResponseBody -split "`r?`n")) {
                            Write-Host ("[Debug] | {0}" -f $ln) -ForegroundColor DarkMagenta
                        }
                    }
                }
                Write-Host ""
            }
        }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $statusCode = Invoke-HttpWebRequestBasic -Url $Url `
                                                    -ProxyUrl $proxyUrl `
                                                    -UserName $userName `
                                                    -Password ([string]$uiCred.Password) `
                                                    -TimeoutSec $TimeoutSec
            $sw.Stop()
            if ($statusCode -ge 200 -and $statusCode -lt 400) {
                return [PSCustomObject]@{
                    Status    = 'Pass'
                    Detail    = "HTTP $statusCode (proxy auth via $SchemesLabel, $credLabel)"
                    ElapsedMs = [int]$sw.ElapsedMilliseconds
                }
            }
            $lastResult = [PSCustomObject]@{
                Status    = 'Warn'
                Detail    = "HTTP $statusCode after proxy auth via $SchemesLabel, $credLabel (server returned error)"
                ElapsedMs = [int]$sw.ElapsedMilliseconds
            }
        } catch {
            $sw.Stop()
            $attemptResult = ConvertFrom-ProxyRetryException -ErrorRecord $_ `
                                                             -ElapsedMs ([int]$sw.ElapsedMilliseconds) `
                                                             -SchemesLabel $SchemesLabel `
                                                             -CredLabel $credLabel
            $lastResult = $attemptResult
            # Only a 407 (still rejected) warrants trying the next username
            # variant - other failures won't change with a different username.
            if ($attemptResult.Status -eq 'Fail' -and
                $attemptResult.Detail -match '^HTTP 407\b') {
                continue
            }
            return $attemptResult
        }
    }

    return $lastResult
}

function ConvertFrom-ProxyRetryException {
    <#
        Shared translator from an Invoke-WebRequest / HttpWebRequest failure
        into a Test-UrlConnection-shaped result object. Used by both the
        Integrated and Basic retry paths so they format their results
        identically.
    #>
    param(
        $ErrorRecord,
        [int]$ElapsedMs,
        [string]$SchemesLabel,
        [string]$CredLabel
    )

    $code = Get-HttpStatusFromError -ErrorRecord $ErrorRecord
    if ($null -ne $code) {
        if ($code -eq 407) {
            return [PSCustomObject]@{
                Status    = 'Fail'
                Detail    = "HTTP 407 after retry ($SchemesLabel, $CredLabel rejected)"
                ElapsedMs = $ElapsedMs
            }
        }
        if ($code -ge 200 -and $code -lt 400) {
            return [PSCustomObject]@{
                Status    = 'Pass'
                Detail    = "HTTP $code (proxy auth via $SchemesLabel, $CredLabel)"
                ElapsedMs = $ElapsedMs
            }
        }
        return [PSCustomObject]@{
            Status    = 'Warn'
            Detail    = "HTTP $code after proxy auth via $SchemesLabel, $CredLabel (server returned error)"
            ElapsedMs = $ElapsedMs
        }
    }
    return [PSCustomObject]@{
        Status    = 'Fail'
        Detail    = "Proxy auth retry failed ($SchemesLabel, $CredLabel): $($ErrorRecord.Exception.Message)"
        ElapsedMs = $ElapsedMs
    }
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
            if ($code -eq 403) {
                $respForHeaders = $null
                try { $respForHeaders = $ex.Response } catch { }

                $fromProxy = Test-ResponseIsFromProxy -Response $respForHeaders

                # Body-level fallback: HTTPS CONNECT failures often do not
                # surface the proxy's response headers on PowerShell 5.1,
                # but the HTML error page body is still available via
                # ErrorDetails.Message.
                if (-not $fromProxy) {
                    $body = Get-ErrorResponseBody -ErrorRecord $err
                    if (Test-BodyIsFromProxy -Body $body) { $fromProxy = $true }
                }

                if ($fromProxy) {
                    return [PSCustomObject]@{
                        Status    = 'Fail'
                        Detail    = 'HTTP 403 from intermediate proxy (blocked upstream)'
                        ElapsedMs = $elapsedMs
                    }
                }

                return [PSCustomObject]@{
                    Status    = 'Warn'
                    Detail    = 'HTTP 403 (reachable / server returned error)'
                    ElapsedMs = $elapsedMs
                }
            }
            if ($code -eq 407) {
                $schemes = Get-ProxyAuthSchemes -ErrorRecord $err
                if (($schemes.Count -eq 0) -and $script:ProbedProxySchemes -and $script:ProbedProxySchemes.Count -gt 0) {
                    # Fall back to the CONNECT-probe result captured at startup.
                    $schemes = $script:ProbedProxySchemes
                }
                $schemesLabel = if ($schemes.Count -gt 0) { ($schemes -join ', ') } else { 'unknown' }

                # Attempt order: Integrated (OS credentials) first, then Basic
                # (credentials from UiPath proxy config files). A 407 outcome on
                # one attempt falls through to the next; any other outcome
                # short-circuits.
                #
                # When the Proxy-Authenticate header cannot be read (schemes =
                # unknown, common on PowerShell 5.1 for HTTPS CONNECT failures),
                # we fall back to a best-effort attempt of both modes rather
                # than giving up - the proxy will accept whichever scheme it
                # actually supports.
                $schemesUnknown = ($schemes.Count -eq 0)

                $attempts = @()
                if ($schemesUnknown -or (Test-ProxySchemeIsIntegrated -Schemes $schemes)) {
                    $attempts += @{ Mode = 'Integrated' }
                }
                if ($schemesUnknown -or (Test-ProxySchemeIsBasic -Schemes $schemes)) {
                    $attempts += @{ Mode = 'Basic' }
                }

                $lastResult = $null
                foreach ($attempt in $attempts) {
                    $attemptResult = Invoke-ProxyAuthRetry -Url $Url `
                                                          -TimeoutSec $TimeoutSec `
                                                          -Mode $attempt.Mode `
                                                          -SchemesLabel $schemesLabel
                    if ($null -eq $attemptResult) { continue }  # Mode unavailable (e.g. no creds on disk).
                    $lastResult = $attemptResult
                    if ($attemptResult.Status -ne 'Fail' -or
                        $attemptResult.Detail -notmatch '^HTTP 407\b') {
                        return $attemptResult
                    }
                }

                if ($null -ne $lastResult) { return $lastResult }

                return [PSCustomObject]@{
                    Status    = 'Fail'
                    Detail    = "HTTP 407 (proxy authentication required; scheme=$schemesLabel)"
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

# Script-wide state used by the proxy-auth retry path. Initialised up-front
# (instead of lazily inside the retry loop) so any first-use ordering is
# obvious and so the CONNECT trace below shares the same "already logged"
# set as the per-URL retries.
$script:DebugProxyAuthEnabled    = [bool]$DebugProxyAuth
$script:ProbedProxySchemes       = @()
$script:BasicProbeLoggedVariants = New-Object System.Collections.Generic.HashSet[string]

# One-time proxy-authentication probe. Runs a raw CONNECT against the system
# proxy for a representative target so we can read the Proxy-Authenticate
# header values directly - Invoke-WebRequest on PS 5.1 hides them on HTTPS
# CONNECT 407. The result is shown to the operator and cached for the 407
# handler to consult when its own scheme detection comes up empty.
try {
    $probeTarget = 'https://cloud.uipath.com'
    $probeProxy  = Get-SystemProxyForUrl -Url $probeTarget
    if ($probeProxy) {
        $script:ProbedProxySchemes = Get-ProxyAuthSchemesFromConnect `
                                        -ProxyUrl $probeProxy `
                                        -TargetUrl $probeTarget `
                                        -TimeoutSec 5
        if ($script:ProbedProxySchemes -and $script:ProbedProxySchemes.Count -gt 0) {
            Write-Host ("[Info] Proxy auth schemes advertised by {0}: {1}" `
                            -f $probeProxy, ($script:ProbedProxySchemes -join ', ')) `
                       -ForegroundColor DarkCyan
        } else {
            Write-Host ("[Info] Proxy {0} did not advertise any Proxy-Authenticate scheme on CONNECT probe." `
                            -f $probeProxy) -ForegroundColor DarkCyan
        }
    } else {
        Write-Host "[Info] No system proxy configured for probe target." -ForegroundColor DarkCyan
    }
} catch {
    Write-Host ("[Info] Proxy auth probe failed: {0}" -f $_.Exception.Message) -ForegroundColor DarkCyan
}

# Pre-load UiPath proxy credentials eagerly so the "Loaded proxy credentials"
# line prints cleanly at startup instead of interleaving with a [Chk ] line
# (which uses -NoNewline) on the first 407 retry.
[void](Get-UiPathProxyCredential)
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
