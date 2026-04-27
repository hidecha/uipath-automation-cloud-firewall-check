# UiPath Automation Cloud Firewall Check

[日本語版](./README-jp.md)

A PowerShell script that checks, in bulk, whether the URLs that must be allowed through the firewall to use UiPath Automation Cloud are actually reachable from the current environment, and writes the result to a CSV file.

Reference: [Configuring the firewall for Automation Cloud (UiPath official documentation)](https://docs.uipath.com/automation-cloud/automation-cloud/latest/admin-guide/configuring-the-firewall-for-cloud)

---

## Features

- HTTP(S) reachability check against every URL listed in the official documentation.
- **Duplicate URLs are checked only once.**
- **URLs that contain a wildcard (`*`) are skipped** (because the FQDN cannot be determined).
- `wss://` URLs are normalized to `https://` and tested on the same port (443).
- **Response time (ms)** is measured and recorded for every URL.
- Output is written as a **UTF-8 BOM CSV** (opens cleanly in Excel without garbling).
- Four result categories: **Pass / Warn / Fail / Skip**.
- **HTTP 407 (proxy authentication required) is retried automatically**:
  - **Negotiate / Kerberos / NTLM** → the current Windows user's credentials
    (Windows Integrated Authentication).
  - **Basic** → credentials read from the local UiPath proxy configuration
    files (`C:\ProgramData\UiPath\Shared\proxy.json`, with
    `C:\Program Files\UiPath\Studio\uipath.config` as a fallback). Both the
    plain `UserName` and `Domain\UserName` forms are tried when a Domain is
    configured, because proxies differ in which form they expect.
  - No interactive prompt is shown.
- **HTTP 403 is split** into `Fail` (blocked by an intermediate proxy) and
  `Warn` (returned by the origin web server). For HTTPS targets the decision
  is made by a socket-level `CONNECT` probe against the system proxy, which
  makes the result identical across Windows PowerShell 5.1 and PowerShell 7+.
- **Proxy-detection diagnostic lines** (scheme list and the loaded proxy
  credentials, with the password masked) are appended to the CSV after the
  data rows, separated by a blank line.

---

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows 10 / 11, Windows Server 2016+ |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7.x (both work) |
| Network | Outbound HTTPS (443 / 80) must be permitted to the target URLs |
| Proxy | The system proxy (IE/Edge settings) is used automatically. Kerberos / NTLM / Negotiate proxies are supported with the current Windows credentials. Basic-authentication proxies are supported by reading credentials from the local UiPath config files (see [HTTP 407 handling](#about-http-407)). |

> Some URLs may return 4xx/5xx through a corporate proxy and will be reported as `Warn`. Reachability itself is established, so for firewall requirement purposes the target can be considered reachable.
>
> **HTTP 403** is special-cased: a 403 produced by an intermediate proxy (blocking upstream) is reported as `Fail`, while a 403 returned by the origin web server is reported as `Warn` (see *Decision rules* below).

---

## Usage

### 1. Run the script

```powershell
# When the script is in the current directory
powershell -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1

# Specify an output path and connection timeout
powershell -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1 `
    -OutputPath ".\result.csv" `
    -TimeoutSec 20
```

Use `pwsh` if you are running PowerShell 7.

```powershell
pwsh -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1
```

### 2. Runtime output

Each URL result is printed to the console in real time (the trailing value is the response time).

```
[Chk ] https://cloud.uipath.com  => Pass (HTTP 200) [128 ms]
[Chk ] https://platform-cdn.uipath.com  => Warn (HTTP 400 (reachable / server returned error)) [308 ms]
[Chk ] https://service.signalr.net  => Fail (DNS resolution failure) [45 ms]
[Skip] *-signalr.service.signalr.net
[Dup ] account.uipath.com
```

A summary is printed at the end.

```
Done.
Total : 139
Output: 127
Pass  : 41
Warn  : 52
Fail  : 3
Skip  : 31

CSV: C:\...\AutomationCloudFirewall-CheckResult.csv
```

---

## Parameters

| Name | Default | Description |
|---|---|---|
| `-OutputPath` | `{script folder}\AutomationCloudFirewall-CheckResult.csv` | Destination path of the CSV |
| `-TimeoutSec` | `15` | Connection timeout (seconds) per URL |
| `-DebugProxyAuth` | off | Prints a wire-level CONNECT trace for each Basic-auth variant. Use only when investigating a 407 - the trace includes the proxy's error page body and a partially masked Base64 token. |

---

## CSV columns

| Column | Content |
|---|---|
| `URL` | The normalized URL that was checked (`wss://` converted to `https://`, trailing `/` stripped) |
| `Purpose` | The UiPath service or purpose the domain is used for |
| `Result` | `Pass` / `Warn` / `Fail` / `Skip` |
| `ResponseTimeMs` | Time from request issue to response / error detection, in milliseconds. Empty for `Skip` |
| `Detail` | HTTP status code, or error details |

### Decision rules

| Result | Meaning | Typical cases |
|---|---|---|
| **Pass** | HTTP 2xx / 3xx response. Network reachability OK. | `HTTP 200`, `HTTP 301` |
| **Warn** | HTTP 4xx / 5xx response returned by the **origin web server**. The network is reachable; the server itself responded with an error. | `HTTP 400`, `HTTP 401`, `HTTP 403` (from origin), `HTTP 404`, `HTTP 500` |
| **Fail** | **Network unreachable**, or the request was blocked / authenticated by an intermediate proxy. The firewall / proxy / DNS is likely to blame. | Timeout / DNS failure / connection refused / SSL/TLS error / **HTTP 407 (proxy authentication rejected after integrated-auth retry)** / **HTTP 403 returned by an intermediate proxy** |
| **Skip** | Not checked | URL contains the wildcard `*` |

<a id="about-http-407"></a>
> **About HTTP 407**: `407 Proxy Authentication Required` means the proxy is
> requesting authentication. The script retries the request based on what the
> proxy advertises in `Proxy-Authenticate`:
> - **Negotiate / Kerberos / NTLM** — retried with the **current Windows user's
>   credentials** (Integrated Authentication).
> - **Basic** — retried with credentials read from the local UiPath proxy
>   configuration files, in this priority order:
>   1. `C:\ProgramData\UiPath\Shared\proxy.json`
>   2. `C:\Program Files\UiPath\Studio\uipath.config` (the `<webProxySettings>` section)
>
>   If a `Domain` is present in the file, both `UserName` and
>   `Domain\UserName` are tried (proxies differ in the form they accept). If
>   `Domain` is empty, only the plain `UserName` is sent.
>
> At startup the script runs a one-shot CONNECT probe to the system proxy so
> it can still pick the right retry path on PowerShell 5.1, which otherwise
> hides the `Proxy-Authenticate` header on HTTPS CONNECT failures. The probe
> result is printed as `[Info] Proxy auth schemes advertised by ...`.
>
> If the retry succeeds, the URL is reported as **Pass** (or **Warn** for a
> 4xx/5xx from the origin). If every retry is still rejected, the URL is
> reported as **Fail**.

> **About HTTP 403**: A 403 response is classified by looking at who returned it:
> - **Fail** — the 403 came from an intermediate proxy. The request was blocked before reaching the origin, so the firewall/proxy requirement is not satisfied.
> - **Warn** — the 403 came from the origin web server. Reachability itself is fine; the server simply returned 403 for an unauthenticated GET against the root path.
>
> Proxy-origin detection is **skipped when no system proxy is configured** for the URL, because in that case a 403 cannot have come from a corporate blocking proxy. This avoids false `Fail` results when the origin or its CDN happens to emit headers or error-page text the generic heuristics would otherwise pick up (e.g. Azure Front Door in front of `pkgs.dev.azure.com` returning `X-Cache` headers or the word `gateway` in its error page).
>
> For **HTTPS** targets with a proxy configured, the decision is made by a
> socket-level `CONNECT host:443` probe against the system proxy:
> - The proxy returns `2xx` → the tunnel is allowed → the 403 must have come from origin → `Warn`.
> - The proxy returns `4xx/5xx` (excluding `401/407`) → the proxy itself refuses the tunnel → `Fail`.
> - The proxy returns `407` / `401` → auth challenge to our unauthenticated probe (inconclusive). Fall back to the elapsed-time tiebreaker: a proxy rejection returns from the LAN in a few milliseconds, while an end-to-end origin 403 carries internet-scale RTT (the cutoff is 50 ms).
>
> Using the socket-level answer means the classification is **identical on Windows PowerShell 5.1 and PowerShell 7+**, which previously differed because the two runtimes surface different amounts of proxy-side information on a failed response.
>
> For **HTTP** targets (no tunnel), the classification falls back to the
> classic header/body heuristics: `Via`, `Proxy-Connection`, `X-Cache`,
> `X-Cache-Lookup`, a `Server` header containing `proxy` / `cache` /
> `gateway`, or body markers such as `cache administrator` or
> `requested URL could not be retrieved`.

> **Tip**: From a firewall requirement standpoint, **`Warn` is acceptable**. 4xx/5xx commonly happen when the server requires authentication or when the root path simply serves no content, and do not indicate a reachability problem.
>
> **URLs that come back as `Fail` are most likely being blocked** somewhere along the path - review the firewall and proxy configuration.

### Handling of skipped URLs

Wildcard URLs (e.g. `*.blob.core.windows.net`) are not checked directly, but **they still must be allowed in the real environment**. If you want to check a specific FQDN, add it to `$urlList` inside the script.

---

## Sample CSV

```csv
URL,Purpose,Result,ResponseTimeMs,Detail
https://account.uipath.com,Automation Cloud portal / Basic authentication sign-in,Pass,1271,HTTP 200
https://cloud.uipath.com,Automation Cloud portal / Basic authentication sign-in,Pass,128,HTTP 200
https://platform-cdn.uipath.com,Automation Cloud portal / Basic authentication sign-in,Warn,308,HTTP 400 (reachable / server returned error)
*-signalr.service.signalr.net,Automation Cloud portal / UiPath Assistant sign-in,Skip,,Contains wildcard - not checked directly
https://service.signalr.net,Task Mining / SignalR,Fail,45,DNS resolution failure
https://gallery.uipath.com,Automation Cloud portal / UiPath Studio sign-in,Fail,4,HTTP 403 from intermediate proxy (blocked upstream)
https://example.proxy-required.local,(proxy auth required),Fail,12,HTTP 407 after retry (Negotiate, OS credentials rejected)

[Info] Proxy auth schemes advertised by http://proxy01.lab.test:8080/: Negotiate
[Info] Loaded proxy credentials: Source=C:\Program Files\UiPath\Studio\uipath.config, UserName=admin01, Domain=(empty), Password=***, ProxyAddress=http://proxy01.lab.test:8080
```

> **Note**: The CSV footer includes the detected proxy scheme, credential
> source file, and user name (the password is always masked as `***`).
> Review the footer before sharing the CSV externally if those details are
> considered sensitive in your environment.

---

## Troubleshooting

### CSV write fails

If the previous result CSV is still open in Excel, the write will fail. In that case the script automatically falls back to a timestamped filename such as `AutomationCloudFirewall-CheckResult_yyyyMMdd_HHmmss.csv`. The actual saved path is printed on the `CSV:` line in the console.

### Every URL comes back as Fail

- In a proxy environment, confirm that PowerShell is picking up the proxy configuration.
- Corporate SSL inspection appliances may cause SSL/TLS errors. If so, verify that the enterprise root CA is installed in the trust store.

### Every URL fails with `HTTP 407 ... rejected`

The proxy is requesting authentication but your credentials are not being accepted.

1. Check the `[Info] Loaded proxy credentials:` line printed at startup. If it reports `No UiPath proxy credentials found`, place a valid `proxy.json` at `C:\ProgramData\UiPath\Shared\proxy.json` (or populate `<webProxySettings>` in `C:\Program Files\UiPath\Studio\uipath.config`).
2. Check the `[Info] Proxy auth schemes advertised by ...` line. If it lists something other than `Basic` / `Negotiate` / `NTLM` / `Kerberos`, the proxy is using a scheme the script does not support.
3. Re-run with `-DebugProxyAuth` to see the full CONNECT trace (request and the proxy's error response) for each credential variant. The trace makes it easy to tell whether the password is wrong, the `Domain` field should be empty, or the proxy is rejecting the user account itself.

### Cannot run due to ExecutionPolicy

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Check-AutomationCloudFirewall.ps1
```

Temporarily set the scope to `Bypass`, or start the script with `powershell -ExecutionPolicy Bypass -File ...`.

---

## Notes

- The URL list embedded in the script is based on the official documentation as of 2026-04-26. If UiPath updates its documentation, edit `$urlList` to keep up.
- IP-based allow lists (such as the Integration Service outbound IP ranges) are out of scope for this script. Refer to the official documentation directly.
- This script only checks network-layer reachability. Whether UiPath services themselves function correctly has to be verified by actually using the relevant feature inside Automation Cloud.

---

## File layout

```
AC_FW_Check/
├─ Check-AutomationCloudFirewall.ps1                  # Main script
├─ AutomationCloudFirewall-CheckResult.csv            # Result (generated after the first run)
├─ README-jp.md                                       # Documentation (Japanese)
└─ README.md                                          # Documentation (English)
```
