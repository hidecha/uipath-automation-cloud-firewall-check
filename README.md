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

---

## Requirements

| Item | Requirement |
|---|---|
| OS | Windows 10 / 11, Windows Server 2016+ |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7.x (both work) |
| Network | Outbound HTTPS (443 / 80) must be permitted to the target URLs |
| Proxy | The system proxy (IE/Edge settings) is used automatically |

> Some URLs may return 4xx/5xx through a corporate proxy and will be reported as `Warn`. Reachability itself is established, so for firewall requirement purposes the target can be considered reachable.

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
| **Warn** | HTTP 4xx / 5xx response. **The network is reachable** but the server responded with an error. | `HTTP 400`, `HTTP 401`, `HTTP 403`, `HTTP 404`, `HTTP 500` |
| **Fail** | **Network unreachable**, or proxy authentication required. The firewall / proxy / DNS is likely to blame. | Timeout / DNS failure / connection refused / SSL/TLS error / **HTTP 407 (proxy authentication required)** |
| **Skip** | Not checked | URL contains the wildcard `*` |

> **About HTTP 407**: `407 Proxy Authentication Required` means the proxy is requesting authentication and the UiPath endpoint itself has not been reached. The firewall requirement is therefore **not** satisfied, so this is treated as **Fail**. Configure credentials on the proxy and re-run.

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
https://example.proxy-required.local,(proxy auth required),Fail,12,HTTP 407 (proxy authentication required)
```

---

## Troubleshooting

### CSV write fails

If the previous result CSV is still open in Excel, the write will fail. In that case the script automatically falls back to a timestamped filename such as `AutomationCloudFirewall-CheckResult_yyyyMMdd_HHmmss.csv`. The actual saved path is printed on the `CSV:` line in the console.

### Every URL comes back as Fail

- In a proxy environment, confirm that PowerShell is picking up the proxy configuration.
- Corporate SSL inspection appliances may cause SSL/TLS errors. If so, verify that the enterprise root CA is installed in the trust store.

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
