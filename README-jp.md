# UiPath Automation Cloud Firewall Check

[English version](./README.md)

UiPath Automation Cloud をネットワークから利用するために許可が必要な URL 群に対し、現在の環境から実際にアクセスできるかを PowerShell で一括チェックし、結果を CSV に出力するスクリプトです。

参照: [Automation Cloud のファイアウォール設定 (UiPath 公式ドキュメント)](https://docs.uipath.com/ja/automation-cloud/automation-cloud/latest/admin-guide/configuring-the-firewall-for-cloud)

---

## 主な機能

- 公式ドキュメントに記載された許可対象 URL 一式に対して HTTP(S) で疎通確認
- **重複した URL は 1 回だけ** チェック
- **ワイルドカード (`*`) を含む URL はスキップ** （FQDN が確定しないため）
- `wss://` は `https://` に正規化して同一ポート (443) で疎通確認
- 各 URL の **応答時間 (ms)** を計測して記録
- 結果を **UTF-8 BOM 付き CSV** に出力（Excel でそのまま開いても文字化けしない）
- 判定区分は **Pass / Warn / Fail / Skip** の 4 種類

---

## 前提環境

| 項目 | 条件 |
|---|---|
| OS | Windows 10 / 11, Windows Server 2016+ |
| PowerShell | Windows PowerShell 5.1 または PowerShell 7.x どちらも動作 |
| ネットワーク | チェック対象 URL へ HTTPS (443 / 80) で発信可能であること |
| プロキシ | システム設定のプロキシ (IE/Edge 設定) が自動で使われます |

> ※ 社内プロキシ経由では一部 URL が 4xx/5xx を返す場合があります（`Warn` 扱い）。疎通そのものは成立しているため、ファイアウォール要件としては到達可能と判断できます。

---

## 使い方

### 1. スクリプトを実行

```powershell
# カレントディレクトリにスクリプトがある場合
powershell -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1

# 出力先や接続タイムアウトを指定する場合
powershell -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1 `
    -OutputPath ".\result.csv" `
    -TimeoutSec 20
```

PowerShell 7 で実行する場合は `pwsh` を使ってください。

```powershell
pwsh -ExecutionPolicy Bypass -File .\Check-AutomationCloudFirewall.ps1
```

### 2. 実行中の表示

各 URL のチェック結果がリアルタイムにコンソールに表示されます（末尾は応答時間）。スクリプト本体のメッセージは英語で出力されます。

```
[Chk ] https://cloud.uipath.com  => Pass (HTTP 200) [128 ms]
[Chk ] https://platform-cdn.uipath.com  => Warn (HTTP 400 (reachable / server returned error)) [308 ms]
[Chk ] https://service.signalr.net  => Fail (DNS resolution failure) [45 ms]
[Skip] *-signalr.service.signalr.net
[Dup ] account.uipath.com
```

末尾にサマリが表示されます。

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

## パラメーター

| 名前 | 既定値 | 説明 |
|---|---|---|
| `-OutputPath` | `{スクリプトと同じフォルダ}\AutomationCloudFirewall-CheckResult.csv` | CSV の出力先パス |
| `-TimeoutSec` | `15` | 1 URL あたりの接続タイムアウト秒数 |

---

## CSV 出力項目

CSV のヘッダー行は英語です。

| 列 (CSV ヘッダー) | 内容 |
|---|---|
| `URL` | 正規化後のチェック対象 URL（`wss://` → `https://` 変換済み、末尾 `/` 除去） |
| `Purpose` | そのドメインが使用されるサービス名 / 用途 |
| `Result` | `Pass` / `Warn` / `Fail` / `Skip` |
| `ResponseTimeMs` | リクエスト発行から応答受信 / エラー検知までの所要時間（ミリ秒）。`Skip` の場合は空欄 |
| `Detail` | ステータスコード、またはエラー内容 |

### 判定ルール

| 判定 | 意味 | 代表的なケース |
|---|---|---|
| **Pass** | HTTP 2xx / 3xx で正常応答。ネットワーク到達 OK | `HTTP 200`, `HTTP 301` |
| **Warn** | HTTP 4xx / 5xx 応答。**ネットワークは到達している** がサーバ側でエラー応答 | `HTTP 400`, `HTTP 401`, `HTTP 403`, `HTTP 404`, `HTTP 500` |
| **Fail** | **ネットワーク到達不可**、またはプロキシ認証が必要。ファイアウォール / プロキシ / DNS の問題が疑われる | タイムアウト / 名前解決失敗 / 接続拒否 / SSL・TLS エラー / **HTTP 407 (プロキシ認証要求)** |
| **Skip** | チェック対象外 | URL にワイルドカード `*` を含む |

> **HTTP 407 の扱い**: `407 Proxy Authentication Required` はプロキシが認証を要求している状態で、UiPath のエンドポイントまでの到達が成立していません。ファイアウォール要件を満たさないため **Fail** として扱います。プロキシに認証情報を設定したうえで再実行してください。

> **ポイント**: ファイアウォール要件の観点では **Warn は許容** です。4xx/5xx は「サーバに到達した上で認証が必要」「そもそもルートパスにコンテンツがない」といった理由で発生するためで、到達性に問題はありません。
>
> **Fail が出た URL は通信経路が遮断されている可能性が高い** ため、ファイアウォール / プロキシの設定を見直してください。

### Skip された URL の扱い

ワイルドカードを含む URL（例: `*.blob.core.windows.net`）はチェック対象外ですが、**実環境では必ず許可が必要です**。
代表的な FQDN を個別に追加チェックしたい場合は、スクリプト内の `$urlList` に具体的な FQDN を追加してください。

---

## CSV 例

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

## トラブルシューティング

### CSV 書き込みに失敗する

前回の結果 CSV を Excel で開いたまま再実行すると書き込みに失敗します。その場合、自動的に `AutomationCloudFirewall-CheckResult_yyyyMMdd_HHmmss.csv` のようなタイムスタンプ付きファイル名にフォールバックして保存されます。コンソールの `CSV:` 行に実際の保存パスが表示されます。

### すべての URL が Fail になる

- プロキシ環境の場合は PowerShell にプロキシ設定が反映されているか確認してください。
- 会社のセキュリティ製品による SSL インスペクションが原因で SSL/TLS エラーになっているケースがあります。その場合は信頼された CA のインストール状況を確認してください。

### ExecutionPolicy で実行できない

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Check-AutomationCloudFirewall.ps1
```

のように一時的に Bypass にするか、`powershell -ExecutionPolicy Bypass -File ...` で起動してください。

---

## 注意事項

- スクリプト内の URL 一覧は、作成時点（2026-04-26）の公式ドキュメントに基づいて埋め込まれています。UiPath 側で更新された場合は追従のため `$urlList` を編集してください。
- IP アドレスベースの許可リスト（Integration Service の送信 IP 範囲など）はこのスクリプトでは扱っていません。公式ドキュメントを直接ご参照ください。
- このスクリプトはネットワーク経路上の到達性確認のみを行います。UiPath 各サービスの機能が実際に問題なく動作するかは、Automation Cloud 上で当該機能を実行して確認してください。

---

## ファイル構成

```
AC_FW_Check/
├─ Check-AutomationCloudFirewall.ps1                  # 本体スクリプト
├─ AutomationCloudFirewall-CheckResult.csv            # 実行結果 (初回実行後に生成)
├─ README-jp.md                                       # 本ドキュメント (日本語)
└─ README.md                                          # 本ドキュメント (英語)
```
