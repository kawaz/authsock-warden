# DR-014: macOS FDA (Full Disk Access) による TCC 問題の解決

- **Status**: Active
- **Date**: 2026-04-03

## 背景

[DR-012](DR-012-app-bundle-wrapper.md) で .app バンドル化を決定し、Bundle ID ベースの TCC 許可の永続化を実現した。しかし、1Password の op CLI が `~/Library/Group Containers/2BUA8C4S2C.com.1password/` にアクセスする際の TCC カテゴリが `kTCCServiceSystemPolicyAppData`（ほかのアプリからのデータへのアクセス権）であり、このカテゴリは .app バンドル化しても以下の問題が残った:

- **許可が永続化されない**: kTCCServiceSystemPolicyAppData の許可ダイアログは、LaunchAgent 経由で毎回表示される
- **バックグラウンドでダイアログが出る**: LaunchAgent からの起動では GUI でのユーザー操作が期待できない

## 検討した選択肢

### A. kTCCServiceSystemPolicyAppData の個別許可

- **利点**: 最小権限の原則に沿う
- **欠点**: LaunchAgent 経由ではダイアログが毎回表示され、許可が永続化されない。ユーザー体験が壊れる

### B. Full Disk Access (kTCCServiceSystemPolicyAllFiles) の付与

- **利点**: kTCCServiceSystemPolicyAllFiles は kTCCServiceSystemPolicyAppData を包含する。一度 ON にすれば永続的。System Settings の UI で ON/OFF を切り替えるだけ
- **欠点**: 過剰な権限に見える。ただし authsock-warden がアクセスするのは 1Password の Group Containers のみであり、実際にファイルシステム全体にアクセスするわけではない

### C. 1Password のデータを別経路で取得

- **利点**: TCC を回避できる可能性
- **欠点**: op CLI は 1Password アプリ経由でデータを取得しており、Group Containers へのアクセスは op CLI の内部実装。回避する手段がない

## 決定

**B. Full Disk Access (FDA) の付与で解決。**

service register 時に FDA の状態をチェックし、未設定ならユーザーに案内する。

## 設計

### FDA チェックの仕組み

FDA の ON/OFF を確認するには `/Library/Application Support/com.apple.TCC/TCC.db` の読み取りを試みる。このデータベース自体の読み取りに FDA が必要であるため、読み取れれば FDA が有効、読み取れなければ無効と判断できる。

```
読み取り成功 → FDA が ON
読み取り失敗 → FDA が OFF、または FDA リストに未登録
```

FDA の OFF と未登録は区別できない（TCC DB の読み取り自体に FDA が必要なため）。

### .app 経由での FDA チェック

FDA の許可は TCC の "responsible process" に対して付与される。CLI から直接チェックすると Terminal.app の FDA 状態を見てしまう。.app 自身の FDA 状態をチェックするには、.app として起動する必要がある。

```bash
open --wait-apps /Applications/AuthsockWarden.app --args internal fda-check --raw --result-file /tmp/result
```

`open` コマンドで .app を起動することで、responsible process が AuthsockWarden.app になり、正しい TCC identity でチェックできる。

### TCC リストへの自動追加

.app を `open` コマンドで起動すると、macOS は自動的にその .app を FDA リスト（System Settings > Privacy & Security > Full Disk Access）に追加する。ユーザーは「+」ボタンでアプリを追加する必要がなく、トグルを ON にするだけでよい。

### service register 時のフロー

```
1. LaunchAgent plist を生成・配置
2. 設定ファイルに op:// ソースが含まれるかチェック
3. check_fda_via_app() を実行
   - .app パスを解決（argv[0] → .app バンドル検出）
   - `open --wait-apps` で fda-check --raw を実行
   - 結果を temp file 経由で受け取る
4. FDA が未設定の場合:
   a. 案内メッセージを表示
   b. System Settings の FDA ページを自動オープン
      (`open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"`)
   c. 2つのスレッドで並行待ち:
      - FDA ポーリング（2秒間隔で check_fda_via_app() を再実行）
      - Enter キー待ち（FDA なしで続行）
   d. FDA が ON になったら自動的に続行
   e. Enter が押されたら警告付きで続行
5. サービスをロード・開始
```

### LSBackgroundOnly アプリの stderr ノイズ

`LSBackgroundOnly = true` に設定した .app を `open --wait-apps` で起動すると、`open` コマンドが stderr に "Unable to block" 等のメッセージを出力する。これは LSBackgroundOnly アプリが GUI イベントループを持たないことに起因する正常な挙動であり、FDA チェックの動作には影響しない。stderr を `/dev/null` にリダイレクトして抑制する。

## 理由

- **kTCCServiceSystemPolicyAppData は LaunchAgent 経由で永続化されない**: .app バンドル化（DR-012）で Bundle ID ベースの識別は実現したが、このカテゴリの許可ダイアログは依然として毎回出る
- **FDA は包含的に解決する**: kTCCServiceSystemPolicyAllFiles は AppData を包含するため、FDA を ON にすれば AppData の問題も解消される
- **ユーザー体験**: service register 時の案内 + ポーリングにより、ユーザーは System Settings で ON にするだけ。`open` による .app 起動で TCC リストに自動追加されるため、「+」ボタンの操作も不要

## リスク/トレードオフ

- **過剰な権限に見える**: FDA は名目上「フルディスクアクセス」だが、authsock-warden が実際にアクセスするのは 1Password の Group Containers のみ。service register 時の案内で理由を説明する
- **FDA の OFF と未登録の区別不能**: TCC DB の読み取り自体に FDA が必要なため、OFF と未登録を区別できない。実用上は `open` で .app を起動した時点でリストに追加されるため問題にならない

## 関連

- [DR-012](DR-012-app-bundle-wrapper.md) — .app バンドルラッパーによる TCC 許可の永続化
- [docs/macos-tcc-fda.md](../macos-tcc-fda.md) — macOS TCC/FDA の詳細な技術知見
