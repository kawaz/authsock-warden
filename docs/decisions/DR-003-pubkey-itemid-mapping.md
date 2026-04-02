# DR-003: 公開鍵→itemidマッピング戦略

- **Status**: Active
- **Date**: 2026-04-02

## 背景
authsock-wardenは1Passwordに保管された秘密鍵を遅延取得する。署名リクエスト時に「どの公開鍵に対応するitemid」かを知る必要がある。

## 調査結果

### ssh-add -L のコメントフィールド
1Password SSH agentが返す公開鍵のコメントは単なるラベル文字列（例: `SSH: kawaz@kawaz-mbp.local_20151013`）。itemid やvault情報は含まれない。

### op CLI の公開鍵フィールド
`op item get <itemid> --fields public_key` で `ssh-ed25519 AAAA...` 形式（コメントなし）の公開鍵が取得できる。ssh-add -L の先頭2フィールドと完全一致。

### op item list の additional_information
`op item list --categories "SSH Key"` の各itemに `additional_information` として SHA256 fingerprint が含まれる。

### SSH agent protocol の公開鍵形式
署名リクエストの key_blob は SSH wire format。ssh-add -L の authorized_keys 形式は wire format の base64 ラッパー。`ssh.PublicKey.Marshal()` 相当のバイト列でマップキーにできる。

## 検討した選択肢

### A. op item list (1回) + op item get xN件（各公開鍵取得）
- 各 `op item get` が TouchID を要求する（PID ごとにキャッシュだが CLI 呼び出しは毎回別PID）
- N+1 回の TouchID → 非実用的

### B. fingerprint ベースマッチング（op item list 1回のみ）
- ssh-add -L で公開鍵一覧 → fingerprint 計算
- op item list で fingerprint 付き item 一覧取得（TouchID 1回）
- fingerprint でマッチング → {pubkey_wire_format → itemid} マップ構築
- TouchID 1回で完了

## 決定
**B. fingerprint ベースマッチング。op item list の1回のみでマップ構築。**

## 理由
op CLI は呼び出しごとに TouchID を要求する（実測で確認）。ただし同一PID祖先チェーン内ではキャッシュが効くため、warden プロセスから直接呼び出す場合は初回の1回のみ。op item list の additional_information に含まれる fingerprint と ssh-add -L から計算した fingerprint を照合することで、op item get を使わずにマッピングを構築できる。
