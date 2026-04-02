# DR-005: 鍵ソースの抽象化（KeySource trait）

- **Status**: Superseded by [DR-010](DR-010-source-group-design.md)
- **Date**: 2026-04-02

## 背景
当初は1Password（op CLI）のみを鍵ソースとしていたが、以下の要件が明確になった:
- 1Password SSH agentへのプロキシ転送（authsock-filter互換のフィルタリング機能）
- ファイルベースの秘密鍵読み込み（パスフレーズ付き鍵の管理）
- 将来の鍵ソース追加への拡張性

単一ソースを前提としたアーキテクチャでは、これらを統一的に扱えない。

## 検討した選択肢

### A. ソースタイプごとに個別実装
各ソースタイプ（agent proxy、op CLI、ファイル）を独立した仕組みで実装する。

- **利点**: 各ソースの特性に最適化できる
- **欠点**: コードの重複。ソケットが複数ソースを集約する際の統一的な扱いが困難

### B. KeySource traitで抽象化
共通インタフェース（discover, sign, forget）を trait として定義し、各ソースタイプが実装する。

- **利点**: ソケットが複数ソースを統一的に集約可能。新しいソースタイプの追加が容易
- **欠点**: 抽象化の設計コスト。agent proxyのようにメモリに鍵を持たないソースと、ローカル署名するソースの振る舞いの差をtraitで表現する必要がある

## 決定
**B. KeySource traitで抽象化。** type = "agent" | "op" | "file" の3種類をサポート。

| ソースタイプ | type値 | 署名方式 | 鍵の在処 | 認証 |
|---|---|---|---|---|
| agent (proxy) | `"agent"` | upstream に転送 | upstream が保持 | upstream 任せ |
| 1Password | `"op"` | warden がローカル署名 | op CLI で遅延取得 → メモリ | TouchID |
| ファイル | `"file"` | warden がローカル署名 | ファイルから読み込み → メモリ | パスフレーズ |

ソケット定義で `sources = [...]` により複数ソースを集約する。

## 理由
- authsock-filter の機能（upstream agent へのフィルタリングプロキシ）を包含できる
- 1Passwordのop CLIによるローカル署名とagent proxyを同じアーキテクチャで扱える
- 将来の鍵ソース（FIDO2トークン、HSM等）追加時も trait 実装の追加のみで対応可能
- ソケットが複数ソースを集約する設計により、用途別のソケットを柔軟に構成できる
