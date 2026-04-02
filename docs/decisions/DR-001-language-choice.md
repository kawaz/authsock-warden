# DR-001: 実装言語の選択

- **Status**: Active
- **Date**: 2026-04-02

## 背景
authsock-wardenはSSH agentプロキシとして秘密鍵をメモリ上で扱う。言語選択はメモリ安全性に直結する。

## 検討した選択肢

### Go
- **利点**: golang.org/x/crypto/ssh/agent が圧倒的に成熟。agent.ServeAgent 一発でプロキシ実装可能。クロスコンパイルが容易。
- **欠点**: GCが秘密鍵データをヒープ上でコピー・移動する可能性がある。runtime/secret (Go 1.26) は macOS 非対応。memguard を使っても標準暗号ライブラリとの接合点で GC 管轄コピーが生じるリスクが残る。

### Rust
- **利点**: 所有権システムにより秘密鍵の意図しないコピーをコンパイル時に防止。zeroize/secrecy クレートで Drop 時ゼロ化を保証。GC がないためメモリレイアウトを完全制御可能。
- **欠点**: SSH agent protocol のライブラリ（ssh-agent-lib）はGoほど成熟していない。開発速度はGoより遅い。

## 決定
**Rust を採用。**

## 理由
メモリ保護がプロジェクトの存在意義に直結する。SSH agent protocol の差は ssh-agent-lib や自前実装で埋められるが、メモリ保護の差は言語を変えない限り埋められない。authsock-filter も Rust で実装済みであり、コード移植が容易。
