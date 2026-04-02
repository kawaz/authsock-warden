# DR-006: 鍵の4状態ライフサイクル

- **Status**: Active
- **Date**: 2026-04-02

## 背景
従来の設計では鍵は「メモリにある/ない」の2状態だった。しかし以下の課題が浮上した:
- リモートからのAI agent操作時にTouchIDが物理的に不可能
- タイムアウト後の再認証にTouchIDを毎回要求するのは、リモートシナリオで破綻する
- メモリに鍵を保持したまま署名だけロックし、軽量な代替認証（スマホPasskey等）で再開したい

2状態ではこの「鍵はあるが署名は止めたい」状態を表現できない。

## 検討した選択肢

### A. 2状態のまま（Not Loaded / Active）
- **利点**: シンプル
- **欠点**: タイムアウト後は必ず鍵を破棄→再取得（TouchID必須）。リモートからの操作が事実上不可能

### B. 3状態（Not Loaded / Active / Forgotten）
on_timeout で即座に forget。再認証は常に鍵の再取得（TouchID）。
- **利点**: Aよりは明示的
- **欠点**: リモートからの re-auth 問題は未解決

### C. 4状態（Not Loaded / Active / Locked / Forgotten）
Locked 状態でメモリに鍵を保持しつつ署名をロック。re-auth で Active に復帰。
- **利点**: Locked → Active の遷移で軽量な代替認証（command, passkey等）が使える
- **欠点**: 状態遷移が複雑化

## 決定
**C. 4状態ライフサイクルを採用。**

```
Not Loaded → Active → Locked → Forgotten
                ↑        │
                └────────┘ (re-auth)
```

| 状態 | メモリ | 署名 | 遷移条件 |
|---|---|---|---|
| Not Loaded | なし | 不可 | → Active: 初回取得（TouchID/パスフレーズ） |
| Active | あり | 可 | → Locked: timeout (on_timeout = "lock") |
| Locked | あり | 不可（re-auth待ち） | → Active: re-auth 成功 |
| Forgotten | ゼロクリア済み | 不可 | → Active: 再取得（TouchID必須） |

- `on_timeout = "lock"`: Active → Locked（メモリ保持、re-auth で復帰可能）
- `on_timeout = "forget"`: Active → Forgotten（即座にゼロクリア、再取得にはTouchID必須）
- `forget_after`: Locked → Forgotten（Locked状態が一定時間続いたら強制破棄）

agent (proxy) ソースはメモリに鍵を持たないので lock/forget 対象外。

## 理由
リモートからのAI agent操作時にTouchIDが物理的に不可能なケースへの対応が主目的。Locked 状態を導入することで、メモリ上の鍵を保持したまま署名を一時停止し、スマホPasskey や外部コマンド等の軽量な代替認証で再開できる。forget_after による安全弁も用意し、Locked のまま放置されてもいずれゼロクリアされることを保証する。
