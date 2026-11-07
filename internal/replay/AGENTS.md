# replay：凭据收紧的核对

整套恢复的 6.7：凭据收紧（本成员改的密码、重置的第二因素；比较时在 Casdoor 里看到的变更）不重放，重放时对照 Casdoor 核对（线协议 P12.20，SDK 的 `Replays.Check`）；不成立或账号不在答 `inconsistent`。账号状态与强制登出的重放在 `core.Store`（`ReplayStatus`、`ReplayLogout`）。

## 负责与不负责

- 负责：`clockSkew`、`CheckCredential`、`parseProductTime`、`notBefore`。
- 不负责：状态的重放（`core`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `replay.go` | 上面全部 |

## 依赖与被依赖

- 依赖：`core`。
- 被依赖：入口的 `Replays`。

## 规则在哪

`docs/design.md` 实现状态 3.0.30、3.0.25；协议 15；线协议 P12.19–P12.21；决定 A141。

## 测试

`itest/replay_integration_test.go`（`replay`）。
