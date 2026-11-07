# sessions：会话的系统面

边缘（`infra/edge`）用会话换访问令牌（`Exchange`：会话行的锁让同一会话的换取一个一个来，令牌带账号当前的安全版本；会话结束答 `SESSION_ENDED`），读已结束的会话（`Ended`：结束的行提交之后才编号，读的一方要反复拉）；用户改自己的密码；整套恢复之后清扫恢复之前的会话。

## 负责与不负责

- 负责：`NewSessions`（`SessionService` 的实现）、`Exchange`、`Ended`；`ChangePassword`、`ownPassword`；`EndSessionsBeforeRecovery`。
- 不负责：会话怎样存（`core`）；浏览器的登录（`login`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `sessions.go` | 上面全部 |

## 依赖与被依赖

- 依赖：`core`、`login`、`provider`。
- 被依赖：入口。

## 规则在哪

组件协议 P8.27、P8.28；协议 15 的 6.6。

## 测试

`itest/sessions_integration_test.go`（`edgeSessions`、`passwordChange`、`idleAndLogout`）、`itest/recovery_integration_test.go`（`recovery`）。
