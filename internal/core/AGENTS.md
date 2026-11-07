# core：名字、存储与证据（共用）

全组件的名字，以及每个模块都要用的存储：登录中的请求（只存状态参数的摘要、只用一次）、按签发者与 subject 的账号绑定、会话（只存 Cookie 秘密的摘要；记下创建时的恢复代次）、账号的状态与安全标记、状态的证据与重放、Casdoor 比较的基线。改这里会影响所有模块。

## 负责与不负责

- 负责：组件 ID、版本、事件流与类型、资源与操作、默认的时长、资源定义 `Definitions()`（`names.go`）；`Store` 与它的全部方法（`store.go`）；证据的步骤（`evidence.go`：意图、事务里的结论、没发生就取消、一般记录）；`Base`（`base.go`）。
- 不负责：登录流程与令牌（`login`）、会话的系统面（`sessions`）、账号操作的顺序（`accounts`）、比较的调度（`reconcile`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `base.go` | `Base`：运行时、存储、实现实例、Casdoor 客户端、密钥环、签发者与受众、令牌与会话的时长、Cookie、开发换取、拉取间隔与收紧窗口、授权成员的账号服务 |
| `names.go` | 常量；`Definitions()` |
| `store.go` | `Store`、`ErrNoLogin`、`AccountRow`；登录中的请求（`Begin`、`Take`）、绑定（`Adopt`、`Principal`）、会话（`Open`、`Use`、`End`、`EndBeforeRecovery`、`ended`）、安全变更与状态（`SecurityChange`、`Change`、`ChangeEv`、`status`）、重放（`UsernameOf`、`ReplayStatus`、`ReplayLogout`、`lockAccount`、`ReasonFor`）、比较（`InFlight`、`Compare`、`ConsoleIntent`、`statusEvidence`、`BaselinePassword`）、账号操作（`Managed`、`managedAccount`、`Fence`、`SetStatus`、`ResetFactors`） |
| `evidence.go` | `AccountType`、`Intent`、`Effective`、`Settle`、`general`、`GeneralID`、`EvidenceStep`、`Concluded`、`run` |

## 依赖与被依赖

- 依赖：`keys`、`provider`。
- 被依赖：全部业务模块与入口。

## 规则在哪

`docs/design.md`；安全 02、03；协议 15；组件协议第 08 章（P8.27、P8.28）。

## 测试

由 `itest/` 的流程测试覆盖。
