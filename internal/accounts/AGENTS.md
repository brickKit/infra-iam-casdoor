# accounts：账号

两件事：账号状态流的读取（本组件是水位来源，补取者与读取者只有 `infra/authz`：按主体批量读取、快照）；账号操作（受保护的路由，资源 `infra.iam.account`、主体维度 `account`）：停用、冻结、启用（先问授权成员 `CheckAccountChange`，确认随状态发出，写 Casdoor 的顺序见设计）、强制登出、重置第二因素。

## 负责与不负责

- 负责：`AccountStream`、`readAccounts`、`pageAccounts`；`targetOf`、`answerAccount`、`AccountHTTP`、`StatusHTTP`、`secondPerson`（`IAM_T_TIGHT` 之内的第二人确认）、`checkChange`、`ForceLogoutHTTP`、`ResetFactorsHTTP`。
- 不负责：状态的写法（`core.Store` 的 `SetStatus`、`Fence`、`ResetFactors`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `accounts.go` | 账号状态流与两个读取函数 |
| `accountops.go` | 账号操作 |
| `accountops_test.go` | 单元测试：第二人确认的窗口 |

## 依赖与被依赖

- 依赖：`core`、`reconcile`（`PullRef`）。
- 被依赖：入口（路由、事件流）。

## 规则在哪

`docs/design.md` 的接口与实现状态 3.0.22；安全 03；决定 A134。

## 测试

`accountops_test.go`；`itest/accounts_integration_test.go`（`accountReads`、`accountOperations`）。
