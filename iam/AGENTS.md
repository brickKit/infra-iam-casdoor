# iam/：入口与组装

组件对外的一个包：`main.go` 与外壳只引用它（`iam.Definition()`、`iam.New`）。这里只**组装**：读配置建 `core.Base`（存储、Casdoor 客户端、签名密钥、令牌与会话的设置、授权成员的账号服务），把 `internal/` 下模块的函数登记成 SDK 要的路由、系统面、作业、启动钩子与证据的重放；业务一行也不写。

## 负责与不负责

- 负责：版本与端口之外的组件定义、配置键（`Keys`）、迁移、两条事件流（账号状态流经 `reconcile.PullRef` 在补取之前先比较）；启动的前提（`DEPLOYMENT_ID`、正的拉取间隔、能拨通授权成员、能签名，开发换取要有开发客户端）；路由（开发换取只在 `IAM_DEV_EXCHANGE` 为真时登记）；系统面只许 `infra/edge`；证据的重放。
- 不负责：业务规则（去 [internal/AGENTS.md](../internal/AGENTS.md) 找模块）；名字（`internal/core/names.go`）；集成测试（`itest/`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `definition.go` | `GRPCPort`、迁移、`Keys`；`Definition()`（版本在 `core.Version`） |
| `module.go` | `Module` 与 `New`；`Jobs`（拉取 Casdoor → `reconcile.Pull`）、`Start`（接收旧行的签发者，清扫恢复之前的会话）、`Routes`、`Services`（`sessions.NewSessions`）、`Replays`（账号状态与强制登出由存储重放，凭据收紧 → `replay.CheckCredential`）；`handler` 适配 |
| `manifest_test.go` | 单元测试：清单的 `configSchema` 与发出的事件 |
| `migrations/` | 表 |

## 依赖与被依赖

- 依赖：`internal/` 下全部包。
- 被依赖：`main.go`、外壳 `be/go-infra`、`itest/`。

## 测试

`go test ./iam/`。
