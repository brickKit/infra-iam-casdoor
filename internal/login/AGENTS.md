# login：浏览器登录与令牌

浏览器的登录流程：`/api/iam/login` 生成状态参数与 PKCE、跳到 Casdoor；`/api/iam/callback` 换授权码、核验 ID 令牌、按签发者与 subject 绑定账号、开会话、写 Cookie；`/api/iam/logout`；`/api/iam/jwks`；开发换取（`IAM_DEV_EXCHANGE`）。访问令牌由本组件签名（`Issue`），不转发 Casdoor 的令牌。

## 负责与不负责

- 负责：`CookieName`、`signedIn`、`returnTo`（只留站内路径）、`Login`、`Callback`、`Session`、`answerToken`、`Logout`、`Jwks`、`DevToken`、`Issue`。
- 不负责：边缘的换取（`sessions`）；密钥（`keys`）；会话的存储（`core`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `login.go` | 上面全部 |
| `tokens_test.go` | 单元测试：令牌通过 SDK 的核验、密钥轮换、返回地址、PKCE |

## 依赖与被依赖

- 依赖：`core`、`keys`、`provider`。
- 被依赖：`sessions`（`Issue`）；入口登记路由。

## 规则在哪

组件协议第 08 章（P8.1、P8.2）；安全 02；“易错点”（`AGENTS.md`，仓库根）。

## 测试

`tokens_test.go`；`itest/login_integration_test.go`（`tokens`）。
