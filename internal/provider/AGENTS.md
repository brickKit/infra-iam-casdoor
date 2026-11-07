# provider：Casdoor（共用）

身份产品 Casdoor 的两侧：OIDC 客户端（授权地址与 PKCE、授权码与密码换取、ID 令牌核验，公钥经 SDK 的调用策略取）与管理接口（读组织的用户、禁用与允许一个用户、结束一个用户的会话、删除第二因素，用登录应用的凭据 Basic）。换一个身份产品时换的就是这个包。

## 负责与不负责

- 负责：`Casdoor`、`ProviderUser`、`Pkce`、`RandomToken`、`HashOf`（会话摘要：小写十六进制 SHA-256，边缘按同样的算法算）、`AuthorizeURL`、`Code`、`Password`、`SetPassword`、`ProductCallLimit`；`ProductUser` 与 `Users`、`User`、`EndSessions`、`DeleteFactors`、`SetForbidden`、`Cut`。
- 不负责：账号与会话的本地状态（`core`）。

## 文件

| 文件 | 内容 |
| --- | --- |
| `casdoor.go` | OIDC 客户端 |
| `product.go` | 管理接口 |

## 依赖与被依赖

- 依赖：`keys`（`B64`）。
- 被依赖：`core`、`login`、`sessions`、`reconcile`；入口建 `Casdoor`。

## 规则在哪

`docs/design.md` 的“设计取舍”（对 Casdoor 的调用全部经 SDK 的调用策略）；安全 11（换身份产品）。

## 测试

`internal/login/tokens_test.go`（`TestPKCE`）；其余在 `itest/`（对真实的 Casdoor）。
