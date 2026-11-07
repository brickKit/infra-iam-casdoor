# internal/：业务模块

身份成员的业务，每个模块一个包。只给本仓库引用（Go 的 `internal`）：别的组件编译期就引用不了（决定 0101）。先按下表找到模块，再读那个目录的 `AGENTS.md`。

## 模块

| 包 | 一句话 | 依赖（本组件内） |
| --- | --- | --- |
| `login` | 浏览器登录、JWKS、开发换取、签发令牌 | `core`、`keys`、`provider` |
| `sessions` | 边缘的会话换取与已结束的会话、改密码、恢复后的清扫 | `core`、`login`、`provider` |
| `accounts` | 账号状态流的读取、账号操作 | `core`、`reconcile` |
| `reconcile` | 与 Casdoor 的全量比较 | `core`、`provider` |
| `replay` | 凭据收紧的核对 | `core` |
| `core`（共用） | 名字与资源定义、存储（登录中的请求、账号、会话、状态与证据）、证据的步骤、`Base` | `keys`、`provider` |
| `provider`（共用） | Casdoor 的 OIDC 客户端与管理接口 | `keys` |
| `keys`（共用） | 签名密钥、kid、JWKS | — |

分层（每个包只引用比它低的层）：`sessions`、`accounts` → `login`、`reconcile`、`replay` → `core` → `provider` → `keys`。这个组件的 `core` 不在最底层：`Base` 带着 Casdoor 客户端与密钥环，它们放在更低的两个包里。

## 共同的写法

- 每个模块的函数先收 `m *core.Base`，入口包的 `Module` 持有它、登记时适配；存储的写法是 `core.Store` 的方法（`m.Store.…`），都在 `core/store.go`。
- 对 Casdoor 的调用全部经 SDK 的调用策略（`provider`），不在事务里；会话结束与安全变更在同一事务里写发件表。
- 账号的安全变更推进安全版本（`be_sv`），令牌带它；状态变更先问授权成员（`m.Authz`），写证据（协议 15）。

## 测试

单元：`login`、`accounts`；其余由 `itest/` 的流程测试覆盖。
