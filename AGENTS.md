# infra/iam-casdoor

身份成员（Casdoor 适配）的代码。用法与边界在 `BRICKKIT.md`，为什么这样设计（术语、数据、规则、实现状态、未决问题）在 [docs/design.md](docs/design.md)；装配项目 be-assembly-standard 的边界卡、安全 02、03、协议 20 与组件协议第 08 章是它的依据。

## 代码地图

代码按业务模块分层。**先读这一节，再进目录**：每个代码目录都有自己的 `AGENTS.md`（同目录的 `CLAUDE.md` 让 Claude Code 读这个目录的文件时自动带上它），写这一层负责什么、不负责什么、每个文件、依赖谁、测在哪。

| 目录 | 是什么 |
| --- | --- |
| `main.go` | 单跑的入口 |
| [`iam/`](iam/AGENTS.md) | 入口：组件定义、配置键与组装（建 `core.Base`，路由、系统面、作业、启动、证据的重放都在这里登记，转给业务模块）；不写业务 |
| [`internal/`](internal/AGENTS.md) | 业务：下面的模块各一个包；模块之间的依赖表与分层在它的 `AGENTS.md` |
| [`itest/`](itest/AGENTS.md) | 集成测试（对真实的 Casdoor），按模块分文件；它的 `AGENTS.md` 是测试索引 |
| `iam/migrations/` | 表：登录中的请求、账号、会话、状态的证据 |
| `contract/events/` | 发出的两种事件的 schema（`iam/manifest_test.go` 核对清单） |
| `docs/design.md` | 设计：术语、数据、规则、接口、实现状态、未决问题 |
| `scripts/dev_setup.py` | 开发与测试环境里准备 Casdoor 的应用、开发客户端与测试用户；`TEST_USERS` 是种子数据的测试账号（账号名是轻量契约，只增不改），`make seed` 只建账号；`--users-only` 把已有的测试账号复原成种子的样子（允许登录、没有第二因素、测试密码：密码经 `set-password`，`update-user` 不改它） |

业务模块（`internal/` 下）：

| 模块 | 负责 |
| --- | --- |
| [`login`](internal/login/AGENTS.md) | 浏览器的登录流程（授权地址与 PKCE、回调、会话 Cookie、登出）、JWKS、开发换取；签发访问令牌 |
| [`sessions`](internal/sessions/AGENTS.md) | 系统面 `be.session.v1.SessionService`（只许边缘 infra/edge）：换取、已结束的会话；改密码；恢复之后的会话清扫 |
| [`accounts`](internal/accounts/AGENTS.md) | 账号状态流的读取（水位来源）；账号操作：停用、冻结、启用、强制登出、重置第二因素 |
| [`reconcile`](internal/reconcile/AGENTS.md) | 与 Casdoor 的全量比较（安全 03）：定期作业与补取的“回声之前” |
| [`replay`](internal/replay/AGENTS.md) | 整套恢复后凭据收紧的核对（对照 Casdoor，不重放） |

共用的（从下往上）：[`keys`](internal/keys/AGENTS.md)（签名密钥、kid、JWKS）、[`provider`](internal/provider/AGENTS.md)（Casdoor 的 OIDC 客户端与管理接口）、[`core`](internal/core/AGENTS.md)（名字与资源定义、登录中的请求、账号与会话的存储、证据、状态的重放、`Base`）。

| 想改 | 从这里开始 | 然后 |
| --- | --- | --- |
| 令牌的形状（声明、头部、算法） | `internal/login` 的 `Issue` | `TestTokensPassTheSDKsVerification`（`internal/login/tokens_test.go`）；协议 P8.1 |
| 会话的寿命、空闲、Cookie | `internal/core/store.go` 的 `Use`、`internal/login` | `itest/sessions_integration_test.go` |
| 账号状态变更的顺序与确认 | `internal/accounts` 的 `StatusHTTP`、`internal/core/store.go` 的 `SetStatus` | `itest/accounts_integration_test.go` |
| 与 Casdoor 比较的规则 | `internal/reconcile`、`internal/core/store.go` 的 `Compare` | `itest/reconcile_integration_test.go` |
| 换一个身份产品 | `internal/provider` | 设计的“部署与替换”；安全 11 |

## 构建与测试

- `go test ./...`：单元测试：令牌能通过 SDK 自己的核验、密钥轮换、返回地址只留站内、PKCE（`internal/login`）；第二人确认的窗口（`internal/accounts`）；清单与合并安全（`iam/`，查入口与 `internal/` 下全部包）。
- `go test -count=1 -tags integration ./itest/`：对真实的 Casdoor、PostgreSQL 与消息系统，每个文件测哪条流程，在 [itest/AGENTS.md](itest/AGENTS.md)。要先运行 `scripts/dev_setup.py`，环境变量写在 `itest/AGENTS.md`；缺一个就失败，不会跳过。
- `brickkit lint`

## 设计取舍

- **令牌由本组件签名，不转发 Casdoor 的令牌**：`sub` 要是平台主体；令牌类型与有效期由协议定，不随身份产品变。换成别的身份成员时，组件看到的令牌形状不变（安全 11）。
- **会话 Cookie 只存随机秘密的摘要**：库里保存的是 SHA-256，数据库泄露也拿不到可用的 Cookie；状态参数同样只存摘要，并且只能用一次。
- **对 Casdoor 的调用全部经 SDK 的调用策略**（截止时间、重试、熔断），公钥也经它取，再交给 keyfunc 解析。Casdoor 拒绝授权时答 400 并带 OAuth 的 `error` 成员，经 `calls.StatusError` 读出，答 `TOKEN_INVALID`；原因不对外显示。
- **开发换取入口只在 `IAM_DEV_EXCHANGE` 为真时注册**：关掉时这条路由根本不存在（答 501 `CAPABILITY_UNSUPPORTED`，这个部署没有它），而不是答“已关闭”。

## 易错点

- 改了令牌的形状（声明、头部、算法），要用 SDK 的核验器重测（`TestTokensPassTheSDKsVerification`）：协议 P8.1 只接受 `at+jwt`、`kid` 与三种算法，并要求正整数的 `be_sv`。
- 会话摘要是 Cookie 值的小写十六进制 SHA-256（`provider.HashOf`），边缘按同样的算法计算；改了编码，边缘就换不到令牌。
- 会话结束的行提交之后才编号，`Ended` 读不到还没编号的行：读的一方（边缘、测试）要反复拉，不能只拉一次。
- `return_to` 只能是站内路径，否则登录就成了开放跳转。
- Casdoor 的 `origin` 设置决定它的 ID 令牌的 `iss`，必须与 `CASDOOR_ISSUER`（默认等于 `CASDOOR_PUBLIC_URL`）一致。

## 改代码前自查

- 改了配置键：`component.yaml` 的 `configSchema` 与 `BRICKKIT.md` 的配置指南一起改了吗？
- 改了版本号吗？每次改动都升版本。
- 端到端测试过了吗？

<!-- brickkit:managed:begin lang=zh -->
<!-- 由 brickkit 维护（init、add、remove、upgrade、skills update）：这对标记之间的改动会被覆盖 -->

## BrickKit

这是一个 BrickKit 组件：平台只读 `component.yaml`。它依赖的规则：

- `configSchema` 的键就是代码读的环境变量名。不能用保留名：`COMPONENT_ID`、`COMPONENT_VERSION`、`PORT`、`BRICKKIT_SERVED_MEMBERS`、`BRICKKIT_SERVED_MEMBERS_CONFIG`，以及任何 `*_ENDPOINT`。
- 依赖写精确版本。依赖的地址以 `<ID>_ENDPOINT` 注入；缺席的可选依赖根本没有这个变量，读的时候要带兜底。
- `/healthz` 只查本进程，不查依赖。迁移命令用同一个镜像跑，遇到不认识的参数必须直接失败；`local.migrationCommand` 从源码跑同一条迁移，给 `mode: local` 用。
- `BRICKKIT.md` 会随版本进入每个使用它的项目，在那里是脱离仓库单独读的：跟代码一起改，不放相对链接。
- 发版：改 `metadata.version`，提交、推送，`brickkit release`。`brickkit lint` 会检查清单和这些文档——在项目里、在这个目录下跑，只查这个组件（`--all` 查整个项目）。
- 完整规则在 `brickkit-component` 技能里（装了技能的项目或仓库根目录下的 `.claude/skills/brickkit-component/SKILL.md`；`brickkit skills update` 会装上）；参数问 `brickkit <命令> --help`；BrickKit 自己的文档用 `brickkit docs` 看。
<!-- brickkit:managed:end -->
