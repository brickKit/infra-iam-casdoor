# infra/iam-casdoor

身份成员（Casdoor 适配）的代码。用法与边界在 `BRICKKIT.md`，为什么这样设计（术语、数据、规则、实现状态、未决问题）在 [docs/design.md](docs/design.md)；装配项目 be-assembly-standard 的边界卡、安全 02、03、协议 20 与组件协议第 08 章是它的依据。

## 代码地图

| 文件 | 内容 |
| --- | --- |
| `main.go` | 单跑的入口 |
| `iam/definition.go` | 组件定义、配置键、迁移、授权定义（系统方法的操作）、两条事件流 |
| `iam/module.go` | 路由：登录、回调、登出、改密码、JWKS、开发换取；启动时接收旧行的签发者 |
| `iam/sessions.go` | 系统面 `be.session.v1.SessionService`（只许 `infra/edge`）：换取、已结束的会话；改密码 |
| `iam/casdoor.go` | 对 Casdoor 的 OIDC 客户端：授权地址与 PKCE、授权码与密码换取、ID 令牌核验 |
| `iam/tokens.go` | 签发访问令牌 |
| `iam/keys.go` | 签名密钥、kid（RFC 7638 指纹）、JWKS |
| `iam/store.go` | 登录中的请求、按签发者与 subject 的账号绑定、会话；会话结束与安全变更在同一事务里写发件表 |
| `iam/product.go` | 对 Casdoor 的管理一侧：读组织的用户、重新禁用一个用户（登录应用的凭据，Basic） |
| `iam/reconcile.go` | 与 Casdoor 的全量比较（安全 03）：定期作业与补取的“回声之前”，每个账号在行锁内比较、记证据 |
| `iam/accounts.go` | 账号状态流的声明（水位来源，补取者与读取者只有 `infra/authz`）与两个读取函数：按主体批量读取、快照 |
| `iam/migrations/` | 表 |
| `contract/events/` | 发出的两种事件的 schema（`iam/manifest_test.go` 核对清单） |
| `docs/design.md` | 设计：术语、数据、规则、接口、实现状态、未决问题 |
| `scripts/dev_setup.py` | 开发与测试环境里准备 Casdoor 的应用、开发客户端与测试用户；`TEST_USERS` 是种子数据的测试账号（账号名是轻量契约，只增不改），`make seed` 只建账号 |

## 构建与测试

- `go test ./...`：单元测试。包括令牌能通过 SDK 自己的核验、密钥轮换、返回地址只留站内、PKCE 与合并安全。
- `go test -tags integration ./iam/`：对真实的 Casdoor、PostgreSQL 与消息系统端到端测一遍，覆盖开发换取、按签发者绑定、浏览器登录、边缘经 mTLS 的换取与已结束会话、改密码（一次性用户，测完删掉）、空闲超时与登出。要先运行 `scripts/dev_setup.py`，所需的环境变量写在测试文件开头；缺一个就失败，不会跳过；系统面的端口 9200 要空着。
- `brickkit lint`

## 设计取舍

- **令牌由本组件签名，不转发 Casdoor 的令牌**：`sub` 要是平台主体；令牌类型与有效期由协议定，不随身份产品变。换成别的身份成员时，组件看到的令牌形状不变（安全 11）。
- **会话 Cookie 只存随机秘密的摘要**：库里保存的是 SHA-256，数据库泄露也拿不到可用的 Cookie；状态参数同样只存摘要，并且只能用一次。
- **对 Casdoor 的调用全部经 SDK 的调用策略**（截止时间、重试、熔断），公钥也经它取，再交给 keyfunc 解析。Casdoor 拒绝授权时答 400 并带 OAuth 的 `error` 成员，经 `calls.StatusError` 读出，答 `TOKEN_INVALID`；原因不对外显示。
- **开发换取入口只在 `IAM_DEV_EXCHANGE` 为真时注册**：关掉时这条路由根本不存在（答 501 `CAPABILITY_UNSUPPORTED`，这个部署没有它），而不是答“已关闭”。

## 易错点

- 改了令牌的形状（声明、头部、算法），要用 SDK 的核验器重测（`TestTokensPassTheSDKsVerification`）：协议 P8.1 只接受 `at+jwt`、`kid` 与三种算法，并要求正整数的 `be_sv`。
- 会话摘要是 Cookie 值的小写十六进制 SHA-256（`hashOf`），边缘按同样的算法计算；改了编码，边缘就换不到令牌。
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
