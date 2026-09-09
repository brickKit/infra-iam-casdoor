# infra-iam-casdoor · AI 助手导读

## 身份证

| 项 | 值 |
|---|---|
| 组件 ID | `infra/iam-casdoor` |
| 仓库名 | `infra-iam-casdoor` |
| 端口 | HTTP `8200` / gRPC `9200`（`registry/ports.tsv`，装配仓库根目录那份） |
| schema / role | `infra_iam_casdoor` / `infra_iam_casdoor_rw`（归档 schema `infra_iam_casdoor_archive`，只有 `webhook_deliveries` 会用到） |
| 语言 / 框架 | Go：Gin + `database/sql` + `pgx/v5/stdlib` + `golang-migrate` |
| 合并部署时进 | 外壳三 `go-infra` |
| 装配角色 | `slot:iam`（Default；替换件 `infra-iam-keycloak` 占 8221/9221，与本组件互斥） |
| 设计真相源 | 装配仓库 `docs/design/infra-iam-casdoor.md`——本文件与它冲突时，以那份为准，回来改这里 |

## 边界

**归我：** Casdoor 官方镜像前面的适配层——应用 token 的签发/刷新/登出、JWKS 端点、`/api/tenant/features`、Casdoor webhook 桥接、首次初始化（建组织/应用/webhook）。这一层才是 `slot:iam`。

**不归我：**

| 什么 | 归谁 | 为什么 |
|---|---|---|
| 用户身份、密码、登录页、OIDC 协议流、MFA、社交登录 | Casdoor 官方镜像 | 浏览器直接和它说话，本组件不代理、不转发。我们零代码的东西不该包成组件 |
| 角色模型、角色-权限分配、用户-角色分配 | `infra-authz` | 这条切分让 `slot:iam` 换 Keycloak 时角色数据一行都不用迁 |
| 单次鉴权判定 | 各组件的 `be-sdk`（进程内 map） | 我不在请求热路径上 |
| 组织架构主数据 | `mdm-org`（阶段五）；阶段三是 `infra-authz` 的临时 `departments` 表 | 我只是把身份 token 换成带 `dept_path` 的应用 token，不持有部门数据本身 |
| 用户的通知通道偏好 | `infra-notification` | 它自己持快照，靠我发的 `infra.iam.user.*.v1` 事件维护 |

⚠️ **`data_scopes: none`**——本组件不做行级过滤，`permissions: []`——本组件没有一个业务权限键，REST 面全部是 `besdk.Public`/`besdk.Authenticated`。

## 契约面与事件

**gRPC `infra.iam.v1.IamService`：** `BatchGetUsers`（读，回源 Casdoor，不落本地表）、`GetTenantFeatures`（读）。⚠️ 包名是 `infra.iam`，不是 `infra.iam_casdoor`——族内契约面要求 `infra-iam-keycloak` 将来能原样实现。

**REST：** 路径**不走** `/{domain}/{name}/**` 前缀（族级、全平台通用）。`POST /api/iam/token`、`POST /api/iam/token/refresh`、`GET /api/tenant/features` 是 `besdk.Public`；`POST /api/iam/logout` 是 `besdk.Authenticated`；`GET /.well-known/jwks.json`、`POST /api/iam/webhooks/casdoor` 不进 `edge_routes`（前者内网直连，后者只供 Casdoor 带外容器直连）。

**发布事件：** `infra.iam.user.created/updated/disabled.v1`（核心）、`infra.iam.login.v1`（旁路）。
**消费事件：** `infra.authz.user_role.changed.v1`（仅 `kicked` 时作废 refresh token）。

## 依赖与「为什么不依赖某某」

`dependencies.components` 只有一条：`infra/authz@1.0.2`（`ResolveClaims`，每次签发/刷新都调一次，绝不缓存）。

- **不依赖 Casdoor 官方镜像（组件意义上）**：它是带外容器，地址走 `configSchema` 的 `casdoorBaseUrl`，不是依赖边。
- **⚠️ 没有任何组件对本组件建依赖边，这是 `slot:iam` 能成立的物理前提**——业务组件要验应用 token 走各自的 `iamJwksUrl` 配置项（不是依赖边），要用户信息走事件快照（`infra-notification` 的既有做法）。谁哪天顺手写了一条 `dependencies.components: [infra/iam-casdoor@x]`，`slot:iam` 当场失效（平台注入的变量名带实现名，换 Keycloak 时那个变量整个消失）。

## 这个组件特有的坑

| 不许 | 症状 | 出处 |
|---|---|---|
| 让 Casdoor 直接签带角色的 token（把 `infra-authz` 的角色镜像进 Casdoor） | 三个独立的致命问题：踢人链路断掉、镜像必然异步产生一个不报错的死循环、把角色数据焊回 Casdoor（违背换 Keycloak 时角色数据一行不迁的设计目标） | 设计计划 §3.2 |
| 给 `ResolveClaims` 加一层"上次拿到的角色"缓存 | 缓存过期时签出的 token 带着旧角色，而 `stale_since` 已经把这个人标记为需要刷新——把刚消掉的死循环问题请回来 | 设计计划 §5 明文决策 |
| 建一张 `users` 影子表同步 Casdoor 的用户主数据 | `slot:iam` 换实现就要迁移这张表的数据，槽位当场失效 | 设计计划 §2 |
| `webhook_deliveries.payload` 列建成 `JSONB` | 不合法 JSON 的投递体会让 `INSERT` 直接失败，与"宽容存储、先存下来再说"的设计意图矛盾——真机测试踩出来的（`docs/dev/实测踩坑记录.md` C10） | `migrations/001_create_iam.up.sql` |
| webhook 去重靠 `INSERT` 撞 `(dedup_key, received_at)` 唯一约束 | 两次真实间隔的重投 `received_at` 几乎必然不同，约束形同虚设，去重从未真正生效——真机测试踩出来的（`docs/dev/实测踩坑记录.md` C9） | `repo/webhookdeliveries.go` 的 `RecordDeliveryAndPublish` |
| refresh token 与应用 token 混用同一个 claims 结构、不带类型标记 | 两者都是本组件自己签的 JWT，字段高度相似，缺少显式 `typ` 区分会让一个 token 被误当另一种接受 | `tokens.go` 的 `refreshClaims.Typ` |
| 生产用的 Casdoor 应用（`CreateApplication`）加 `password` grant type | 浏览器走 `authorization_code` 直连 Casdoor 是刻意的架构选择（本组件不代理密码），`password` grant type 是仅供测试签发 token 用的做法（`createTestAppWithPasswordGrant`），不该混进生产配置 | `casdoor/admin.go` |
| 把 Casdoor 的 `jwks_uri` 硬编码成 `<casdoorBaseUrl>/.well-known/jwks.json` | 真机核对过 Casdoor 实际发布的路径是 `/.well-known/jwks`（没有 `.json` 后缀），与本组件自己的 JWKS 端点路径不同，容易想当然抄错——必须走 OIDC Discovery 现取 | `casdoor/discovery.go` |
| 用户请求路径（`backend/internal/http`/`backend/internal/grpc`）里用 `besdk.SystemClient` | `signAccessTokenFor`（现问 `infra-authz` 的 `ResolveClaims`）刻意放在 `backend/internal/service`，用 `SystemClient`——这不是绕过数据权限的误用（这一刻调用者手上根本没有可转发的应用身份），但仍然必须待在 `make gates` 扫描范围之外的目录 | `service.go` 的 `signAccessTokenFor` 注释 |

## 已知缺口

- **Casdoor webhook 的投递保证与 payload 形状未能 100% 确认**（本次调研受限于自助注册需要短信/邮箱验证码、管理 API 建用户未观察到 webhook 触发）。已确认：Webhook 支持自定义 header（共享密钥校验的前提）。未确认：稳定的投递 ID、失败重投机制、`add-user`/`update-user`/`delete-user` 等 action 名是否准确、payload 里用户对象具体挂在哪个字段。`service/webhook.go` 的解析因此是防御性的（多候选字段名尝试），一旦能接入真实的短信/邮箱验证码服务，应该回来用真实抓包结果核对并收紧解析逻辑。
- **gRPC `BatchGetUsers` 依赖的 Casdoor 管理会话没有自动重连**——会话 cookie 理论上可能过期（多久过期未核实），过期后这个接口会开始报错，直到组件重启换一条新会话，见 `grpc.go` 顶部注释。

## 改代码前的自查

1. **我是不是在给 `ResolveClaims` 的结果加缓存？** 停下——fail-closed 是设计计划 §5 的明文决策，缓存会把死循环重新引进来。
2. **我是不是在建一张 users 或 roles 的本地表？** 停下——那等于把 `slot:iam` 的可替换性焊死。
3. **我改的 webhook 解析逻辑，是不是把"认不出的格式"变成了报错/丢事件？** 停下——payload 解析必须宽容，只有共享密钥校验才允许严格拒绝。
4. **我是不是往 `webhook_deliveries` 加了字段级 JSON 查询？** 停下——`payload` 是 `TEXT`，这是刻意的（見上表 C10）。
5. **我是不是在 `dependencies.components` 之外的地方（比如某个业务组件的 `component.yaml`）加了一条指向本组件的依赖边？** 停下——零入边是 `slot:iam` 的物理前提。
6. **我新建的 Casdoor 应用是不是意外带了 `password` grant type？** 检查是不是把测试专用的建应用逻辑误用到了生产路径（`bootstrap.go`/`CreateApplication`）。
