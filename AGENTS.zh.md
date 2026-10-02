[English](AGENTS.md) · [中文](AGENTS.zh.md)

# infra/iam-casdoor

开发本组件的 AI 指南。用法、边界与契约：BRICKKIT.md；为什么长这样：`docs/design.zh.md`；依赖、配置与部署：component.yaml。

## 代码地图

| 路径 | 负责 |
|---|---|
| `backend/module/module.go` | 唯一入口 `New(ctx, rt)`：装配 repo → service → HTTP + gRPC；`Start` 登记 key ID，在后台起 Casdoor 连接与 OIDC 发现，再跑 outbox 推送、消费者与分区循环。单跑与进外壳是同一个函数 |
| `backend/module/settings.go` | `loadSettings`：一次读完并解析全部配置键（缺键、TTL 不对、PEM 不对 → 点名配置键的 error，绝不 panic） |
| `backend/module/casdoor.go` | 两个等 Casdoor 的后台循环：管理 API 登录 + 启动对账、OIDC 发现（`rebaseHost`） |
| `backend/module/retry.go` | `retryUntilOK`：指数退避、封顶 30 秒，取消不算失败 |
| `backend/cmd/server/main.go` | 一行 `besdk.RunStandalone(module.New)` |
| `backend/cmd/migrate/main.go` | 一行 `migrate.Main(migrations.FS)`：迁移容器的入口（`./migrate up`） |
| `backend/internal/features/` | `FromLockfile`：`ENABLED_COMPONENTS`（项目的 `brickkit.yaml`）→ 已安装的组件 ID |
| `backend/internal/keys/` | PEM 解析、RFC 7638 key ID、JWK 序列化 |
| `backend/internal/tokens/` | 本组件自己的 JWT 的签发与验证：应用 token 与 refresh token（`typ: refresh`） |
| `backend/internal/casdoor/admin.go` | Casdoor 管理 API：一条会话，遇到 "Please login first" 重新登录，每次调用 15 秒上限，`IsUnreachable` |
| `backend/internal/casdoor/discovery.go` | OIDC 发现：issuer 与 `jwks_uri` |
| `backend/internal/casdoor/idtoken.go` | 验 Casdoor 的 id_token（只认 RS256，校验 issuer） |
| `backend/internal/bootstrap/` | Casdoor 组织、应用与 webhook 的启动对账 |
| `backend/internal/repo/` | `refresh_tokens`（签发、带重放检测的轮换、作废）、`signing_keys`、`webhook_deliveries`（advisory 锁下去重）、`bootstrap_state` |
| `backend/internal/service/` | 换 token、刷新、登出、处理 webhook；哨兵错误及其 gRPC 状态码（`status.go`）；REST 与 gRPC 共用 |
| `backend/internal/http/http.go` | REST 路由，全部经 `besdk.GET` / `besdk.POST` 注册；webhook 的共享密钥校验；`dedupKeyFor` |
| `backend/internal/grpc/grpc.go` | `infra.iam.v1.IamService`：`BatchGetUsers`、`GetTenantFeatures` |
| `backend/internal/consumer/` | `infra.authz.user_role.changed.v1`：`kicked` 时作废该用户的 refresh token |
| `backend/internal/partition/` | 后台循环：`event_outbox` / `event_inbox` 提前四周建周分区，`webhook_deliveries` 提前三个月建月分区 |
| `migrations/` | SQL 迁移，由 `migrations/embed.go` 嵌入 |
| `contracts/` | proto、OpenAPI、事件 schema |
| `gen/infra/iam/` | 生成的 Go 代码：独立的嵌套 Go 模块，单独打 tag gen/infra/iam/v1.x.y；绝不手改 |
| `scripts/` | `seed.sh` / `seed-clean.sh`：在 Casdoor 里建本地测试用户与一个开着密码授权的测试应用 |

| 要改什么 | 从这里开始 | 然后 |
|---|---|---|
| 应用 token 里放什么 | `backend/internal/service/service.go`（`signAccessTokenFor`） | `backend/internal/tokens/tokens.go`（`Claims`）、authz 的契约包 |
| refresh token 轮换或重放检测 | `backend/internal/repo/refreshtokens.go`（`RotateRefreshToken`） | `backend/internal/service/service.go`（`RefreshToken`）、`backend/internal/repo/repo_test.go` |
| 签名密钥轮换 | `backend/module/settings.go` | `backend/internal/tokens/tokens.go`（`NewVerifier`）、`backend/internal/http/http_test.go` |
| 解析 Casdoor 的 webhook | `backend/internal/service/webhook.go` | `backend/internal/repo/webhookdeliveries.go`、`contracts/events/iam.events.json` |
| 启动时在 Casdoor 里建哪些对象 | `backend/internal/bootstrap/bootstrap.go` | `backend/internal/casdoor/admin.go`、`backend/module/casdoor.go` |
| features 清单 | `backend/internal/features/features.go` | `backend/internal/http/http.go`（`tenantFeaturesHandler`） |
| 某个错误回错了状态码 | `backend/internal/service/status.go` | `backend/internal/service/errors.go` |

## 构建与测试

```bash
# 测试连测试库 brickkit_test_db，绝不连 brickkit_db（项目根目录 make test-db-init ID=infra/iam-casdoor）
# 密码是项目 .env 里的 POSTGRES_PASSWORD；不要 source .env（Compose 语法，含多行 PEM）
export TEST_PG_DSN="postgres://postgres:<密码>@localhost:5432/brickkit_test_db?sslmode=disable"
make test                    # 每个包都以 "ok" 结尾；没有 TEST_PG_DSN 时拒绝运行
go test ./... -count=1 -v | grep -- '--- SKIP'
#   没有 Casdoor 与 authz 时 6 条 SKIP：bootstrap 3 条、casdoor 2 条、service 的端到端测试
TEST_CASDOOR_BASE_URL=http://localhost:8000 go test ./... -count=1 -v | grep -- '--- SKIP'
#   只剩 1 条：TestExchangeTokenAndRefreshToken_端到端对着真实infra_authz走一遍，它要
#   INFRA_AUTHZ_GRPC_ENDPOINT（项目根目录 make test-cross ID=infra/iam-casdoor 会设）
make check-version dag-check contract-check import-scan module-check   # 每个打印一行 ✓
make docs-check              # "0 with errors, 0 warnings"
```

Casdoor 测试在共享的 Casdoor 里用带时间戳的名字建组织、应用、用户与 webhook，结束后删掉。`buf generate` 之后（契约变了）契约包要打新 tag：见易错点。真机：在项目根目录 `make verify ID=infra/iam-casdoor ROUTE='POST /api/iam/logout' FOCUS=1` 构建镜像、只起本组件需要的部分、核对迁移、健康与受保护路由、跑一次 focus，然后收尾。

## 设计取舍

- **两个 token。** Casdoor 的 id_token 只证明身份；应用 token 由本组件签，claims 在那一刻向 `infra/authz` 现问。登录与每次刷新都调 `ResolveClaims`；没有任何地方缓存 claims。
- **对 authz 失败关闭。** authz 不可达时，换 token 与刷新回 `503`；刷新先验签、先拿 claims，最后才轮换，所以失败的刷新什么都不消耗。
- **没有用户表，也没有角色表。** 用户按需从 Casdoor 读（`BatchGetUsers`）；角色在 authz。
- **启动时等 Casdoor，而不是要求它已经在。** 管理 API 登录、对账与 OIDC 发现都在后台重试；Casdoor 只是不在时记 Warn，Casdoor 明确拒绝时记一条 Error。
- **每次启动都对账**（`bootstrap`）：先查，缺什么建什么，webhook 的地址、密钥或启用状态与配置不同就改写。每一步都可以安全重跑。
- **对谁发来的 webhook 严格，对内容宽容。** 密钥不对 → `401`；解析不了或认不出的投递存为 `IGNORED` / `ERROR`，回 `200`。
- **`ENABLED_COMPONENTS` 就是锁文件本身**（`file://brickkit.yaml`），加组件不需要额外一步；只解码 `components[].id` 与 `kind`。

## 易错点

| 不许 | 症状 | 原因 |
|---|---|---|
| 缓存 `ResolveClaims` 的结果，或 authz 不在时退回上一次的 claims | 什么都不报错；改了角色之后刷新出来的 token 还是旧角色，组件回 `401 token_stale`，前端再刷新，永远转下去 | claims 必须是当前的；停摆用 `503` 回答，不用旧角色回答 |
| 在拿到 claims 之前就轮换 refresh token | authz 抖一下：刷新回 `503`，客户端用同一个 token 重试，撞上重放检测，这个人名下全部会话被作废 | `RefreshToken` 先验签、拿 claims、签名，最后轮换；`TestREST_authz不可达时刷新回503且不消耗refreshToken` |
| 用唯一约束给 webhook 投递去重，或去掉 `RecordDeliveryAndPublish` 里的 advisory 锁 | 重复悄悄通过；同一条用户事件到下游两次 | `webhook_deliveries` 是分区表，唯一索引必须带 `received_at`，而每次重投的它都不同 |
| 把 `webhook_deliveries.payload` 改成 JSONB，或拒收解析不了的投递 | 一条格式不对的投递让 insert 失败；事件丢了，Casdoor 永远重投 | 真机只见过部分动作（见 `docs/design.zh.md`）；payload 存成 `TEXT`，标 `IGNORED` / `ERROR` |
| 只按 JSON 对象解投递体里的 `object` | 每一条真实投递都存成 `IGNORED`（"找不到用户标识"），`infra.iam.user.*.v1` 一条都发不出去，门禁全绿 | Casdoor 发来的 `object` 是编码成 JSON 字符串的；`decodeUser` 两种形式都认，`TestWebhookUserPayload_object是JSON字符串时也能取出用户字段` |
| 把 Casdoor 的 JWKS 地址写死，或原样使用发现文档里的 `jwks_uri` | 换 token 永远回 `503`；keyfunc 报 `404` 或连到自己 | Casdoor 的路径是 `/.well-known/jwks`（没有 `.json`），发现文档里的主机是 Casdoor 的 `origin`，本容器未必够得着；`rebaseHost` 保留路径、换成 `CASDOOR_BASE_URL` 的主机 |
| 给 `bootstrap` 建的应用加上 `password` 授权 | 能用，但登录用的应用从此接受任何人发来的密码 | 浏览器走授权码流程；只有 `casdoor_integration_test.go` 与 `scripts/seed.sh` 里的测试应用开密码授权 |
| refresh token 与应用 token 用同样的 claims、不检查 `typ` | 应用 token 被当成 refresh token 接受，或者反过来 | 两者用同一把钥匙签；`TestVerifyRefreshToken_不接受应用token冒充` |
| 启动时生成签名密钥，或让各副本用不同的钥匙 | 每次重启所有人被登出；两个副本时一半请求验不过 | 钥匙来自 `APP_TOKEN_SIGNING_KEY_PEM`；key ID 是确定性的 RFC 7638 指纹 |
| 改了 `contracts/infra/iam/v1/iam.proto` 的注释或选项却不给契约包打 tag | 本地构建通过（`replace` 遮住了）；外壳拉取 `infra-iam-casdoor/v2` 时对着旧的 `gen/` 编译 | `gen/infra/iam/` 下任何变化都要打新 tag gen/infra/iam/v1.x.y，并让根 `go.mod` require 它 |

## 改代码前自查

1. 这个改动会不会让 claims 比"现在"更旧？会就是把旧 token 死循环请回来，停下。
2. 是不是在加一张用户表或角色表？用户归 Casdoor、角色归 authz；去读，不要复制。
3. webhook 的改动有没有把"认不出的形状"变成报错？只有共享密钥校验可以拒绝。
4. 新的 rpc 或事件，换一个 IAM 实现（Keycloak）能不能同样提供？契约属于 IAM 族，不属于 Casdoor。
5. 有没有人在给本组件加依赖边？其余组件用 `IAM_JWKS_URL` 与用户事件，从不建边。
6. 新建的 Casdoor 对象有没有带密码授权？只有测试应用可以。
