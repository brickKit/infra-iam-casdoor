# infra-iam-casdoor · IAM 适配层

Casdoor 官方镜像前面的薄适配层——应用 token 的签发与刷新（两个 token 架构）、`/api/tenant/features`、Casdoor webhook 桥接。**这一层才是 `slot:iam`**，Casdoor 本身是带外容器（不进 `brickkit.yaml`）。这是全系统第一次有真实签发方能发出验签通过的 JWT——阶段三 Task 7 之前，`iamJwksUrl` 全部留空，所有非 Public 权限键一律 fail-closed 403。

## 它能做什么

- `POST /api/iam/token`：拿浏览器换来的 Casdoor 身份 token，验签后现问 `infra-authz` 的 `ResolveClaims`，签一个带 `roles[]`/`dept_path`/`org_id` 的应用 token + 一个 refresh token
- `POST /api/iam/token/refresh`：刷新——重新问一次 claims（角色天然最新），refresh token 按 rotation 语义轮换（不是滑动续期），带重放检测（用一个已经轮换掉的旧 token 会连坐撤销这个人名下全部 refresh token）
- `POST /api/iam/logout`：作废当前 refresh token，幂等
- `GET /.well-known/jwks.json`：应用 token 的验签公钥——**各组件的 `iamJwksUrl` 指向这里**，不是指向 Casdoor
- `GET /api/tenant/features`：把 `be-ops` 灌进来的"本次装配启用了哪些组件"原样下发
- `POST /api/iam/webhooks/casdoor`：Casdoor 的用户增删改事件回调，共享密钥 header 校验，转发成 `infra.iam.user.*.v1`
- `infra.iam.v1.IamService`（gRPC）：`BatchGetUsers`（回源 Casdoor，不落本地表）、`GetTenantFeatures`

## 需要哪些基础资源

| 资源 | 形态 | 为什么需要 | 怎么起 |
|---|---|---|---|
| PostgreSQL 16 | **A**（`kind: database`） | `refresh_tokens`/`signing_keys`/`webhook_deliveries`/`bootstrap_state` 独占 schema `infra_iam_casdoor` | 装配仓库根目录 `make up` |
| NATS 2.10 | **A**（`kind: mq`） | 发布 `infra.iam.user.*.v1`/`infra.iam.login.v1`，消费 `infra.authz.user_role.changed.v1`（踢人时撤销 refresh token） | 同上 |
| Casdoor（带外容器） | 形态 B，`casdoorBaseUrl` 配置项 | 唯一的身份认证源——账密/MFA/扫码/社交登录全部在它自己的界面完成，本组件不代理、不转发 | 装配仓库根目录 `infra/docker-compose.infra.yml` |

⚠️ **本组件没有任何组件对它建依赖边**——这是 `slot:iam` 能成立的物理前提（§5.11 硬约束）。唯一一条强依赖是它自己指向 `infra-authz`（`ResolveClaims`，每次签发/刷新都调一次，绝不缓存）。

## 怎么起来

```bash
# 装配仓库根目录
make up                        # 起 PostgreSQL/NATS/Casdoor 等默认基础资源
cd components/infra/iam-casdoor
go build -o build/migrate ./backend/cmd/migrate
PG_SCHEMA=infra_iam_casdoor DATABASE_HOST=localhost DATABASE_PORT=5432 \
  DATABASE_USER=postgres DATABASE_PASSWORD=<.env 里的 POSTGRES_PASSWORD> DATABASE_NAME=brickkit_db \
  ./build/migrate up
go run ./backend/cmd/server     # 单独跑：besdk.RunStandalone 读 component.yaml 的端口
```

或者用平台：`brickkit up`（装配仓库根目录，`components/infra/iam-casdoor` 已登记为 submodule 且在 `brickkit.yaml` 里之后）。

## 怎么用

```bash
# 前端拿到 Casdoor 的身份 token 之后换一个应用 token
curl -X POST http://localhost:8200/api/iam/token \
  -H 'Content-Type: application/json' \
  -d '{"casdoor_id_token":"<Casdoor 签的身份 token>"}'
# {"access_token":"...","refresh_token":"...","token_type":"Bearer","expires_in":600}

# 刷新
curl -X POST http://localhost:8200/api/iam/token/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"..."}'

# 登出（需要 Authorization: Bearer <应用 token>）
curl -X POST http://localhost:8200/api/iam/logout \
  -H 'Authorization: Bearer <应用 token>' \
  -H 'Content-Type: application/json' -d '{"refresh_token":"..."}'

# 各组件的 iamJwksUrl 指向这里（内网调用，不经网关）
curl http://localhost:8200/.well-known/jwks.json

# 前端启动时拉，还没登录就要用它决定渲染什么
curl http://localhost:8200/api/tenant/features

# gRPC：批量查用户展示信息
grpcurl -plaintext -d '{"subs":["<Casdoor 内部 UUID>"]}' \
  localhost:9200 infra.iam.v1.IamService/BatchGetUsers
```

## 配置项

| 配置键 | 默认值 | 说明 |
|---|---|---|
| `pgSchema` | `infra_iam_casdoor` | 本组件的 PG schema |
| `iamJwksUrl` | 无默认值 | ⚠️ 真正意义上的自引用——`/api/iam/logout` 用 `besdk.Authenticated`，全系统验应用 token 唯一的 JWKS 来源就是本组件自己的 `/.well-known/jwks.json`，必须配置成指向自己 |
| `casdoorBaseUrl` | 无默认值 | Casdoor 带外容器的地址，`brickkit` 管理的容器要用 `host.docker.internal` 才能连到宿主机上跑的带外容器 |
| `casdoorAdminUsername` | `admin` | 首次初始化调 Casdoor 管理 API 用的身份，Casdoor 官方镜像内置组织 `built-in` 下的默认管理员 |
| `casdoorAdminPassword` | 无默认值，必填 | ⚠️ 同数据库密码一个级别的敏感值 |
| `casdoorOrgName` | `brickkit` | 承载真实用户的组织，首次初始化时若不存在则创建（不用 `built-in`，往它建普通用户默认被拒） |
| `casdoorAppName` | `brickkit-app` | 登录页/OIDC 客户端配置挂在这个应用上，首次初始化时若不存在则创建 |
| `webhookSharedSecret` | 无默认值，必填 | Casdoor 的 webhook 没有内置签名，靠"自定义 header 放共享密钥"这条路自己校验 |
| `webhookCallbackUrl` | `""` | Casdoor（带外容器）回调本组件用的地址，留空表示跳过 webhook 自举这一步 |
| `appTokenSigningKeyPem` | 无默认值，必填 | 应用 token 的当前签名私钥（RSA，PEM）——不自己生成，合并部署多模块同进程会导致每次重启换钥 |
| `appTokenPreviousPublicKeyPem` | `""` | 密钥轮换用，留空表示当前只有一把在用的钥匙 |
| `appTokenTtlSeconds` | `600` | ⚠️ 必须与 `infra-authz` 的 `accessTokenTtlSeconds` 一致 |
| `refreshTokenTtlSeconds` | `604800`（7 天） | rotation 语义，不是滑动续期 |
| `enabledComponents` | `""` | `/api/tenant/features` 的数据来源，逗号分隔字符串 |

### 两个 token：Casdoor 只证明"你是谁"，应用 token 由我签

```
① 浏览器 ↔ Casdoor          纯 OIDC，认证 100% 归它，本组件不在中间
     ↓ 身份 token（只有 sub，没有角色）
② 前端 → 本组件 换一次      验 Casdoor 的签名 → 调 infra-authz 的 ResolveClaims
     ↓                       → 用自己的密钥签出应用 token（roles[]/dept_path/org_id）
③ 业务组件                   验的是本组件的 JWKS（iamJwksUrl 指向这里，不是 Casdoor）
④ 刷新也走本组件             重新调一次 ResolveClaims，角色天然最新
```

不让 Casdoor 直接签带角色的 token（把 `infra-authz` 的角色镜像进去）有三个各自独立的致命问题：踢人链路断掉（`infra-authz` 撤不了 Casdoor 签的 token）、镜像必然异步产生一个不报错的死循环（`stale_since` 已发布而 Casdoor 还没同步）、把角色数据焊回 Casdoor（违背换 Keycloak 时角色数据一行不迁的设计目标）。

## 参考实现

| 项目 | 看的模块 | 借鉴了什么 | 许可证（已复核） | 用法 |
|---|---|---|---|---|
| Casdoor | OIDC 端点与 JWKS、Webhook 配置、`User` 对象字段 | 真机核对确认：Webhook 支持自定义 header（无内置签名）；`sub`/`id` 是内部 UUID，不是用户名；`/api/get-user?userId=<uuid>` 可以直接按 UUID 查用户 | Apache-2.0 | 借鉴实际应用 |
| OAuth 2.0 Token Exchange（RFC 8693） | "拿一个 token 换另一个 token"的请求/响应字段命名 | 不自创请求格式 | 标准文本 | 借鉴逻辑 |
| RFC 7638（JWK Thumbprint） | kid 的确定性推导算法 | `keys.Thumbprint` 严格按官方示例核对过（`backend/internal/keys/keys_test.go`） | 标准文本 | 完整实现标准算法 |

**明确没有参考的**：Ory Hydra / Zitadel 这类自己实现 OIDC Provider 的项目——本组件不实现 Provider，Casdoor 才是。

## 边界与禁令

- **不存用户表**——用户主数据在 Casdoor，查用户信息走 `BatchGetUsers` 回源查询，不落本地影子表（那等于把 `slot:iam` 的可替换性又焊死一次）
- **不存角色**——角色在 `infra-authz`，每次签发/刷新现问，绝不缓存（fail-closed：`infra-authz` 不可达时新登录/刷新会失败，但已登录用户做业务不受影响）
- **不做数据权限**——`data_scopes: none`，本组件的运维数据（refresh token/签名密钥元数据/投递记录/自举标记）不做行级过滤
- **没有任何业务权限键**——REST 面全部是 `besdk.Public`/`besdk.Authenticated`，本组件自己就是"还没有身份"与"有身份"之间的那道门
- **webhook 的 payload 解析是宽容的，共享密钥校验是严格的**——两者不是一回事：认不出的格式标 `IGNORED`/`ERROR` 不影响其它投递，但校验失败一律 401
- **不许在 `dependencies.components` 里被任何组件引用**——`slot:iam` 能成立的物理前提是零入边，谁加了一条依赖边指向本组件，槽位当场失效
