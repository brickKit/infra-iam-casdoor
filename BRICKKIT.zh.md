# infra/iam-casdoor

## 组件定位

Casdoor 与项目其余部分之间的适配层。Casdoor 证明"这个人是谁"；本组件把这份证明换成项目自己的应用 token——里面带着 `infra/authz` 此刻算出的角色、部门路径与组织——其余每个组件都对着本组件的 JWKS 在本地验它。本组件还告诉前端项目里装了哪些组件，并把 Casdoor 的用户 webhook 转成事件。

**拥有**

- 应用 token 的签发、刷新与作废：`POST /api/iam/token` 用 Casdoor 签给可信应用的 id_token 换一个应用 token 加一个 refresh token；刷新时轮换 refresh token，会话在登录后 `REFRESH_TOKEN_TTL_SECONDS` 结束（重放一个已用过的，会作废这个人名下全部 refresh token）；登出作废一个；在 Casdoor 里停用或删除一个人，作废他名下全部。
- 签名密钥的公钥部分，挂在 `/.well-known/jwks.json`（当前一把；轮换期间还有上一把）。
- `GET /api/tenant/features`：项目里装了哪些组件，读自项目的 `brickkit.yaml`。
- 本组件需要的 Casdoor 组织、应用与 webhook，每次启动都按配置对账。
- 事件 `infra.iam.user.created.v1`、`infra.iam.user.updated.v1`、`infra.iam.user.disabled.v1`，由 Casdoor 的 webhook 桥接而来。

**不拥有**

- 用户、密码、登录页、MFA、社交登录：Casdoor。浏览器直接与 Casdoor 说话，本组件既不代理也不转发登录。
- 角色、角色的权限、谁有哪个角色：`infra/authz`。每次签发与刷新时现问，本组件不缓存。
- 请求上的 token 校验与权限判定：每个组件用 SDK 在进程内做，对着 JWKS 与权限包。
- 通知偏好与通道地址：`infra/notification`，它靠 `infra.iam.user.*.v1` 事件维护自己的副本。

## 部署前准备

- **PostgreSQL**：一个 schema 与一个登录角色，名字由你定。`PG_SCHEMA` 是 schema 名（默认 `infra_iam_casdoor`）；`PG_USER` 是角色名，它要在该 schema 上有 `USAGE` 与 `CREATE`，`PG_PASSWORD` 是它的密码。迁移以这个角色运行，里面不写任何角色名或 schema 名：所有对象都不带限定名建在 `PG_SCHEMA` 里，所以归这个角色所有；组件运行时自己建未来的分区，需要这份所有权。角色名从不由 schema 名推出。`<PG_SCHEMA>_archive` schema 可有可无，目前没有任何东西写它。BrickKit 不建这些。BrickEnterprise 组装项目是提供它们的一种方式：`make dev-env` 把密码写进 `.env`，`make db-init` 按它的登记表建 schema `infra_iam_casdoor`、角色 `infra_iam_casdoor_rw` 与授权。
- **NATS** 可经 `NATS_URL` 访问：事件经 outbox 表与后台推送发出；NATS 不在时组件照样启动，事件在 outbox 里等。
- **Casdoor** 在跑，本组件能经 `CASDOOR_BASE_URL` 访问到它，Casdoor 内置组织里有一个管理员账号（`CASDOOR_ADMIN_USERNAME` / `CASDOOR_ADMIN_PASSWORD`）。Casdoor 镜像自带一个人人皆知的默认管理员口令：生产环境必须把 Casdoor 管理员的口令与 `CASDOOR_ADMIN_PASSWORD` 一起改掉（两边对不上时，管理 API 登录在后台反复重试，每次都记一条 Error，最多每 30 秒一次，直到口令改对；在此之前组织、应用、webhook 都不对账，`BatchGetUsers` 回 `UNAVAILABLE`，webhook 投递在队列里等，登录成功后发出；之前某次启动记下过应用 client ID 的话换 token 照常，全新安装时回 `503`）。Casdoor 的 `origin` 配置必须是带端口的完整 URL：它的 OIDC 发现文档里的 issuer 与 JWKS 地址都由它拼出。组织 `CASDOOR_ORG_NAME`、应用 `CASDOOR_APP_NAME` 与 webhook 由本组件自己建；Casdoor 还没起来时本组件在后台反复重试，在第一次连上 Casdoor 之前换 token 回 `503`。
- **签名密钥**：一把 PEM 格式的 RSA 私钥（PKCS #1 或 PKCS #8），例如 `openssl genrsa 2048`。重启前后、各副本之间必须是同一把，否则重启前签出的 token 全部验不过。作为密钥文件保存，用 `file://` 引用。
- **webhook 回调的通路**：Casdoor 必须能访问到本组件。把 Casdoor 容器接进项目的网络（`brickkit-<project>-net`，由 `brickkit up` 建；Casdoor 先起时，用同样的 Compose 标签预先建好），`WEBHOOK_CALLBACK_URL` 写本组件自己的版本化服务名 `http://infra-iam-casdoor-2-0-0:8200/api/iam/webhooks/casdoor`。这个名字在单独运行与外壳托管时都能解析（成员服务名是外壳容器的网络别名），不用开放端口；本组件每次发版都要跟着改，同 `IAM_JWKS_URL`。回调地址留空也合法：用户照样能登录，只是不发 `infra.iam.user.*.v1` 事件。
- **`infra/authz`** 在跑（唯一的依赖，见下）。

## 依赖说明

- `infra/authz`（必需）：每次签发与每次刷新都调它的 gRPC `ResolveClaims`，把用户此刻的角色、部门路径与组织写进应用 token。没有缓存兜底：authz 不可达期间，登录与刷新回 `503`（refresh token 不会被用掉，authz 恢复后用同一个还能刷新），已经拿到应用 token 的人照常使用，直到它过期（`APP_TOKEN_TTL_SECONDS`）。

任何组件都不该依赖本组件。其余组件对着各自 `IAM_JWKS_URL` 的 JWKS 验应用 token，靠 `infra.iam.user.*.v1` 事件了解用户：这是配置与事件，不是依赖边。IAM 的实现能被替换，靠的就是这一点。

Casdoor 本身不是依赖：它是项目之外的资源，经 `CASDOOR_BASE_URL` 访问。

## 配置指南

| 变量 | 含义 |
|---|---|
| `PG_HOST` | PostgreSQL 主机。一般写项目共享值（`$var:PG_HOST`）。 |
| `PG_PORT` | PostgreSQL 端口；默认 `5432`。 |
| `PG_DATABASE` | `PG_SCHEMA` 那个 schema 所在的库（`$var:PG_DATABASE`）。 |
| `PG_USER` | 组件的角色，名字随意（BrickEnterprise 项目里是 `infra_iam_casdoor_rw`）。单跑时组件以它登录。每个事务都切到它（`SET LOCAL ROLE`），所以在外壳里（外壳以自己的角色登录）这个成员的 `PG_USER` 仍是它的事务所用的角色，外壳的角色必须能切到它。 |
| `PG_PASSWORD` | `PG_USER` 的密码。密钥：写 `${INFRA_IAM_CASDOOR_DB_PASSWORD}`（或你的密钥库引用），不写值本身。 |
| `PG_SCHEMA` | 全部表、outbox 与迁移状态表（`schema_migrations_<PG_SCHEMA>`）所在的 schema；默认 `infra_iam_casdoor`。任何合法的名字都行；照样写出字面量。 |
| `NATS_URL` | outbox 推送发往、消费者读取的 NATS（`$var:NATS_URL`）。 |
| `OTEL_BASE_URL` | OpenTelemetry collector 的基地址；为空（默认）不导出。 |
| `IAM_JWKS_URL` | 本组件自己的 JWKS，例如 `http://infra-iam-casdoor-2-0-0:8200/.well-known/jwks.json`：SDK 像在其余组件里一样验 `POST /api/iam/logout` 的 token。必填；为空或不可达时登出回 `403`。与其余组件用同一个项目级取值。 |
| `CASDOOR_BASE_URL` | 从本组件看过去的 Casdoor，例如 Casdoor 跑在宿主机上时写 `http://host.docker.internal:8000`。管理 API 与 OIDC 发现都走它。必填。 |
| `CASDOOR_ADMIN_USERNAME` | Casdoor 内置组织里的管理员；默认 `admin`。 |
| `CASDOOR_ADMIN_PASSWORD` | 它的密码。密钥：写 `${…}` 引用。必填。 |
| `CASDOOR_ORG_NAME` | 存放项目用户的 Casdoor 组织；默认 `brickkit`。不存在就建。 |
| `CASDOOR_APP_NAME` | 用户登录所用的 Casdoor 应用（授权码流程，不开密码授权）；默认 `brickkit-app`。不存在就建；已存在的不改。它的 client ID 就是 Casdoor id_token 要能换 token 必须带的 audience。 |
| `CASDOOR_EXTRA_CLIENT_IDS` | 另外也接受哪些 Casdoor 应用签的 id_token，写 client ID，逗号分隔；默认为空。给作为不同 Casdoor 应用的多个前端，或本地测试应用。生产环境永远不要列开着密码授权的应用。 |
| `WEBHOOK_SHARED_SECRET` | Casdoor 每次回调在 `X-Shared-Secret` header 里带的值；没带或不对的回调一律 `401`。密钥：写 `${…}` 引用，取一个足够长的随机串。必填。 |
| `WEBHOOK_CALLBACK_URL` | Casdoor 发用户 webhook 的地址（从 Casdoor 看过去），以 `/api/iam/webhooks/casdoor` 结尾。每次启动：webhook 不存在就建，地址、密钥或启用状态与配置不同就改写。为空（默认）时什么都不建，已有的 webhook 也不动：不发用户事件。写本组件的版本化服务名（见部署前准备），外壳托管时同样可用；宿主机端口不行，外壳成员的端口不能单独开放。 |
| `APP_TOKEN_SIGNING_KEY_PEM` | 签应用 token 与 refresh token 的 RSA 私钥，PEM。密钥、多行：`file://` 引用密钥文件。必填。它在 JWKS 里的 key ID 是 RFC 7638 指纹，重启前后不变。 |
| `APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM` | 密钥轮换期间上一把钥匙的公钥（PEM 公钥或证书）；默认为空。配了之后 JWKS 同时挂两把，上一把签的 refresh token 仍被认。换钥之后过了最长的 token 有效期，就清空它。 |
| `APP_TOKEN_TTL_SECONDS` | 应用 token 的有效期，正整数秒；默认 `600`。也是 `infra/authz` 停摆时用户还能继续用多久。不是正整数时组件启动即失败。 |
| `REFRESH_TOKEN_TTL_SECONDS` | 会话的有效期，正整数秒，从登录算起；默认 `604800`（七天）。刷新会轮换 refresh token，但从不延长会话：登录后到了这个时长就要重新登录。 |
| `ENABLED_COMPONENTS` | 项目的 `brickkit.yaml`，写 `file://brickkit.yaml`。`GET /api/tenant/features` 回其中 `components` 里不是外壳的那些 ID，每个一次，按字典序。含义是"装了"，不是"在运行"：在部署文件里关掉的组件照样列出。只读组件 ID 与 kind，文件其余内容不解码。必填；旧的逗号分隔写法启动即报错。 |

## 契约索引

- `contracts/infra/iam/v1/iam.proto` — gRPC `infra.iam.v1.IamService`，IAM 族的契约（名字里不带 Casdoor，换一个 IAM 实现也能原样提供）：`BatchGetUsers`（sub 列表 → 显示名、邮箱、手机号、IM 账号；每次调用都回源 Casdoor，查不到的 sub 省略；Casdoor 管理会话未就绪或 Casdoor 出错时回 `UNAVAILABLE`）与 `GetTenantFeatures`（与 REST 路由同一份清单）。Go 包是独立模块 `github.com/brickKit/infra-iam-casdoor/gen/infra/iam`。
- `contracts/iam.openapi.yaml` — REST，路径是 IAM 族共用的固定路径。都不需要权限键：本组件就是"还没有身份"与"有身份"之间的那道门。`POST /api/iam/token`（公开；请求体不对 `400`，Casdoor token 无效、不是签给可信应用的、或这个人在 Casdoor 里已停用 `401`，Casdoor 或 authz 不可达、或还不知道应用的 client ID `503`）、`POST /api/iam/token/refresh`（公开；refresh token 无效、已作废、已过期或被重放 `401`，包括会话已到终点、这个人在 Casdoor 里已停用，authz 不可达 `503`）、`POST /api/iam/logout`（需登录；幂等）、`GET /.well-known/jwks.json`（公开；给其余组件，不经网关）、`GET /api/tenant/features`（公开；前端登录前就要读）、`POST /api/iam/webhooks/casdoor`（公开路由，靠共享密钥 header 认证；投递登记下来就回 `200`，不管这一刻读不读得到 Casdoor；`503` 仍在契约里声明，但这个版本不再返回；只给 Casdoor，不经网关）。
- `contracts/events/iam.events.json` — 经 outbox 发布：`infra.iam.user.created.v1`、`infra.iam.user.updated.v1`（带只增不减的 `version`）、`infra.iam.user.disabled.v1`（删除或停用用户也发这条；同一个事务里作废这个人全部 refresh token）。每条事件带的是处理投递那一刻 Casdoor 里这个人的状态（经管理 API 回读），所以投递乱序到达时下游留下的仍是最新状态；`version` 每人严格递增。投递由后台循环从队列里处理：读不了 Casdoor 时在队列里等，读得到了再发；Casdoor 对某条投递一直出错的，试满 10 次标 `FAILED`，记一条 Warn。只带 owner 与 name 的投递经 Casdoor 找到这个人；用最小请求体 `delete-user` 一个本组件从没为他发过事件的人，存成 `IGNORED`。Casdoor 大约每 30 秒成批发一次 webhook，发送失败不重投，所以本组件停着期间的变化不会被桥接（这期间被重新启用的人，在 Casdoor 里下一次改动他之前登录不了；随便改一下就行）。`infra.iam.login.v1` 已声明、尚未发布。消费：`infra.authz.user_role.changed.v1`，`change_type: kicked` 时作废这个人名下全部 refresh token；其余变化不动 refresh token，下次刷新自然拿到新角色。
- `assembly.yaml` — 本项目的元数据：换 token、刷新、登出、features 四条网关路由；没有权限键、没有菜单；schema 与角色；`data_scopes: none`。

## 外壳声明

不是外壳。可以由 Go 外壳托管（BrickEnterprise 项目里是 `be/go-infra`），也可以单独运行；两种方式代码相同。进外壳托管后它的端口不能单独开放；Casdoor 经成员服务名回调 webhook，外壳同样应答这个名字（见 `WEBHOOK_CALLBACK_URL`）。
