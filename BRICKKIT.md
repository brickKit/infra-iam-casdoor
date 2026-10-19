# infra/iam-casdoor

## 组件定位

身份成员（Casdoor 适配），担起下面几件事：
- 浏览器登录：授权码加 PKCE，本组件作为客户端完成登录，在服务端保存会话，向浏览器发 `HttpOnly`、`SameSite=Lax` 的会话 Cookie；
- 给每个会话签发短期访问令牌，供边缘按会话换取；
- 提供本组件签名密钥的公开 JWKS。

令牌的 `sub` 是平台主体（UUIDv7），由本组件把 Casdoor 账号绑定到平台主体，Casdoor 的用户 ID 不离开本组件。令牌只带身份，不带角色或部门：授权只来自授权视图。

开发与测试环境另有一个换取入口：用户名与密码换访问令牌，供种子数据与自动化测试使用（A101）。它只在 `IAM_DEV_EXCHANGE` 为真时存在。

当前版本是代表部署实验第 5 步做到的范围。下面几项随后续加入：
- 账号停用的拉取与事件 `infra.iam.account_status_changed.v1`；
- 补取与水位回声；
- 边缘的会话缓存插件与失效推送；
- 移动端的刷新令牌。

Casdoor 给不出可靠的变更序号，本组件按外部来源声明：Casdoor 的操作记录连失败的请求也写，webhook 不带序号、约每 30 秒批量发出。

## 部署前准备

- **数据库**：自己的 schema、运行角色与属主角色（装配项目注册表的 `infra_iam_casdoor`）。
- **Casdoor 里的登录应用**：
  - 授权方式只开授权码；
  - 回调地址是本组件的 `/api/iam/callback`，即 `IAM_CALLBACK_URL`；
  - 令牌格式 JWT；
  - 它的 client ID 与密钥分别是 `CASDOOR_CLIENT_ID` 与 `CASDOOR_CLIENT_SECRET`。
- **签名密钥**：Ed25519 私钥，PKCS #8 的 PEM 格式，例如 `openssl genpkey -algorithm ed25519`。经 `IAM_SIGNING_KEY_FILE` 挂载为文件，SDK 在密钥轮换时重读。另备一把 `IAM_SIGNING_KEY_NEXT_FILE`。
- **签发方**：`IAM_TOKEN_ISSUER` 等于每个组件的 `IAM_ISSUER`；每个组件的 `IAM_JWKS_URL` 指向本组件的 `/api/iam/jwks`。
- **只在开发与测试环境**：
  - 在 Casdoor 里另建一个只开密码授权的客户端，配置 `IAM_DEV_EXCHANGE=true`、`IAM_DEV_CLIENT_ID`、`IAM_DEV_CLIENT_SECRET`；
  - 仓库里的 `scripts/dev_setup.py` 按幂等的方式建好登录应用、开发客户端与测试用户。
- **上线检查**：确认 `IAM_DEV_EXCHANGE` 没有打开，且身份产品里没有开着密码授权的客户端（A101）。

## 依赖说明

- 必需：Casdoor（基础资源，不是组件）与数据库。
- 不调用其他组件。
- 只有 `/healthz` 不依赖 Casdoor：Casdoor 暂时不可用时，已经登录的会话照常换取令牌，新的登录与开发换取失败。

## 配置指南

全部键见 `component.yaml` 的 `configSchema`。

| 键 | 说明 |
| --- | --- |
| `IAM_TOKEN_ISSUER` | 令牌的 `iss` |
| `IAM_SIGNING_KEY`（或 `_FILE`） | 当前的签名密钥 |
| `IAM_SIGNING_KEY_NEXT`（或 `_FILE`） | 预先发布的备用密钥 |
| `IAM_ACCESS_TOKEN_TTL` | 访问令牌有效期，默认 5 分钟 |
| `IAM_CALLBACK_URL` | Casdoor 里登记的回调地址 |
| `IAM_AFTER_LOGIN_URL` | 没有 `return_to` 时登录后去哪，默认 `/` |
| `IAM_COOKIE_SECURE` | 会话 Cookie 是否 `Secure`，默认真，只有明文 HTTP 的开发环境关 |
| `IAM_SESSION_IDLE` | 会话空闲超时，默认 30 分钟 |
| `IAM_SESSION_ABSOLUTE` | 会话绝对超时，默认 12 小时 |
| `CASDOOR_URL` | Casdoor 的后端通道：换取令牌、取公钥 |
| `CASDOOR_PUBLIC_URL` | 浏览器访问 Casdoor 的地址 |
| `CASDOOR_ISSUER` | Casdoor ID 令牌的 `iss`，即它的 `origin` 设置，默认等于 `CASDOOR_PUBLIC_URL` |
| `CASDOOR_CLIENT_ID`、`CASDOOR_CLIENT_SECRET` | 登录应用 |
| `IAM_DEV_EXCHANGE`、`IAM_DEV_CLIENT_ID`、`IAM_DEV_CLIENT_SECRET` | 只在开发与测试环境 |
| `DEPLOYMENT_ID`（必填） | 令牌的受众是 `be:deployment:<DEPLOYMENT_ID>` |
| `PG_HOST`、`PG_DATABASE`、`PG_USER`、`PG_PASSWORD`、`PG_SCHEMA`（必填） | 自己的数据库目标、运行角色与 schema，密码是密钥；迁移另用属主角色 `PG_OWNER_USER`、`PG_OWNER_PASSWORD` |

**换签名密钥**：
1. 新密钥先作为 `IAM_SIGNING_KEY_NEXT` 发布，至少等 1 小时，让各组件的公钥缓存都取到它；
2. 两者对调：新密钥签名，旧密钥作为备用继续发布，直到旧令牌全部过期（访问令牌有效期）；
3. 再撤下旧密钥。

密钥泄露时直接对调，并缩短撤下前的等待。

## 契约索引

用户面全部是公开路由，它们本身就是取得凭据的入口：

| 路由 | 用途 |
| --- | --- |
| `GET /api/iam/login?return_to=<站内路径>` | 跳到 Casdoor 登录 |
| `GET /api/iam/callback` | 登录回调：发会话 Cookie，再跳回 `return_to` |
| `POST /api/iam/session/token` | 凭会话 Cookie 换访问令牌，回答 `access_token`、`expires_in`、`principal`。会话已结束时答 401，原因是 `SESSION_ENDED`，属于 `infra/iam-casdoor` 域 |
| `POST /api/iam/logout` | 结束会话并清除 Cookie |
| `GET /api/iam/jwks` | 公钥集合 |
| `POST /api/iam/dev/token`（只在开发与测试环境） | 请求体 `{"username","password"}` |

凭据与事件的族契约见 `contract-infra-iam` 仓库。

## 外壳声明

不是外壳。可以被 Go 的基础外壳（`be/go-infra`）承载。
