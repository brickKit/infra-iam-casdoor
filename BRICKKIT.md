# infra/iam-casdoor

## 组件定位

身份成员（Casdoor 适配），担起下面几件事：
- 浏览器登录：授权码加 PKCE，本组件作为客户端完成登录，在服务端保存会话，向浏览器发 `HttpOnly`、`SameSite=Lax` 的会话 Cookie；
- 给每个会话签发短期访问令牌，令牌带账号的安全状态版本 `be_sv`；只有边缘能换取，经系统面的标准方法 `be.session.v1.SessionService`（线协议 P8.28），浏览器的脚本拿不到令牌；
- 会话的每一次结束（登出、超时、改密码结束其他会话）写进流 `be.session.ended`，边缘按位置拉取；
- 改密码：经本组件办理，旧密码由 Casdoor 核对；账号的安全状态版本加一，其他会话结束，当前会话的下一次换取拿到新版本的令牌，账号状态（`be.security.account_status`，带版本）经发件表发出；
- 账号状态是授权成员的内部来源（水位来源）：账号绑定时、每次安全变更时发出状态；授权成员经系统面补取（标准方法 `be.source.v1.WatermarkService`）、按 ID 批量读取与取快照（`be.source.v1.RecordService`，线协议 P9.30）；
- 提供本组件签名密钥的公开 JWKS。

令牌的 `sub` 是平台主体（UUIDv7），由本组件把 Casdoor 账号按“签发者加 subject”绑定到平台主体，Casdoor 的用户 ID 不离开本组件；同一邮箱、同一登录名、别的签发者的同一 subject 都不接管已有的主体。令牌只带身份，不带角色或部门：授权只来自授权视图。

开发与测试环境另有一个换取入口：用户名与密码换访问令牌，供种子数据与自动化测试使用（A101）。它只在 `IAM_DEV_EXCHANGE` 为真时存在。

在 Casdoor 里直接做的变更（3.0.21 起）：Casdoor 给不出可靠的变更序号（操作记录连失败的请求也写，webhook 不带序号），本组件每 `IAM_PULL_INTERVAL`（起始 1 分钟）、以及授权成员每次补取账号状态之前，把绑定的每个账号与 Casdoor 里的用户全量比较一次：
- 在控制台停用或删除：照常生效——账号停用，安全状态版本加一，会话结束，停用的账号状态发出，本组件记下证据（Casdoor 的 `updatedTime` 作为产品坐标）；
- 在本组件停用的账号在 Casdoor 里又被启用（控制台重新启用，或产品的库回退）：不认作启用，本组件在 Casdoor 里重新禁用它并记错误日志；本组件自己也拒绝它登录。重新启用只能经本组件办理；
- 在 Casdoor 里改了密码（`lastChangePasswordTime`）或第二因素：安全状态版本加一，会话结束。经本组件改密码时，下一次比较不再计一次。

比较读不到 Casdoor 时，授权成员的这次补取不写回声（水位不推进）。比较只看本组件配置的签发者绑定的账号。比较用登录应用的凭据（`CASDOOR_CLIENT_ID`、`CASDOOR_CLIENT_SECRET`）读写用户：这个应用要能管理它所在组织的用户（Casdoor 4.1.0 默认如此）。

账号操作（3.0.22 起，受授权保护的用户面路由，资源 `infra.iam.account`，主体维度 `account`）：管理员停用、冻结、启用账号，强制登出，重置第二因素。
- 停用、冻结与启用之前先问授权成员（`AccountService.CheckAccountChange`，`infra/authz` 3.0.25 起，“证明不了”的回答 3.0.26 起）：对象持有授权管理员资格时一律要另一名授权管理员的确认，答 202 `CONFIRMATION_REQUIRED`；拿到确认（授权成员的 `POST /api/authz/confirmations`，带 `account` 与 `target_state`）后带 `confirmation` 再请求，确认随这次的账号状态发出。请求者的视图依据过旧（超过 `IAM_T_TIGHT`，起始 1 小时）时，停用与冻结普通账号也要第二人。管理员账号的状态变更写错误级日志（严重告警）。
- 顺序保证 Casdoor 不比本组件更开放：停用与冻结先在本组件生效（版本加一、会话结束、状态发出、记下请求者与确认的证据），再在 Casdoor 里禁用；启用先在 Casdoor 里允许，再在本组件生效。写 Casdoor 失败时请求答错误，本组件已做的部分保留，同一请求再来一次让 Casdoor 跟上，期间的比较也会把它禁用回去。
- 询问之后账号又变了（版本不同）答 `CHANGE_REVISION_STALE`，重新请求。
- 强制登出：本组件的会话全部结束、版本加一，再结束这个用户在 Casdoor 里的全部会话（任何应用）。重置第二因素：先在 Casdoor 里删除，再加版本、结束会话，比较不再计一次。
- 全量比较遇到本组件一分钟内改过状态的账号，这一轮不比较它的状态（密码与第二因素照常比较）。

证据（3.0.23 起，协议 15）：停用、冻结、改密码、重置第二因素、强制登出在动手之前先把意图交给证据存储（审计组件），完成时写结论；启用、比较发现的回退与产品侧的凭据变更写一般记录。证据存储不可达时照常办理，意图改写进告警渠道（运行档案，`RUN_PROFILE_*`），都写不进时记一条严重日志。

重放（3.0.25 起）：整套恢复第 6 步，恢复工具（`ops/recover`）经 `be.evidence.v1.ReplayService` 让本组件按证据重新施加账号状态与强制登出（操作 `infra.iam.account_status.replay`），只写本地；Casdoor 那一侧由与它的比较照常对齐。凭据收紧不重放。

整套恢复中（3.0.26 起，协议 15 的 6.6）：恢复进行时（`RECOVERY_PHASE` 不为空）不签发令牌，边缘的换取答“维护中”；公钥集合在用户面，同样答“维护中”。每个会话记下创建时的部署恢复代次；恢复推进代次之后，本组件启动时（`frozen` 阶段除外：那时库正在恢复）把之前的会话全部结束（原因 `recovery`），写进边缘读取的已结束流，并结束这些人在 Casdoor 里的会话（只是本平台的登录应用的；他们在别的应用里的会话不动，Casdoor 不在恢复组内）；Casdoor 调用失败的记警告日志，本平台的会话照样结束。代次推进后边缘的游标属于旧纪元，第一次读答“重置”，边缘据此丢掉全部缓存的令牌。签名密钥由部署的密钥文件提供，不随库恢复回退；恢复时换新的密钥文件由恢复工具做。

移动端的刷新令牌随后续加入。

## 部署前准备

- **数据库**：PostgreSQL 16 及以上；schema `infra_iam_casdoor`，属主角色 `infra_iam_casdoor_owner`（只供迁移）与运行角色 `infra_iam_casdoor_rw`，名字来自装配项目的注册表。三者由部署方在第一次启动前建好（be-assembly-standard 的 `make db-init` 按装配进项目的组件配置生成并执行）；表由本组件的迁移建。
- **Casdoor 里的登录应用**：
  - 授权方式只开授权码；
  - 回调地址是本组件的 `/api/iam/callback`，即 `IAM_CALLBACK_URL`；
  - 令牌格式 JWT；
  - 它的 client ID 与密钥分别是 `CASDOOR_CLIENT_ID` 与 `CASDOOR_CLIENT_SECRET`。
- **签名密钥**：Ed25519 私钥，PKCS #8 的 PEM 格式，例如 `openssl genpkey -algorithm ed25519`。经 `IAM_SIGNING_KEY_FILE` 挂载为文件，SDK 在密钥轮换时重读。另备一把 `IAM_SIGNING_KEY_NEXT_FILE`。
- **签发方**：`IAM_TOKEN_ISSUER` 等于每个组件的 `IAM_ISSUER`；每个组件的 `IAM_JWKS_URL` 指向本组件的 `/api/iam/jwks`。
- **只在开发与测试环境**：
  - 在 Casdoor 里另建一个只开密码授权的客户端，配置 `IAM_DEV_EXCHANGE=true`、`IAM_DEV_CLIENT_ID`、`IAM_DEV_CLIENT_SECRET`；
  - 仓库里的 `scripts/dev_setup.py` 按幂等的方式建好登录应用、开发客户端与测试用户（种子数据的测试账号；只建账号：`make seed`）。
- **服务身份与授权**：系统面（端口 9200）只接受部署 mTLS，`SessionService` 只许边缘的服务身份 `infra/edge` 调用；本组件的证书、`AUTHZ_GRPC_URL` 与 `AUDIT_GRPC_URL` 与其他组件一样配置（它向授权成员提交自己的定义，账号状态变更之前经同一地址调用 `AccountService.CheckAccountChange`，要 `infra/authz` 3.0.25 起，且授权成员的 `IAM_COMPONENT` 是本组件）。账号操作的权限键（`infra.iam.account.*`）要登记在授权成员的注册表里。
- **消息系统**：`BUS_URL` 与 `IMPLEMENTATION_INSTANCE` 照其他发出事件的组件配置。
- **上线检查**：确认 `IAM_DEV_EXCHANGE` 没有打开，且身份产品里没有开着密码授权的客户端（A101）。

## 依赖说明

- 必需：Casdoor（基础资源，不是组件）、数据库与消息系统。
- 授权成员：提交自己的定义；账号的停用、冻结与启用之前调用 `AccountService.CheckAccountChange`（不可达时这三个操作答错误，其余照常）。
- 只有 `/healthz` 不依赖 Casdoor：Casdoor 暂时不可用时，已经登录的会话照常换取令牌，新的登录、改密码与开发换取失败。

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
| `IAM_PULL_INTERVAL` | 与 Casdoor 全量比较的间隔（安全 03 的 `P_pull`），默认 1 分钟；授权成员每次补取之前另比较一次 |
| `IAM_T_TIGHT` | 安全 03 的 `T_tight`，默认 1 小时：视图依据过旧超过它时，停用与冻结要第二人 |
| `CASDOOR_URL` | Casdoor 的后端通道：换取令牌、取公钥 |
| `CASDOOR_PUBLIC_URL` | 浏览器访问 Casdoor 的地址 |
| `CASDOOR_ISSUER` | Casdoor ID 令牌的 `iss`，即它的 `origin` 设置，默认等于 `CASDOOR_PUBLIC_URL` |
| `CASDOOR_CLIENT_ID`、`CASDOOR_CLIENT_SECRET` | 登录应用 |
| `IAM_DEV_EXCHANGE`、`IAM_DEV_CLIENT_ID`、`IAM_DEV_CLIENT_SECRET` | 只在开发与测试环境 |
| `DEPLOYMENT_ID`（必填） | 令牌的受众是 `be:deployment:<DEPLOYMENT_ID>` |
| `BUS_URL`、`IMPLEMENTATION_INSTANCE`（必填） | 消息系统与本实现实例的标识；已结束会话的游标带着它，换了实例时边缘清空缓存 |
| `SERVICE_TLS_CERT_FILE`、`SERVICE_TLS_KEY_FILE`、`SERVICE_TLS_CA_FILE`、`AUTHZ_GRPC_URL`、`AUDIT_GRPC_URL` | 服务身份与授权、审计成员，与其他组件相同 |
| `PG_HOST`、`PG_DATABASE`、`PG_USER`、`PG_PASSWORD`、`PG_SCHEMA`（必填） | 自己的数据库目标、运行角色与 schema，密码是密钥；迁移另用属主角色 `PG_OWNER_USER`、`PG_OWNER_PASSWORD` |

**换签名密钥**：
1. 新密钥先作为 `IAM_SIGNING_KEY_NEXT` 发布，至少等 1 小时，让各组件的公钥缓存都取到它；
2. 两者对调：新密钥签名，旧密钥作为备用继续发布，直到旧令牌全部过期（访问令牌有效期）；
3. 再撤下旧密钥。

密钥泄露时直接对调，并缩短撤下前的等待。

## 契约索引

登录相关的用户面是公开路由：它们本身就是取得凭据的入口，其余的由会话 Cookie 保护：

| 路由 | 用途 |
| --- | --- |
| `GET /api/iam/login?return_to=<站内路径>` | 跳到 Casdoor 登录 |
| `GET /api/iam/callback` | 登录回调：发会话 Cookie，再跳回 `return_to` |
| `POST /api/iam/logout` | 结束会话并清除 Cookie |
| `POST /api/iam/password` | 改密码：会话 Cookie 加请求体 `{"old_password","new_password"}`；旧密码不对答 400 `REQUEST_INVALID`，会话已结束答 401 `SESSION_ENDED` |
| `GET /api/iam/jwks` | 公钥集合 |
| `POST /api/iam/dev/token`（只在开发与测试环境） | 请求体 `{"username","password"}` |

账号操作是受保护的路由（令牌加授权，3.0.22 起）；看不见这个账号答 404，别的 Casdoor 的账号也答 404：

| 路由 | 操作 | 说明 |
| --- | --- | --- |
| `GET /api/iam/accounts/{principal}` | `infra.iam.account.read` | 账号的 `principal`、`username`、`status`、`security_mark`、`security_version` |
| `POST /api/iam/accounts/{principal}/disable` | `infra.iam.account.disable`（只减少访问） | 停用；请求体可带 `security_mark`（`compromised`、`suspicious`）与 `confirmation` |
| `POST /api/iam/accounts/{principal}/freeze` | `infra.iam.account.freeze`（只减少访问） | 冻结（`security_frozen`）；可带 `confirmation` |
| `POST /api/iam/accounts/{principal}/enable` | `infra.iam.account.enable` | 启用（从停用或冻结）；可带 `confirmation` |
| `POST /api/iam/accounts/{principal}/logout` | `infra.iam.account.logout`（只减少访问） | 强制登出 |
| `POST /api/iam/accounts/{principal}/reset-second-factor` | `infra.iam.account.reset_second_factor` | 重置第二因素 |

停用、冻结、启用：已是目标状态时只让 Casdoor 跟上，答 200；要确认时答 202（`reason: CONFIRMATION_REQUIRED`、`administrator`、`target_state`、`security_version`）；确认人的资格此刻证明不了（身份来源停住，管理员账号的确认人要此刻可证明）答 202（`outcome: processing`、`reason: ADMIN_AVAILABILITY_UNPROVABLE`），什么也没改，来源恢复后再请求；授权成员驳回答 403；成功答 200 与账号。

系统面（gRPC，端口 9200）：`be.session.v1.SessionService`（`be-protocol` 的 `proto/be/session/v1/session.proto`，调用组件只有 `infra/edge`）：
- `Exchange`：会话 Cookie 值的摘要（小写十六进制 SHA-256）换访问令牌；会话已结束答 `SESSION_ENDED`；`renew_idle` 为假时不续期空闲超时；
- `Ended`：按游标分页返回已结束的会话；游标属于别的实例或纪元、或已被清理时回答 `reset`。

系统面另有 SDK 自带的两个标准方法，对象是流 `infra.iam.account_status`，调用组件只有授权成员 `infra/authz`：`be.source.v1.WatermarkService/Pull`（补取）、`be.source.v1.RecordService`（`Read` 按主体批量读取账号状态，不认识的主体答“已清理”；`Snapshot` 按主体分页列出全部账号的状态）。读到的内容与事件的载荷是同一份字节。

事件（`contract/events/`）：`be.session.ended.v1`（流 `be.session.ended`，一个分区）、`infra.iam.account_status_changed.v1`（流 `infra.iam.account_status`，四个分区，水位来源：每个事件列出账号的主体；载荷是安全记录 `be.security.account_status`）。

## 外壳声明

不是外壳。可以被 Go 的基础外壳（`be/go-infra`）承载。
