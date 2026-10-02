[English](design.md) · [中文](design.zh.md)

# infra/iam-casdoor 设计

只写结论，给要改本组件设计的人。怎么用：`BRICKKIT.zh.md`；代码怎么布局：`AGENTS.zh.md`。

## 边界

本组件是 Casdoor 前面的适配层，也是 IAM 槽位里唯一的成员：把 Casdoor 换成 Keycloak，就是换掉本组件，别的不动。它拥有应用 token 的签发、刷新与作废，其余组件验 token 所用的 JWKS，给前端的"已安装组件"清单，Casdoor 用户 webhook 到事件的桥接，以及启动时对本组件所需 Casdoor 对象的对账。

| 不在这里 | 归谁 | 为什么 |
|---|---|---|
| 用户、密码、登录页、OIDC 流程、MFA、社交登录 | Casdoor | 本项目不写代码的东西不包成组件。浏览器直接与 Casdoor 说话；本组件只在认证完成之后接手 |
| 角色模型、角色的权限、用户的角色 | `infra/authz` | 角色从不放进 Casdoor，所以换 IAM 实现时角色数据一行不迁 |
| 请求上的 token 校验与权限判定 | 每个组件里的 SDK | 验签是对着 JWKS 与权限包的本地计算；本组件不在请求路径上 |
| 组织架构 | 目前是 `infra/authz`，以后是组织主数据组件 | 本组件只是把 `dept_path` 字符串抄进 token |
| 通知偏好与地址 | `infra/notification` | 它靠用户事件维护自己的副本 |

所有登录方式（账号密码、微信、QQ、Google，以及 Casdoor 以后加的）都在 Casdoor 里配置：不管哪种方式，Casdoor 产出的都是同一种 OIDC id_token，本组件只认这个 token。自助注册或社交登录产生的账号在 authz 里**没有任何角色**，它的应用 token 里 `roles[]` 是空的，在管理员授角色之前每个业务路由都回 `403`。不许给新账号自动授任何角色：那等于把注册入口变成提权入口。

登录方式里没有钉钉，所以 Casdoor 不知道用户的钉钉身份。通知改为按手机号送达钉钉：本组件把手机号放进用户事件，`integration/im-dingtalk` 把它映射成钉钉用户。

## 拥有的数据

| 表 | 分区 | 说明 |
|---|---|---|
| `refresh_tokens` | 否 | 主键 `jti`，`sub`、`expires_at`、`revoked_at`（null = 有效）、`rotated_from`（轮换链）。行数受在线用户数约束 |
| `signing_keys` | 否 | 当前与上一把签名密钥的 key ID 与算法，供排查。私钥从不落库：它来自配置 |
| `webhook_deliveries` | 按 `received_at` 月分区 | 每次 Casdoor 投递一行：去重键、动作、原始 payload（`TEXT`）、状态 `RECEIVED` / `PROCESSED` / `IGNORED` / `ERROR` |
| `bootstrap_state` | 否 | 每个对账步骤一行（`casdoor_org`、`casdoor_app`、`casdoor_webhook`）及其产物（应用的 client ID） |
| `event_outbox`、`event_inbox` | 按 `created_at` 周分区 | 标准 outbox 与消费者的 inbox |

终态：已作废或已过期的 refresh token；webhook 投递写入即终态。没有用户表，也没有角色表：用户在被问到时从 Casdoor 读（`BatchGetUsers`），角色在每次签发时从 authz 读。用户影子表会把 IAM 槽位焊死在这个实现上；角色的缓存副本会把下面"契约面"里说的旧 token 死循环请回来。

`payload` 是 `TEXT` 不是 JSONB：JSONB 在写入时校验，一条不合法的 JSON 投递会让 insert 失败、投递丢失，而这一列的用途正是保留 Casdoor 发来的原文供排查。

## 契约面

gRPC `infra.iam.v1.IamService`，IAM 族的契约（包名不带实现名，`infra/iam-keycloak` 能实现同一份 proto，调用方的 import 不变）：

| rpc | 类型 | 说明 |
|---|---|---|
| `BatchGetUsers` | 读 | 批量读：sub 列表 → 显示名、邮箱、手机号、IM 账号。每次调用都回源 Casdoor（Casdoor 没有按 ID 批量查的接口；批量省的是调用方的往返）。查不到的 sub 省略；Casdoor 出错或管理会话未就绪 → `UNAVAILABLE`，绝不当成"省略" |
| `GetTenantFeatures` | 读 | 已安装的组件，与 REST 相同 |

REST，路径是 IAM 族共用的固定路径；没有一条需要权限键，因为本组件就是"没有身份"与"有身份"之间的那道门：

| 路径 | 访问 | 说明 |
|---|---|---|
| `POST /api/iam/token` | 公开 | Casdoor id_token → 应用 token + refresh token |
| `POST /api/iam/token/refresh` | 公开 | refresh token 自己证明自己；轮换它 |
| `POST /api/iam/logout` | 需登录 | 作废调用者的一个 refresh token；幂等；别人的 token 不受影响 |
| `GET /.well-known/jwks.json` | 公开 | 给其余组件里的 SDK；不经网关 |
| `GET /api/tenant/features` | 公开 | 前端登录之前就要读 |
| `POST /api/iam/webhooks/casdoor` | 公开路由，共享密钥 | Casdoor 的 webhook 没有签名，但能带自定义 header，所以把 `X-Shared-Secret` 与 `WEBHOOK_SHARED_SECRET` 比对（常数时间）；不经网关 |

**Casdoor 怎么到达 webhook。** Casdoor 是基础资源，不是组件，默认不在项目的网络里。把它接进项目网络，`WEBHOOK_CALLBACK_URL` 写本组件的版本化服务名。经宿主机端口（`expose: true` 加 `host.docker.internal`）的做法没有采用：它只在单独运行时成立，外壳成员的端口不能单独开放，而服务名同时也是外壳容器的网络别名。代价是地址带版本号，每次发版都要改，同 `IAM_JWKS_URL`。

**一次投递长什么样**（在真实 Casdoor 上抓到的）：请求体是 Casdoor 的 `Record`。`action` 是动作名（`update-user`、`login` 等）；`object` 是**编码成 JSON 字符串的**请求体，所以内容就是调用方发了什么：发送整个用户对象的 `update-user` 时是那个对象（口令已被掩码成 `***`），`login` 时是登录表单、没有用户 ID；`user` 是发起操作的账号（管理员改别人时是 `admin`），不是被操作的用户。所以用户字段从 `object` 里取，字符串与对象两种形式都认。经管理 API 做的改动同样会触发投递。

**两个 token。** 认证留在浏览器与 Casdoor 之间；应用 token 必须带 `roles[]`、`dept_path`、`org_id`，而这些只有 authz 知道。所以：(1) 浏览器从 Casdoor 拿到 id_token；(2) 前端到本组件换一次：本组件对着 Casdoor 的 JWKS 验它（只认 RS256，校验 issuer），调 authz `ResolveClaims`，用自己的钥匙签出应用 token；(3) 业务组件对着本组件的 JWKS 验应用 token；(4) 刷新也到这里，再调一次 `ResolveClaims`，所以角色永远是当前的。第 1 步之后 Casdoor 就退出了。

让 Casdoor 直接签带角色的 token（把角色镜像进 Casdoor）被否决，三条理由各自独立：authz 想作废会话就得反过来调 IAM（边的方向反了）；镜像必然是异步的，改了角色之后刷新拿回来的还是旧角色，组件回 `401 token_stale`，前端再刷新，永远转下去，而每一行日志都看起来正常；角色数据又被焊回了 Casdoor。

**成为签发方要做对的事：** 签名密钥来自配置（自己生成的话每次重启都会变、各副本也不同）；它的 key ID 是 RFC 7638 指纹，所以稳定；轮换期间 JWKS 同时挂上一把公钥，用它签的 refresh token 仍然能验；refresh token 每用一次就轮换（不滑动续期），重放一个已轮换的会作废这个人名下全部 refresh token，因为正常的客户端永远不会出示已轮换的 token。refresh token 也是同一把钥匙签的 JWT，靠 `typ: refresh` 与应用 token 区分。

**刷新的顺序。** 先验 refresh token、拿 claims、签名，最后才轮换。先轮换的话，authz 抖一下就会用掉调用方的 token：重试撞上重放检测，这个人在所有地方被登出。

**对 authz 失败关闭。** 不退回更早的 claims：安全组件不能签出自己无法担保的 token；部署形态是一台机器，"别的都在跑、唯独 authz 挂了"很少见；缓存会重新打开"`stale_since` 已经作废、token 却还带着旧角色"的时间窗。authz 停摆期间，手上有 token 的人照常使用到它过期（`APP_TOKEN_TTL_SECONDS`，默认 600 秒）；登录与刷新回 `503`。

**已安装组件。** `ENABLED_COMPONENTS` 就是项目的 `brickkit.yaml`（`file://brickkit.yaml`）：`brickkit add` / `remove` / `upgrade` 维护的锁文件是"装了什么"唯一的真相源，加组件不需要任何重新生成的步骤。只解码 `components[].id` 与 `kind`；跳过外壳；同一 ID 的多个版本只算一次；结果排序。文件其余内容（带 token 的 sources、installer 设置）从不解码，也从不出现在报错里。"装了"不等于"在运行"：在部署文件里关掉的组件照样列出。

## 事件

经 outbox 发布，与登记 webhook 投递在同一个事务里：

| Subject | 分级 | 何时 | Payload |
|---|---|---|---|
| `infra.iam.user.created.v1` | 核心 | Casdoor 报告新用户 | `sub`、`display_name`、`email`、`phone`、`im_accounts` |
| `infra.iam.user.updated.v1` | 核心 | 用户有变化 | 同上加 `version` |
| `infra.iam.user.disabled.v1` | 核心 | 用户被停用**或删除** | `sub` |
| `infra.iam.login.v1` | 旁路 | 为登录审计而声明 | `sub`、`ip`、`occurred_at`；尚未发布 |

用户事件是核心而不是旁路：`infra/notification` 靠它们维护"给谁发、发到哪"，丢一条就是一条通知悄无声息地发不出去。删除按 `disabled` 发：下游要的是"别再给他发了"，不是"把他的历史删了"。`version` 是处理投递时刻的纳秒数，因为没有用户行可以做版本；它只增不减，这就是消费者需要的全部。

消费：`infra.authz.user_role.changed.v1`。`change_type: kicked` 时作废这个人名下全部 refresh token（与 inbox 记录在同一个事务里），"踢人"就是这样让用户在下一次刷新时被登出。其余变化（granted、revoked、expired）不动 refresh token：下次刷新带上新角色即可，每次调角色都作废的话，每次调整组织都会把人登出。

Casdoor 的 webhook 投递按请求体哈希去重（Casdoor 有没有稳定的投递 ID 尚未确认）。去重检查在按去重键取的事务级 advisory 锁下进行：表的唯一索引必须带分区键 `received_at`，而每次重投它都不同，约束去不了重；只查不锁的"先查再插"会让两份并发到达的副本都发布。

## 依赖

| 依赖 | 用来做什么 | 为什么是同步的 |
|---|---|---|
| `infra/authz`（必需） | 每次签发与刷新调 `ResolveClaims` | token 必须带此刻的角色 |

预期中有、实际没有的：

| 不是依赖 | 为什么 |
|---|---|
| Casdoor | 项目之外的资源，经 `CASDOOR_BASE_URL` 访问；本组件在后台等它，而不是启动即失败 |
| `infra/notification` | 它消费用户事件；本组件不需要知道通知发没发出去 |
| 任何依赖本组件的组件 | 必须保持如此：各组件经 `IAM_JWKS_URL` 验 token、靠事件了解用户。一条依赖边会把这个实现的名字放进它们的环境变量，换 IAM 时它们就坏了 |

## 在同步调用图里的位置

一条出边 `infra/iam-casdoor → infra/authz`，authz 没有出边，所以从这里出发的路径长度恒为 1，不可能成环。入边：没有，这是设计（见"依赖"）；前端与 SDK 经配置的 URL 访问它。它在三个枢纽（主数据、`erp/inventory`、`erp/finance`）之外，也不碰 CRM 与 ERP。

## 分区与归档

| 数据 | 热数据 | 归档条件 | 去哪 |
|---|---|---|---|
| `refresh_tokens` | 未过期、未作废 | 过期或作废满 30 天后删除 | 不归档 |
| `signing_keys` | 当前与上一把 | 更早的条目满 90 天后删除 | 不归档 |
| `bootstrap_state` | 一直 | 从不 | — |
| `webhook_deliveries` | 最近 30 天 | 超过 30 天的整月分区 | `infra_iam_casdoor_archive` |
| `event_outbox`、`event_inbox` | 发布后 30 天内 | 更早的 | 删除 |

组件自己建未来的分区，启动时一次、之后每 24 小时一次：outbox 与 inbox 提前四周建周分区，`webhook_deliveries` 提前三个月建月分区。写入落到没有分区的时间段会直接失败，所以事件与 webhook 能不能流动，靠的就是这个循环。`refresh_tokens` 永不分区：它很小，而每次刷新都按 `jti` 查一行。表里的删除与归档尚未实现（见"未决问题"）。

## 数据范围

没有（`data_scopes: none`）。这些表是本组件自己的运维数据（签出的 token、密钥元数据、投递、对账状态）；没有面向最终用户的界面列出它们，也就没有要限定范围的东西。

## 参考实现

| 项目 | 版本 | 看的模块 | 借鉴了什么 | 许可证 | 用法 |
|---|---|---|---|---|---|
| Casdoor | 未钉 | OIDC 端点与 JWKS、id_token 字段、webhook 设置、`User.Properties` | webhook 没有签名但能带自定义 header（于是用共享密钥）；有自定义 claims（`JWT-Custom`），所以把角色镜像进 Casdoor 技术上可行，否决它纯粹出于架构理由 | Apache-2.0 | 借鉴逻辑 |
| OAuth 2.0 Token Exchange（RFC 8693） | — | 用一个 token 换另一个 token 的请求与响应 | 用 id_token 换应用 token 是有标准的；重叠处字段名照它 | 标准文本 | 借鉴逻辑 |
| Keycloak | 未钉 | protocol mapper | 族契约取两种实现都能提供的交集 | Apache-2.0 | 借鉴实际应用 |
| Dex | 未钉 | connector | 反例：运行时多路复用多个上游 IdP 用不上；IAM 槽位是组装时二选一 | Apache-2.0 | 借鉴逻辑 |
| Grafana | — | OIDC 集成、"角色从哪个 claim 读" | 佐证角色放进 IdP 签的 token 是常见形态（只看文档） | AGPL-3 | 借鉴实际应用 |

**刻意避开的**：在适配层建用户影子表（IAM 槽位从此不做数据迁移就换不了）；Casdoor 自带的 RBAC（角色数据焊死在一个实现上）；把权限键放进 JWT（管理员的键集合撑爆 8 KB 的 header 上限，登录之后每个请求都 `431`）。自己实现 OIDC Provider（Ory Hydra、Zitadel）不在考虑之内：Casdoor 就是 Provider。

没有新的槽位族：Casdoor 与 Keycloak 之争就是 IAM 槽位本身，本组件是它的默认成员。

## 未决问题

| 问题 | 目前的答案 |
|---|---|
| Casdoor 有没有稳定的投递 ID？ | 没有：见过的每一次投递里记录的 `id` 都是 `0`，所以去重用请求体哈希（请求体带记录的 `name` 与 `createdTime`，两次不同的变化不会字节完全相同） |
| 本组件停着期间的投递会丢 | 真机所见：Casdoor 大约每 30 秒成批发一次 webhook，发送失败记成一条单独的 `send-webhook` 记录，原记录不重投。本组件停机或重新部署期间的变化永远不会被桥接。启动时对账用户（比对 Casdoor 与下游最后收到的）需要一份用户副本，而本组件刻意不存；未定 |
| 同一批里对同一个用户的两次修改可能以错误的顺序到达下游 | 真机所见：同一秒里建的两条 `update-user` 记录按新到旧的顺序投递。事件的 `version` 取本组件处理时的时间，于是较旧的那次修改拿到较大的版本号，下游留下了它，而 Casdoor 里是较新的那次。记录的 `createdTime` 只精确到秒，同一秒内的先后它也排不出来。候选：发 Casdoor 此刻持有的用户（每次投递读一次管理 API，每条事件都带当前状态），或者 `version` 以 `createdTime` 为基础（只解决不在同一秒的修改）。未定 |
| 不带用户 ID 的 `add-user` / `delete-user` 投递 | 真机所见：`object` 是请求体，只发 `owner` 与 `name` 的管理 API 调用不带 `id`，投递存成 `IGNORED`，`created` / `disabled` 事件发不出去。新建的用户可以按 owner 与 name 反查；已删除的没有用户副本就查不出来。Casdoor 自己的界面发不发 ID 没有核对 |
| `infra.iam.login.v1` 已声明但从未发布 | 还没有消费者（审计组件在规划中）；有了就在换 token 时发 |
| 过期与作废的 refresh token、旧的密钥元数据、旧的 webhook 投递从不删除或归档 | 这些表增长缓慢（受用户数与 Casdoor 活动约束）；计划在分区循环旁边加一个清理循环 |
| 不校验 Casdoor id_token 的 audience | 同一个 Casdoor 实例里的任何应用都能产出本组件接受的 id_token；只要这个 Casdoor 只服务本项目就可以接受。拿应用的 client ID 校验 `aud` 就能堵上 |
| 族契约对不对？ | 只有第二个实现（`infra/iam-keycloak`）能检验；加 rpc 之前先问 Keycloak 能不能提供 |
