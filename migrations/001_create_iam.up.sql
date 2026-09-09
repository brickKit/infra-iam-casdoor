-- 设计计划 §2 的四张运维表。⚠️ 本组件刻意没有 users/roles 表——用户主数据
-- 在 Casdoor 里，角色在 infra-authz 里，这里只存"我自己签发过什么"
-- （设计计划 §2 末尾两条 ⚠️）。

-- refresh_tokens：应用 token 的刷新凭据，按"当前在线人数 × 12 小时窗口"
-- 有界（几百到几千行），永不分区（§7：分区只会让这条热路径查询跨分区
-- 找行，与 erp-inventory 的 inventory_balances 不分区是同一个理由）。
--
-- 实现选择（设计计划没钉死到这一层，这里是落地时的具体决定）：refresh
-- token 本身也是一个由本组件签名的 JWT（复用 appTokenSigningKeyPem，
-- `typ` claim 标成 "refresh" 与应用 token 区分），jti 就是这个 JWT 的
-- jti claim。这样验一个 refresh token 不需要先查库——先验签+过期，
-- 查库只为确认它没被撤销/没被轮换掉（revoked_at IS NULL），复用应用
-- token 那套验签代码，不需要另外维护一份"秘密值哈希"。
CREATE TABLE refresh_tokens (
    jti          TEXT        PRIMARY KEY,
    sub          TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,          -- NULL = 仍有效。登出/踢人/轮换掉都是写这一列
    rotated_from TEXT        REFERENCES refresh_tokens(jti), -- 轮换链：本行是由哪一行换出来的
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_sub_idx ON refresh_tokens (sub);
-- 踢人（消费 infra.authz.user_role.changed.v1）要"撤销这个 sub 名下所有
-- 仍有效的 refresh token"，这是它的专用索引。
CREATE INDEX refresh_tokens_sub_active_idx ON refresh_tokens (sub) WHERE revoked_at IS NULL;
-- 一次性检测"用一个已经被轮换掉的旧 jti 再刷新"（refresh token 重放的
-- 典型信号）：查 rotated_from 指向的那一行是否 revoked_at 不为空即可，
-- 不需要额外索引——rotated_from 本身已经是外键，走主键查找。

-- signing_keys：应用 token 签名密钥的元数据，⚠️ 私钥本身不落库，从
-- configSchema 的 appTokenSigningKeyPem/appTokenPreviousPublicKeyPem 注入
-- （设计计划 §3.3、§9 第 1b 条）。kid 由启动时对公钥算 JWK thumbprint
-- 得出（确定性推导，同一把钥匙每次启动算出同一个 kid，天然幂等）。
-- 这张表存在的意义是审计与自检：JWKS 端点该出几把钥匙、每把钥匙从
-- 什么时候开始/停止被当作"当前"，都能在这里查到，而不需要翻部署日志。
CREATE TABLE signing_keys (
    kid        TEXT        PRIMARY KEY,
    alg        TEXT        NOT NULL DEFAULT 'RS256',
    not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_after  TIMESTAMPTZ,           -- NULL = 目前仍在 JWKS 里挂着
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- webhook_deliveries：Casdoor webhook 投递去重（§2、§9 第 2 条：投递 ID
-- 稳定性与重投机制未能在本次真机核对中完全确认，见 AGENTS.md 的踩坑记录）。
-- ⚠️ dedup_key 退化设计：优先用 Casdoor 回调体里能找到的稳定字段
-- （如果有的话）；找不到就退化成"事件动作 + payload 内容哈希"，在
-- 应用代码里算好再写入——迁移层不关心具体算法，只保证这一列上有
-- 唯一约束。payload 整体落 JSONB 是刻意的宽容存储：payload 形状没有
-- 100% 确认之前，先存下来再说，别在解析阶段就丢数据。
CREATE TABLE webhook_deliveries (
    id           BIGSERIAL,
    dedup_key    TEXT        NOT NULL,
    event_action TEXT        NOT NULL DEFAULT '', -- 尽力标注的动作名（如 "add-user"），仅供排查，不参与业务判断
    payload      JSONB       NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status       TEXT        NOT NULL DEFAULT 'RECEIVED', -- RECEIVED / PROCESSED / IGNORED / ERROR
    error        TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);
-- 月分区（同 infra-authz 的 role_changes：这张表的活跃窗口天然是"最近
-- 30 天"，见 §7，月粒度足够，不需要周分区）。初始建当前月起 4 个月，
-- 其余由组件内置定时任务自动建（决策 54）。
CREATE TABLE webhook_deliveries_2026_09_01 PARTITION OF webhook_deliveries
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE webhook_deliveries_2026_10_01 PARTITION OF webhook_deliveries
  FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE webhook_deliveries_2026_11_01 PARTITION OF webhook_deliveries
  FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE webhook_deliveries_2026_12_01 PARTITION OF webhook_deliveries
  FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE UNIQUE INDEX webhook_deliveries_dedup_idx ON webhook_deliveries (dedup_key, received_at);

-- ⚠️ 实测踩坑（同 infra-authz/erp-finance 等组件的分区表迁移）：建分区
-- 要求执行者是父表的 owner，迁移用管理凭据跑，建出来的表默认属于那个
-- 账号；分区维护后台任务运行时用 infra_iam_casdoor_rw（SET LOCAL ROLE
-- 切换）建未来的分区，两者不是同一身份，必须显式把 owner 转过去。
ALTER TABLE webhook_deliveries OWNER TO infra_iam_casdoor_rw;

-- bootstrap_state：首次初始化的幂等标记（设计计划 §9 第 5 条：倾向"每次
-- 启动都对账"而不是"只跑一次"，用这张表记录每一步是否已完成，与
-- erp-inventory 的 claim-first 幂等是同一个判断——单机测试测不出
-- "跑了一半挂了"的中间态，所以每一步都要能安全重跑）。
CREATE TABLE bootstrap_state (
    step       TEXT        PRIMARY KEY, -- 如 'casdoor_org' / 'casdoor_app' / 'casdoor_webhook'
    done_at    TIMESTAMPTZ,             -- NULL = 还没做过/还没确认过
    detail     JSONB       NOT NULL DEFAULT '{}', -- 该步产生的可复用信息（如建好的 app client_id）
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
