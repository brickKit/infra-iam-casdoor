-- Outbox / Inbox。所有组件都有这两张表，且都按 created_at 周分区（§11.2.5）
-- 保留周期：已发布成功超过 30 天可清理（§11.7、决策 62）
--
-- ⚠️ 初始分区覆盖当前周起 4 周（迁移执行时是 2026-09-07 那一周）。
-- 其余分区由组件内置定时任务自动建（决策 54、§11.5.1）——这里只需要
-- 保证迁移跑完那一刻起系统能正常写入，不需要预先建满未来所有分区。

CREATE TABLE event_outbox (
    id           BIGSERIAL,
    subject      TEXT        NOT NULL,
    aggregate_id TEXT        NOT NULL,
    version      BIGINT      NOT NULL,
    trace_id     TEXT        NOT NULL DEFAULT '',
    causation_id TEXT        NOT NULL DEFAULT '',
    hop_count    INT         NOT NULL DEFAULT 0,
    payload      JSONB       NOT NULL,
    published_at TIMESTAMPTZ,
    attempts     INT         NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    status       TEXT        NOT NULL DEFAULT 'PENDING',
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
CREATE TABLE event_outbox_2026_09_07 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-07') TO ('2026-09-14');
CREATE TABLE event_outbox_2026_09_14 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-14') TO ('2026-09-21');
CREATE TABLE event_outbox_2026_09_21 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-21') TO ('2026-09-28');
CREATE TABLE event_outbox_2026_09_28 PARTITION OF event_outbox
  FOR VALUES FROM ('2026-09-28') TO ('2026-10-05');
CREATE INDEX event_outbox_pending ON event_outbox (status, created_at)
  WHERE status = 'PENDING';

-- ⚠️ 实测踩坑（同其余组件的 002 迁移）：建分区要求执行者是父表的
-- owner，迁移用管理凭据跑，建出来的表默认属于那个账号；分区维护后台
-- 任务运行时用 infra_iam_casdoor_rw（SET LOCAL ROLE 切换）建未来的
-- 分区，两者不是同一身份，必须显式把 owner 转过去。
ALTER TABLE event_outbox OWNER TO infra_iam_casdoor_rw;

CREATE TABLE event_inbox (
    id              BIGSERIAL,
    idempotency_key TEXT        NOT NULL,
    subject         TEXT        NOT NULL,
    aggregate_id    TEXT        NOT NULL,
    version         BIGINT      NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT        NOT NULL DEFAULT 'PROCESSED',
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
CREATE TABLE event_inbox_2026_09_07 PARTITION OF event_inbox
  FOR VALUES FROM ('2026-09-07') TO ('2026-09-14');
CREATE TABLE event_inbox_2026_09_14 PARTITION OF event_inbox
  FOR VALUES FROM ('2026-09-14') TO ('2026-09-21');
CREATE TABLE event_inbox_2026_09_21 PARTITION OF event_inbox
  FOR VALUES FROM ('2026-09-21') TO ('2026-09-28');
CREATE TABLE event_inbox_2026_09_28 PARTITION OF event_inbox
  FOR VALUES FROM ('2026-09-28') TO ('2026-10-05');
-- 消费幂等靠这个唯一约束（§4.6）。本组件只消费一条 subject
-- （infra.authz.user_role.changed.v1，见设计计划 §4），幂等键是
-- "sub + authz_revision"（设计计划 §4 消费表最后一列）。
CREATE UNIQUE INDEX event_inbox_idem ON event_inbox (idempotency_key, created_at);

ALTER TABLE event_inbox OWNER TO infra_iam_casdoor_rw;

-- ⚠️ 没有 command_idempotency 表：本组件的写命令天然自带幂等语义，不
-- 需要额外的幂等键表——登出撤销一个已撤销的 refresh token 是空操作
-- （查 revoked_at），刷新用掉的 refresh token 立刻失效、重放会在
-- refresh_tokens 的 revoked_at 检查那一步天然被拒绝（起到了幂等键
-- 表通常起的"防重复执行"作用，见 001 迁移 refresh_tokens 表注释）。
