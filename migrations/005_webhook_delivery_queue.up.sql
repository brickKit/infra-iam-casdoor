-- webhook_deliveries 变成一个队列：Casdoor 从不重发投递，webhook 收到就登记成 RECEIVED、
-- 回 200，回 Casdoor 读用户当前状态再发事件交给后台循环（docs/design.md"投递队列"）。
--   - attempts：已经失败过几次（Casdoor 在、但对这条投递回错误）。Casdoor 不可达不算次数，
--     整个循环退避；到上限标 FAILED；
--   - next_attempt_at：下一次可以认领的时刻（失败后按指数退避往后推）；
--   - status 多一个终态 FAILED：RECEIVED / PROCESSED / IGNORED / ERROR / FAILED。
-- 循环按 next_attempt_at 取到期的 RECEIVED 行（FOR UPDATE SKIP LOCKED），下面的部分索引
-- 只含还在排队的行，已处理的投递再多也不影响认领。
ALTER TABLE webhook_deliveries ADD COLUMN attempts INT NOT NULL DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at) WHERE status = 'RECEIVED';
