-- user_event_versions：infra.iam.user.*.v1 每个人的事件版本号，外加最近一次回读到的
-- owner/name。⚠️ 不是用户影子表：用户资料仍然只在 Casdoor 里，这里只有"给这个人发到
-- 第几版了"和"这个 sub 在 Casdoor 里叫什么名字"。
--
-- 每次 webhook 投递在同一个事务里先对这一行加锁取下一个版本号，再回 Casdoor 读这个人的
-- 当前状态、写 outbox（docs/design.md"用户事件怎么发"）：
--   - 行锁让同一个人的投递按人串行，后回读的一定拿到更大的版本号；
--   - version = max(处理时刻 unix 纳秒, 上一版 + 1)：时钟回拨或多副本时钟不齐也严格递增，
--     而且不小于 1.x 用纳秒时间戳发过的版本号（下游存着的就是那个量级）；
--   - owner/name 让只带 owner 与 name 的 delete-user 投递（人已不在 Casdoor，回读查不到）
--     仍能找到 sub。
-- 行数等于见过事件的用户数，有界，不分区。
CREATE TABLE user_event_versions (
    sub        TEXT        PRIMARY KEY,
    version    BIGINT      NOT NULL,
    owner      TEXT        NOT NULL DEFAULT '',
    name       TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 不唯一：删掉的人的名字可以被新建的人复用，按 updated_at 取最近的那个。
CREATE INDEX user_event_versions_name_idx ON user_event_versions (owner, name, updated_at DESC);
