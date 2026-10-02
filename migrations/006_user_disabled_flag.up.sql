-- user_event_versions.disabled：最近一次处理投递时，这个人在 Casdoor 里是不是停用 / 删除 /
-- 已经不在（即最近一次发的是 infra.iam.user.disabled.v1）。每次处理投递都改写；换 token 时
-- 查它：停用的人手里还没过期的 Casdoor id_token 不能再换出新会话。重新启用（下一次投递发
-- created / updated）就清掉。仍然不是用户资料，只是本组件自己发到了哪一步。
ALTER TABLE user_event_versions ADD COLUMN disabled BOOLEAN NOT NULL DEFAULT false;
