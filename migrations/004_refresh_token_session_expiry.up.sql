-- refresh_tokens.session_expires_at：这条轮换链（一次登录）的总期限，登录时定下，轮换时
-- 原样继承。⚠️ 没有它，每次轮换都重新给一整个 REFRESH_TOKEN_TTL_SECONDS，只要客户端
-- 还在刷新，会话永远不结束（在 Casdoor 里停用的人也一样）。轮换出的新 token 的
-- expires_at = min(轮换时刻 + 有效期, session_expires_at)，过了 session_expires_at
-- 就只能重新登录。
--
-- 已有的行用它自己的 expires_at 补：1.x 的会话从这次升级起最多再活一个有效期。
ALTER TABLE refresh_tokens ADD COLUMN session_expires_at TIMESTAMPTZ;
UPDATE refresh_tokens SET session_expires_at = expires_at WHERE session_expires_at IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN session_expires_at SET NOT NULL;
