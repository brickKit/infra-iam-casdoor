package repo

import (
	"context"
	"database/sql"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// IssueRefreshToken 登记一个全新的 refresh token（没有轮换来源）——只在
// POST /api/iam/token（登录，不是刷新）用一次。它的 expires_at 同时是这个会话的
// 总期限（session_expires_at），之后每次轮换原样继承，见 RotateRefreshToken。
func (r *Repo) IssueRefreshToken(ctx context.Context, jti, sub string, expiresAt time.Time) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		if err := lockSubTokensTx(ctx, tx, sub); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO refresh_tokens (jti, sub, expires_at, session_expires_at) VALUES ($1, $2, $3, $3)`,
			jti, sub, expiresAt)
		return err
	})
	return wrap("登记 refresh token", err)
}

// MintRefreshToken 由调用方（service 层）签一个轮换出的 refresh token：notAfter 是这个
// 会话的总期限，新 token 不能晚于它过期。返回新 token 的 jti 与过期时间。
type MintRefreshToken func(notAfter time.Time) (jti string, expiresAt time.Time, err error)

// RotateRefreshToken 是刷新路径的核心：验证旧 jti 仍然有效，撤销它，
// 登记一个指向它的新行——三步在同一个事务里原子完成（每次刷新都
// 轮换）。
//
// ⚠️ 重放检测（与 rotation 语义天然一致，不需要新表）：如果 oldJTI 存在但**已经被撤销**
// （不管是登出撤销的还是之前一次轮换撤销的），说明有人拿着一个已经用
// 过的 refresh token 在重放——这时不仅拒绝这次刷新，还要把这个 sub
// 名下**全部**仍然有效的 refresh token 一并撤销，强制这个人重新走一遍
// 登录流程。这是 refresh token rotation 的标准配套防护：一个正常客户端
// 不会出现"用一个已经轮换掉的旧 token"这种情况，出现了就该按"这个
// token 可能已经泄露"处理。
//
// ⚠️ 实现上的一个容易踩的坑：判定"这次刷新是否有效"与"撤销全部 token
// 这个副作用要不要提交"必须分开——用一个闭包外的 invalid 标志记录判定
// 结果，fn 本身除了真正的数据库错误外一律返回 nil（让事务正常提交），
// 判定结果留到 WithTx 返回之后再翻译成 ErrRefreshTokenInvalid。如果直接
// 在检测到重放时让 fn return ErrRefreshTokenInvalid，defer 里的
// tx.Rollback() 会把刚刚那条"撤销全部 token"的 UPDATE 也一并回滚掉——
// 保护措施本身被自己的失败路径撤销，是曾经在写这段代码时先写错、又
// 立刻发现的一版。
//
// ⚠️ 会话总期限：新 token 由 mint 签，notAfter 传旧行的 session_expires_at（登录时定下），
// 新行原样继承它；过了它就判无效、只能重新登录。轮换不续期——否则只要客户端还在刷新，
// 会话永远不结束。
func (r *Repo) RotateRefreshToken(ctx context.Context, oldJTI, sub string, mint MintRefreshToken) error {
	invalid := false
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		if err := lockSubTokensTx(ctx, tx, sub); err != nil {
			return err
		}
		var gotSub string
		var revokedAt sql.NullTime
		var expiresAt, sessionExpiresAt time.Time
		row := tx.QueryRowContext(ctx,
			`SELECT sub, revoked_at, expires_at, session_expires_at FROM refresh_tokens WHERE jti = $1 FOR UPDATE`, oldJTI)
		switch scanErr := row.Scan(&gotSub, &revokedAt, &expiresAt, &sessionExpiresAt); {
		case scanErr == sql.ErrNoRows:
			invalid = true
			return nil
		case scanErr != nil:
			return scanErr
		}

		if gotSub != sub {
			// jti 存在但 sub 对不上——JWT 本身的签名已经保证了 sub 字段
			// 没被篡改，这种情况只可能是"拿别人的 jti 硬拼进自己 token
			// 里"这类不该发生的调用方错误，一律当无效处理，不给出更
			// 具体的错误信息（避免枚举探测）。
			invalid = true
			return nil
		}
		if revokedAt.Valid {
			if _, err := tx.ExecContext(ctx,
				`UPDATE refresh_tokens SET revoked_at = now(), updated_at = now()
				 WHERE sub = $1 AND revoked_at IS NULL`, sub); err != nil {
				return err
			}
			invalid = true
			return nil
		}
		if now := time.Now(); !now.Before(expiresAt) || !now.Before(sessionExpiresAt) {
			invalid = true
			return nil
		}

		newJTI, newExpiresAt, err := mint(sessionExpiresAt)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET revoked_at = now(), updated_at = now() WHERE jti = $1`,
			oldJTI); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO refresh_tokens (jti, sub, expires_at, session_expires_at, rotated_from) VALUES ($1, $2, $3, $4, $5)`,
			newJTI, sub, newExpiresAt, sessionExpiresAt, oldJTI)
		return err
	})
	if err != nil {
		return wrap("轮换 refresh token", err)
	}
	if invalid {
		return ErrRefreshTokenInvalid
	}
	return nil
}

// RevokeRefreshToken 撤销一个 refresh token——幂等：不存在或已撤销都
// 视为成功（登出对一个已经作废的 token 重复调用同样返回 200）。sub 由调用方（service 层）传入并核对，防止用别人的 jti 登出
// 别人的会话（jti 本身如果是随机生成的很难猜，但"防御纵深"这一步不
// 依赖 jti 猜不中这个假设）。
func (r *Repo) RevokeRefreshToken(ctx context.Context, jti, sub string) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET revoked_at = now(), updated_at = now()
			 WHERE jti = $1 AND sub = $2 AND revoked_at IS NULL`, jti, sub)
		return err
	})
	return wrap("撤销 refresh token", err)
}

// RevokeAllRefreshTokensForSub 撤销一个 sub 名下全部仍然有效的 refresh
// token——供 HTTP 层等"自己没有现成事务"的调用方用（目前没有这样的
// 调用方，踢人走的是下面的 RevokeAllRefreshTokensForSubTx，这个非 Tx
// 版本留着给以后可能出现的直接调用场景，比如管理 API 手动踢人）。
// 幂等：这个 sub 本来就没有任何有效 token 时是空操作。
func (r *Repo) RevokeAllRefreshTokensForSub(ctx context.Context, sub string) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		return RevokeAllRefreshTokensForSubTx(ctx, tx, sub)
	})
	return wrap("撤销用户全部 refresh token", err)
}

// RevokeAllRefreshTokensForSubTx 是同一件事的"复用调用方已有事务"版本
// ——事件消费者（consumer 包）必须用这个，不能用上面那个：
// besdk.Consume 给 handler 的 tx 已经在一个事务里（inbox 去重记录也在
// 这个事务里），handler 内部如果再调 RevokeAllRefreshTokensForSub（它
// 会自己开一个全新的 besdk.WithTx，即 db.BeginTx 出的另一条独立连接/
// 事务），"撤销 token"与"记录这条事件已处理"就不再是原子的——进程
// 崩在两次提交之间，会出现"inbox 说处理过了，但 token 其实没撤销"这种
// 悄悄漏判的情况（同 erp-finance consumer.go 的既有教训：那边的
// PostSalesOrderEntryTx 就是为了同一个理由才拆出 Tx 版本）。
//
// ⚠️ 先拿 lockSubTokensTx：这个人正好有一次刷新在轮换中途时，只靠行锁会漏掉轮换提交的
// 新 token（见 lockSubTokensTx）。
func RevokeAllRefreshTokensForSubTx(ctx context.Context, tx *sql.Tx, sub string) error {
	if err := lockSubTokensTx(ctx, tx, sub); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), updated_at = now()
		 WHERE sub = $1 AND revoked_at IS NULL`, sub)
	return err
}

// lockSubTokensTx 取一把按人的事务级 advisory 锁：登记、轮换、撤销全部一个人的 refresh
// token 都先拿它，同一个人的这几件事因此串行。
//
// ⚠️ 只靠行锁不够：撤销全部（UPDATE … WHERE sub = $1）碰上一次轮换中途，会在旧行上等
// FOR UPDATE；等到时旧行已被轮换撤销（跳过），轮换刚插的新行又不在这条 UPDATE 的快照里，
// 新 token 就漏网了——在 Casdoor 里停用的人恰好在那一刻刷新，就还能一直刷下去。拿了这把锁，
// 撤销要么在轮换之前（轮换看到旧行已撤销，按重放处理、401），要么在轮换提交之后开始
// （看得到新行）。TestRevokeAll_与轮换并发_轮换出的新token也被撤销。
func lockSubTokensTx(ctx context.Context, tx *sql.Tx, sub string) error {
	_, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('infra_iam_casdoor.refresh_tokens'), hashtext($1))`, sub)
	return err
}
