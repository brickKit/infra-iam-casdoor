package repo

import (
	"context"
	"database/sql"
	"errors"
)

// NextUserEventVersionTx 给 sub 取下一个事件版本号：max(floor, 上一版 + 1)，第一次见到
// 这个人时就是 floor（调用方传处理时刻的 unix 纳秒）。⚠️ 这条 upsert 同时锁住这个人的
// 那一行直到事务结束——调用方在它之后才回 Casdoor 读当前状态，同一个人的投递因此按人
// 串行：后拿到锁的那次回读得更晚、版本号更大。表的设计见 003 号迁移。
func (r *Repo) NextUserEventVersionTx(ctx context.Context, tx *sql.Tx, sub string, floor int64) (int64, error) {
	var v int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO user_event_versions (sub, version) VALUES ($1, $2)
		ON CONFLICT (sub) DO UPDATE
		   SET version = GREATEST(EXCLUDED.version, user_event_versions.version + 1), updated_at = now()
		RETURNING version`, sub, floor).Scan(&v)
	return v, wrap("取用户事件版本号", err)
}

// RememberUserNameTx 记下 sub 最近一次回读到的 owner/name（只带名字的 delete-user 靠它找 sub）。
func (r *Repo) RememberUserNameTx(ctx context.Context, tx *sql.Tx, sub, owner, name string) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE user_event_versions SET owner = $2, name = $3, updated_at = now() WHERE sub = $1`, sub, owner, name)
	return wrap("记下用户名", err)
}

// SubByNameTx 按最近一次见到的 owner/name 找 sub；没见过返回 ""。
func (r *Repo) SubByNameTx(ctx context.Context, tx *sql.Tx, owner, name string) (string, error) {
	var sub string
	err := tx.QueryRowContext(ctx,
		`SELECT sub FROM user_event_versions WHERE owner = $1 AND name = $2 ORDER BY updated_at DESC LIMIT 1`,
		owner, name).Scan(&sub)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return sub, wrap("按用户名找 sub", err)
}

// SetUserDisabledTx 记下这个人最近一次处理投递时是不是停用（发的是 disabled 事件）。调用方
// 已经用 NextUserEventVersionTx 锁住了这一行。
func (r *Repo) SetUserDisabledTx(ctx context.Context, tx *sql.Tx, sub string, disabled bool) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE user_event_versions SET disabled = $2, updated_at = now() WHERE sub = $1`, sub, disabled)
	return wrap("记下用户是否停用", err)
}
