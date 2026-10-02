package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

// DeliveryHandler 处理一条新投递（只对新投递调用），在登记这条投递的同一个事务里
// 执行（Outbox Pattern：写事件与登记必须同一事务）。返回的 status/errMsg 写进
// 这条投递；返回 error 时整个事务回滚，投递不登记，重投时还会再处理一次。
type DeliveryHandler func(tx *sql.Tx) (status, errMsg string, err error)

// RecordDelivery 是 webhook 投递的唯一写入口：去重登记 + （新投递时）执行 handle +
// 落地 handle 给出的状态，三步在同一个事务里完成（进程崩在中间不会出现"记录了投递
// 但事件没发出去"或反过来）。
//
// ⚠️ 去重不能靠唯一约束：webhook_deliveries 按 received_at 分区，PostgreSQL
// 要求分区表的唯一索引包含分区键，唯一索引只能是 (dedup_key, received_at)，
// 两次重投的 received_at 几乎必然不同，约束拦不住。所以在同一个事务里先按
// dedup_key 取一把事务级 advisory 锁，再查"有没有登记过"、没有才插：同一条投递
// 并发到达时（Casdoor 超时重投而前一次还没处理完），后到的事务等前一个提交，
// 再查就看得到那一行，判为重投、不再处理。只查不锁的话，两个事务都会在对方
// 提交前查到"不存在"，于是都插、都发。锁随事务结束释放，不需要解锁。
//
// dedupKey 已存在时 isNew=false，handle 不会被调用（重投沿用第一次的处理结果）。
func (r *Repo) RecordDelivery(ctx context.Context, dedupKey, eventAction string, payload []byte,
	handle DeliveryHandler) (isNew bool, err error) {
	isNew = true
	txErr := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext('infra_iam_casdoor.webhook_deliveries'), hashtext($1))`,
			dedupKey); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM webhook_deliveries WHERE dedup_key = $1)`, dedupKey,
		).Scan(&exists); err != nil {
			return err
		}
		if exists {
			isNew = false
			return nil
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO webhook_deliveries (dedup_key, event_action, payload) VALUES ($1, $2, $3)`,
			dedupKey, eventAction, payload); err != nil {
			return err
		}
		status, errMsg, err := handle(tx)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE webhook_deliveries SET status = $2, error = $3 WHERE dedup_key = $1`,
			dedupKey, status, errMsg)
		return err
	})
	return isNew, wrap("处理 webhook 投递", txErr)
}
