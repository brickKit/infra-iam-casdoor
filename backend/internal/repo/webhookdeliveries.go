package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

// RecordDeliveryAndPublish 是 webhook 投递的唯一写入口：去重登记 + （新
// 投递时）执行 publish 回调 + 落地最终状态，三步在同一个事务里完成
// （Outbox Pattern：写业务效果与写事件必须同一事务，否则进程崩在中间就是
// "记录了投递但事件没发出去"或反过来）。
//
// ⚠️ 去重不能靠唯一约束：webhook_deliveries 按 received_at 分区，PostgreSQL
// 要求分区表的唯一索引包含分区键，唯一索引只能是 (dedup_key, received_at)，
// 两次重投的 received_at 几乎必然不同，约束拦不住。所以在同一个事务里先按
// dedup_key 取一把事务级 advisory 锁，再查"有没有登记过"、没有才插：同一条投递
// 并发到达时（Casdoor 超时重投而前一次还没处理完），后到的事务等前一个提交，
// 再查就看得到那一行，判为重投、不再发布。只查不锁的话，两个事务都会在对方
// 提交前查到"不存在"，于是都插、都发。锁随事务结束释放，不需要解锁。
//
// dedupKey 已存在时 isNew=false，publish 不会被调用，status/errMsg 也
// 不会被使用（重投沿用第一次的处理结果，不重复记录）。publish 为 nil
// 表示"这条投递确实是新的，但解析阶段已经决定不需要发任何事件"（如
// payload 缺失关键字段），此时只登记 status/errMsg。
func (r *Repo) RecordDeliveryAndPublish(ctx context.Context, dedupKey, eventAction string, payload []byte,
	status, errMsg string, publish func(tx *sql.Tx) error) (isNew bool, err error) {
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
		if publish != nil {
			if err := publish(tx); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx,
			`UPDATE webhook_deliveries SET status = $2, error = $3 WHERE dedup_key = $1`,
			dedupKey, status, errMsg)
		return err
	})
	return isNew, wrap("处理 webhook 投递", txErr)
}
