package repo

import (
	"context"
	"database/sql"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

// RecordDelivery 是 webhook 投递的唯一写入口：去重登记一条投递，状态由调用方给
// （要回读 Casdoor 的用户变更是 RECEIVED，等后台循环处理；认不出的是 IGNORED / ERROR）。
// 只登记、不处理：Casdoor 从不重发投递，登记失败之外的任何原因都不能让这条投递丢掉。
//
// ⚠️ 去重不能靠唯一约束：webhook_deliveries 按 received_at 分区，PostgreSQL
// 要求分区表的唯一索引包含分区键，唯一索引只能是 (dedup_key, received_at)，
// 两次重投的 received_at 几乎必然不同，约束拦不住。所以在同一个事务里先按
// dedup_key 取一把事务级 advisory 锁，再查"有没有登记过"、没有才插：同一条投递
// 并发到达时，后到的事务等前一个提交，再查就看得到那一行，判为重投、不再登记。
// 只查不锁的话，两个事务都会在对方提交前查到"不存在"，于是都插、都发。锁随事务
// 结束释放，不需要解锁。
//
// dedupKey 已存在时 isNew=false，什么都不写（重投沿用第一次的处理结果）。
func (r *Repo) RecordDelivery(ctx context.Context, dedupKey, eventAction string, payload []byte,
	status, errMsg string) (isNew bool, err error) {
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
		_, err := tx.ExecContext(ctx,
			`INSERT INTO webhook_deliveries (dedup_key, event_action, payload, status, error) VALUES ($1, $2, $3, $4, $5)`,
			dedupKey, eventAction, payload, status, errMsg)
		return err
	})
	return isNew, wrap("登记 webhook 投递", txErr)
}

// Delivery 是队列里待处理的一条投递。
type Delivery struct {
	ID         int64
	ReceivedAt time.Time
	DedupKey   string
	Payload    []byte
	Attempts   int // 之前失败过几次
}

// DeliveryHandler 处理一条认领到的投递，在认领它的那个事务里执行（Outbox Pattern：写事件
// 与改投递状态同一事务）。返回的 status/errMsg 写进这条投递；返回 error 时它写过的东西
// 全部回滚，由 DeliveryRetry 决定这条投递怎么记。
type DeliveryHandler func(tx *sql.Tx, d Delivery) (status, errMsg string, err error)

// RetryDecision 是一次处理失败之后这条投递怎么记。
type RetryDecision struct {
	Leave  bool          // 原样留在队列里、不计次数（Casdoor 不可达：调用方让整个循环退避）
	Failed bool          // 终态 FAILED，不再认领
	After  time.Duration // 不是终态时，多久之后再认领
	ErrMsg string        // 写进 error 列
}

// DeliveryRetry 由调用方给：看这条投递之前失败过几次与这次的错误，给出 RetryDecision。
type DeliveryRetry func(d Delivery, err error) RetryDecision

// ProcessNextDelivery 认领一条到期的 RECEIVED 投递交给 handle：found=false 表示没有到期的；
// handleErr 是 handle 这次的错误（已经按 retry 的决定记好）；err 是认领或记录本身的数据库错误。
//
// ⚠️ 认领用 FOR UPDATE SKIP LOCKED：两个副本（或外壳里与单跑的两个进程）同时处理时，
// 别的实例正在处理的行直接跳过，一条投递只会被一个实例处理、事件只发一次。只 SELECT 不锁
// 的话两个实例会拿到同一行、各发一次。锁的顺序在每个事务里都是"这条投递的行锁 → 这个人
// 版本号那一行的行锁"（后者见 NextUserEventVersionTx），认领从不等锁，不会死锁。
//
// handle 在一个 savepoint 里执行：失败时回滚到 savepoint（撤掉它写的版本号、outbox 等），
// 行锁还在，再在同一个事务里记下次数与下次时间，别的实例不会在这中间插进来。
//
// keyPrefix 只给测试隔离用（只认领 dedup_key 以它开头的投递）；生产传 ""。
func (r *Repo) ProcessNextDelivery(ctx context.Context, keyPrefix string, handle DeliveryHandler,
	retry DeliveryRetry) (found bool, handleErr error, err error) {
	txErr := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		var d Delivery
		var payload string
		err := tx.QueryRowContext(ctx, `
			SELECT id, received_at, dedup_key, payload, attempts FROM webhook_deliveries
			 WHERE status = 'RECEIVED' AND next_attempt_at <= now() AND starts_with(dedup_key, $1)
			 ORDER BY next_attempt_at, id
			 LIMIT 1
			 FOR UPDATE SKIP LOCKED`, keyPrefix).Scan(&d.ID, &d.ReceivedAt, &d.DedupKey, &payload, &d.Attempts)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		found, d.Payload = true, []byte(payload)

		if _, err := tx.ExecContext(ctx, `SAVEPOINT handle_delivery`); err != nil {
			return err
		}
		status, errMsg, herr := handle(tx, d)
		if herr == nil {
			_, err := tx.ExecContext(ctx,
				`UPDATE webhook_deliveries SET status = $3, error = $4 WHERE id = $1 AND received_at = $2`,
				d.ID, d.ReceivedAt, status, errMsg)
			return err
		}
		handleErr = herr
		if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT handle_delivery`); err != nil {
			return err
		}
		dec := retry(d, herr)
		if dec.Leave {
			return nil
		}
		status = "RECEIVED"
		if dec.Failed {
			status = "FAILED"
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE webhook_deliveries
			   SET attempts = attempts + 1, status = $3, error = $4,
			       next_attempt_at = now() + make_interval(secs => $5)
			 WHERE id = $1 AND received_at = $2`,
			d.ID, d.ReceivedAt, status, dec.ErrMsg, dec.After.Seconds())
		return err
	})
	return found, handleErr, wrap("处理 webhook 投递", txErr)
}
