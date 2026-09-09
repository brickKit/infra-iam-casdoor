package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

// RecordDeliveryAndPublish 是 webhook 投递的唯一写入口：去重登记 + （新
// 投递时）执行 publish 回调 + 落地最终状态，三步在同一个事务里完成
// （设计计划 §3.10 Outbox Pattern 的一贯要求——写业务效果与写事件必须
// 同一事务，否则进程崩在中间就是"记录了投递但事件没发出去"或反过来）。
//
// ⚠️ 去重判据是显式的"先查再插"（SELECT EXISTS ... 再 INSERT），不是
// 单靠 INSERT 撞唯一约束——这是写这份代码时真的踩出来的一个坑：
// `webhook_deliveries` 是按 received_at 分区的表，PostgreSQL 要求分区表
// 的唯一索引必须包含分区键，所以唯一索引只能是
// (dedup_key, received_at) 这一对组合，而不是 dedup_key 单独一列。两次
// 重投的 received_at 几乎必然不同（哪怕只差几微秒），composite 唯一
// 约束根本拦不住——第一版实现只依赖这条唯一约束，写测试时
// "同一个 dedup_key 插两次，第二次应该判定为重投" 直接断言失败，
// 才发现这个组合键约束在这里形同虚设。改成显式 SELECT EXISTS 之后
// 拦住了（`webhook_deliveries_dedup_idx` 支持只用 dedup_key 作为
// leading column 高效查询，不需要额外建索引）。⚠️ 代价：两次真正
// **同时**（同一事务隔离级别下）到达的重投仍可能都通过 EXISTS 检查
// 各自插入成功——这是可接受的残余风险（webhook 重投是串行重试，不是
// 并发请求；真撞上的话唯一约束仍会在极小概率下拦下完全同 received_at
// 的那一种）。
//
// dedupKey 已存在时 isNew=false，publish 不会被调用，status/errMsg 也
// 不会被使用（重投沿用第一次的处理结果，不重复记录）。publish 为 nil
// 表示"这条投递确实是新的，但解析阶段已经决定不需要发任何事件"（如
// payload 缺失关键字段），此时只登记 status/errMsg。
func (r *Repo) RecordDeliveryAndPublish(ctx context.Context, dedupKey, eventAction string, payload []byte,
	status, errMsg string, publish func(tx *sql.Tx) error) (isNew bool, err error) {
	isNew = true
	txErr := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
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
			// 走到这里说明极小概率的并发双插撞上了唯一约束——当成
			// 真正的错误抛出，不静默改判成"重投"（那会让一条真实的
			// 新投递被错误地跳过处理）。
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
