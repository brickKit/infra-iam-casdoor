// Package partition 是 Module.Start 的后台循环之一：为 event_outbox /
// event_inbox 提前建未来的周分区，为 webhook_deliveries 提前建未来的月分区
// （它的活跃窗口是最近一个月左右，量小，月粒度足够）。写入落到一个不存在的
// 分区会直接失败——发事件、收 Casdoor 回调全部报错；迁移只建了最初的几周 /
// 几个月，往后由这里接着建。
//
// refresh_tokens、signing_keys、bootstrap_state 不分区，不在这里。
package partition

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

const (
	checkInterval   = 24 * time.Hour
	lookAheadWeeks  = 4 // 提前建好当前周 + 未来 4 周
	lookAheadMonths = 3 // 提前建好当前月 + 未来 3 个月
)

var (
	weeklyPartitionedTables  = []string{"event_outbox", "event_inbox"}
	monthlyPartitionedTables = []string{"webhook_deliveries"}
)

// Start 立刻检查一次，之后每 24 小时检查一次。单次失败只记日志、不退出循环：
// 下一轮还能补上；后台循环一退出就再也不会建分区，也不能因为这个后台任务拖垮
// 整个进程（进外壳后是所有成员）。只在 ctx 取消时返回。
func Start(ctx context.Context, db *sql.DB, role, schema string, logger *slog.Logger) error {
	checkOnce := func() {
		// 离没有分区还有好几周，一次失败不需要人立刻处理，但连续失败就会到期：
		// 记 Error，让运维在到期之前看到。关停时的取消不算失败。
		if err := ensureAll(ctx, db, role, schema); err != nil && ctx.Err() == nil {
			logger.Error("分区维护失败，24 小时后重试", "error", err)
		}
	}
	checkOnce()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			checkOnce()
		}
	}
}

func ensureAll(ctx context.Context, db *sql.DB, role, schema string) error {
	return besdk.WithTx(ctx, db, role, schema, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		week := mondayOf(now)
		for i := 0; i <= lookAheadWeeks; i++ {
			from := week.AddDate(0, 0, 7*i)
			for _, table := range weeklyPartitionedTables {
				if err := ensurePartition(ctx, tx, table, from, from.AddDate(0, 0, 7)); err != nil {
					return err
				}
			}
		}
		month := firstOfMonth(now)
		for i := 0; i <= lookAheadMonths; i++ {
			from := month.AddDate(0, i, 0)
			for _, table := range monthlyPartitionedTables {
				if err := ensurePartition(ctx, tx, table, from, from.AddDate(0, 1, 0)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// mondayOf 把任意时间点归到它所在周的周一 00:00 UTC——分区边界必须是固定的
// 锚点，不能是"从现在起 7 天"这种滑动窗口，否则相邻两次检查算出来的分区边界
// 会对不上。
func mondayOf(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 { // time.Sunday == 0，此处要归到"上一周的周一"而不是当天
		weekday = 7
	}
	d := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return d.AddDate(0, 0, -(weekday - 1))
}

// firstOfMonth 把任意时间点归到它所在月的 1 号 00:00 UTC（同 mondayOf：边界是
// 固定锚点）。
func firstOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ensurePartition 用 to_regclass 先确认分区存不存在，不存在才建。
//
// 不能反过来"先建、报 already exists 就忽略"：PostgreSQL 里一条语句失败会让
// 整个事务进入 aborted 状态，Go 这边忽略了错误，后面的语句照样全部失败。
func ensurePartition(ctx context.Context, tx *sql.Tx, table string, from, to time.Time) error {
	name := fmt.Sprintf("%s_%s", table, from.Format("2006_01_02"))

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		return fmt.Errorf("检查分区是否存在 %s: %w", name, err)
	}
	if exists {
		return nil
	}

	// table 只来自本文件顶部的固定清单，from/to 是格式化过的日期字符串，
	// 都不是外部输入，拼 SQL 是安全的。
	stmt := fmt.Sprintf(
		`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
		name, table, from.Format("2006-01-02"), to.Format("2006-01-02"),
	)
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("建分区 %s: %w", name, err)
	}
	return nil
}
