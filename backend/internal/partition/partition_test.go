package partition

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	testRole   = "infra_iam_casdoor_rw"
	testSchema = "infra_iam_casdoor"
)

func TestMondayOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-09-06", "2026-08-31"}, // 周日 -> 上一周一
		{"2026-08-31", "2026-08-31"}, // 周一 -> 自己
		{"2026-09-02", "2026-08-31"}, // 周三 -> 本周一
	}
	for _, c := range cases {
		in, _ := time.Parse("2006-01-02", c.in)
		want, _ := time.Parse("2006-01-02", c.want)
		if got := mondayOf(in); !got.Equal(want) {
			t.Errorf("mondayOf(%s) = %s，期望 %s", c.in, got.Format("2006-01-02"), c.want)
		}
	}
}

func TestFirstOfMonth(t *testing.T) {
	in, _ := time.Parse(time.RFC3339, "2026-10-31T23:59:59Z")
	if got := firstOfMonth(in).Format("2006-01-02"); got != "2026-10-01" {
		t.Fatalf("firstOfMonth = %s，期望 2026-10-01", got)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_PG_DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func partitionExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, testSchema+"."+name).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// 迁移只建了最初几周的 outbox / inbox 分区与最初几个月的 webhook_deliveries
// 分区；写入落到没有分区的时间段直接失败（发事件、收 Casdoor 回调全部报错）。
// 这里核对后台维护真的建出了往后的分区，并且连跑两次都成功（幂等）。
func TestEnsureAll_建出往后的周分区与月分区且连跑两次都成功(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if err := ensureAll(ctx, db, testRole, testSchema); err != nil {
			t.Fatalf("第 %d 次执行失败：%v", i, err)
		}
	}

	week := mondayOf(time.Now().UTC())
	for i := 0; i <= lookAheadWeeks; i++ {
		d := week.AddDate(0, 0, 7*i).Format("2006_01_02")
		for _, table := range []string{"event_outbox", "event_inbox"} {
			if !partitionExists(t, db, table+"_"+d) {
				t.Errorf("期望分区 %s_%s 已经建好", table, d)
			}
		}
	}
	month := firstOfMonth(time.Now().UTC())
	for i := 0; i <= lookAheadMonths; i++ {
		d := month.AddDate(0, i, 0).Format("2006_01_02")
		if !partitionExists(t, db, "webhook_deliveries_"+d) {
			t.Errorf("期望分区 webhook_deliveries_%s 已经建好", d)
		}
	}
}
