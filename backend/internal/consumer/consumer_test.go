package consumer

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
)

const (
	testRole   = "infra_iam_casdoor_rw"
	testSchema = "infra_iam_casdoor"
)

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

// issue 给 sub 登记两条有效的 refresh token。
func issue(t *testing.T, db *sql.DB, sub string) {
	t.Helper()
	r := repo.New(db, testRole, testSchema)
	for i := 0; i < 2; i++ {
		jti := fmt.Sprintf("%s-jti-%d", sub, i)
		if err := r.IssueRefreshToken(context.Background(), jti, sub, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
}

func activeTokens(t *testing.T, db *sql.DB, sub string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM infra_iam_casdoor.refresh_tokens WHERE sub = $1 AND revoked_at IS NULL`,
		sub).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// handle 像 besdk.Consume 那样在一个带 SET LOCAL ROLE / search_path 的事务里调 handler。
func handle(t *testing.T, db *sql.DB, payload string) error {
	t.Helper()
	h := userRoleChangedHandler(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ev := besdk.Event{Subject: subjectUserRoleChanged, AggregateID: "agg", Payload: []byte(payload)}
	return besdk.WithTx(context.Background(), db, testRole, testSchema, func(tx *sql.Tx) error {
		return h(context.Background(), tx, ev)
	})
}

// 踢人：这个人名下全部 refresh token 立刻作废，下次刷新就得重新登录。
func TestUserRoleChanged_kicked作废该用户全部refreshToken(t *testing.T) {
	db := testDB(t)
	sub := fmt.Sprintf("consumer-kicked-%d", time.Now().UnixNano())
	other := sub + "-other"
	issue(t, db, sub)
	issue(t, db, other)

	if err := handle(t, db, fmt.Sprintf(`{"sub":%q,"change_type":"kicked"}`, sub)); err != nil {
		t.Fatal(err)
	}
	if n := activeTokens(t, db, sub); n != 0 {
		t.Fatalf("踢人后该用户应没有有效 refresh token，实际 %d 条", n)
	}
	if n := activeTokens(t, db, other); n != 2 {
		t.Fatalf("别人的 refresh token 不该受影响，实际有效 %d 条", n)
	}
}

// 普通的加 / 减角色、到期：不动 refresh token（下次刷新自然拿到新角色）。顺手作废的
// 话，每次调整角色都把这个人踢下线。
func TestUserRoleChanged_普通角色变化不动refreshToken(t *testing.T) {
	db := testDB(t)
	for _, ct := range []string{"granted", "revoked", "expired"} {
		sub := fmt.Sprintf("consumer-%s-%d", ct, time.Now().UnixNano())
		issue(t, db, sub)
		if err := handle(t, db, fmt.Sprintf(`{"sub":%q,"role_code":"r","change_type":%q}`, sub, ct)); err != nil {
			t.Fatal(err)
		}
		if n := activeTokens(t, db, sub); n != 2 {
			t.Fatalf("change_type=%s 不该作废 refresh token，实际有效 %d 条", ct, n)
		}
	}
}

// kicked 却没有 sub：跳过、不报错（报错会让这条事件反复重投）。payload 不是 JSON：
// 报错，交给 besdk.Consume 的重投 / 死信处理。
func TestUserRoleChanged_sub为空跳过且坏payload报错(t *testing.T) {
	db := testDB(t)
	if err := handle(t, db, `{"sub":"","change_type":"kicked"}`); err != nil {
		t.Fatalf("sub 为空应跳过，实际报错：%v", err)
	}
	if err := handle(t, db, `not json`); err == nil {
		t.Fatal("payload 不是 JSON 应报错")
	}
}
