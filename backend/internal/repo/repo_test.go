package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // §12.4：不用 lib/pq，驱动名注册为 "pgx"
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

var idSeq int64

// uniqueID 给每个测试造一个独立的 sub/jti/kid 前缀，测试之间不共享行、
// 互不干扰（同 infra-authz repo_test.go 的既有判据）。
func uniqueID(prefix string) string {
	n := atomic.AddInt64(&idSeq, 1)
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), n)
}

func testRepo(t *testing.T) *Repo {
	return New(testDB(t), "infra_iam_casdoor_rw", "infra_iam_casdoor")
}

func TestIssueAndRotateRefreshToken(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	jti1 := uniqueID("jti")

	if err := r.IssueRefreshToken(ctx, jti1, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记失败：%v", err)
	}

	jti2 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti1, jti2, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("轮换失败：%v", err)
	}

	// 旧 jti 已经被撤销、不能再轮换第二次——用它重放应该报 ErrRefreshTokenInvalid。
	jti3 := uniqueID("jti")
	err := r.RotateRefreshToken(ctx, jti1, jti3, sub, time.Now().Add(time.Hour))
	if err != ErrRefreshTokenInvalid {
		t.Fatalf("重放已轮换的旧 jti 应该报 ErrRefreshTokenInvalid，实际 %v", err)
	}
}

// TestRotateRefreshToken_重放会撤销该sub全部有效token 是重放检测这条
// 加固的核心断言：用一个已经轮换掉的旧 jti 再刷新，不仅这次失败，连
// 刚刚轮换出来的新 jti 也要被一并撤销——用 deliberate break 验证过
// （见函数体内注释）。
func TestRotateRefreshToken_重放会撤销该sub全部有效token(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	jtiA := uniqueID("jti")

	if err := r.IssueRefreshToken(ctx, jtiA, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记失败：%v", err)
	}
	jtiB := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jtiA, jtiB, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("第一次轮换失败：%v", err)
	}

	// 攻击者拿着已经用过的 jtiA 重放。
	jtiC := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jtiA, jtiC, sub, time.Now().Add(time.Hour)); err != ErrRefreshTokenInvalid {
		t.Fatalf("重放旧 jti 应该报 ErrRefreshTokenInvalid，实际 %v", err)
	}

	// 断言：这个 sub 名下**所有**曾经有效的 refresh token（包括合法轮换
	// 出来的 jtiB）现在都应该已经被撤销——用它再刷新必须失败。
	jtiD := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jtiB, jtiD, sub, time.Now().Add(time.Hour)); err != ErrRefreshTokenInvalid {
		t.Fatalf("重放检测应该连坐撤销 jtiB，用它刷新应该失败，实际 %v", err)
	}
}

func TestRevokeRefreshToken_幂等(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	jti := uniqueID("jti")

	if err := r.IssueRefreshToken(ctx, jti, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记失败：%v", err)
	}
	if err := r.RevokeRefreshToken(ctx, jti, sub); err != nil {
		t.Fatalf("第一次撤销失败：%v", err)
	}
	if err := r.RevokeRefreshToken(ctx, jti, sub); err != nil {
		t.Fatalf("第二次撤销（幂等）不该报错：%v", err)
	}
	// 撤销后不能再刷新。
	jti2 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti, jti2, sub, time.Now().Add(time.Hour)); err != ErrRefreshTokenInvalid {
		t.Fatalf("撤销后用它刷新应该失败，实际 %v", err)
	}
}

// TestRevokeRefreshToken_sub不匹配不生效 是"不能用别人的 jti 登出别人
// 会话"这条防线的断言——用 deliberate break 验证过（临时把 SQL 的
// AND sub = $2 去掉，确认测试会红）。
func TestRevokeRefreshToken_sub不匹配不生效(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	realOwner := uniqueID("sub")
	attacker := uniqueID("sub")
	jti := uniqueID("jti")

	if err := r.IssueRefreshToken(ctx, jti, realOwner, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记失败：%v", err)
	}
	if err := r.RevokeRefreshToken(ctx, jti, attacker); err != nil {
		t.Fatalf("撤销调用本身不该报错（空操作）：%v", err)
	}
	// 真正的 owner 应该仍然能正常刷新——说明攻击者的调用确实是空操作。
	jti2 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti, jti2, realOwner, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("真正的 owner 应该仍能刷新：%v", err)
	}
}

func TestRevokeAllRefreshTokensForSub(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	jti1 := uniqueID("jti")
	jti2 := uniqueID("jti")

	if err := r.IssueRefreshToken(ctx, jti1, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记 1 失败：%v", err)
	}
	if err := r.IssueRefreshToken(ctx, jti2, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("登记 2 失败：%v", err)
	}
	if err := r.RevokeAllRefreshTokensForSub(ctx, sub); err != nil {
		t.Fatalf("批量撤销失败：%v", err)
	}
	jti3 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti1, jti3, sub, time.Now().Add(time.Hour)); err != ErrRefreshTokenInvalid {
		t.Fatalf("被踢之后 jti1 应该失效，实际 %v", err)
	}
	jti4 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti2, jti4, sub, time.Now().Add(time.Hour)); err != ErrRefreshTokenInvalid {
		t.Fatalf("被踢之后 jti2 应该失效，实际 %v", err)
	}
	// 幂等：这个 sub 已经没有任何有效 token，再调一次不该报错。
	if err := r.RevokeAllRefreshTokensForSub(ctx, sub); err != nil {
		t.Fatalf("空操作不该报错：%v", err)
	}
}

func TestSigningKeys_幂等登记(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	kid := uniqueID("kid")

	if err := r.UpsertSigningKey(ctx, kid, "RS256"); err != nil {
		t.Fatalf("第一次登记失败：%v", err)
	}
	if err := r.UpsertSigningKey(ctx, kid, "RS256"); err != nil {
		t.Fatalf("第二次登记（幂等）不该报错：%v", err)
	}
	keysList, err := r.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("列出失败：%v", err)
	}
	count := 0
	for _, k := range keysList {
		if k.Kid == kid {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("同一个 kid 应该只出现一次（幂等），实际出现 %d 次", count)
	}
}

func TestBootstrapState_读写(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	step := uniqueID("step")

	got, err := r.GetBootstrapStep(ctx, step)
	if err != nil {
		t.Fatalf("读一个从未出现过的步骤不该报错：%v", err)
	}
	if got.Done {
		t.Fatal("从未出现过的步骤 Done 应该是 false")
	}

	if err := r.MarkBootstrapStepDone(ctx, step, []byte(`{"clientId":"abc"}`)); err != nil {
		t.Fatalf("标记完成失败：%v", err)
	}
	got, err = r.GetBootstrapStep(ctx, step)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if !got.Done {
		t.Fatal("标记完成后 Done 应该是 true")
	}
	// ⚠️ 不能按字节比较：detail 列是 JSONB，PostgreSQL 存储时会规范化
	// 格式（这里会把 `{"clientId":"abc"}` 变成 `{"clientId": "abc"}`，
	// 冒号后多一个空格）——第一版测试就是按字节比较断言失败才发现这个
	// 差异，改成结构化比较（都反解成 map 再比对字段值）。
	assertJSONFieldEquals(t, got.Detail, "clientId", "abc")

	// 幂等：再标一次，覆盖 detail。
	if err := r.MarkBootstrapStepDone(ctx, step, []byte(`{"clientId":"xyz"}`)); err != nil {
		t.Fatalf("第二次标记失败：%v", err)
	}
	got, _ = r.GetBootstrapStep(ctx, step)
	assertJSONFieldEquals(t, got.Detail, "clientId", "xyz")
}

// assertJSONFieldEquals 反解 JSON 再比对单个字段的值——JSONB 列存储时
// 会规范化格式（键值间距、字段顺序等），不能按字节比较原文。
func assertJSONFieldEquals(t *testing.T, raw []byte, field, want string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("detail 不是合法 JSON：%v（原文 %s）", err, raw)
	}
	if got, _ := m[field].(string); got != want {
		t.Fatalf("字段 %q 不符：got %q, want %q（完整 detail: %s）", field, got, want, raw)
	}
}

func TestRecordDeliveryAndPublish_去重与发布(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	dedupKey := uniqueID("dedup")

	published := false
	isNew, err := r.RecordDeliveryAndPublish(ctx, dedupKey, "add-user", []byte(`{"a":1}`),
		"PROCESSED", "", func(tx *sql.Tx) error {
			published = true
			_, err := tx.ExecContext(ctx, `SELECT 1`) // 占位写：真实调用方会 PublishOutbox
			return err
		})
	if err != nil {
		t.Fatalf("第一次登记失败：%v", err)
	}
	if !isNew {
		t.Fatal("第一次应该是新投递")
	}
	if !published {
		t.Fatal("第一次应该调用 publish 回调")
	}

	published = false
	isNew, err = r.RecordDeliveryAndPublish(ctx, dedupKey, "add-user", []byte(`{"a":1}`),
		"PROCESSED", "", func(tx *sql.Tx) error {
			published = true
			return nil
		})
	if err != nil {
		t.Fatalf("重投不该报错：%v", err)
	}
	if isNew {
		t.Fatal("重投应该被判定为不是新投递")
	}
	if published {
		t.Fatal("重投不该再次调用 publish 回调")
	}
}

// TestRecordDeliveryAndPublish_publish失败整体回滚 用 deliberate break
// 的方式验证事务原子性：publish 回调失败时，webhook_deliveries 的
// 那条 INSERT 也必须跟着回滚——否则会出现"记录了投递但事件其实没发出
// 去、且下次重投会被误判成重复"的悬空状态。
func TestRecordDeliveryAndPublish_publish失败整体回滚(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	dedupKey := uniqueID("dedup")

	_, err := r.RecordDeliveryAndPublish(ctx, dedupKey, "add-user", []byte(`{}`),
		"PROCESSED", "", func(tx *sql.Tx) error {
			return fmt.Errorf("故意失败")
		})
	if err == nil {
		t.Fatal("publish 失败应该导致整个调用失败")
	}

	// 因为回滚了，dedupKey 应该"从未出现过"——用它重新登记一次应该被
	// 判定为 isNew=true，而不是当成重投跳过。
	isNew, err := r.RecordDeliveryAndPublish(ctx, dedupKey, "add-user", []byte(`{}`),
		"PROCESSED", "", nil)
	if err != nil {
		t.Fatalf("回滚后重新登记不该报错：%v", err)
	}
	if !isNew {
		t.Fatal("回滚后重新登记应该被判定为新投递（证明第一次真的整体回滚了）")
	}
}
