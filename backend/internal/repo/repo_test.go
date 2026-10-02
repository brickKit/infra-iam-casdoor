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

	_ "github.com/jackc/pgx/v5/stdlib" // 锁定栈用 pgx，不用 lib/pq；驱动名注册为 "pgx"
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
	if err := r.RotateRefreshToken(ctx, jti1, sub, mintAs(jti2, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("轮换失败：%v", err)
	}

	// 旧 jti 已经被撤销、不能再轮换第二次——用它重放应该报 ErrRefreshTokenInvalid。
	jti3 := uniqueID("jti")
	err := r.RotateRefreshToken(ctx, jti1, sub, mintAs(jti3, time.Now().Add(time.Hour)))
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
	if err := r.RotateRefreshToken(ctx, jtiA, sub, mintAs(jtiB, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("第一次轮换失败：%v", err)
	}

	// 攻击者拿着已经用过的 jtiA 重放。
	jtiC := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jtiA, sub, mintAs(jtiC, time.Now().Add(time.Hour))); err != ErrRefreshTokenInvalid {
		t.Fatalf("重放旧 jti 应该报 ErrRefreshTokenInvalid，实际 %v", err)
	}

	// 断言：这个 sub 名下**所有**曾经有效的 refresh token（包括合法轮换
	// 出来的 jtiB）现在都应该已经被撤销——用它再刷新必须失败。
	jtiD := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jtiB, sub, mintAs(jtiD, time.Now().Add(time.Hour))); err != ErrRefreshTokenInvalid {
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
	if err := r.RotateRefreshToken(ctx, jti, sub, mintAs(jti2, time.Now().Add(time.Hour))); err != ErrRefreshTokenInvalid {
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
	if err := r.RotateRefreshToken(ctx, jti, realOwner, mintAs(jti2, time.Now().Add(time.Hour))); err != nil {
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
	if err := r.RotateRefreshToken(ctx, jti1, sub, mintAs(jti3, time.Now().Add(time.Hour))); err != ErrRefreshTokenInvalid {
		t.Fatalf("被踢之后 jti1 应该失效，实际 %v", err)
	}
	jti4 := uniqueID("jti")
	if err := r.RotateRefreshToken(ctx, jti2, sub, mintAs(jti4, time.Now().Add(time.Hour))); err != ErrRefreshTokenInvalid {
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

func TestRecordDelivery_去重(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	dedupKey := uniqueID("dedup")

	isNew, err := r.RecordDelivery(ctx, dedupKey, "add-user", []byte(`{"a":1}`), "RECEIVED", "")
	if err != nil {
		t.Fatalf("第一次登记失败：%v", err)
	}
	if !isNew {
		t.Fatal("第一次应该是新投递")
	}
	isNew, err = r.RecordDelivery(ctx, dedupKey, "add-user", []byte(`{"a":1}`), "IGNORED", "不该写进去")
	if err != nil {
		t.Fatalf("重投不该报错：%v", err)
	}
	if isNew {
		t.Fatal("重投应该被判定为不是新投递")
	}
	var status string
	if err := testDB(t).QueryRow(`SELECT status FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedupKey).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "RECEIVED" {
		t.Fatalf("重投不该改第一次登记的状态，实际 %s", status)
	}
}

// 处理失败时 handle 写过的东西必须全部回滚（savepoint），投递按重试决定记次数、往后推；
// 否则会出现"版本号已经占了、事件却没发"这类悬空状态。
func TestProcessNextDelivery_处理失败时回滚handle写的东西并记次数(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	prefix := uniqueID("q") + ":"
	dedupKey := prefix + "1"
	sub := uniqueID("sub")
	if _, err := r.RecordDelivery(ctx, dedupKey, "update-user", []byte(`{}`), "RECEIVED", ""); err != nil {
		t.Fatal(err)
	}

	found, handleErr, err := r.ProcessNextDelivery(ctx, prefix,
		func(tx *sql.Tx, d Delivery) (string, string, error) {
			if d.DedupKey != dedupKey {
				t.Errorf("认领到 %s，期望 %s", d.DedupKey, dedupKey)
			}
			if _, err := r.NextUserEventVersionTx(ctx, tx, sub, 1); err != nil {
				return "", "", err
			}
			return "", "", fmt.Errorf("故意失败")
		},
		func(d Delivery, err error) RetryDecision { return RetryDecision{After: time.Hour, ErrMsg: err.Error()} })
	if err != nil || !found || handleErr == nil {
		t.Fatalf("期望认领到并记下处理错误，found=%v handleErr=%v err=%v", found, handleErr, err)
	}

	db := testDB(t)
	var versions int
	if err := db.QueryRow(`SELECT count(*) FROM infra_iam_casdoor.user_event_versions WHERE sub = $1`, sub).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 0 {
		t.Fatal("handle 失败后它取的版本号应该回滚掉")
	}
	var status, msg string
	var attempts int
	var later bool
	if err := db.QueryRow(`SELECT status, error, attempts, next_attempt_at > now() + interval '50 minutes'
		FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedupKey).Scan(&status, &msg, &attempts, &later); err != nil {
		t.Fatal(err)
	}
	if status != "RECEIVED" || attempts != 1 || !later || msg != "故意失败" {
		t.Fatalf("期望 RECEIVED、attempts=1、一小时后再试、记下错误，实际 %s/%d/往后推=%v/%q", status, attempts, later, msg)
	}
	if found, _, err := r.ProcessNextDelivery(ctx, prefix,
		func(*sql.Tx, Delivery) (string, string, error) { return "PROCESSED", "", nil },
		func(Delivery, error) RetryDecision { return RetryDecision{} }); err != nil || found {
		t.Fatalf("还没到重试时刻不该被认领，found=%v err=%v", found, err)
	}
}

// Leave（Casdoor 不可达）：投递原样留着，不计次数，下一轮马上还能认领。
func TestProcessNextDelivery_Leave不计次数且仍可认领(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	prefix := uniqueID("q") + ":"
	dedupKey := prefix + "1"
	if _, err := r.RecordDelivery(ctx, dedupKey, "update-user", []byte(`{}`), "RECEIVED", ""); err != nil {
		t.Fatal(err)
	}
	fail := func(*sql.Tx, Delivery) (string, string, error) { return "", "", fmt.Errorf("Casdoor 不在") }
	leave := func(Delivery, error) RetryDecision { return RetryDecision{Leave: true} }
	if _, handleErr, err := r.ProcessNextDelivery(ctx, prefix, fail, leave); err != nil || handleErr == nil {
		t.Fatalf("handleErr=%v err=%v", handleErr, err)
	}
	found, _, err := r.ProcessNextDelivery(ctx, prefix,
		func(_ *sql.Tx, d Delivery) (string, string, error) {
			if d.Attempts != 0 {
				t.Errorf("Leave 不该计次数，attempts=%d", d.Attempts)
			}
			return "PROCESSED", "", nil
		}, leave)
	if err != nil || !found {
		t.Fatalf("Leave 之后应该马上还能认领，found=%v err=%v", found, err)
	}
}

// Casdoor 超时重投时，前一次投递可能还没登记完：同一条投递并发到达多次，只能登记一次
// （之后也只会被处理一次）。先查再插的两个事务都会在对方提交之前查到"不存在"，于是都插。
func TestRecordDelivery_同一投递并发到达只登记一次(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	dedupKey := uniqueID("dedup-concurrent")

	const n = 8
	var fresh atomic.Int32
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			isNew, err := r.RecordDelivery(ctx, dedupKey, "add-user", []byte(`{"a":1}`), "RECEIVED", "")
			if isNew {
				fresh.Add(1)
			}
			errs <- err
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("并发投递不该报错：%v", err)
		}
	}
	if got := fresh.Load(); got != 1 {
		t.Fatalf("同一投递并发到达 %d 次，应恰好 1 次判为新投递，实际 %d 次", n, got)
	}
	var rows int
	if err := testDB(t).QueryRow(`SELECT count(*) FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedupKey).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("应只登记 1 行，实际 %d 行", rows)
	}
}

// mintAs 是 RotateRefreshToken 的签发回调替身：给出固定的新 jti 与过期时间（不超过会话期限）。
func mintAs(jti string, expiresAt time.Time) MintRefreshToken {
	return func(notAfter time.Time) (string, time.Time, error) {
		if notAfter.Before(expiresAt) {
			expiresAt = notAfter
		}
		return jti, expiresAt, nil
	}
}

// 撤销一个人全部 refresh token 时，他正好有一次刷新在轮换中途：轮换提交的新 token 也必须
// 被撤掉。只靠行锁不够——撤销的 UPDATE 在旧行上等锁，等到的时候旧行已经被撤销（跳过），
// 新插的行不在它的快照里，新 token 就漏网了。两边都先拿同一把按人的 advisory 锁。
func TestRevokeAll_与轮换并发_轮换出的新token也被撤销(t *testing.T) {
	r := testRepo(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	jti1, jti2 := uniqueID("jti"), uniqueID("jti")
	if err := r.IssueRefreshToken(ctx, jti1, sub, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	minting := make(chan struct{})
	release := make(chan struct{})
	rotated := make(chan error, 1)
	go func() {
		rotated <- r.RotateRefreshToken(ctx, jti1, sub, func(notAfter time.Time) (string, time.Time, error) {
			close(minting)
			<-release // 停在轮换事务中途（旧行已加 FOR UPDATE，新行还没插）
			return jti2, notAfter, nil
		})
	}()
	<-minting
	revoked := make(chan error, 1)
	go func() { revoked <- r.RevokeAllRefreshTokensForSub(ctx, sub) }()
	time.Sleep(200 * time.Millisecond) // 让撤销在轮换提交之前开始等
	close(release)
	if err := <-rotated; err != nil {
		t.Fatalf("轮换失败：%v", err)
	}
	if err := <-revoked; err != nil {
		t.Fatalf("撤销失败：%v", err)
	}

	var live int
	if err := testDB(t).QueryRow(`SELECT count(*) FROM infra_iam_casdoor.refresh_tokens WHERE sub = $1 AND revoked_at IS NULL`, sub).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("撤销之后这个人还有 %d 个有效 refresh token（轮换中途插进来的新 token 漏网）", live)
	}
}
