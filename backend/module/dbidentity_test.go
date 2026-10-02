package module

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/migrate"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace/noop"

	besdk "github.com/brickKit/be-sdk-go"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/partition"
	"github.com/brickKit/infra-iam-casdoor/v2/migrations"
)

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// TestDBIdentity_非默认schema与不按schema起名的登录角色_迁移并经模块读写 证明数据库身份
// 只来自配置：schema 是 PG_SCHEMA，角色是 PG_USER，两者都不是默认值，角色名也故意不是
// "<schema>_rw"。在测试库里建这一对（只给角色 schema 上的 USAGE 与 CREATE，BRICKKIT
// "Before you deploy" 写的就是这个最小要求），以这个角色跑全部迁移，再用这个角色登录的池
// 构造模块，经 HTTP 写一条 webhook 投递、再投一次同样的内容（去重要先读到第一条），
// 最后跑一轮分区维护（建分区要求是父表的 owner）。用完删掉 schema 与角色。
func TestDBIdentity_非默认schema与不按schema起名的登录角色_迁移并经模块读写(t *testing.T) {
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_PG_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbName := strings.TrimPrefix(u.Path, "/")

	suffix := randomHex(t, 4)
	schema := "r63_iam_" + suffix
	role := "r63_iam_login_" + suffix // 故意不是 schema + "_rw"
	password := randomHex(t, 16)

	mustExec := func(q string) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, role, password))
	t.Cleanup(func() {
		// schema 里的对象全归这个角色；先删 schema，再撤掉它在库上的权限，最后删角色
		c := context.Background()
		for _, q := range []string{
			fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, schema),
			fmt.Sprintf(`DROP OWNED BY %s`, role),
			fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role),
		} {
			if _, err := admin.ExecContext(c, q); err != nil {
				t.Errorf("清理失败 %s: %v", q, err)
			}
		}
	})
	mustExec(fmt.Sprintf(`CREATE SCHEMA %s`, schema))
	mustExec(fmt.Sprintf(`GRANT USAGE, CREATE ON SCHEMA %s TO %s`, schema, role))
	mustExec(fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`, dbName, role))

	env := map[string]string{
		"PG_HOST": u.Hostname(), "PG_PORT": u.Port(), "PG_DATABASE": dbName,
		"PG_USER": role, "PG_PASSWORD": password, "PG_SCHEMA": schema,
	}
	if env["PG_PORT"] == "" {
		env["PG_PORT"] = "5432"
	}

	// 1. 迁移以这个角色跑：迁移里没有写死的角色名或 schema 名，全部对象归它所有
	if err := migrate.Run(ctx, env, []string{"up"}, migrations.FS); err != nil {
		t.Fatalf("以角色 %s 迁移进 schema %s 失败：%v", role, schema, err)
	}
	var tables, notOwned int
	if err := admin.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE pg_get_userbyid(c.relowner) <> $2)
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1 AND c.relkind IN ('r', 'p')`, schema, role).Scan(&tables, &notOwned); err != nil {
		t.Fatal(err)
	}
	if tables == 0 || notOwned != 0 {
		t.Fatalf("schema %s 里有 %d 张表，其中 %d 张不归 %s 所有", schema, tables, notOwned, role)
	}

	// 2. 以这个角色登录的池构造模块（单跑时 PG_USER 就是登录角色）
	pool, err := besdk.PGDSN(besdk.NewConfig(env))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cfgMap := validConfig(t)
	for k, v := range env {
		cfgMap[k] = v
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := &besdk.Runtime{
		ComponentID: "infra/iam-casdoor", Config: besdk.NewConfig(cfgMap), DB: db, Logger: logger,
		Tracer: noop.NewTracerProvider().Tracer("test"), Registry: prometheus.NewRegistry(),
	}
	mod, err := New(ctx, rt)
	if err != nil {
		t.Fatal(err)
	}

	// 3. 写：登记一条投递；读：同样的内容再投一次，去重先读到第一条，不再登记
	body := fmt.Sprintf(`{"action":"update-user","object":"{\"id\":\"r63-%s\"}"}`, suffix)
	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/iam/webhooks/casdoor", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(webhookSharedSecretHeader, cfgMap["WEBHOOK_SHARED_SECRET"])
		w := httptest.NewRecorder()
		mod.HTTPHandler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Logf("响应体：%s", w.Body.String())
		}
		return w.Code
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("第一次投递期望 200，实际 %d", code)
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("重投期望 200，实际 %d", code)
	}
	sum := sha256.Sum256([]byte(body))
	var rows int
	if err := admin.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT count(*) FROM %s.webhook_deliveries WHERE dedup_key = $1`, schema),
		hex.EncodeToString(sum[:])).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("schema %s 里这条投递有 %d 行，期望 1 行（写进了这个 schema，重投读到了它）", schema, rows)
	}

	// 4. 分区维护以配置给的角色建未来的分区：这是迁移曾经要转 owner 的原因
	s, err := loadSettings(rt.Config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	want := "webhook_deliveries_" + time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).
		AddDate(0, 3, 0).Format("2006_01_02")
	pctx, pcancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- partition.Start(pctx, db, s.role, s.schema, logger) }()
	var owner string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		err := admin.QueryRowContext(ctx, `
			SELECT pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = $1 AND c.relname = $2`, schema, want).Scan(&owner)
		if err == nil {
			break
		}
	}
	pcancel()
	<-done
	if owner != role {
		t.Fatalf("分区维护没有在 %s 里建出 %s（owner=%q，期望 %s）", schema, want, owner, role)
	}
}
