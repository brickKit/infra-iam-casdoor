package bootstrap

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/backend/internal/repo"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

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

func testAdminClient(t *testing.T) *casdoor.AdminClient {
	t.Helper()
	base := os.Getenv("TEST_CASDOOR_BASE_URL")
	if base == "" {
		t.Skip("未设置 TEST_CASDOOR_BASE_URL")
	}
	c, err := casdoor.NewAdminClient(context.Background(), base,
		envOr("TEST_CASDOOR_ADMIN_USERNAME", "admin"), envOr("TEST_CASDOOR_ADMIN_PASSWORD", "123"))
	if err != nil {
		t.Fatalf("登录 Casdoor 管理 API 失败：%v", err)
	}
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var idSeq int64

func uniqueID(prefix string) string {
	n := atomic.AddInt64(&idSeq, 1)
	return prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.FormatInt(n, 10)
}

// TestRun_每一步都幂等可重跑 是设计计划 §9 第 5 条"每次启动都对账"的
// 核心断言：跑两遍 Run，第二遍必须是纯粹的"发现已存在、跳过创建"，不
// 报任何错误，也不会重复创建导致 Casdoor 那边出现重名冲突报错。
func TestRun_每一步都幂等可重跑(t *testing.T) {
	db := testDB(t)
	r := repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor")
	c := testAdminClient(t)
	ctx := context.Background()

	orgName := uniqueID("bootstraptest-org")
	appName := uniqueID("bootstraptest-app")
	whName := uniqueID("bootstraptest-wh")

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_ = c.DeleteWebhook(cleanupCtx, whName, orgName)
		_ = c.DeleteApplication(cleanupCtx, appName, orgName)
		_ = c.DeleteOrganization(cleanupCtx, orgName)
	})

	cfg := Config{
		OrgName: orgName, AppName: appName, AppRedirectURIs: []string{"http://localhost:3000/callback"},
		WebhookName: whName, WebhookCallbackURL: "http://127.0.0.1:9999/webhook",
		WebhookSharedHeader: "X-Shared-Secret", WebhookSharedSecretVal: "test-secret",
	}

	Run(ctx, c, r, cfg, testLogger())
	assertBootstrapped(t, ctx, c, r, orgName, appName, whName)

	// 第二遍：全部应该是"已存在，跳过创建"，不应该报错、也不应该产生
	// Casdoor 侧的重名冲突。
	Run(ctx, c, r, cfg, testLogger())
	assertBootstrapped(t, ctx, c, r, orgName, appName, whName)
}

func assertBootstrapped(t *testing.T, ctx context.Context, c *casdoor.AdminClient, r *repo.Repo, orgName, appName, whName string) {
	t.Helper()
	if exists, err := c.OrganizationExists(ctx, orgName); err != nil || !exists {
		t.Fatalf("组织应该存在：exists=%v, err=%v", exists, err)
	}
	if app, err := c.GetApplication(ctx, appName); err != nil || app == nil {
		t.Fatalf("应用应该存在：app=%+v, err=%v", app, err)
	}
	if exists, err := c.WebhookExists(ctx, whName); err != nil || !exists {
		t.Fatalf("webhook 应该存在：exists=%v, err=%v", exists, err)
	}
	if step, err := r.GetBootstrapStep(ctx, "casdoor_org"); err != nil || !step.Done {
		t.Fatalf("本地 bootstrap_state 应该标记 casdoor_org 完成：%+v, err=%v", step, err)
	}
	if step, err := r.GetBootstrapStep(ctx, "casdoor_app"); err != nil || !step.Done {
		t.Fatalf("本地 bootstrap_state 应该标记 casdoor_app 完成：%+v, err=%v", step, err)
	}
	if step, err := r.GetBootstrapStep(ctx, "casdoor_webhook"); err != nil || !step.Done {
		t.Fatalf("本地 bootstrap_state 应该标记 casdoor_webhook 完成：%+v, err=%v", step, err)
	}
}

// TestRun_webhookCallbackURL为空时跳过webhook步骤 断言 bootstrap.go 的
// "留空表示跳过"分支——组件还没规划好带外网络地址时不该因为这一步
// 失败而拖累组织/应用两步。
//
// ⚠️ `bootstrap_state` 的三个 step（casdoor_org/casdoor_app/
// casdoor_webhook）在生产里是**全局单例**（一次部署只自举一次），这里
// 测试前必须先把 casdoor_webhook 这一行清掉——否则会读到
// `TestRun_每一步都幂等可重跑` 那条测试留下的、真正标记过完成的旧行，
// 断言"这次没被标记完成"就会误判失败（两条测试共用同一张真实表，
// 不是各自隔离的 fixture，这是第一版忘了清理时真的踩出来的）。
func TestRun_webhookCallbackURL为空时跳过webhook步骤(t *testing.T) {
	db := testDB(t)
	if _, err := db.ExecContext(context.Background(), `DELETE FROM bootstrap_state WHERE step = 'casdoor_webhook'`); err != nil {
		t.Fatalf("清理 bootstrap_state 失败：%v", err)
	}
	r := repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor")
	c := testAdminClient(t)
	ctx := context.Background()

	orgName := uniqueID("bootstraptest-org")
	appName := uniqueID("bootstraptest-app")
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_ = c.DeleteApplication(cleanupCtx, appName, orgName)
		_ = c.DeleteOrganization(cleanupCtx, orgName)
	})

	Run(ctx, c, r, Config{
		OrgName: orgName, AppName: appName, AppRedirectURIs: []string{"http://localhost:3000/callback"},
		WebhookName: "unused", WebhookCallbackURL: "", // 留空
	}, testLogger())

	if exists, err := c.OrganizationExists(ctx, orgName); err != nil || !exists {
		t.Fatalf("组织应该照样建成：exists=%v, err=%v", exists, err)
	}
	if step, err := r.GetBootstrapStep(ctx, "casdoor_webhook"); err != nil || step.Done {
		t.Fatalf("webhookCallbackUrl 为空时 casdoor_webhook 不该被标记完成：%+v, err=%v", step, err)
	}
}
