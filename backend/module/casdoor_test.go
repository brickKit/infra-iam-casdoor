package module

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
)

// levelRecorder 记下每条日志的级别，用来断言"Casdoor 暂时不在"只记 Warn。
type levelRecorder struct {
	mu     sync.Mutex
	levels []slog.Level
}

func (h *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.levels = append(h.levels, r.Level)
	return nil
}
func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelRecorder) WithGroup(string) slog.Handler      { return h }

func (h *levelRecorder) count(l slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, x := range h.levels {
		if x == l {
			n++
		}
	}
	return n
}

// flakyCasdoor 是一个假 Casdoor：login、get-organization 前若干次回 503（模拟
// Casdoor 比本组件起得晚、或对账中途抖动），之后正常回答；组织与应用都已存在。
type flakyCasdoor struct {
	loginFails, orgFails int32
	orgCalls             atomic.Int32
}

func (f *flakyCasdoor) start(t *testing.T) string {
	t.Helper()
	ok := func(w http.ResponseWriter, data any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": data})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&f.loginFails, -1) >= 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ok(w, nil)
	})
	mux.HandleFunc("/api/get-organization", func(w http.ResponseWriter, r *http.Request) {
		f.orgCalls.Add(1)
		if atomic.AddInt32(&f.orgFails, -1) >= 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ok(w, map[string]any{"name": "org"})
	})
	mux.HandleFunc("/api/get-application", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{"clientId": "cid"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func testRepo(t *testing.T) *repo.Repo {
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
	return repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor")
}

// runConnect 跑 connectCasdoorAdmin 直到它返回（成功）或超时。
func runConnect(t *testing.T, f *flakyCasdoor) (*atomic.Pointer[casdoor.AdminClient], *levelRecorder) {
	t.Helper()
	cfg := settings{
		casdoorBaseURL: f.start(t), casdoorAdminUsername: "admin", casdoorAdminPassword: "pw",
		casdoorOrgName: "org", casdoorAppName: "app", // WEBHOOK_CALLBACK_URL 留空：webhook 一步跳过
	}
	r := testRepo(t)
	var holder atomic.Pointer[casdoor.AdminClient]
	rec := &levelRecorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connectCasdoorAdmin(ctx, cfg, r, &holder, slog.New(rec))
	if ctx.Err() != nil {
		t.Fatal("20 秒内 connectCasdoorAdmin 没有返回")
	}
	return &holder, rec
}

// Casdoor 比本组件起得晚：登录在后台重试直到成功，成功后 gRPC BatchGetUsers 才
// 拿得到管理会话。只登录一次的话，Casdoor 晚起几秒，BatchGetUsers 就一直回
// Unavailable，直到本组件重启。连不上属于"暂时不在"，只记 Warn。
func TestConnectCasdoorAdmin_登录失败在后台重试直到成功且只记Warn(t *testing.T) {
	f := &flakyCasdoor{loginFails: 2}
	holder, rec := runConnect(t, f)
	if holder.Load() == nil {
		t.Fatal("登录成功后应把管理会话交给 BatchGetUsers")
	}
	if n := rec.count(slog.LevelWarn); n != 2 {
		t.Fatalf("两次连不上应记 2 条 Warn，实际 %d", n)
	}
	if n := rec.count(slog.LevelError); n != 0 {
		t.Fatalf("Casdoor 暂时不在不该记 Error，实际 %d 条", n)
	}
}

// 登录成功之后、对账途中 Casdoor 抖了一下：这一轮对账要整轮重来（每一步都先查
// 再建，重跑是安全的），否则组织 / 应用 / webhook 停在旧状态直到本组件重启
// （例如换了 WEBHOOK_CALLBACK_URL 的那次启动，Casdoor 继续往旧地址投）。
func TestConnectCasdoorAdmin_对账途中Casdoor不可达时整轮重试且只记Warn(t *testing.T) {
	f := &flakyCasdoor{orgFails: 1}
	_, rec := runConnect(t, f)
	if n := f.orgCalls.Load(); n < 2 {
		t.Fatalf("对账途中 Casdoor 不可达应整轮重试，get-organization 实际只调了 %d 次", n)
	}
	if n := rec.count(slog.LevelError); n != 0 {
		t.Fatalf("Casdoor 暂时不在不该记 Error，实际 %d 条", n)
	}
}
