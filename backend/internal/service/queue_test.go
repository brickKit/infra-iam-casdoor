package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
)

// 这一组测的是投递队列（发布前审查 I2）：Casdoor 从不重发投递，所以本组件收到就登记成
// RECEIVED、回 200，回读与发事件交给后台循环。Casdoor 暂时读不了时投递留在队列里，
// 恢复后照常发出；读得到但一直出错的，有限次重试后标 FAILED。

// fakeCasdoorAPI 是 Casdoor 管理 API 的替身（只有本组件回读用到的 /api/login 与
// /api/get-user），接真实的 casdoor.AdminClient。down 为 true 时一律回 503——
// AdminClient 把非 200 当成"Casdoor 不可达"，与真 Casdoor 停机时一样。
type fakeCasdoorAPI struct {
	srv   *httptest.Server
	down  atomic.Bool
	mu    sync.Mutex
	users map[string]casdoor.User
}

func newFakeCasdoorAPI(t *testing.T) *fakeCasdoorAPI {
	t.Helper()
	f := &fakeCasdoorAPI{users: map[string]casdoor.User{}}
	ok := func(w http.ResponseWriter, data any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "msg": "", "data": data})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) { ok(w, "ok") })
	mux.HandleFunc("/api/get-user", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		q := r.URL.Query()
		for _, u := range f.users {
			if u.ID == q.Get("userId") || (q.Get("id") != "" && u.Owner+"/"+u.Name == q.Get("id")) {
				ok(w, u)
				return
			}
		}
		ok(w, nil)
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCasdoorAPI) put(u casdoor.User) { f.mu.Lock(); f.users[u.ID] = u; f.mu.Unlock() }

// adminClient 在 Casdoor 还在时登录一次，之后的调用走这条会话。
func (f *fakeCasdoorAPI) adminClient(t *testing.T) *casdoor.AdminClient {
	t.Helper()
	c, err := casdoor.NewAdminClient(context.Background(), f.srv.URL, "admin", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// dedupFor 给 svc 起一个去重键：带上 svc 的队列前缀，这个测试的处理循环只认领自己的投递
// （别的包的测试同时往同一张表里写）。
func dedupFor(svc *Service) string { return svc.claimPrefix + uniqueID("d") }

// deliver 登记一条投递并把队列处理完，返回它的去重键（同步处理，代替后台循环）。
func deliver(t *testing.T, svc *Service, body []byte) string {
	t.Helper()
	dedup := dedupFor(svc)
	if err := svc.HandleWebhookDelivery(context.Background(), dedup, body); err != nil {
		t.Fatalf("登记投递失败：%v", err)
	}
	if _, err := svc.ProcessDueDeliveries(context.Background(), discardLogger()); err != nil {
		t.Fatalf("处理投递失败：%v", err)
	}
	return dedup
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) }

// waitFor 每 20ms 查一次 cond，超时 fatal。
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%v 内没等到：%s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func deliveryAttempts(t *testing.T, db *sql.DB, dedup string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT attempts FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedup).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWebhook_Casdoor不可达时登记RECEIVED_恢复后由后台循环发出当前状态(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	api := newFakeCasdoorAPI(t)
	client := api.adminClient(t)
	svc.SetUserReader(func() UserReader { return client })
	sub := uniqueID("casdoor-uuid")
	api.put(casdoor.User{ID: sub, Owner: "brickkit", Name: "zhou", DisplayName: "停机前"})
	api.down.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	go func() { loopDone <- svc.RunDeliveryLoop(ctx, discardLogger()) }()
	defer func() {
		cancel()
		if err := <-loopDone; err != nil {
			t.Errorf("循环在关停时应返回 nil，实际 %v", err)
		}
	}()

	dedup := dedupFor(svc)
	if err := svc.HandleWebhookDelivery(ctx, dedup,
		deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "zhou", "id": sub})); err != nil {
		t.Fatalf("Casdoor 不可达时投递也应登记成功（webhook 回 200），实际 %v", err)
	}
	if status, _ := deliveryStatus(t, db, dedup); status != "RECEIVED" {
		t.Fatalf("投递状态 %q，期望 RECEIVED", status)
	}

	time.Sleep(400 * time.Millisecond) // 循环在 Casdoor 停机期间试过几轮
	if status, msg := deliveryStatus(t, db, dedup); status != "RECEIVED" {
		t.Fatalf("Casdoor 停机期间投递应留在队列里，实际 %s（%s）", status, msg)
	}
	if n := deliveryAttempts(t, db, dedup); n != 0 {
		t.Fatalf("Casdoor 不可达不该消耗重试次数，attempts=%d", n)
	}
	if _, ok := downstreamView(t, db, sub); ok {
		t.Fatal("Casdoor 停机期间不该发出事件")
	}

	api.put(casdoor.User{ID: sub, Owner: "brickkit", Name: "zhou", DisplayName: "恢复后"})
	api.down.Store(false)
	waitFor(t, 5*time.Second, "投递变成 PROCESSED", func() bool {
		status, _ := deliveryStatus(t, db, dedup)
		return status == "PROCESSED"
	})
	ev, ok := downstreamView(t, db, sub)
	if !ok || ev.Subject != "infra.iam.user.updated.v1" || ev.Payload.DisplayName != "恢复后" {
		t.Fatalf("恢复后期望发出 updated 且是 Casdoor 当前的值 \"恢复后\"，实际 %+v（有事件=%v）", ev, ok)
	}
}

// 两个处理实例（两个副本，或外壳里与单跑的两个进程）同时处理同一个队列：每条投递只能被
// 一个实例认领，事件只发一次。
func TestWebhook_两个处理实例并发_每条投递只发一次事件(t *testing.T) {
	svcA, _ := newTestService(t)
	svcB, _ := newTestService(t)
	svcB.claimPrefix = svcA.claimPrefix
	db := testDB(t)
	users := newFakeUsers()
	users.afterRead = func(int) { time.Sleep(5 * time.Millisecond) } // 让两个实例的处理时间重叠
	svcA.SetUserReader(func() UserReader { return users })
	svcB.SetUserReader(func() UserReader { return users })

	const n = 30
	subs := make([]string, n)
	for i := range subs {
		subs[i] = uniqueID("casdoor-uuid")
		users.put(casdoor.User{ID: subs[i], Owner: "brickkit", Name: subs[i], DisplayName: "并发"})
		if err := svcA.HandleWebhookDelivery(context.Background(), dedupFor(svcA),
			deliveryWithObject(t, "update-user", map[string]any{"id": subs[i]})); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	var processed atomic.Int64
	for _, svc := range []*Service{svcA, svcB} {
		wg.Add(1)
		go func(svc *Service) {
			defer wg.Done()
			got, err := svc.ProcessDueDeliveries(context.Background(), discardLogger())
			if err != nil {
				t.Errorf("处理失败：%v", err)
			}
			processed.Add(int64(got))
		}(svc)
	}
	wg.Wait()

	for _, sub := range subs {
		var events int
		if err := db.QueryRow(`SELECT count(*) FROM infra_iam_casdoor.event_outbox WHERE aggregate_id = $1`, sub).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if events != 1 {
			t.Fatalf("sub %s 有 %d 条事件，期望恰好 1 条（两个实例处理了同一条投递）", sub, events)
		}
	}
	if processed.Load() != n {
		t.Fatalf("两个实例一共处理了 %d 条，期望 %d", processed.Load(), n)
	}
}

// Casdoor 在、但对这条投递一直回错误：有限次重试（带退避）后标 FAILED，记 Warn，不发事件。
func TestWebhook_回读一直出错_重试有限次后标FAILED并记Warn(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	users := withUsers(svc)
	users.failWith = errors.New("Casdoor 返回错误: 测试用的拒绝")
	sub := uniqueID("casdoor-uuid")
	dedup := dedupFor(svc)
	if err := svc.HandleWebhookDelivery(context.Background(), dedup,
		deliveryWithObject(t, "update-user", map[string]any{"id": sub})); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	waitFor(t, 5*time.Second, "投递变成 FAILED", func() bool {
		if _, err := svc.ProcessDueDeliveries(context.Background(), logger); err != nil {
			t.Fatalf("单条投递出错不该让整轮处理报错：%v", err)
		}
		status, _ := deliveryStatus(t, db, dedup)
		return status == "FAILED"
	})
	if n := deliveryAttempts(t, db, dedup); n != maxDeliveryAttempts {
		t.Fatalf("attempts=%d，期望 %d", n, maxDeliveryAttempts)
	}
	if _, msg := deliveryStatus(t, db, dedup); !strings.Contains(msg, "测试用的拒绝") {
		t.Fatalf("FAILED 的投递应记下最后一次的错误，实际 %q", msg)
	}
	if _, ok := downstreamView(t, db, sub); ok {
		t.Fatal("FAILED 的投递不该发出事件")
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, dedup) {
		t.Fatalf("标 FAILED 时应记一条带去重键的 Warn，日志：\n%s", out)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Fatalf("单条投递失败不需要人立刻处理，不该记 Error，日志：\n%s", out)
	}
}
