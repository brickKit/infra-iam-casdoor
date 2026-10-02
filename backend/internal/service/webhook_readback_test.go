package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
)

// 这一组测的是 R61：每次投递都回 Casdoor 读这个人的当前状态再发事件，所以投递
// 以什么顺序到达都不影响下游最后留下的值。2026-10-02 真机上 Casdoor 把同一秒里的
// 两次 update-user 按新到旧投递，下游留下了旧值。

// deliveryWithObject 拼一条真机形状的投递，object 是给定字段（再被 JSON 编码成字符串）。
func deliveryWithObject(t *testing.T, action string, object map[string]any) []byte {
	t.Helper()
	obj, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"id": 0, "owner": "built-in", "name": uniqueID("record"),
		"createdTime": "2026-10-02T11:46:29Z", "organization": "built-in",
		"user": "admin", "method": "POST", "action": action,
		"object": string(obj), "statusCode": 200, "extendedUser": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// outboxEvent 是 outbox 里的一行（信封 version 与 payload）。
type outboxEvent struct {
	Subject string
	Version int64
	Payload userEventPayload
}

// downstreamView 按下游消费者的规则（infra-notification：同一个 sub 只接受
// version 严格更大的事件）算出下游最后留下的那条事件；没有事件时 ok=false。
func downstreamView(t *testing.T, db *sql.DB, sub string) (ev outboxEvent, ok bool) {
	t.Helper()
	rows, err := db.Query(`SELECT subject, version, payload::text FROM infra_iam_casdoor.event_outbox
		WHERE aggregate_id = $1 ORDER BY id`, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var e outboxEvent
		var payload string
		if err := rows.Scan(&e.Subject, &e.Version, &payload); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(payload), &e.Payload); err != nil {
			t.Fatal(err)
		}
		if !ok || e.Version > ev.Version {
			ev, ok = e, true
		}
	}
	return ev, ok
}

func deliveryStatus(t *testing.T, db *sql.DB, dedup string) (status, errMsg string) {
	t.Helper()
	err := db.QueryRow(`SELECT status, error FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedup).
		Scan(&status, &errMsg)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return status, errMsg
}

func TestWebhook_两次修改倒序到达_下游留下的是最新状态(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	users := withUsers(svc)
	sub := uniqueID("casdoor-uuid")
	// Casdoor 里先改成"旧"、再改成"新"；两次修改的投递按新到旧到达。
	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: "zhangsan", DisplayName: "新"})
	newer := deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "zhangsan", "id": sub, "displayName": "新"})
	older := deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "zhangsan", "id": sub, "displayName": "旧"})

	for _, d := range [][]byte{newer, older} {
		deliver(t, svc, d)
	}

	ev, ok := downstreamView(t, db, sub)
	if !ok {
		t.Fatal("outbox 里没有这个人的事件")
	}
	if ev.Subject != "infra.iam.user.updated.v1" || ev.Payload.DisplayName != "新" {
		t.Fatalf("下游最后留下 %s display_name=%q，期望 updated 且是 Casdoor 当前的值 \"新\"", ev.Subject, ev.Payload.DisplayName)
	}
	if ev.Payload.Version != ev.Version {
		t.Fatalf("payload.version=%d 应等于信封 version=%d", ev.Payload.Version, ev.Version)
	}
}

// 同一个人的两次投递由两个处理实例并发处理：先开始的那次回读停在中间时 Casdoor 里又改了
// 一次。回读与定版本号必须按人串行，否则后回读（拿到新值）的那次可能先定下更小的版本号。
func TestWebhook_同一用户两次投递并发_后回读的拿到更大的版本号(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	ctx := context.Background()
	users := withUsers(svc)
	sub := uniqueID("casdoor-uuid")
	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: "lisi", DisplayName: "第一次"})

	firstReading := make(chan struct{})
	release := make(chan struct{})
	users.afterRead = func(n int) {
		if n == 1 {
			close(firstReading)
			<-release
		}
	}
	object := map[string]any{"owner": "brickkit", "name": "lisi", "id": sub}
	record := func() {
		if err := svc.HandleWebhookDelivery(ctx, dedupFor(svc), deliveryWithObject(t, "update-user", object)); err != nil {
			t.Fatalf("登记失败：%v", err)
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	process := func() {
		defer wg.Done()
		_, err := svc.ProcessDueDeliveries(ctx, discardLogger())
		errs <- err
	}
	record()
	wg.Add(1)
	go process() // 认领第一条，回读停在中间
	select {
	case <-firstReading:
	case <-time.After(5 * time.Second):
		t.Fatal("第一次投递一直没有回读 Casdoor")
	}
	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: "lisi", DisplayName: "第二次"})
	record()
	wg.Add(1)
	go process()                       // 第一条被锁着，认领第二条
	time.Sleep(300 * time.Millisecond) // 让第二个实例有机会抢在第一个提交之前跑完
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("处理失败：%v", err)
		}
	}

	if ev, _ := downstreamView(t, db, sub); ev.Payload.DisplayName != "第二次" {
		t.Fatalf("下游最后留下 display_name=%q，期望 Casdoor 的最新值 \"第二次\"", ev.Payload.DisplayName)
	}
}

func TestWebhook_update_user到达时人已被删_发disabled(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	withUsers(svc) // Casdoor 里已经没有这个人
	sub := uniqueID("casdoor-uuid")
	d := deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "wangwu", "id": sub, "displayName": "王五"})

	deliver(t, svc, d)
	if ev, ok := downstreamView(t, db, sub); !ok || ev.Subject != "infra.iam.user.disabled.v1" {
		t.Fatalf("Casdoor 里已没有这个人，期望 disabled，实际 %+v（有事件=%v）", ev, ok)
	}
}

func TestWebhook_update_user把人停用_发disabled(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	sub := uniqueID("casdoor-uuid")
	withUsers(svc).put(casdoor.User{ID: sub, Owner: "brickkit", Name: "zhaoliu", DisplayName: "赵六", IsForbidden: true})
	d := deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "zhaoliu", "id": sub, "isForbidden": true})

	deliver(t, svc, d)
	if ev, ok := downstreamView(t, db, sub); !ok || ev.Subject != "infra.iam.user.disabled.v1" {
		t.Fatalf("Casdoor 里这个人已停用，期望 disabled，实际 %+v（有事件=%v）", ev, ok)
	}
}

// 只带 owner 与 name 的 add-user（管理 API 用最小请求体建人时就是这样）：回读按
// owner/name 找到 sub；之后同样只带 owner/name 的 delete-user 到达时人已不在 Casdoor，
// 靠之前见过的名字找到 sub。
func TestWebhook_只带owner与name的增删用户_经回读找到sub(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	users := withUsers(svc)
	sub := uniqueID("casdoor-uuid")
	name := uniqueID("sunqi")
	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: name, DisplayName: "孙七", Email: "s@example.com"})

	addDedup := deliver(t, svc, deliveryWithObject(t, "add-user", map[string]any{"owner": "brickkit", "name": name}))
	if status, msg := deliveryStatus(t, db, addDedup); status != "PROCESSED" {
		t.Fatalf("add-user 投递状态 %s（%s），期望 PROCESSED", status, msg)
	}
	if ev, ok := downstreamView(t, db, sub); !ok || ev.Subject != "infra.iam.user.created.v1" || ev.Payload.Email != "s@example.com" {
		t.Fatalf("期望 created 且字段来自回读，实际 %+v（有事件=%v）", ev, ok)
	}

	users.remove(sub)
	delDedup := deliver(t, svc, deliveryWithObject(t, "delete-user", map[string]any{"owner": "brickkit", "name": name}))
	if status, msg := deliveryStatus(t, db, delDedup); status != "PROCESSED" {
		t.Fatalf("delete-user 投递状态 %s（%s），期望 PROCESSED", status, msg)
	}
	if ev, ok := downstreamView(t, db, sub); !ok || ev.Subject != "infra.iam.user.disabled.v1" {
		t.Fatalf("期望 disabled，实际 %+v（有事件=%v）", ev, ok)
	}
}

// 从没见过的名字、Casdoor 里也查不到：不知道 sub，只能 IGNORED（写明原因）。
func TestWebhook_只带owner与name且查不到的人_标IGNORED(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	withUsers(svc)
	dedup := deliver(t, svc, deliveryWithObject(t, "delete-user", map[string]any{"owner": "brickkit", "name": uniqueID("ghost")}))
	if status, _ := deliveryStatus(t, db, dedup); status != "IGNORED" {
		t.Fatalf("投递状态 %s，期望 IGNORED", status)
	}
}

// Casdoor 管理会话还没就绪时读不回当前状态：照样登记（RECEIVED）、回成功，等会话就绪后
// 由队列处理（Casdoor 从不重发投递，回 503 就永远丢了；发布前审查 I2 推翻了 R61 时的
// "回 503、不登记"）。
func TestWebhook_Casdoor会话未就绪_登记RECEIVED且回成功(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	svc.SetUserReader(func() UserReader { return nil })
	dedup := dedupFor(svc)
	err := svc.HandleWebhookDelivery(context.Background(), dedup,
		deliveryWithObject(t, "update-user", map[string]any{"owner": "brickkit", "name": "x", "id": uniqueID("casdoor-uuid")}))
	if err != nil {
		t.Fatalf("期望登记成功，实际 %v", err)
	}
	if status, _ := deliveryStatus(t, db, dedup); status != "RECEIVED" {
		t.Fatalf("投递状态 %q，期望 RECEIVED", status)
	}
	if _, err := svc.ProcessDueDeliveries(context.Background(), discardLogger()); !errors.Is(err, errSessionNotReady) {
		t.Fatalf("会话没就绪时队列不该认领，期望 errSessionNotReady，实际 %v", err)
	}
	if status, _ := deliveryStatus(t, db, dedup); status != "RECEIVED" {
		t.Fatalf("会话没就绪时投递应留在队列里，实际 %q", status)
	}
}

// 认不出的动作（login 等）不需要回读，Casdoor 会话没就绪也照样 IGNORED。
func TestWebhook_login不回读Casdoor_标IGNORED(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	svc.SetUserReader(func() UserReader { return nil })
	dedup := uniqueID("dedup")
	if err := svc.HandleWebhookDelivery(context.Background(), dedup,
		deliveryWithObject(t, "login", map[string]any{"organization": "brickkit", "username": "x", "type": "login"})); err != nil {
		t.Fatalf("处理失败：%v", err)
	}
	if status, _ := deliveryStatus(t, db, dedup); status != "IGNORED" {
		t.Fatalf("投递状态 %s，期望 IGNORED", status)
	}
}

// 版本号每人单调递增，且不小于处理时刻的 unix 纳秒：1.x 发过的事件用的就是纳秒
// 时间戳，下游存着的版本号是这个量级，新版本号要比它们大才会被接受。
func TestWebhook_版本号每人单调且不小于处理时刻纳秒(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	sub := uniqueID("casdoor-uuid")
	withUsers(svc).put(casdoor.User{ID: sub, Owner: "brickkit", Name: "v", DisplayName: "v"})
	start := time.Now().UnixNano()
	for i := 0; i < 3; i++ {
		deliver(t, svc, deliveryWithObject(t, "update-user", map[string]any{"id": sub}))
	}
	rows, err := db.Query(`SELECT version FROM infra_iam_casdoor.event_outbox WHERE aggregate_id = $1 ORDER BY id`, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var prev int64
	n := 0
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		if v < start || v <= prev {
			t.Fatalf("第 %d 条 version=%d，期望 ≥ %d 且 > 上一条 %d", n+1, v, start, prev)
		}
		prev = v
		n++
	}
	if n != 3 {
		t.Fatalf("期望 3 条事件，实际 %d", n)
	}
}
