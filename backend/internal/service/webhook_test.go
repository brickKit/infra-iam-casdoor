package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// casdoorRecordPayload 按 2026-10-02 真机抓到的 Casdoor webhook 投递体拼出来：
// 投递体就是 Casdoor 的 Record 对象，object 是**被 JSON 编码成字符串**的请求体
// （update-user 时是整个用户对象，口令字段 Casdoor 已掩码成 "***"），user 是
// 发起操作的账号名（这里是管理员 admin，不是被改的用户），extendedUser 为 null。
// 顶层键与真机投递逐一对过：action、clientIp、createdTime、detail、extendedUser、
// id、isTriggered、language、method、name、object、organization、owner、
// requestUri、response、statusCode、user。
func casdoorRecordPayload(t *testing.T, action, sub, displayName, email string) []byte {
	t.Helper()
	user, err := json.Marshal(map[string]any{
		"owner": "brickkit", "name": "dev.finance.viewer", "id": sub,
		"displayName": displayName, "email": email, "phone": "",
		"password": "***", "type": "normal-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"id": 0, "owner": "built-in", "name": uniqueID("record"),
		"createdTime": "2026-10-02T11:33:35Z", "organization": "built-in",
		"clientIp": "172.18.0.1", "user": "admin", "method": "POST",
		"requestUri": "/api/update-user?id=brickkit/dev.finance.viewer",
		"action":     action, "language": "en", "object": string(user),
		"response": `{"status":"ok","msg":""}`, "statusCode": 200,
		"isTriggered": false, "detail": "", "extendedUser": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestWebhookUserPayload_object是JSON字符串时也能取出用户字段(t *testing.T) {
	sub := "915d1763-586b-4526-a9d8-589194a624f5"
	var p webhookUserPayload
	if err := json.Unmarshal(casdoorRecordPayload(t, "update-user", sub, "财务只读", "f@example.com"), &p); err != nil {
		t.Fatalf("解析真机形状的投递体失败：%v", err)
	}
	if got := p.Sub(); got != sub {
		t.Fatalf("Sub() = %q，期望从字符串形式的 object 里取出 %q", got, sub)
	}
	if f := p.userFields(); f.DisplayName != "财务只读" || f.Email != "f@example.com" {
		t.Fatalf("userFields() = %+v，期望 displayName / email 来自 object", f)
	}
}

func TestHandleWebhookDelivery_真机形状的update_user标PROCESSED并写进outbox(t *testing.T) {
	svc, _ := newTestService(t)
	db := testDB(t)
	ctx := context.Background()
	sub := uniqueID("casdoor-uuid")
	dedup := uniqueID("dedup")

	if err := svc.HandleWebhookDelivery(ctx, dedup, casdoorRecordPayload(t, "update-user", sub, "张三", "a@b.com")); err != nil {
		t.Fatalf("处理失败：%v", err)
	}

	var status, errMsg string
	if err := db.QueryRowContext(ctx,
		`SELECT status, error FROM infra_iam_casdoor.webhook_deliveries WHERE dedup_key = $1`, dedup).
		Scan(&status, &errMsg); err != nil {
		t.Fatalf("查投递记录：%v", err)
	}
	if status != "PROCESSED" {
		t.Fatalf("投递状态 = %s（%s），期望 PROCESSED", status, errMsg)
	}

	var subject, payload string
	if err := db.QueryRowContext(ctx,
		`SELECT subject, payload::text FROM infra_iam_casdoor.event_outbox WHERE aggregate_id = $1`, sub).
		Scan(&subject, &payload); err != nil {
		t.Fatalf("outbox 里应有 aggregate_id=%s 的一行：%v", sub, err)
	}
	if subject != "infra.iam.user.updated.v1" {
		t.Fatalf("subject = %s，期望 infra.iam.user.updated.v1", subject)
	}
	var ev userEventPayload
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Sub != sub || ev.DisplayName != "张三" || ev.Version == 0 {
		t.Fatalf("事件 payload = %s，期望 sub、display_name 来自 object，version 非零", fmt.Sprint(payload))
	}
}
