package casdoor

import (
	"context"
	"testing"
)

// 管理会话会过期（Casdoor 回 "Please login first"）。过期后不该一直报错到组件
// 重启：重新登录一次、重试这一次调用。
func TestGetUserBySub_会话过期后重新登录并重试(t *testing.T) {
	f := newFakeCasdoor(t)
	f.users["u-1"] = "张三"
	ctx := context.Background()
	c, err := NewAdminClient(ctx, f.server.URL, "admin", "pw")
	if err != nil {
		t.Fatal(err)
	}
	f.expireSession()

	u, err := c.GetUserBySub(ctx, "u-1")
	if err != nil || u == nil || u.DisplayName != "张三" {
		t.Fatalf("会话过期后应重新登录并查到用户：u=%+v err=%v", u, err)
	}
	if n := f.loginCount(); n != 2 {
		t.Fatalf("应恰好重新登录一次（共 2 次登录），实际 %d 次", n)
	}
}

func TestGetUserBySub_查不到是nil不是错误(t *testing.T) {
	f := newFakeCasdoor(t)
	c, err := NewAdminClient(context.Background(), f.server.URL, "admin", "pw")
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.GetUserBySub(context.Background(), "nobody")
	if err != nil || u != nil {
		t.Fatalf("查不到应返回 (nil, nil)，实际 u=%+v err=%v", u, err)
	}
}
