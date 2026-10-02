package module

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryUntilOK_失败就退避重试直到成功(t *testing.T) {
	calls, fails := 0, 0
	retryUntilOK(context.Background(), time.Millisecond, func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("还没好")
		}
		return nil
	}, func(error, time.Duration) { fails++ })
	if calls != 3 || fails != 2 {
		t.Fatalf("应调用 3 次、报告 2 次失败，实际 %d / %d", calls, fails)
	}
}

// 关停时 ctx 取消：立刻返回，取消本身不算一次失败（不打日志）。
func TestRetryUntilOK_ctx取消就返回且不报告失败(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fails := 0
	done := make(chan struct{})
	go func() {
		retryUntilOK(ctx, time.Hour, func(ctx context.Context) error {
			cancel()
			return ctx.Err()
		}, func(error, time.Duration) { fails++ })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后没有返回")
	}
	if fails != 0 {
		t.Fatalf("ctx 取消不该算失败，实际报告了 %d 次", fails)
	}
}
