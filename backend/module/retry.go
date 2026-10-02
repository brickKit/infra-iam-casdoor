package module

import (
	"context"
	"time"
)

// maxBackoff 是后台重试的退避上限：依赖慢启动几秒到几十秒都追得上，长时间不可达
// 时也不会疯狂重试。
const maxBackoff = 30 * time.Second

// retryUntilOK 反复调 fn 直到它成功或 ctx 取消；每次失败先调 onFail（由调用方
// 决定日志级别），再按指数退避等待（从 first 起翻倍，封顶 maxBackoff）。ctx 取消
// （关停）时立刻返回，取消本身不算失败、不调 onFail。
func retryUntilOK(ctx context.Context, first time.Duration, fn func(context.Context) error, onFail func(err error, next time.Duration)) {
	backoff := first
	for {
		err := fn(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		onFail(err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
