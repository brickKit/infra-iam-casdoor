package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 会话的总期限从登录那一刻算，轮换不续期：一个每隔几分钟刷新一次的会话，过了登录时
// 定下的期限就必须重新登录。否则只要客户端还在刷新，会话永远不结束——在 Casdoor 里
// 停用的人也一样（发布前审查 I1）。
func TestRefreshToken_轮换不延长会话_过了登录时的期限就拒绝(t *testing.T) {
	const ttl = 2 * time.Second
	svc, _ := newServiceWithAuthz(t, ttl)
	ctx := context.Background()

	pair, err := svc.issueFor(ctx, uniqueID("sub"))
	if err != nil {
		t.Fatalf("登录失败：%v", err)
	}
	start := time.Now()
	rt := pair.RefreshToken
	rotations := 0
	refusedAt := time.Duration(-1)
	for time.Since(start) < ttl+2*time.Second {
		time.Sleep(600 * time.Millisecond)
		p, err := svc.RefreshToken(ctx, rt)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("第 %d 次刷新期望成功或 ErrUnauthenticated，实际 %v", rotations+1, err)
			}
			refusedAt = time.Since(start)
			break
		}
		rotations++
		rt = p.RefreshToken
	}
	if refusedAt < 0 {
		t.Fatalf("登录后 %v 里轮换了 %d 次，每次都成功：每次轮换都重新给了 %v，会话一直续期；期望过了登录时的期限就拒绝",
			time.Since(start).Round(100*time.Millisecond), rotations, ttl)
	}
	if rotations == 0 {
		t.Fatalf("期限之内的刷新也被拒绝了（%v 时第一次刷新就失败）", refusedAt)
	}
	if refusedAt > ttl+time.Second {
		t.Fatalf("到 %v 才拒绝，期望在登录后 %v 左右", refusedAt, ttl)
	}
}
