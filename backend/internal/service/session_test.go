package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
)

// 会话的总期限从登录那一刻算，轮换不续期：一个每隔几分钟刷新一次的会话，过了登录时
// 定下的期限就必须重新登录。否则只要客户端还在刷新，会话永远不结束——在 Casdoor 里
// 停用的人也一样。
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

// 在 Casdoor 里停用或删掉一个人：投递处理完之后这个人的 refresh token 全部作废，下一次
// 刷新就是 401（应用 token 最多再用 APP_TOKEN_TTL_SECONDS）。只撤这个人的，别人不受影响。
func TestWebhook_停用或删除用户_他的refreshToken立即作废(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state func(users *fakeUsers, sub string)
	}{
		{"isForbidden", func(users *fakeUsers, sub string) {
			users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: sub, DisplayName: "停用", IsForbidden: true})
		}},
		{"Casdoor里已删除", func(users *fakeUsers, sub string) { users.remove(sub) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newServiceWithAuthz(t, time.Hour)
			ctx := context.Background()
			users := withUsers(svc)
			sub, other := uniqueID("casdoor-uuid"), uniqueID("casdoor-uuid")
			users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: sub, DisplayName: "在职"})
			pair, err := svc.issueFor(ctx, sub)
			if err != nil {
				t.Fatal(err)
			}
			otherPair, err := svc.issueFor(ctx, other)
			if err != nil {
				t.Fatal(err)
			}

			tc.state(users, sub)
			deliver(t, svc, deliveryWithObject(t, "update-user", map[string]any{"id": sub}))

			if _, err := svc.RefreshToken(ctx, pair.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("停用后刷新期望 ErrUnauthenticated（401），实际 %v", err)
			}
			if _, err := svc.RefreshToken(ctx, otherPair.RefreshToken); err != nil {
				t.Fatalf("别人的 refresh token 不该受影响：%v", err)
			}
		})
	}
}

// 停用之后，这个人手里还没过期的 Casdoor id_token 也不能再换出新会话（Casdoor 的 id_token
// 一般能用一天，停用前拿到的那张照样验签通过）。重新启用、投递处理完之后又可以登录。
func TestExchangeToken_Casdoor里停用的人不能拿旧id_token换新会话_重新启用后恢复(t *testing.T) {
	svc, _ := newServiceWithAuthz(t, time.Hour)
	ctx := context.Background()
	fake := newFakeCasdoorJWKS(t)
	svc.SetIDVerifier(fake.verifier(t))
	users := withUsers(svc)
	sub := uniqueID("casdoor-uuid")
	idToken := fake.sign(t, sub) // 停用之前拿到的 id_token

	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: sub, IsForbidden: true})
	deliver(t, svc, deliveryWithObject(t, "update-user", map[string]any{"id": sub}))
	if _, err := svc.ExchangeToken(ctx, idToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("停用后拿旧 id_token 换 token 期望 ErrUnauthenticated（401），实际 %v", err)
	}

	users.put(casdoor.User{ID: sub, Owner: "brickkit", Name: sub, DisplayName: "复职"})
	deliver(t, svc, deliveryWithObject(t, "update-user", map[string]any{"id": sub}))
	if _, err := svc.ExchangeToken(ctx, idToken); err != nil {
		t.Fatalf("重新启用后应能登录，实际 %v", err)
	}
}

// Casdoor id_token 的 aud 必须是本组件信任的应用：同一个 Casdoor 里别的应用（含内置的
// app-built-in）签给用户的 id_token 不能换出本项目的应用 token。
func TestExchangeToken_只认可信应用签给用户的id_token(t *testing.T) {
	const extra = "extra-trusted-client-id"
	for _, tc := range []struct {
		name string
		aud  jwt.ClaimStrings
		ok   bool
	}{
		{"本组件的应用", jwt.ClaimStrings{testClientID}, true},
		{"CASDOOR_EXTRA_CLIENT_IDS 里的应用", jwt.ClaimStrings{extra}, true},
		{"别的应用", jwt.ClaimStrings{"another-casdoor-app"}, false},
		{"没有 aud", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newServiceWithAuthz(t, time.Hour)
			svc.SetAudienceSource(func(context.Context) ([]string, error) { return []string{testClientID, extra}, nil })
			fake := newFakeCasdoorJWKS(t)
			svc.SetIDVerifier(fake.verifier(t))
			_, err := svc.ExchangeToken(context.Background(), fake.signFor(t, uniqueID("sub"), tc.aud))
			switch {
			case tc.ok && err != nil:
				t.Fatalf("aud=%v 应能换 token，实际 %v", tc.aud, err)
			case !tc.ok && !errors.Is(err, ErrUnauthenticated):
				t.Fatalf("aud=%v 期望 ErrUnauthenticated（401），实际 %v", tc.aud, err)
			}
		})
	}
}

// 本组件 Casdoor 应用的 client ID 还不知道（启动对账从没成功过）：换 token 回 503，
// 不是 401——id_token 本身可能没问题，只是这一刻判断不了它是不是给本项目的。
func TestExchangeToken_还不知道应用的clientID时回Unavailable(t *testing.T) {
	svc, _ := newServiceWithAuthz(t, time.Hour)
	svc.SetAudienceSource(func(context.Context) ([]string, error) { return nil, nil })
	fake := newFakeCasdoorJWKS(t)
	svc.SetIDVerifier(fake.verifier(t))
	if _, err := svc.ExchangeToken(context.Background(), fake.sign(t, uniqueID("sub"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("期望 ErrUnavailable（503），实际 %v", err)
	}
}
