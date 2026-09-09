package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	_ "github.com/jackc/pgx/v5/stdlib" // §12.4：不用 lib/pq，驱动名注册为 "pgx"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/backend/internal/repo"
)

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

var idSeq int64

func uniqueID(prefix string) string {
	n := atomic.AddInt64(&idSeq, 1)
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), n)
}

func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newTestService 构造一个用真实 Postgres 的 Service。idVerifier 不填
// （测试需要真的验一个 Casdoor id_token 时用 fakeCasdoorJWKS 另外挂）。
func newTestService(t *testing.T) (*Service, *repo.Repo) {
	t.Helper()
	db := testDB(t)
	r := repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor")
	signingKey := testSigningKey(t)
	svc := New(r, "infra_iam_casdoor", signingKey, "test-kid", nil, "",
		10*time.Minute, 7*24*time.Hour, []string{"mdm/customer", "erp/sales"},
		"shared-secret-for-test", "X-Shared-Secret")
	return svc, r
}

// fakeCasdoorJWKS 是"自己签发、自己验签"的测试夹具（同 be-sdk-go
// jwt_test.go 的 testJWKS 判据：真实的 RSA 密钥对、真实的 JWKS 端点、
// 真实的 RS256 签名与验签，只是身份是测试用的）。
type fakeCasdoorJWKS struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	kid    string
	issuer string
}

func newFakeCasdoorJWKS(t *testing.T) *fakeCasdoorJWKS {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCasdoorJWKS{priv: priv, kid: "fake-casdoor-key", issuer: "http://fake-casdoor.test"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk, err := jwkset.NewJWKFromKey(f.priv.Public(), jwkset.JWKOptions{
			Metadata: jwkset.JWKMetadataOptions{KID: f.kid, ALG: jwkset.AlgRS256, USE: jwkset.UseSig},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := map[string]any{"keys": []jwkset.JWKMarshal{jwk.Marshal()}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCasdoorJWKS) verifier(t *testing.T) *casdoor.IDTokenVerifier {
	t.Helper()
	v, err := casdoor.NewIDTokenVerifier(context.Background(), f.server.URL+"/.well-known/jwks", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *fakeCasdoorJWKS) sign(t *testing.T, sub string) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   sub,
		Issuer:    f.issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	signed, err := tok.SignedString(f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// ── ExchangeToken：idVerifier 未就绪 / 凭据无效两条错误路径不需要
// infra-authz 就能测——ResolveClaims 根本没被调到（signAccessTokenFor
// 在 Verify 失败时提前返回）。──────────────────────────────────────────

func TestExchangeToken_idVerifier未就绪返回Unavailable(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.ExchangeToken(context.Background(), "whatever")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("期望 ErrUnavailable，实际 %v", err)
	}
}

func TestExchangeToken_伪造的CasdoorToken返回Unauthenticated(t *testing.T) {
	svc, _ := newTestService(t)
	fake := newFakeCasdoorJWKS(t)
	svc.SetIDVerifier(fake.verifier(t))

	_, err := svc.ExchangeToken(context.Background(), "not-a-real-jwt")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("期望 ErrUnauthenticated，实际 %v", err)
	}
}

// TestExchangeToken_签名被篡改返回Unauthenticated 用 deliberate break
// 的方式核对过：如果 ExchangeToken 忘了检查 v.Verify 的 error（比如把
// sub 直接从未验证的 token 里裸解出来），这条测试会变红。
func TestExchangeToken_签名被篡改返回Unauthenticated(t *testing.T) {
	svc, _ := newTestService(t)
	fake := newFakeCasdoorJWKS(t)
	svc.SetIDVerifier(fake.verifier(t))

	tok := fake.sign(t, "some-sub")
	tampered := tok[:len(tok)-2] + "xx"
	_, err := svc.ExchangeToken(context.Background(), tampered)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("期望 ErrUnauthenticated，实际 %v", err)
	}
}

// TestExchangeTokenAndRefreshToken_端到端对着真实infra_authz走一遍
// 是本组件最核心的路径——验 Casdoor 身份 token → 现问 infra-authz 的
// ResolveClaims → 签应用 token + refresh token → 用 refresh token 刷新
// → 登出——全部对着真实基础设施（真实 Postgres + 真实跑着的 infra-authz
// 容器），不用任何 mock。
//
// ⚠️ 需要显式设置 TEST_INFRA_AUTHZ_GRPC_ENDPOINT（比如
// `http://<容器IP>:9223`）——infra-authz 的 gRPC 端口默认不映射到宿主
// 机（同 erp-sales 当初记录的"gRPC 端口只能走容器 Docker 网络 IP"这条
// 限制），本机可以用 `docker inspect <容器名> --format
// '{{json .NetworkSettings.Networks}}'` 拿到容器 IP，Docker 默认桥接
// 网络允许宿主机直接连容器内部端口，不需要显式 publish。CI/别人的机器
// 上没有这个环境变量时跳过，不阻塞默认的 `go test ./...`。
func TestExchangeTokenAndRefreshToken_端到端对着真实infra_authz走一遍(t *testing.T) {
	endpoint := os.Getenv("TEST_INFRA_AUTHZ_GRPC_ENDPOINT")
	if endpoint == "" {
		t.Skip("未设置 TEST_INFRA_AUTHZ_GRPC_ENDPOINT，跳过端到端测试")
	}
	t.Setenv("INFRA_AUTHZ_GRPC_ENDPOINT", endpoint) // besdk.SystemClient 直接读这个环境变量

	svc, _ := newTestService(t)
	fake := newFakeCasdoorJWKS(t)
	svc.SetIDVerifier(fake.verifier(t))

	sub := uniqueID("e2e-sub")
	casdoorToken := fake.sign(t, sub)

	pair, err := svc.ExchangeToken(context.Background(), casdoorToken)
	if err != nil {
		t.Fatalf("ExchangeToken 失败：%v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.ExpiresIn <= 0 {
		t.Fatalf("签出来的 token pair 不完整：%+v", pair)
	}

	// 用签出来的 refresh token 刷新一次——验证轮换链路真的走通。
	newPair, err := svc.RefreshToken(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken 失败：%v", err)
	}
	if newPair.AccessToken == "" || newPair.RefreshToken == "" {
		t.Fatalf("刷新后的 token pair 不完整：%+v", newPair)
	}
	if newPair.RefreshToken == pair.RefreshToken {
		t.Fatal("刷新后的 refresh token 不该和旧的一样（rotation 语义）")
	}

	// 旧 refresh token 已经被轮换掉，不能再用来刷新。
	if _, err := svc.RefreshToken(context.Background(), pair.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("用已经轮换掉的旧 refresh token 刷新应该失败，实际 %v", err)
	}

	// 用新的 refresh token 登出。
	if err := svc.Logout(context.Background(), newPair.RefreshToken, sub); err != nil {
		t.Fatalf("登出失败：%v", err)
	}
	if _, err := svc.RefreshToken(context.Background(), newPair.RefreshToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("登出后用它刷新应该失败，实际 %v", err)
	}
}

// ── Logout：完全不需要 infra-authz，用真实 Postgres 端到端测 ──────────

func TestLogout_幂等且只能作废自己的token(t *testing.T) {
	svc, r := newTestService(t)
	ctx := context.Background()
	sub := uniqueID("sub")
	other := uniqueID("sub")

	refreshToken, jti, expiresAt, err := svc.issuer.SignRefreshToken(sub)
	if err != nil {
		t.Fatalf("签发失败：%v", err)
	}
	if err := r.IssueRefreshToken(ctx, jti, sub, expiresAt); err != nil {
		t.Fatalf("登记失败：%v", err)
	}

	// 别人拿这个 refresh token 字符串去登出，不该生效。
	if err := svc.Logout(ctx, refreshToken, other); err != nil {
		t.Fatalf("Logout 调用本身不该报错：%v", err)
	}
	// 真正的 owner 登出应该成功且幂等。
	if err := svc.Logout(ctx, refreshToken, sub); err != nil {
		t.Fatalf("owner 登出失败：%v", err)
	}
	if err := svc.Logout(ctx, refreshToken, sub); err != nil {
		t.Fatalf("重复登出（幂等）不该报错：%v", err)
	}
}

func TestLogout_伪造的refreshToken不报错(t *testing.T) {
	svc, _ := newTestService(t)
	// "反正肯定作废不了的东西"登出应该安全返回，不是内部错误
	// （service.Logout 的既有设计：验签失败当"没有可撤销的东西"处理）。
	if err := svc.Logout(context.Background(), "garbage", "some-sub"); err != nil {
		t.Fatalf("伪造 token 登出不该报错：%v", err)
	}
}

// ── HandleWebhookDelivery：完全不需要 infra-authz/Casdoor ────────────

func TestHandleWebhookDelivery_合法payload发布事件(t *testing.T) {
	svc, _ := newTestService(t)
	sub := uniqueID("casdoor-uuid")
	payload := fmt.Sprintf(`{"action":"add-user","object":{"id":%q,"displayName":"张三","email":"a@b.com"}}`, sub)

	if err := svc.HandleWebhookDelivery(context.Background(), uniqueID("dedup"), []byte(payload)); err != nil {
		t.Fatalf("处理失败：%v", err)
	}
}

func TestHandleWebhookDelivery_认不出的action标记IGNORED不报错(t *testing.T) {
	svc, _ := newTestService(t)
	sub := uniqueID("casdoor-uuid")
	payload := fmt.Sprintf(`{"action":"some-unknown-action","object":{"id":%q}}`, sub)

	if err := svc.HandleWebhookDelivery(context.Background(), uniqueID("dedup"), []byte(payload)); err != nil {
		t.Fatalf("认不出的 action 不该报错：%v", err)
	}
}

func TestHandleWebhookDelivery_解析失败不报错(t *testing.T) {
	svc, _ := newTestService(t)
	if err := svc.HandleWebhookDelivery(context.Background(), uniqueID("dedup"), []byte("不是 JSON")); err != nil {
		t.Fatalf("解析失败不该向上层报错：%v", err)
	}
}

// ── 共享密钥校验 ────────────────────────────────────────────────────

func TestWebhookSharedSecretValid(t *testing.T) {
	svc, _ := newTestService(t)
	if !svc.WebhookSharedSecretValid("shared-secret-for-test") {
		t.Fatal("正确的共享密钥应该通过")
	}
	if svc.WebhookSharedSecretValid("wrong") {
		t.Fatal("错误的共享密钥不该通过")
	}
	if svc.WebhookSharedSecretValid("") {
		t.Fatal("空字符串不该通过（哪怕共享密钥本身配置错误变成空）")
	}
}

