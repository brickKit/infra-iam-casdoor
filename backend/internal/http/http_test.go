package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace/noop"

	besdk "github.com/brickKit/be-sdk-go"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/keys"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/service"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/tokens"
)

// 这里测的是 REST 面对外承诺的状态码：路由用真实的 RegisterRoutes 挂在
// besdk.NewGinEngine 上（错误映射中间件把 service 的 gRPC status 翻成 HTTP
// 状态码），service 连真实的测试库。

const testSecret = "shared-secret-for-http-test"

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

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	eng     *gin.Engine
	repo    *repo.Repo
	key     *rsa.PrivateKey
	kid     string
	prevKey *rsa.PrivateKey
	prevKid string
}

// newFixture 起一套 REST 面。cfg 里不放 INFRA_AUTHZ_GRPC_ENDPOINT 时，签发路径
// 拨不到 infra-authz（ResolveClaims 失败）——正好是"依赖不可用"那一条路径。
func newFixture(t *testing.T, cfg besdk.Config, withPrevious bool) *fixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := testDB(t)
	f := &fixture{repo: repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor"), key: newKey(t)}
	f.kid = keys.Thumbprint(&f.key.PublicKey)
	var prevPub *rsa.PublicKey
	if withPrevious {
		f.prevKey = newKey(t)
		prevPub = &f.prevKey.PublicKey
		f.prevKid = keys.Thumbprint(prevPub)
	}
	svc := service.New(f.repo, cfg, "infra_iam_casdoor", f.key, f.kid, prevPub, f.prevKid,
		10*time.Minute, 24*time.Hour, []string{"infra/authz", "mdm/customer"}, testSecret, "X-Shared-Secret")
	rt := &besdk.Runtime{
		ComponentID: "infra/iam-casdoor", Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Tracer: noop.NewTracerProvider().Tracer("test"), Registry: prometheus.NewRegistry(),
	}
	f.eng = besdk.NewGinEngine(rt)
	RegisterRoutes(f.eng, svc)
	return f
}

func (f *fixture) do(t *testing.T, method, path, body string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.eng.ServeHTTP(w, req)
	return w
}

var seq int64

func uniqueSub(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), atomic.AddInt64(&seq, 1))
}

// issueRefresh 用与被测 service 同一把钥匙签一个 refresh token 并登记进库。
func (f *fixture) issueRefresh(t *testing.T, key *rsa.PrivateKey, kid, sub string) string {
	t.Helper()
	tok, jti, exp, err := tokens.NewIssuer(key, kid, time.Minute, time.Hour).SignRefreshToken(sub)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.IssueRefreshToken(context.Background(), jti, sub, exp); err != nil {
		t.Fatal(err)
	}
	return tok
}

// ── 契约里写明的错误码 ────────────────────────────────────────────────

func TestREST_换token请求体缺字段回400(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	if w := f.do(t, http.MethodPost, "/api/iam/token", `{}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d（%s）", w.Code, w.Body.String())
	}
}

func TestREST_Casdoor验证器未就绪时换token回503(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	w := f.do(t, http.MethodPost, "/api/iam/token", `{"casdoor_id_token":"x"}`, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("期望 503，实际 %d（%s）", w.Code, w.Body.String())
	}
}

func TestREST_刷新用伪造的token回401(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	w := f.do(t, http.MethodPost, "/api/iam/token/refresh", `{"refresh_token":"garbage"}`, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d（%s）", w.Code, w.Body.String())
	}
}

func TestREST_刷新请求体缺字段回400(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	if w := f.do(t, http.MethodPost, "/api/iam/token/refresh", `{}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d（%s）", w.Code, w.Body.String())
	}
}

// infra-authz 暂时不可达时刷新回 503，而且这次失败不能消耗掉调用方的 refresh
// token：authz 恢复后用同一个 token 再刷新必须还能成功。消耗掉的话，第二次
// 会撞上重放检测（401，并撤销这个人名下全部 refresh token）——一次依赖抖动就
// 把在线用户全部踢下线。
func TestREST_authz不可达时刷新回503且不消耗refreshToken(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(map[string]string{
		"INFRA_AUTHZ_GRPC_ENDPOINT": "http://127.0.0.1:1", // 没有任何东西在听
	}), false)
	sub := uniqueSub("refresh-authz-down")
	tok := f.issueRefresh(t, f.key, f.kid, sub)
	body := fmt.Sprintf(`{"refresh_token":%q}`, tok)

	for i := 1; i <= 2; i++ {
		w := f.do(t, http.MethodPost, "/api/iam/token/refresh", body, nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("第 %d 次刷新期望 503（authz 不可达），实际 %d（%s）", i, w.Code, w.Body.String())
		}
	}
}

func TestREST_webhook共享密钥不对回401(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	for name, hdr := range map[string]map[string]string{
		"没带":  nil,
		"带错了": {"X-Shared-Secret": "wrong"},
	} {
		if w := f.do(t, http.MethodPost, "/api/iam/webhooks/casdoor", `{}`, hdr); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s：期望 401，实际 %d", name, w.Code)
		}
	}
}

func TestREST_webhook共享密钥对时认不出的内容也回200(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	body := fmt.Sprintf(`{"action":"unknown-%s"}`, uniqueSub("wh"))
	w := f.do(t, http.MethodPost, "/api/iam/webhooks/casdoor", body, map[string]string{"X-Shared-Secret": testSecret})
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200（宽容解析：认不出的投递存档为 IGNORED），实际 %d（%s）", w.Code, w.Body.String())
	}
}

func TestREST_features按清单下发(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), false)
	w := f.do(t, http.MethodGet, "/api/tenant/features", "", nil)
	var got struct {
		Enabled []string `json:"enabled_components"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("期望 200 + JSON，实际 %d（%s）", w.Code, w.Body.String())
	}
	if strings.Join(got.Enabled, ",") != "infra/authz,mdm/customer" {
		t.Fatalf("清单不对：%q", got.Enabled)
	}
}

// ── 签名密钥轮换 ──────────────────────────────────────────────────────

// 轮换期间 JWKS 同时挂新旧两把公钥：用上一把私钥签的应用 token（换钥前签出、
// 还没过期的）在别的组件那里照样能验过——它们用 keyfunc 读本端点按 kid 选钥，
// 这里走的是同一条路。
func TestREST_轮换期JWKS同时挂两把钥匙且旧钥匙签的token能验过(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), true)
	srv := httptest.NewServer(f.eng)
	t.Cleanup(srv.Close)

	var set struct {
		Keys []keys.JWK `json:"keys"`
	}
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	kids := map[string]bool{}
	for _, k := range set.Keys {
		kids[k.Kid] = true
	}
	if len(set.Keys) != 2 || !kids[f.kid] || !kids[f.prevKid] {
		t.Fatalf("JWKS 应恰好有当前与上一把两把钥匙，实际 %+v", set.Keys)
	}

	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{srv.URL + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]struct {
		key *rsa.PrivateKey
		kid string
	}{"当前钥匙": {f.key, f.kid}, "上一把钥匙": {f.prevKey, f.prevKid}} {
		tok, _, err := tokens.NewIssuer(signer.key, signer.kid, time.Minute, time.Hour).
			SignAccessToken(tokens.Claims{Sub: "rotation-sub"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jwt.Parse(tok, kf.Keyfunc, jwt.WithValidMethods([]string{"RS256"})); err != nil {
			t.Fatalf("%s签的应用 token 应能用 JWKS 验过：%v", name, err)
		}
	}
}

// 轮换期间，上一把钥匙签出的 refresh token 也照样认（验签过了，才走到依赖
// 那一步）：authz 不可达时回 503，而不是把它当伪造的 token 回 401。
func TestREST_轮换期上一把钥匙签的refreshToken仍被认(t *testing.T) {
	f := newFixture(t, besdk.NewConfig(nil), true)
	tok := f.issueRefresh(t, f.prevKey, f.prevKid, uniqueSub("refresh-prev-key"))
	w := f.do(t, http.MethodPost, "/api/iam/token/refresh", fmt.Sprintf(`{"refresh_token":%q}`, tok), nil)
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("上一把钥匙签的 refresh token 被当成无效（401）：%s", w.Body.String())
	}
}
