package casdoor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 这份文件是真机集成测试：对着一个真实跑着的 Casdoor 容器（同
// docs/design/infra-iam-casdoor.md §8/§9 记录的那次真机核对用的同一个
// be-casdoor），完整走一遍"建组织 → 建应用 → 建用户 → 密码授权换
// token → 验签 → 建 webhook → 清理"。⚠️ 门禁/CI 环境没有这个容器时
// 必须能跳过，不能把默认的 `go test ./...` 拖住——同 repo 层测试用
// TEST_PG_DSN 的既有约定（infra-authz 的 repo_test.go）。
//
// 建的全部对象都用带时间戳的名字，并在 t.Cleanup 里删除，避免污染
// 共享的开发环境 Casdoor 实例——这是本组件设计阶段调研时定下的纪律
// （AGENTS.md：真机核对完必须清理测试产物）。
func testCasdoorBaseURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_CASDOOR_BASE_URL")
	if base == "" {
		t.Skip("未设置 TEST_CASDOOR_BASE_URL，跳过 Casdoor 真机集成测试")
	}
	return base
}

func testSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func TestAdminClient与IDTokenVerifier_真机走一遍完整流程(t *testing.T) {
	base := testCasdoorBaseURL(t)
	ctx := context.Background()

	adminUser := envOr("TEST_CASDOOR_ADMIN_USERNAME", "admin")
	adminPass := envOr("TEST_CASDOOR_ADMIN_PASSWORD", "123")

	c, err := NewAdminClient(ctx, base, adminUser, adminPass)
	if err != nil {
		t.Fatalf("登录 Casdoor 管理 API 失败：%v", err)
	}

	suffix := testSuffix()
	orgName := "iamtest-org-" + suffix
	appName := "iamtest-app-" + suffix
	tokenAppName := "iamtest-tokenapp-" + suffix
	userName := "iamtestuser" + suffix
	whName := "iamtest-wh-" + suffix

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = c.post(cleanupCtx, "/api/delete-webhook", map[string]any{
			"owner": c.username, "name": whName, "organization": orgName,
		})
		_, _ = c.post(cleanupCtx, "/api/delete-user", map[string]any{
			"owner": orgName, "name": userName,
		})
		_, _ = c.post(cleanupCtx, "/api/delete-application", map[string]any{
			"owner": c.username, "name": appName, "organization": orgName,
		})
		_, _ = c.post(cleanupCtx, "/api/delete-application", map[string]any{
			"owner": c.username, "name": tokenAppName, "organization": orgName,
		})
		_, _ = c.post(cleanupCtx, "/api/delete-organization", map[string]any{
			"owner": c.username, "name": orgName,
		})
	})

	// ── 组织 ──────────────────────────────────────────────────────
	if exists, err := c.OrganizationExists(ctx, orgName); err != nil {
		t.Fatalf("查组织失败：%v", err)
	} else if exists {
		t.Fatalf("组织 %s 不应该已经存在", orgName)
	}
	if err := c.CreateOrganization(ctx, orgName, "iam-casdoor 集成测试"); err != nil {
		t.Fatalf("建组织失败：%v", err)
	}
	if exists, err := c.OrganizationExists(ctx, orgName); err != nil || !exists {
		t.Fatalf("建完之后组织应该存在：exists=%v, err=%v", exists, err)
	}

	// ── 应用 ──────────────────────────────────────────────────────
	if app, err := c.GetApplication(ctx, appName); err != nil {
		t.Fatalf("查应用失败：%v", err)
	} else if app != nil {
		t.Fatalf("应用 %s 不应该已经存在", appName)
	}
	if err := c.CreateApplication(ctx, appName, orgName, []string{"http://localhost:3000/callback"}); err != nil {
		t.Fatalf("建应用失败：%v", err)
	}
	app, err := c.GetApplication(ctx, appName)
	if err != nil {
		t.Fatalf("查应用失败：%v", err)
	}
	if app == nil || app.ClientID == "" || app.ClientSecret == "" {
		t.Fatalf("建完之后应用应该有 clientId/clientSecret：%+v", app)
	}

	// ── 用户（走 add-user，不是自助注册——测试只关心"能不能验签一个真实
	// Casdoor 签的 token"，不关心注册流程本身）───────────────────────
	if _, err := c.post(ctx, "/api/add-user", map[string]any{
		"owner": orgName, "name": userName, "password": "Passw0rd!",
		"email": userName + "@example.com", "displayName": "集成测试用户",
		"type": "normal-user", "isAdmin": false, "countryCode": "CN",
	}); err != nil {
		t.Fatalf("建用户失败：%v", err)
	}

	// ── 密码授权换 token（真实 OIDC token 端点，不经过 AdminClient——
	// 这一步模拟的是浏览器 ↔ Casdoor 之间的标准流，本组件生产代码里
	// 从不调用这个端点，只是测试需要一个真实签发的 token）。
	//
	// ⚠️ 不能直接用上面 CreateApplication 建出来的 app：生产代码的
	// grantTypes 里刻意不含 "password"（设计计划 §6.1——浏览器直连
	// Casdoor 走 authorization_code，本组件不代理密码），真机测试踩出来
	// 的报错原文是 "grant_type: password is not supported in this
	// application"。这里单独建一个只给测试用的"能走密码授权"的应用，
	// 不代表生产配置——生产应用永远不加 password 这个 grant type。
	tokenApp := createTestAppWithPasswordGrant(ctx, t, c, tokenAppName, orgName)
	idToken := passwordGrantIDToken(t, base, tokenApp.ClientID, tokenApp.ClientSecret, userName, "Passw0rd!")

	// ── 发现 + 验签：这是本组件生产代码真正会跑的两步 ────────────────
	issuer, jwksURI, err := DiscoverOIDC(ctx, base)
	if err != nil {
		t.Fatalf("OIDC 发现失败：%v", err)
	}
	if issuer == "" || jwksURI == "" {
		t.Fatalf("发现文档不完整：issuer=%q jwksURI=%q", issuer, jwksURI)
	}
	v, err := NewIDTokenVerifier(ctx, jwksURI, issuer)
	if err != nil {
		t.Fatalf("构造验证器失败：%v", err)
	}
	sub, err := v.Verify(idToken)
	if err != nil {
		t.Fatalf("验签真实 Casdoor id_token 失败：%v", err)
	}
	if sub == "" {
		t.Fatal("验签成功但 sub 为空")
	}

	// ── GetUserBySub：gRPC BatchGetUsers 真正会跑的那一步 ────────────
	u, err := c.GetUserBySub(ctx, sub)
	if err != nil {
		t.Fatalf("按 sub 查用户失败：%v", err)
	}
	if u == nil || u.ID != sub {
		t.Fatalf("查回来的用户 ID 应该等于 sub：%+v", u)
	}
	if u.DisplayName != "集成测试用户" {
		t.Fatalf("displayName 不符：got %q", u.DisplayName)
	}
	if unknown, err := c.GetUserBySub(ctx, "not-a-real-uuid"); err != nil || unknown != nil {
		t.Fatalf("查一个不存在的 sub 应该返回 (nil, nil)：got (%+v, %v)", unknown, err)
	}

	// 同一个用户再走一遍密码授权，两次拿到的 sub 必须相同——sub 是
	// Casdoor 内部的用户 UUID，不会因为重新登录而改变（真机核对过，
	// 见 docs/design/infra-iam-casdoor.md §9 第 2 条一带而过的调研记录；
	// 这里在测试里把它钉成一条可回归的断言）。
	idToken2 := passwordGrantIDToken(t, base, tokenApp.ClientID, tokenApp.ClientSecret, userName, "Passw0rd!")
	sub2, err := v.Verify(idToken2)
	if err != nil {
		t.Fatalf("第二次验签失败：%v", err)
	}
	if sub2 != sub {
		t.Fatalf("同一用户两次登录的 sub 不一致：%q != %q", sub, sub2)
	}

	// ── Webhook ───────────────────────────────────────────────────
	if exists, err := c.WebhookExists(ctx, whName); err != nil {
		t.Fatalf("查 webhook 失败：%v", err)
	} else if exists {
		t.Fatalf("webhook %s 不应该已经存在", whName)
	}
	if err := c.CreateWebhook(ctx, whName, orgName, "http://127.0.0.1:9999/webhook", "X-Shared-Secret", "test-secret"); err != nil {
		t.Fatalf("建 webhook 失败：%v", err)
	}
	if exists, err := c.WebhookExists(ctx, whName); err != nil || !exists {
		t.Fatalf("建完之后 webhook 应该存在：exists=%v, err=%v", exists, err)
	}
}

// TestIDTokenVerifier_拒绝错误issuer 用一个真实 token + 故意写错的
// issuer 断言 jwt.WithIssuer 真的在生效——不是形式上传了这个选项就
// 万事大吉，得真的用一个会失败的输入验证它确实失败。
func TestIDTokenVerifier_拒绝错误issuer(t *testing.T) {
	base := testCasdoorBaseURL(t)
	ctx := context.Background()

	_, jwksURI, err := DiscoverOIDC(ctx, base)
	if err != nil {
		t.Fatalf("OIDC 发现失败：%v", err)
	}
	v, err := NewIDTokenVerifier(ctx, jwksURI, "https://issuer-that-is-definitely-wrong.example.com")
	if err != nil {
		t.Fatalf("构造验证器失败：%v", err)
	}

	adminUser := envOr("TEST_CASDOOR_ADMIN_USERNAME", "admin")
	adminPass := envOr("TEST_CASDOOR_ADMIN_PASSWORD", "123")
	c, err := NewAdminClient(ctx, base, adminUser, adminPass)
	if err != nil {
		t.Fatalf("登录失败：%v", err)
	}
	// 内置的 app-built-in 同样不带 password 这个 grant type（Casdoor 的
	// 默认配置），这里借用内置组织 built-in 建一个临时的"能走密码授权"
	// 应用，只为了签出一个真实 token 来验证 issuer 校验——本身与
	// TestAdminClient... 那条用例里的理由完全相同。
	suffix := testSuffix()
	tokenAppName := "iamtest-tokenapp-issuer-" + suffix
	t.Cleanup(func() {
		_, _ = c.post(context.Background(), "/api/delete-application", map[string]any{
			"owner": c.username, "name": tokenAppName, "organization": builtInOrg,
		})
	})
	tokenApp := createTestAppWithPasswordGrant(ctx, t, c, tokenAppName, builtInOrg)
	idToken := passwordGrantIDToken(t, base, tokenApp.ClientID, tokenApp.ClientSecret, adminUser, adminPass)

	if _, err := v.Verify(idToken); err == nil {
		t.Fatal("issuer 不匹配时应该验签失败")
	}
}

// createTestAppWithPasswordGrant 建一个**仅供测试**签发 token 用的应用
// ——与生产代码的 CreateApplication 刻意不同：这里的 grantTypes 里加了
// "password"，纯粹是为了让测试不需要一个真的浏览器就能拿到一个真实
// Casdoor 签发的 token。生产应用永远不应该带这个 grant type（见调用处
// 的注释）。
func createTestAppWithPasswordGrant(ctx context.Context, t *testing.T, c *AdminClient, name, organization string) *Application {
	t.Helper()
	_, err := c.post(ctx, "/api/add-application", map[string]any{
		"owner":                c.username,
		"name":                 name,
		"displayName":          name,
		"organization":         organization,
		"cert":                 "cert-built-in",
		"enablePassword":       true,
		"enableSignUp":         false,
		"redirectUris":         []string{"http://localhost:3000/callback"},
		"grantTypes":           []string{"authorization_code", "password", "refresh_token"},
		"tokenFormat":          "JWT",
		"expireInHours":        24,
		"refreshExpireInHours": 168,
	})
	if err != nil {
		t.Fatalf("建测试用 token 应用失败：%v", err)
	}
	app, err := c.GetApplication(ctx, name)
	if err != nil || app == nil {
		t.Fatalf("查测试用 token 应用失败：app=%+v, err=%v", app, err)
	}
	return app
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// passwordGrantIDToken 走 OAuth2 密码授权拿一个真实签发的 id_token——
// 只在测试里用，生产代码从不代替用户走这个授权类型（浏览器直连
// Casdoor，见包顶部注释）。
func passwordGrantIDToken(t *testing.T, base, clientID, clientSecret, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"password"},
		"username":      {username},
		"password":      {password},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid profile email"},
	}
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(base, "/")+"/api/login/oauth/access_token",
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		t.Fatalf("构造密码授权请求失败：%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("密码授权请求失败：%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("密码授权返回 HTTP %d：%s", resp.StatusCode, string(body))
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析密码授权响应失败：%v（body=%s）", err, string(body))
	}
	if out.IDToken == "" {
		t.Fatalf("响应里没有 id_token：%s", string(body))
	}
	return out.IDToken
}
