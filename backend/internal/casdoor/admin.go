// Package casdoor 是本组件与 Casdoor 官方镜像之间唯二的两条接触面：
// ① 管理 API（会话 cookie 认证，供首次初始化建组织/应用/webhook 用，
// admin.go）；② OIDC 发现 + JWKS 验签（验浏览器换来的身份 token，
// discovery.go/idtoken.go）。除此之外本组件不碰 Casdoor 的任何东西——
// 认证流、用户资料、密码全部在 Casdoor 自己的界面里完成（设计计划
// §1、§6.1）。
package casdoor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// builtInOrg/builtInApp 是 Casdoor 官方镜像**自带**的初始组织与应用
// （不是本组件选的名字）——任何一个全新的 Casdoor 实例开箱都有这两个
// 对象，内置管理员账号挂在这个组织下（真机核对过：docker 起一个全新
// be-casdoor 容器，未做任何配置就能用 admin/123 登录 built-in/app-built-in）。
// 管理 API 走会话 cookie 认证，登录用的正是这一对，与本组件之后要建的
// casdoorOrgName/casdoorAppName（给真实用户登录用）完全是两码事。
const (
	builtInOrg = "built-in"
	builtInApp = "app-built-in"
)

// AdminClient 是一条已登录的 Casdoor 管理 API 会话。⚠️ 只应在
// backend/module（Start()）里构造和使用——它对应的是"这个组件自己要
// 对 Casdoor 做什么"，不是用户请求路径，不受 SystemClient 那一整套
// 顾虑约束（那是给组件间 gRPC 用的，这里连协议都不是 gRPC）。
type AdminClient struct {
	baseURL  string
	username string // 也是 Casdoor 里 organization/application/webhook 等对象的 owner 字段
	http     *http.Client
}

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// NewAdminClient 登录一次，返回一条带会话 cookie 的客户端。登录失败
// （Casdoor 暂时不可达、密码错误）返回 error——调用方（bootstrap 包）
// 决定这是不是要阻断这一轮启动的自举尝试，本函数本身不重试。
func NewAdminClient(ctx context.Context, baseURL, username, password string) (*AdminClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("建 cookie jar 失败: %w", err)
	}
	c := &AdminClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		http:     &http.Client{Jar: jar, Timeout: 15 * time.Second},
	}
	if _, err := c.post(ctx, "/api/login", map[string]any{
		"application":  builtInApp,
		"organization": builtInOrg,
		"username":     username,
		"password":     password,
		"autoSignin":   true,
		"type":         "login",
	}); err != nil {
		return nil, fmt.Errorf("登录 Casdoor 管理 API 失败: %w", err)
	}
	return c, nil
}

// Username 是这条会话对应的 Casdoor 用户名——同时也是本组件创建的组织/
// 应用/webhook 等对象的 owner 字段（Casdoor 的对象模型：owner 就是创建
// 它的那个已登录用户，真机核对过）。
func (c *AdminClient) Username() string { return c.username }

func (c *AdminClient) post(ctx context.Context, path string, body any) (json.RawMessage, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *AdminClient) get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *AdminClient) do(req *http.Request) (json.RawMessage, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Casdoor 失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取 Casdoor 响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Casdoor 返回 HTTP %d: %s", resp.StatusCode, string(body))
	}
	var env apiResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("解析 Casdoor 响应失败: %w（body=%s）", err, string(body))
	}
	if env.Status != "ok" {
		return nil, fmt.Errorf("Casdoor 返回错误: %s", env.Msg)
	}
	return env.Data, nil
}

// ── 组织 ─────────────────────────────────────────────────────────────

// OrganizationExists 查一个组织是不是已经存在——Casdoor 对不存在的对象
// 返回 status:"ok" + data:null（不是 404，真机核对过），"存在" 的判据是
// data 不为 JSON null。
func (c *AdminClient) OrganizationExists(ctx context.Context, name string) (bool, error) {
	data, err := c.get(ctx, "/api/get-organization", url.Values{"id": {c.username + "/" + name}})
	if err != nil {
		return false, err
	}
	return !isJSONNull(data), nil
}

// CreateOrganization 建一个新组织——本组件用它承载真实用户（不用
// built-in，那是 Casdoor 自己的内置管理组织，见 AGENTS.md 的真机核对
// 记录："往 built-in 建普通用户默认被拒"）。
func (c *AdminClient) CreateOrganization(ctx context.Context, name, displayName string) error {
	_, err := c.post(ctx, "/api/add-organization", map[string]any{
		"owner":              c.username,
		"name":               name,
		"displayName":        displayName,
		"websiteUrl":         "https://example.com",
		"passwordType":       "bcrypt",
		"passwordOptions":    []string{"AtLeast6"},
		"countryCodes":       []string{"CN", "US"},
		"tags":               []string{},
		"languages":          []string{"en", "zh"},
		"initScore":          0,
		"enableSoftDeletion": false,
		"isProfilePublic":    false,
		"useEmailAsUsername": false,
	})
	return err
}

// ── 用户（只读，回源查询，不落本地表）──────────────────────────────────

// User 是 gRPC BatchGetUsers 关心的字段子集——Casdoor 的 User 对象有
// 一百多个字段（社交登录各家一列），这里只取跟"给用户一个可展示身份"
// 有关的那几个。
type User struct {
	ID          string `json:"id"` // 全系统身份的 sub，见 idtoken.go 顶部注释
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Dingtalk    string `json:"dingtalk"` // 阶段三 Task 9 起可能非空，见设计计划 §9 第 3 条
}

// GetUserBySub 按 sub（Casdoor 内部 UUID）查用户——真机核对过
// `GET /api/get-user?userId=<uuid>` 直接按这个字段查，不需要先知道
// owner/name（那对参数走的是另一种 id=owner/name 的查法，两者是 Casdoor
// 同一个接口支持的两种输入形式）。查不到返回 (nil, nil)，同其余
// XxxExists/GetXxx 方法的既有判据。
func (c *AdminClient) GetUserBySub(ctx context.Context, sub string) (*User, error) {
	data, err := c.get(ctx, "/api/get-user", url.Values{"userId": {sub}})
	if err != nil {
		return nil, err
	}
	if isJSONNull(data) {
		return nil, nil
	}
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, fmt.Errorf("解析 user 失败: %w", err)
	}
	return &u, nil
}

// ── 应用 ─────────────────────────────────────────────────────────────

type Application struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// GetApplication 查一个应用；不存在时返回 (nil, nil)——不是错误，调用方
// （bootstrap 包）据此决定要不要走 CreateApplication。
func (c *AdminClient) GetApplication(ctx context.Context, name string) (*Application, error) {
	data, err := c.get(ctx, "/api/get-application", url.Values{"id": {c.username + "/" + name}})
	if err != nil {
		return nil, err
	}
	if isJSONNull(data) {
		return nil, nil
	}
	var app Application
	if err := json.Unmarshal(data, &app); err != nil {
		return nil, fmt.Errorf("解析 application 失败: %w", err)
	}
	return &app, nil
}

// CreateApplication 建一个 OIDC 应用，登录页/客户端配置都挂在它上面
// （设计计划 §1.1：账密 + 微信 + QQ + Google 四种方式全在 Casdoor 侧对
// 这个应用配置，本组件零代码）。grantTypes 里的
// urn:ietf:params:oauth:grant-type:token-exchange 目前用不上（本组件走
// 的是"拿身份 token 自己验签"而不是标准 OIDC token exchange 端点），但
// 保留它不影响功能，方便以后有需要时不用回来改应用配置。
func (c *AdminClient) CreateApplication(ctx context.Context, name, organization string, redirectURIs []string) error {
	_, err := c.post(ctx, "/api/add-application", map[string]any{
		"owner":                c.username,
		"name":                 name,
		"displayName":          name,
		"organization":         organization,
		"cert":                 "cert-built-in",
		"enablePassword":       true,
		"enableSignUp":         true, // 设计计划 §1.1："自助注册开放"
		"redirectUris":         redirectURIs,
		"grantTypes":           []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"tokenFormat":          "JWT",
		"expireInHours":        24,
		"refreshExpireInHours": 168,
	})
	return err
}

// DeleteApplication 删一个应用——生产代码从不调用这个方法（自举只建
// 不删），存在的唯一理由是让别的包（bootstrap 等）的集成测试能清理自己
// 建的临时对象，不污染共享的开发环境 Casdoor 实例。
func (c *AdminClient) DeleteApplication(ctx context.Context, name, organization string) error {
	_, err := c.post(ctx, "/api/delete-application", map[string]any{
		"owner": c.username, "name": name, "organization": organization,
	})
	return err
}

// DeleteOrganization 同上，删一个组织。
func (c *AdminClient) DeleteOrganization(ctx context.Context, name string) error {
	_, err := c.post(ctx, "/api/delete-organization", map[string]any{
		"owner": c.username, "name": name,
	})
	return err
}

// ── Webhook ──────────────────────────────────────────────────────────

// WebhookExists 查一个 webhook 是不是已经存在（同 OrganizationExists 的
// data:null 判据）。
func (c *AdminClient) WebhookExists(ctx context.Context, name string) (bool, error) {
	data, err := c.get(ctx, "/api/get-webhook", url.Values{"id": {c.username + "/" + name}})
	if err != nil {
		return false, err
	}
	return !isJSONNull(data), nil
}

// CreateWebhook 建一个用户增删改事件的回调，用**自定义 header** 携带
// 共享密钥——真机核对过 Casdoor 的 Webhook 对象确实支持自定义 header
// （见 AGENTS.md/实测踩坑记录），这是它没有内置签名机制时唯一能用的
// 认证方式。callbackURL 由调用方（bootstrap 包）算好传入——Casdoor 是
// 带外容器，回调地址必须是"从 Casdoor 容器视角能访问到本组件"的地址
// （桥接网关 IP + 宿主机映射端口，不是 host.docker.internal，两者的
// 网络方向相反，见 AGENTS.md）。
func (c *AdminClient) CreateWebhook(ctx context.Context, name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue string) error {
	_, err := c.post(ctx, "/api/add-webhook", map[string]any{
		"owner":          c.username,
		"name":           name,
		"organization":   organization,
		"url":            callbackURL,
		"method":         "POST",
		"contentType":    "application/json",
		"events":         []string{"signup", "login", "update-user", "add-user", "delete-user"},
		"isUserExtended": false,
		"singleOrgOnly":  false,
		"isEnabled":      true,
		"headers": []map[string]string{
			{"name": sharedSecretHeaderName, "value": sharedSecretValue},
		},
	})
	return err
}

// DeleteWebhook 同 DeleteApplication/DeleteOrganization：生产代码不用，
// 只给测试清理用。
func (c *AdminClient) DeleteWebhook(ctx context.Context, name, organization string) error {
	_, err := c.post(ctx, "/api/delete-webhook", map[string]any{
		"owner": c.username, "name": name, "organization": organization,
	})
	return err
}

func isJSONNull(data json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(data))
	return trimmed == "" || trimmed == "null"
}
