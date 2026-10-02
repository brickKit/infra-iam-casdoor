// Package casdoor 是本组件与 Casdoor 官方镜像之间唯二的两条接触面：
// ① 管理 API（会话 cookie 认证，供首次初始化建组织/应用/webhook 用，
// admin.go）；② OIDC 发现 + JWKS 验签（验浏览器换来的身份 token，
// discovery.go/idtoken.go）。除此之外本组件不碰 Casdoor 的任何东西——
// 认证流、用户资料、密码全部在 Casdoor 自己的界面里完成。
package casdoor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
// CASDOOR_ORG_NAME / CASDOOR_APP_NAME（给真实用户登录用）完全是两码事。
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
	password string // 会话过期时重新登录用；只在内存里，不进日志
	http     *http.Client
}

// requestTimeout 是每一次 Casdoor 管理 API 调用（含重新登录）的上限：Casdoor 卡住
// 时，调用方（启动对账、gRPC BatchGetUsers）不至于一直挂着。
const requestTimeout = 15 * time.Second

// sessionExpiredMsg 是 Casdoor 对"没有有效管理会话"的回答（HTTP 200 +
// status:error，真机核对过）。会话 cookie 会过期，遇到它就重新登录一次再重试。
const sessionExpiredMsg = "Please login first"

// errSessionExpired 在 do 里标出"会话过期"这一种错误，供 call 决定要不要重登。
var errSessionExpired = errors.New("Casdoor 管理会话已过期")

type apiResponse struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// NewAdminClient 登录一次，返回一条带会话 cookie 的客户端。登录失败
// （Casdoor 暂时不可达、密码错误）返回 error——调用方（module.Start）决定这一轮
// 启动要不要跳过自举，本函数本身不重试。会话之后过期时，每次调用自己重新登录。
func NewAdminClient(ctx context.Context, baseURL, username, password string) (*AdminClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("建 cookie jar 失败: %w", err)
	}
	c := &AdminClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		http:     &http.Client{Jar: jar, Timeout: requestTimeout},
	}
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *AdminClient) login(ctx context.Context) error {
	_, err := c.once(ctx, http.MethodPost, "/api/login", nil, map[string]any{
		"application":  builtInApp,
		"organization": builtInOrg,
		"username":     c.username,
		"password":     c.password,
		"autoSignin":   true,
		"type":         "login",
	})
	if err != nil {
		return fmt.Errorf("登录 Casdoor 管理 API 失败: %w", err)
	}
	return nil
}

// Username 是这条会话对应的 Casdoor 用户名——同时也是本组件创建的组织/
// 应用/webhook 等对象的 owner 字段（Casdoor 的对象模型：owner 就是创建
// 它的那个已登录用户，真机核对过）。
func (c *AdminClient) Username() string { return c.username }

func (c *AdminClient) post(ctx context.Context, path string, body any) (json.RawMessage, error) {
	return c.call(ctx, http.MethodPost, path, nil, body)
}

func (c *AdminClient) get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	return c.call(ctx, http.MethodGet, path, query, nil)
}

// call 发一次请求；Casdoor 回"会话过期"时重新登录一次、重试一次。重试仍失败就
// 原样返回错误，不再循环。
func (c *AdminClient) call(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	data, err := c.once(ctx, method, path, query, body)
	if !errors.Is(err, errSessionExpired) {
		return data, err
	}
	if lerr := c.login(ctx); lerr != nil {
		return nil, lerr
	}
	return c.once(ctx, method, path, query, body)
}

func (c *AdminClient) once(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求体失败: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.do(req)
}

func (c *AdminClient) do(req *http.Request) (json.RawMessage, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &unreachableError{err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &unreachableError{fmt.Errorf("读取响应失败: %w", err)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &unreachableError{fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	var env apiResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("解析 Casdoor 响应失败: %w", err)
	}
	if env.Status != "ok" {
		if env.Msg == sessionExpiredMsg {
			return nil, errSessionExpired
		}
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
// built-in，那是 Casdoor 自己的内置管理组织：真机核对过，往 built-in 建普通
// 用户默认被拒）。
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
	Dingtalk    string `json:"dingtalk"` // 用户在 Casdoor 绑定了钉钉才有值，否则为空
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
// （账密、微信、QQ、Google 等登录方式全在 Casdoor 侧对这个应用配置，
// 本组件零代码）。grantTypes 里的
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
		"enableSignUp":         true, // 自助注册开放
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

// Webhook 是对账要比较的字段子集。
type Webhook struct {
	URL       string          `json:"url"`
	IsEnabled bool            `json:"isEnabled"`
	Headers   []WebhookHeader `json:"headers"`
}

// WebhookHeader 是 Casdoor webhook 的自定义 header。
type WebhookHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HeaderValue 返回名为 name 的 header 的值，没有时返回空串。
func (w *Webhook) HeaderValue(name string) string {
	for _, h := range w.Headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

// GetWebhook 查一个 webhook；不存在时返回 (nil, nil)。⚠️ 返回值里有共享密钥
// header 的明文，只用来比对，不许打进日志。
func (c *AdminClient) GetWebhook(ctx context.Context, name string) (*Webhook, error) {
	data, err := c.get(ctx, "/api/get-webhook", url.Values{"id": {c.username + "/" + name}})
	if err != nil {
		return nil, err
	}
	if isJSONNull(data) {
		return nil, nil
	}
	var w Webhook
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("解析 webhook 失败: %w", err)
	}
	return &w, nil
}

// CreateWebhook 建一个用户增删改事件的回调，用**自定义 header** 携带共享
// 密钥——Casdoor 的 webhook 没有内置签名，自定义 header 是唯一能用的认证方式。
// callbackURL 由调用方（bootstrap 包）传入：Casdoor 不在本组件所在的 Docker
// 网络里，回调地址必须是"从 Casdoor 那一侧能访问到本组件对外暴露的端口"的地址
// （部署条目 expose: true，Casdoor 经宿主机访问），不能自动推导。
func (c *AdminClient) CreateWebhook(ctx context.Context, name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue string) error {
	_, err := c.post(ctx, "/api/add-webhook",
		c.webhookBody(name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue))
	return err
}

// UpdateWebhook 把已有 webhook 整个改写成当前配置（回调地址、共享密钥 header、
// 启用状态、事件集合）。Casdoor 的 update 接口按 id 定位、用请求体整体覆盖。
func (c *AdminClient) UpdateWebhook(ctx context.Context, name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue string) error {
	_, err := c.post(ctx, "/api/update-webhook?id="+url.QueryEscape(c.username+"/"+name),
		c.webhookBody(name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue))
	return err
}

func (c *AdminClient) webhookBody(name, organization, callbackURL, sharedSecretHeaderName, sharedSecretValue string) map[string]any {
	return map[string]any{
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
	}
}

// DeleteWebhook 同 DeleteApplication/DeleteOrganization：生产代码不用，
// 只给测试清理用。
func (c *AdminClient) DeleteWebhook(ctx context.Context, name, organization string) error {
	_, err := c.post(ctx, "/api/delete-webhook", map[string]any{
		"owner": c.username, "name": name, "organization": organization,
	})
	return err
}

// unreachableError 标出"没能从 Casdoor 拿到一个正常的回答"：连不上、超时、
// HTTP 状态码不是 200。与 Casdoor 明确回 status:error（拒绝）区分开。
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return "Casdoor 不可达: " + e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// IsUnreachable 判断 err 是不是"Casdoor 暂时不在"（调用方据此打 Warn 并稍后重试），
// 而不是 Casdoor 明确拒绝（口令错、对象非法——要人去处理）。
func IsUnreachable(err error) bool {
	var u *unreachableError
	return errors.As(err, &u)
}

func isJSONNull(data json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(data))
	return trimmed == "" || trimmed == "null"
}
