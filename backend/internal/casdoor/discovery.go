package casdoor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// oidcConfig 只取本组件真正用得上的两个字段——完整的发现文档还有一堆
// 我们不消费的端点（authorization_endpoint 等，那些是浏览器直连 Casdoor
// 走标准 OIDC 流用的，本组件不代理），没必要照单全收。
type oidcConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// DiscoverOIDC 走标准 OIDC Discovery（RFC 8414）取 issuer 与 jwks_uri。
//
// ⚠️ jwks_uri **不能**硬编码成 "<casdoorBaseUrl>/.well-known/jwks.json"
// ——真机核对过 Casdoor 实际发布的路径是 "/.well-known/jwks"（没有
// .json 后缀，与本组件自己的 JWKS 端点路径恰好不同，容易想当然抄错）。
// 走发现文档而不是硬编码，这个差异从一开始就不构成隐患。
func DiscoverOIDC(ctx context.Context, baseURL string) (issuer, jwksURI string, err error) {
	url := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("请求 OIDC 发现文档失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("读取 OIDC 发现文档失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("OIDC 发现文档返回 HTTP %d: %s", resp.StatusCode, string(body))
	}
	var cfg oidcConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", "", fmt.Errorf("解析 OIDC 发现文档失败: %w", err)
	}
	if cfg.Issuer == "" || cfg.JWKSURI == "" {
		return "", "", fmt.Errorf("OIDC 发现文档缺少 issuer 或 jwks_uri")
	}
	return cfg.Issuer, cfg.JWKSURI, nil
}
