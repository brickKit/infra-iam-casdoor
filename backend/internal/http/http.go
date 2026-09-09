// Package http 是 infra-iam-casdoor 的 REST 面——见 contracts/
// iam.openapi.yaml 与 assembly.yaml 的 edge_routes 注释：路径不走
// /{domain}/{name}/** 前缀（族级、全平台通用），/.well-known/jwks.json
// 与 /api/iam/webhooks/casdoor 不出现在 edge_routes 里（内网/带外直连）。
package http

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	besdk "github.com/brickKit/be-sdk-go"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/service"
)

// RegisterRoutes 挂载全部路由。⚠️ 本组件没有一条真实业务权限键
// （assembly.yaml 的 permissions: []）——REST 面全部是 besdk.Public/
// besdk.Authenticated，这是刻意的：本组件自己就是"还没有身份"与"有
// 身份"之间的那道门，门本身不需要门禁（component.yaml、assembly.yaml
// 的注释）。
func RegisterRoutes(eng *gin.Engine, svc *service.Service) {
	besdk.POST(eng, "/api/iam/token", besdk.Public, exchangeTokenHandler(svc))
	besdk.POST(eng, "/api/iam/token/refresh", besdk.Public, refreshTokenHandler(svc))
	besdk.POST(eng, "/api/iam/logout", besdk.Authenticated, logoutHandler(svc))
	besdk.GET(eng, "/.well-known/jwks.json", besdk.Public, jwksHandler(svc))
	besdk.GET(eng, "/api/tenant/features", besdk.Public, tenantFeaturesHandler(svc))

	// webhook 路由的"校验"不是权限键——besdk.Public 只是"不走进程内
	// bundle map 查找"，真正的校验（比对共享密钥 header）在
	// casdoorWebhookHandler 内部做。⚠️ 必须仍然经 besdk.POST 注册
	// （不许裸用 eng.POST，导读第 23 条）——这里不是"权限键场景不适用
	// 就绕过 SDK 封装"，而是"这条路由的校验方式不是权限键，但依然要
	// 走统一注册入口"。
	besdk.POST(eng, "/api/iam/webhooks/casdoor", besdk.Public, casdoorWebhookHandler(svc))
}

type exchangeTokenRequest struct {
	CasdoorIDToken string `json:"casdoor_id_token" binding:"required"`
}

type tokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func toResponse(p *service.TokenPair) tokenPairResponse {
	return tokenPairResponse{
		AccessToken: p.AccessToken, RefreshToken: p.RefreshToken,
		TokenType: "Bearer", ExpiresIn: p.ExpiresIn,
	}
}

func exchangeTokenHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req exchangeTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		pair, err := svc.ExchangeToken(c.Request.Context(), req.CasdoorIDToken)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.JSON(http.StatusOK, toResponse(pair))
	}
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func refreshTokenHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		pair, err := svc.RefreshToken(c.Request.Context(), req.RefreshToken)
		if err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.JSON(http.StatusOK, toResponse(pair))
	}
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// logoutHandler：sub 从已验签的应用 token 取（besdk.Authenticated 保证
// ctx 里一定有 Claims），只能作废"自己"的 refresh token（同
// service.Logout 的注释）。
func logoutHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req logoutRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		callerSub := besdk.ScopeOf(c.Request.Context()).Owner
		if err := svc.Logout(c.Request.Context(), req.RefreshToken, callerSub); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		c.Status(http.StatusOK)
	}
}

func jwksHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"keys": svc.JWKS()})
	}
}

func tenantFeaturesHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		enabled := svc.EnabledComponents()
		if enabled == nil {
			enabled = []string{}
		}
		c.JSON(http.StatusOK, gin.H{"enabled_components": enabled})
	}
}

// casdoorWebhookHandler 先校验共享密钥 header（openapi 契约、AGENTS.md
// 明确禁令：漏了这条校验等于开了一个任何人都能伪造用户事件的口子），
// 再登记+宽容解析投递。header 名是配置项（固定叫 X-Shared-Secret——见
// openapi 契约的 securitySchemes，CreateWebhook 建 webhook 时配的是
// 同一个名字，两边必须一致）。
func casdoorWebhookHandler(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := svc.WebhookSharedSecretHeader()
		if !svc.WebhookSharedSecretValid(c.GetHeader(header)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "共享密钥校验失败"})
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "读取请求体失败"})
			return
		}
		if err := svc.HandleWebhookDelivery(c.Request.Context(), dedupKeyFor(body), body); err != nil {
			_ = c.Error(service.ToStatus(err))
			return
		}
		// ⚠️ 200 不代表事件已经处理完——Outbox 异步发布（openapi 契约的
		// 明文说明）。这里只承诺"收到了、已经安全落库去重"。
		c.Status(http.StatusOK)
	}
}

// dedupKeyFor 退化成内容哈希——Casdoor 有没有稳定的投递 ID 未能在本次
// 调研里确认（设计计划 §9 第 2 条、AGENTS.md 已知缺口），内容哈希是
// 唯一不依赖那个假设的去重键：同一条投递内容重投两次会算出同一个哈希，
// 天然去重；代价是"同一个用户在同一秒发生了两次内容完全相同的变更"这
// 种极小概率场景会被误判成重投而漏发一条——可接受，见调用处注释。
func dedupKeyFor(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
