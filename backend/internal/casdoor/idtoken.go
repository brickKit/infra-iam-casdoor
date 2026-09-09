package casdoor

import (
	"context"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// IDTokenVerifier 验证浏览器换来的 Casdoor 身份 token（POST
// /api/iam/token 的入参）——只信 RS256、只信发现文档给出的 issuer，用
// keyfunc 挂 Casdoor 自己的 JWKS（同 be-sdk-go 的 jwtVerifier 用一样的
// 库，两处的"信任第三方签的 JWT"是同一类问题，没必要用两套实现）。
type IDTokenVerifier struct {
	kf     keyfunc.Keyfunc
	issuer string
}

// idTokenClaims 只取本组件真正要用的字段：sub 是全系统身份的最终来源
// （真机核对过——Casdoor 的 id_token/access_token 的 sub 是它内部的
// 用户 UUID，不是用户名，见 docs/dev/实测踩坑记录.md 或 AGENTS.md 的
// 记录）。email/displayName/phone 都用不上：token 交换这一步只需要
// sub 去调 ResolveClaims，用户资料由 webhook 事件（infra.iam.user.
// created/updated.v1）携带给真正关心它们的下游。
type idTokenClaims struct {
	jwt.RegisteredClaims
}

// NewIDTokenVerifier 用发现文档给出的 jwksURI/issuer 构造验证器。ctx 用于
// 结束 keyfunc 内部的后台刷新协程（同 be-sdk-go newJWTVerifier 的约定，
// 传 RunStandalone 收到 SIGTERM 时会取消的那个 ctx）。
func NewIDTokenVerifier(ctx context.Context, jwksURI, issuer string) (*IDTokenVerifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURI})
	if err != nil {
		return nil, fmt.Errorf("初始化 Casdoor JWKS 客户端失败: %w", err)
	}
	return &IDTokenVerifier{kf: kf, issuer: issuer}, nil
}

// Verify 验签 + 校验 issuer，返回 sub。⚠️ 只认 RS256——Casdoor 的发现
// 文档列出的 id_token_signing_alg_values_supported 里还有 ES256 等
// 曲线算法，本组件不打算支持它们（RS256 是默认且最广泛支持的一种，
// 换算法属于 Casdoor 侧的配置变更，届时再扩），显式白名单防算法混淆。
func (v *IDTokenVerifier) Verify(tokenString string) (sub string, err error) {
	var claims idTokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, v.kf.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer))
	if err != nil {
		return "", fmt.Errorf("验签失败: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("token 无效")
	}
	s, err := claims.GetSubject()
	if err != nil || s == "" {
		return "", fmt.Errorf("token 缺少 sub")
	}
	return s, nil
}
