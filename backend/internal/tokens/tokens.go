// Package tokens 签发与验证本组件自己的两种 JWT：应用 token（带
// roles[]/dept_path/org_id，供其余组件用各自的 iamJwksUrl 验签）与
// refresh token（只在本组件内部消费，不对外暴露验签面）。
//
// ⚠️ 这两种 token 用同一把私钥签，但绝不能互相冒充——refresh token 带一个
// 自定义 claim "typ": "refresh"，VerifyRefreshToken 显式核对这个字段，
// 防止有人拿一个（可能通过某种途径拿到的）应用 token 冒充 refresh token
// 去调 /api/iam/token/refresh（两者字段高度相似：都有 sub、都是我们
// 自己签的，唯一能分辨的只有这个显式类型标记）。
package tokens

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims 是应用 token 携带的身份信息，字段与 be-sdk-go 的 jwt.go
// （jwtClaims）逐字对应——本组件是全系统唯一的签发方，字段名必须与
// 消费方解析用的完全一致，任何一个不对都会在验签阶段"缺少 xxx"或
// 悄悄读到空值。
type Claims struct {
	Sub      string
	Roles    []string
	DeptPath string
	OrgID    string
}

// appClaims 是签发应用 token 时用的具体 JWT 结构。
type appClaims struct {
	jwt.RegisteredClaims
	Roles    []string `json:"roles"`
	DeptPath string   `json:"dept_path"`
	OrgID    string   `json:"org_id"`
}

// refreshClaims 是签发/验证 refresh token 时用的具体 JWT 结构。
type refreshClaims struct {
	jwt.RegisteredClaims
	Typ string `json:"typ"` // 恒为 "refresh"，见包注释
}

const refreshTokenTyp = "refresh"

// Issuer 持有当前签名私钥，签发应用 token 与 refresh token。
type Issuer struct {
	signingKey *rsa.PrivateKey
	kid        string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewIssuer(signingKey *rsa.PrivateKey, kid string, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{signingKey: signingKey, kid: kid, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// SignAccessToken 签一个应用 token。返回 token 字符串与它的 TTL 秒数
// （TokenPair.expires_in 直接用这个值，不需要调用方自己重算一遍）。
func (iss *Issuer) SignAccessToken(c Claims) (string, int, error) {
	now := time.Now()
	claims := appClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   c.Sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(iss.accessTTL)),
		},
		Roles:    c.Roles,
		DeptPath: c.DeptPath,
		OrgID:    c.OrgID,
	}
	token, err := iss.sign(claims)
	if err != nil {
		return "", 0, err
	}
	return token, int(iss.accessTTL.Seconds()), nil
}

// SignRefreshToken 签一个新的 refresh token，jti 内部随机生成（调用方不
// 需要也不应该自己起 jti——重复的 jti 会撞 refresh_tokens 的主键）。
// 返回 token 字符串、它的 jti（登记进 repo.IssueRefreshToken/
// RotateRefreshToken 用）与过期时间。
func (iss *Issuer) SignRefreshToken(sub string) (token, jti string, expiresAt time.Time, err error) {
	jti = uuid.NewString()
	now := time.Now()
	expiresAt = now.Add(iss.refreshTTL)
	claims := refreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Typ: refreshTokenTyp,
	}
	token, err = iss.sign(claims)
	return token, jti, expiresAt, err
}

func (iss *Issuer) sign(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = iss.kid
	return t.SignedString(iss.signingKey)
}

// Verifier 验证本组件自己签发的 refresh token——只在 /api/iam/token/
// refresh 与 /api/iam/logout 两处用，验的是内部凭据，不走 JWKS 端点（那
// 是给其余组件验**应用 token**用的，见 http 包的 jwks 端点）。
//
// ⚠️ keys 用 kid 区分现在这把签名钥匙与"上一把"（轮换期间旧 refresh
// token 仍要能验，同应用 token 的双挂逻辑，设计计划 §3.3）。
type Verifier struct {
	keys map[string]*rsa.PublicKey
}

func NewVerifier(current *rsa.PublicKey, currentKid string, previous *rsa.PublicKey, previousKid string) *Verifier {
	keys := map[string]*rsa.PublicKey{currentKid: current}
	if previous != nil && previousKid != "" {
		keys[previousKid] = previous
	}
	return &Verifier{keys: keys}
}

// VerifyRefreshToken 验签 + 解析，返回 sub 与 jti。exp 由 golang-jwt 的
// 默认校验器自动检查（claims 里带了 ExpiresAt 就会被验），过期的 token
// 在这一步就会报错，不需要 repo 层重复判断——repo 层的 expires_at 检查
// 是数据库侧的独立冗余（防止有人拿着一个签名没过期但数据库记录已经被
// 提前撤销的 token），两处检查方向不同，都保留。
func (v *Verifier) VerifyRefreshToken(tokenString string) (sub, jti string, err error) {
	var claims refreshClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, v.keyfunc,
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return "", "", fmt.Errorf("验签失败: %w", err)
	}
	if !token.Valid {
		return "", "", fmt.Errorf("token 无效")
	}
	if claims.Typ != refreshTokenTyp {
		return "", "", fmt.Errorf("不是 refresh token（typ=%q）", claims.Typ)
	}
	if claims.Subject == "" || claims.ID == "" {
		return "", "", fmt.Errorf("token 缺少 sub 或 jti")
	}
	return claims.Subject, claims.ID, nil
}

func (v *Verifier) keyfunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	pub, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("未知的 kid：%q", kid)
	}
	return pub, nil
}
