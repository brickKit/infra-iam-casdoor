package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/keys"
)

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试密钥失败：%v", err)
	}
	return key, keys.Thumbprint(&key.PublicKey)
}

func TestSignAccessToken_字段与claims一一对应(t *testing.T) {
	priv, kid := testKey(t)
	iss := NewIssuer(priv, kid, 10*time.Minute, 7*24*time.Hour)

	tok, expiresIn, err := iss.SignAccessToken(Claims{
		Sub: "u-1", Roles: []string{"sales_rep", "u:u-1"}, DeptPath: "/1/12/", OrgID: "1",
	})
	if err != nil {
		t.Fatalf("签发应用 token 失败：%v", err)
	}
	if expiresIn != 600 {
		t.Fatalf("expires_in 应该是 600，实际 %d", expiresIn)
	}
	if !strings.HasPrefix(tok, "eyJ") { // JWT header 固定以此开头（base64url("{"))
		t.Fatalf("签出来的不像一个 JWT：%s", tok)
	}
}

// TestVerifyRefreshToken_签发后能验签通过 是最基本的往返断言：签出来的
// refresh token 必须能用同一把（公钥对应的）Verifier 验回去，且 sub/jti
// 与签发时一致。
func TestVerifyRefreshToken_签发后能验签通过(t *testing.T) {
	priv, kid := testKey(t)
	iss := NewIssuer(priv, kid, 10*time.Minute, 7*24*time.Hour)
	v := NewVerifier(&priv.PublicKey, kid, nil, "")

	tok, jti, expiresAt, err := iss.SignRefreshToken("u-1")
	if err != nil {
		t.Fatalf("签发 refresh token 失败：%v", err)
	}
	if time.Until(expiresAt) <= 0 {
		t.Fatal("expiresAt 应该在未来")
	}

	gotSub, gotJTI, err := v.VerifyRefreshToken(tok)
	if err != nil {
		t.Fatalf("验签失败：%v", err)
	}
	if gotSub != "u-1" || gotJTI != jti {
		t.Fatalf("往返不一致：got (%q, %q), want (%q, %q)", gotSub, gotJTI, "u-1", jti)
	}
}

// TestVerifyRefreshToken_不接受应用token冒充 是包顶部注释承诺的那条断言：
// 用 SignAccessToken 签出来的 token（没有 typ:"refresh"）必须被
// VerifyRefreshToken 拒绝，即使签名本身完全合法。
//
// ⚠️ 这条测试第一版直接拿 SignAccessToken 的产出喂给 VerifyRefreshToken，
// 移掉 typ 校验那一行后测试竟然照样通过——排查后发现是假阳性：应用
// token 根本没设 jti（RegisteredClaims.ID），所以即使去掉了 typ 检查，
// 后面那行"claims.ID == \"\" 就报错"的检查照样会把它拦下来，测试测的
// 其实是另一条防线，不是 typ 检查本身。这里改成手工构造一个"sub 和 jti
// 都齐全、只是 typ 不对"的伪造 token，才能真正只隔离出 typ 这一个维度
// ——同 be-sdk-ts 的 A8 踩坑同一个教训：故意破坏被测的那一行代码，
// 确认测试真的会红，而不是想当然地相信断言覆盖了它。
func TestVerifyRefreshToken_不接受应用token冒充(t *testing.T) {
	priv, kid := testKey(t)
	v := NewVerifier(&priv.PublicKey, kid, nil, "")

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u-1",
			ID:        "some-jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Typ: "access", // ⚠️ 唯一被测试的差异点：sub/jti 都合法，只有 typ 不对
	})
	forged.Header["kid"] = kid
	forgedTok, err := forged.SignedString(priv)
	if err != nil {
		t.Fatalf("构造伪造 token 失败：%v", err)
	}

	if _, _, err := v.VerifyRefreshToken(forgedTok); err == nil {
		t.Fatal("typ 不是 refresh 的 token 不该被接受，即使 sub/jti 都合法")
	}
}

// TestVerifyRefreshToken_过期拒绝 用一个 TTL 为负数的 issuer 签出一个
// "签发时就已经过期"的 token——不用真的等待，直接构造过期状态。
func TestVerifyRefreshToken_过期拒绝(t *testing.T) {
	priv, kid := testKey(t)
	iss := NewIssuer(priv, kid, 10*time.Minute, -1*time.Second)
	v := NewVerifier(&priv.PublicKey, kid, nil, "")

	tok, _, _, err := iss.SignRefreshToken("u-1")
	if err != nil {
		t.Fatalf("签发失败：%v", err)
	}
	if _, _, err := v.VerifyRefreshToken(tok); err == nil {
		t.Fatal("已过期的 refresh token 应该验签失败")
	}
}

// TestVerifyRefreshToken_签名篡改拒绝：翻转最后一个字符可能因为 RS256 签名字节长度对
// base64url 编码分组的巧合而解码不出差异，这里翻转中间字符，确定性地
// 破坏签名。
func TestVerifyRefreshToken_签名篡改拒绝(t *testing.T) {
	priv, kid := testKey(t)
	iss := NewIssuer(priv, kid, 10*time.Minute, 7*24*time.Hour)
	v := NewVerifier(&priv.PublicKey, kid, nil, "")

	tok, _, _, err := iss.SignRefreshToken("u-1")
	if err != nil {
		t.Fatalf("签发失败：%v", err)
	}
	mid := len(tok) / 2
	flipped := byte('A')
	if tok[mid] == 'A' {
		flipped = 'B'
	}
	tampered := tok[:mid] + string(flipped) + tok[mid+1:]

	if _, _, err := v.VerifyRefreshToken(tampered); err == nil {
		t.Fatal("篡改签名后的 token 应该验签失败")
	}
}

// TestVerifyRefreshToken_轮换窗口内旧公钥仍能验签 是密钥轮换双挂逻辑
// 的断言：previous 公钥对应的 token 在 Verifier 同时持有新旧两把钥匙时
// 仍然验签通过。
func TestVerifyRefreshToken_轮换窗口内旧公钥仍能验签(t *testing.T) {
	oldPriv, oldKid := testKey(t)
	newPriv, newKid := testKey(t)

	oldIssuer := NewIssuer(oldPriv, oldKid, 10*time.Minute, 7*24*time.Hour)
	tok, _, _, err := oldIssuer.SignRefreshToken("u-1")
	if err != nil {
		t.Fatalf("用旧钥匙签发失败：%v", err)
	}

	// 轮换后的 Verifier：current 是新钥匙，previous 是旧钥匙。
	v := NewVerifier(&newPriv.PublicKey, newKid, &oldPriv.PublicKey, oldKid)
	if _, _, err := v.VerifyRefreshToken(tok); err != nil {
		t.Fatalf("轮换窗口内旧钥匙签的 token 应该仍能验签：%v", err)
	}
}

// TestVerifyRefreshToken_旧公钥从Verifier移除后拒绝 确认"旧钥匙不是
// 永久保留"——一旦调用方在下一次重启时不再传入 previous（运维清空了
// APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM），用它签的 token 就该验签失败，不是
// 无限期有效。
func TestVerifyRefreshToken_旧公钥从Verifier移除后拒绝(t *testing.T) {
	oldPriv, oldKid := testKey(t)
	newPriv, newKid := testKey(t)

	oldIssuer := NewIssuer(oldPriv, oldKid, 10*time.Minute, 7*24*time.Hour)
	tok, _, _, err := oldIssuer.SignRefreshToken("u-1")
	if err != nil {
		t.Fatalf("用旧钥匙签发失败：%v", err)
	}

	v := NewVerifier(&newPriv.PublicKey, newKid, nil, "")
	if _, _, err := v.VerifyRefreshToken(tok); err == nil {
		t.Fatal("移除旧钥匙后，旧钥匙签的 token 应该验签失败")
	}
}

// TestSignAccessToken_dept_path原样抄进token不替换 锁住"本组件只转抄 dept_path"：
// authz 给空串（没分部门）就签空串，给 "/" 或真实路径就签原值。be-sdk-go v0.5.0 起
// 消费方的 ScopeOf 把空串解释成 org 维哨兵（besdk.NoDeptPath，只剩本人）；签发方要是
// 把空串换成 "/"、或者自己写进哨兵，没分部门的人就会变成看全公司（或语义被签发方篡改）。
func TestSignAccessToken_dept_path原样抄进token不替换(t *testing.T) {
	priv, kid := testKey(t)
	iss := NewIssuer(priv, kid, 10*time.Minute, 7*24*time.Hour)
	for _, dept := range []string{"", "/", "/1/", "/1/12/"} {
		tok, _, err := iss.SignAccessToken(Claims{Sub: "u-1", Roles: []string{"u:u-1"}, DeptPath: dept, OrgID: "1"})
		if err != nil {
			t.Fatalf("dept_path=%q：签发失败：%v", dept, err)
		}
		claims := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil }); err != nil {
			t.Fatalf("dept_path=%q：验签失败：%v", dept, err)
		}
		got, ok := claims["dept_path"].(string)
		if !ok || got != dept {
			t.Fatalf("dept_path 应原样是 %q，实际 %#v", dept, claims["dept_path"])
		}
		if got == besdk.NoDeptPath {
			t.Fatalf("签发方不应写入哨兵 %q", besdk.NoDeptPath)
		}
	}
}
