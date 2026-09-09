// Package keys 只做一件事：把 configSchema 注入的 PEM 文本解析成
// crypto/rsa 的 Go 类型，并按 RFC 7638 算出确定性的 kid（JWK
// Thumbprint）——同一把公钥每次启动都算出同一个 kid，这是
// UpsertSigningKey 能安全幂等调用的前提（设计计划 §3.3、§9 第 1b 条）。
//
// ⚠️ 私钥材料只在这个包和调用它的 tokens 包里短暂存在于内存，绝不落库
// （见 repo/signingkeys.go 顶部注释）、绝不打进日志。
package keys

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// ParsePrivateKeyPEM 解析 PKCS#1 或 PKCS#8 编码的 RSA 私钥 PEM。
func ParsePrivateKeyPEM(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("appTokenSigningKeyPem 不是合法的 PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败（既不是 PKCS1 也不是 PKCS8）：%w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("appTokenSigningKeyPem 不是 RSA 私钥")
	}
	return rsaKey, nil
}

// ParsePublicKeyPEM 解析 PKIX 编码的 RSA 公钥 PEM（appTokenPreviousPublicKeyPem
// 用——密钥轮换期间只需要旧公钥来验签，不需要旧私钥）。也接受 x509 证书
// PEM（取证书里的公钥），方便直接从"上一版 appTokenSigningKeyPem 对应的
// 证书"复制过来，不强制运维人员单独导出一份裸公钥。
func ParsePublicKeyPEM(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("appTokenPreviousPublicKeyPem 不是合法的 PEM")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("证书里的公钥不是 RSA")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败：%w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("appTokenPreviousPublicKeyPem 不是 RSA 公钥")
	}
	return rsaPub, nil
}

// jwkThumbprintInput 的字段顺序与命名必须严格按 RFC 7638 §3.2：RSA 公钥
// 只取 e/kty/n 三个必需成员，键名按字典序排列，序列化成没有空白的紧凑
// JSON 后取 SHA-256。golang 的 encoding/json 按 struct 字段声明顺序
// （不是字母序）输出，所以这里手写字段顺序为 e, kty, n——凑巧字母序与
// 字段声明顺序一致，两者都满足。
type jwkThumbprintInput struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

// Thumbprint 按 RFC 7638 算 RSA 公钥的 kid。⚠️ 用的是 base64url **不带
// padding**（RFC 7638 §3.1 要求 JWK 序列化用 base64url-encode，JWK 规范
// RFC 7518 §6.3.1 规定 n/e 不带 padding）——用带 padding 的
// StdEncoding/URLEncoding 会算出与其他任何标准实现都对不上的 kid。
func Thumbprint(pub *rsa.PublicKey) string {
	in := jwkThumbprintInput{
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E)),
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	}
	body, _ := json.Marshal(in) // 字段固定为字符串，Marshal 不会失败
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// JWK 是标准 JSON Web Key（RFC 7517）里 RSA 公钥那一种的最小字段集合，
// 供 GET /.well-known/jwks.json 直接序列化用。
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ToJWK 把一把 RSA 公钥连同它的 kid 转成标准 JWK 结构。
func ToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E)),
	}
}

// bigIntToBytes 把 RSA 公钥指数（Go 里是 int，通常是 65537）编码成 JWK
// 要求的大端最短字节序列——不能直接用 big.Int(e).Bytes() 因为 e 是 int
// 不是 big.Int，这里手动按大端拼出最短表示（65537 = 0x010001，3 字节）。
func bigIntToBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
