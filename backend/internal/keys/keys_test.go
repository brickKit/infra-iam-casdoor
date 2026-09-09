package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

// TestThumbprint_对照RFC7638官方示例 用 IETF RFC 7638 Appendix A 给出的
// 官方示例 JWK 与官方给出的期望 kid 值直接核对——不是自己造数据自己验，
// 是对照标准文本里权威机构给出的已知正确答案（同项目里"读标准文本，
// 不猜格式"的一贯做法，见 infra-iam-casdoor 设计计划 §8 对 RFC 8693 的
// 引用态度）。
func TestThumbprint_对照RFC7638官方示例(t *testing.T) {
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const e = "AQAB"
	const wantKid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		t.Fatalf("解码 n 失败：%v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		t.Fatalf("解码 e 失败：%v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	got := Thumbprint(pub)
	if got != wantKid {
		t.Fatalf("kid 与 RFC 7638 官方示例不符：got %q, want %q", got, wantKid)
	}
}

func TestParsePrivateKeyPEM_PKCS1与PKCS8都能解析(t *testing.T) {
	pkcs1 := generateTestKeyPEM(t, "PKCS1")
	if _, err := ParsePrivateKeyPEM(pkcs1); err != nil {
		t.Fatalf("PKCS1 解析失败：%v", err)
	}
	pkcs8 := generateTestKeyPEM(t, "PKCS8")
	if _, err := ParsePrivateKeyPEM(pkcs8); err != nil {
		t.Fatalf("PKCS8 解析失败：%v", err)
	}
}

func TestParsePrivateKeyPEM_非法PEM报错而不是panic(t *testing.T) {
	if _, err := ParsePrivateKeyPEM("不是 PEM"); err == nil {
		t.Fatal("非法 PEM 应该报错")
	}
}

func TestParsePublicKeyPEM_能从证书里取公钥(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	pub, err := ParsePublicKeyPEM(certPEM)
	if err != nil {
		t.Fatalf("从证书解析公钥失败：%v", err)
	}
	if pub == nil {
		t.Fatal("公钥不应为 nil")
	}
}

// TestThumbprint_同一把钥匙两次调用结果相同 是 UpsertSigningKey 幂等性的
// 前提断言：kid 必须是确定性推导，不能每次启动算出不同值。
func TestThumbprint_同一把钥匙两次调用结果相同(t *testing.T) {
	priv := generateTestRSAKey(t)
	kid1 := Thumbprint(&priv.PublicKey)
	kid2 := Thumbprint(&priv.PublicKey)
	if kid1 != kid2 {
		t.Fatalf("同一把公钥算出了不同的 kid：%q != %q", kid1, kid2)
	}
}
