package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试 RSA 密钥失败：%v", err)
	}
	return key
}

func generateTestKeyPEM(t *testing.T, format string) string {
	t.Helper()
	key := generateTestRSAKey(t)
	var der []byte
	var blockType string
	switch format {
	case "PKCS1":
		der = x509.MarshalPKCS1PrivateKey(key)
		blockType = "RSA PRIVATE KEY"
	case "PKCS8":
		var err error
		der, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey 失败：%v", err)
		}
		blockType = "PRIVATE KEY"
	default:
		t.Fatalf("未知格式 %q", format)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func generateTestCertPEM(t *testing.T) string {
	t.Helper()
	key := generateTestRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成测试证书失败：%v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
