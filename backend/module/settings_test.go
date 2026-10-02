package module

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
)

func pemPrivate(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), k
}

func pemPublic(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// validConfig 是一份 required 键齐全的配置（值的形态与 brickKit 注入的一致：全是字符串）。
func validConfig(t *testing.T) map[string]string {
	t.Helper()
	priv, _ := pemPrivate(t)
	return map[string]string{
		"CASDOOR_BASE_URL":          "http://host.docker.internal:8000",
		"CASDOOR_ADMIN_PASSWORD":    "pw",
		"WEBHOOK_SHARED_SECRET":     "secret",
		"APP_TOKEN_SIGNING_KEY_PEM": priv,
		"ENABLED_COMPONENTS":        "components:\n  - id: mdm/customer\n    version: 2.0.0\n",
	}
}

func TestLoadSettings_齐全的配置按值解析(t *testing.T) {
	m := validConfig(t)
	_, prev := pemPrivate(t)
	m["APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM"] = pemPublic(t, prev)
	m["APP_TOKEN_TTL_SECONDS"] = "300"
	m["REFRESH_TOKEN_TTL_SECONDS"] = "3600"
	m["CASDOOR_ORG_NAME"] = "acme"
	m["WEBHOOK_CALLBACK_URL"] = "http://host.docker.internal:8200/api/iam/webhooks/casdoor"

	s, err := loadSettings(besdk.NewConfig(m))
	if err != nil {
		t.Fatal(err)
	}
	if s.schema != "infra_iam_casdoor" || s.role != "infra_iam_casdoor_rw" {
		t.Fatalf("schema/role 默认值不对：%q / %q", s.schema, s.role)
	}
	if s.accessTTL != 5*time.Minute || s.refreshTTL != time.Hour {
		t.Fatalf("TTL 没按配置值：%v / %v", s.accessTTL, s.refreshTTL)
	}
	if s.casdoorOrgName != "acme" || s.casdoorAppName != "brickkit-app" || s.casdoorAdminUsername != "admin" {
		t.Fatalf("Casdoor 名称不对：%q %q %q", s.casdoorOrgName, s.casdoorAppName, s.casdoorAdminUsername)
	}
	if s.webhookCallbackURL != m["WEBHOOK_CALLBACK_URL"] {
		t.Fatalf("回调地址不对：%q", s.webhookCallbackURL)
	}
	if !reflect.DeepEqual(s.enabledComponents, []string{"mdm/customer"}) {
		t.Fatalf("组件清单不对：%q", s.enabledComponents)
	}
	if s.signingKey == nil || s.currentKid == "" || s.previousPub == nil || s.previousKid == "" || s.previousKid == s.currentKid {
		t.Fatalf("两把钥匙没解析好：current=%q previous=%q", s.currentKid, s.previousKid)
	}
}
