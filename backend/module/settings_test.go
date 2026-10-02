package module

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
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

// 缺 required 键时返回 error（并点名缺哪些），不 panic：进外壳后一个成员 panic
// 会让同一进程里的全部成员一起退出。
func TestLoadSettings_缺必填键返回error点名而不panic(t *testing.T) {
	m := validConfig(t)
	delete(m, "CASDOOR_ADMIN_PASSWORD")
	delete(m, "WEBHOOK_SHARED_SECRET")
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("缺键时 panic 了：%v", r)
			}
		}()
		_, err = loadSettings(besdk.NewConfig(m))
	}()
	if err == nil {
		t.Fatal("缺必填键应该报错")
	}
	for _, k := range []string{"CASDOOR_ADMIN_PASSWORD", "WEBHOOK_SHARED_SECRET"} {
		if !strings.Contains(err.Error(), k) {
			t.Fatalf("报错应点名 %s：%v", k, err)
		}
	}
}

// 配了却不是整数的 TTL（"10m"、"600s"）不能悄悄退回默认值：值配了、组件却按
// 默认值跑，从外面看不出来。
func TestLoadSettings_TTL不是整数秒时报错而不是用默认值(t *testing.T) {
	for _, key := range []string{"APP_TOKEN_TTL_SECONDS", "REFRESH_TOKEN_TTL_SECONDS"} {
		for _, v := range []string{"10m", "600s", "0", "-5"} {
			m := validConfig(t)
			m[key] = v
			if s, err := loadSettings(besdk.NewConfig(m)); err == nil {
				t.Fatalf("%s=%q 应该报错，实际 access=%v refresh=%v", key, v, s.accessTTL, s.refreshTTL)
			} else if !strings.Contains(err.Error(), key) {
				t.Fatalf("报错应点名 %s：%v", key, err)
			}
		}
	}
}

// PEM 解析失败的报错用的是配置键名（运维在 config/ 里找得到的名字）。
func TestLoadSettings_PEM不对时报错点名配置键(t *testing.T) {
	for _, key := range []string{"APP_TOKEN_SIGNING_KEY_PEM", "APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM"} {
		m := validConfig(t)
		m[key] = "not a pem"
		_, err := loadSettings(besdk.NewConfig(m))
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("%s 不是 PEM 时应报错并点名这个键，实际 %v", key, err)
		}
	}
}

// CASDOOR_EXTRA_CLIENT_IDS：默认空（只信本组件自己的 Casdoor 应用）；逗号分隔，忽略空白与空项。
func TestLoadSettings_额外信任的client_ID按逗号拆分且默认为空(t *testing.T) {
	s, err := loadSettings(besdk.NewConfig(validConfig(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.extraClientIDs) != 0 {
		t.Fatalf("默认应为空，实际 %q", s.extraClientIDs)
	}
	m := validConfig(t)
	m["CASDOOR_EXTRA_CLIENT_IDS"] = " local-dev-seed-app, ,mobile-app ,"
	if s, err = loadSettings(besdk.NewConfig(m)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.extraClientIDs, []string{"local-dev-seed-app", "mobile-app"}) {
		t.Fatalf("拆分结果不对：%q", s.extraClientIDs)
	}
}
