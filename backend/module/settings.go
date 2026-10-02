package module

import (
	"crypto/rsa"
	"fmt"
	"time"

	besdk "github.com/brickKit/be-sdk-go"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/features"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/keys"
)

// settings 是从 rt.Config 读出、解析好的全部配置。New 只调 loadSettings 一次，
// 之后不再碰 rt.Config 的键名（拨 infra/authz 时 SystemClient 读依赖地址除外）。
type settings struct {
	schema, role string

	casdoorBaseURL       string
	casdoorAdminUsername string
	casdoorAdminPassword string
	casdoorOrgName       string
	casdoorAppName       string

	webhookSharedSecret string
	webhookCallbackURL  string

	signingKey  *rsa.PrivateKey
	currentKid  string
	previousPub *rsa.PublicKey // 为 nil 表示不在轮换期
	previousKid string

	accessTTL  time.Duration
	refreshTTL time.Duration

	enabledComponents []string
}

func loadSettings(cfg besdk.Config) (settings, error) {
	var s settings
	s.schema = cfg.StringOr("PG_SCHEMA", "infra_iam_casdoor")
	s.role = s.schema + "_rw"

	s.casdoorBaseURL = cfg.MustString("CASDOOR_BASE_URL")
	s.casdoorAdminUsername = cfg.StringOr("CASDOOR_ADMIN_USERNAME", "admin")
	s.casdoorAdminPassword = cfg.MustString("CASDOOR_ADMIN_PASSWORD")
	s.casdoorOrgName = cfg.StringOr("CASDOOR_ORG_NAME", "brickkit")
	s.casdoorAppName = cfg.StringOr("CASDOOR_APP_NAME", "brickkit-app")
	s.webhookSharedSecret = cfg.MustString("WEBHOOK_SHARED_SECRET")
	s.webhookCallbackURL = cfg.StringOr("WEBHOOK_CALLBACK_URL", "")
	s.accessTTL = time.Duration(cfg.IntOr("APP_TOKEN_TTL_SECONDS", 600)) * time.Second
	s.refreshTTL = time.Duration(cfg.IntOr("REFRESH_TOKEN_TTL_SECONDS", 604800)) * time.Second

	var err error
	if s.enabledComponents, err = features.FromLockfile(cfg.StringOr("ENABLED_COMPONENTS", "")); err != nil {
		return s, err
	}
	if s.signingKey, err = keys.ParsePrivateKeyPEM(cfg.MustString("APP_TOKEN_SIGNING_KEY_PEM")); err != nil {
		return s, fmt.Errorf("解析 appTokenSigningKeyPem 失败: %w", err)
	}
	s.currentKid = keys.Thumbprint(&s.signingKey.PublicKey)
	if prev := cfg.StringOr("APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM", ""); prev != "" {
		if s.previousPub, err = keys.ParsePublicKeyPEM(prev); err != nil {
			return s, fmt.Errorf("解析 appTokenPreviousPublicKeyPem 失败: %w", err)
		}
		s.previousKid = keys.Thumbprint(s.previousPub)
	}
	return s, nil
}
