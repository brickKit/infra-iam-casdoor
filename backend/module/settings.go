package module

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"
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
	extraClientIDs       []string // CASDOOR_EXTRA_CLIENT_IDS：换 token 时也信任这些 Casdoor 应用签的 id_token

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

// requiredKeys 是 configSchema 里没有默认值的本组件自有键（PG_* / NATS_URL /
// IAM_JWKS_URL 由 SDK 读，不在这里）。brickKit 在它们填好之前拒绝启动，这里
// 再核对一次是为了缺键时返回 error、不 panic。
var requiredKeys = []string{
	"CASDOOR_BASE_URL", "CASDOOR_ADMIN_PASSWORD", "WEBHOOK_SHARED_SECRET",
	"APP_TOKEN_SIGNING_KEY_PEM", "ENABLED_COMPONENTS",
}

// loadSettings 读完并解析全部配置；任何一项不对都返回 error（模块启动即失败），
// 不 panic、不悄悄退回默认值。
func loadSettings(cfg besdk.Config) (settings, error) {
	var missing []string
	for _, k := range requiredKeys {
		if v, ok := cfg.String(k); !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return settings{}, fmt.Errorf("缺少必填配置：%s", strings.Join(missing, ", "))
	}

	var s settings
	s.schema = cfg.StringOr("PG_SCHEMA", "infra_iam_casdoor")
	s.role = s.schema + "_rw"

	s.casdoorBaseURL, _ = cfg.String("CASDOOR_BASE_URL")
	s.casdoorAdminUsername = cfg.StringOr("CASDOOR_ADMIN_USERNAME", "admin")
	s.casdoorAdminPassword, _ = cfg.String("CASDOOR_ADMIN_PASSWORD")
	s.casdoorOrgName = cfg.StringOr("CASDOOR_ORG_NAME", "brickkit")
	s.casdoorAppName = cfg.StringOr("CASDOOR_APP_NAME", "brickkit-app")
	for _, id := range strings.Split(cfg.StringOr("CASDOOR_EXTRA_CLIENT_IDS", ""), ",") {
		if id = strings.TrimSpace(id); id != "" {
			s.extraClientIDs = append(s.extraClientIDs, id)
		}
	}
	s.webhookSharedSecret, _ = cfg.String("WEBHOOK_SHARED_SECRET")
	s.webhookCallbackURL = cfg.StringOr("WEBHOOK_CALLBACK_URL", "")

	var err error
	if s.accessTTL, err = secondsOr(cfg, "APP_TOKEN_TTL_SECONDS", 600); err != nil {
		return s, err
	}
	if s.refreshTTL, err = secondsOr(cfg, "REFRESH_TOKEN_TTL_SECONDS", 604800); err != nil {
		return s, err
	}

	raw, _ := cfg.String("ENABLED_COMPONENTS")
	if s.enabledComponents, err = features.FromLockfile(raw); err != nil {
		return s, err
	}
	pemText, _ := cfg.String("APP_TOKEN_SIGNING_KEY_PEM")
	if s.signingKey, err = keys.ParsePrivateKeyPEM(pemText); err != nil {
		return s, fmt.Errorf("APP_TOKEN_SIGNING_KEY_PEM: %w", err)
	}
	s.currentKid = keys.Thumbprint(&s.signingKey.PublicKey)
	if prev := cfg.StringOr("APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM", ""); prev != "" {
		if s.previousPub, err = keys.ParsePublicKeyPEM(prev); err != nil {
			return s, fmt.Errorf("APP_TOKEN_PREVIOUS_PUBLIC_KEY_PEM: %w", err)
		}
		s.previousKid = keys.Thumbprint(s.previousPub)
	}
	return s, nil
}

// secondsOr 读一个"正整数秒"的键：没配用默认值；配了却不是正整数就报错。
// （SDK 的 IntOr 在值不是整数时静默退回默认值——值配了、组件却按默认值跑。）
func secondsOr(cfg besdk.Config, key string, def int) (time.Duration, error) {
	v, ok := cfg.String(key)
	if !ok || v == "" {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s 应是正整数秒，实际 %q", key, v)
	}
	return time.Duration(n) * time.Second, nil
}
