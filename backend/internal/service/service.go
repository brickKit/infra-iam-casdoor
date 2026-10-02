// Package service 是 infra-iam-casdoor 的业务编排层——HTTP 与 gRPC 两个
// 对外面共用同一份逻辑（同 infra-authz 的分层判据）。
package service

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	besdk "github.com/brickKit/be-sdk-go"

	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/keys"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/tokens"
)

// Service 持有签发/验证应用 token 用的密钥材料、refresh_tokens 的
// 存取，以及一个"验 Casdoor 身份 token 用的验证器"的原子指针——后者
// 由 module 层的后台发现循环填入，构造 Service 时允许还没有（Casdoor
// 暂时不可达是合法的启动态，见 module.go 的重试循环注释）。
type Service struct {
	repo         *repo.Repo
	cfg          besdk.Config // 只为拨 infra/authz（INFRA_AUTHZ_GRPC_ENDPOINT）用
	schema       string       // 只为 PublishOutbox 拼表名用（besdk.PublishOutbox 的签名要求）
	issuer       *tokens.Issuer
	verifier     *tokens.Verifier
	idVerifier   atomic.Pointer[casdoor.IDTokenVerifier]
	jwkSet       []keys.JWK        // 当前 + 上一把公钥，启动时算好，不随请求变化
	enabled      []string          // ENABLED_COMPONENTS 拆分结果
	sharedSecret string            // webhook 共享密钥
	sharedHeader string            // 共享密钥所在的 header 名
	users        func() UserReader // webhook 回读用户当前状态用；返回 nil = Casdoor 管理会话还没就绪
}

// UserReader 是 webhook 投递回读用户当前状态用的 Casdoor 查询，*casdoor.AdminClient
// 满足它。查不到用户返回 (nil, nil)。
type UserReader interface {
	GetUserBySub(ctx context.Context, sub string) (*casdoor.User, error)
	GetUserByName(ctx context.Context, owner, name string) (*casdoor.User, error)
}

// New 构造 Service。currentPub/currentKid 恒非空（APP_TOKEN_SIGNING_KEY_PEM
// 是必填项）；previousPub/previousKid 任一为空表示当前只有一把在用的
// 钥匙（密钥轮换的非轮换态）。
func New(r *repo.Repo, cfg besdk.Config, schema string, signingKey *rsa.PrivateKey, currentKid string,
	previousPub *rsa.PublicKey, previousKid string,
	accessTTL, refreshTTL time.Duration,
	enabledComponents []string, webhookSharedSecret, webhookSharedHeader string,
) *Service {
	jwkSet := []keys.JWK{keys.ToJWK(&signingKey.PublicKey, currentKid)}
	if previousPub != nil && previousKid != "" {
		jwkSet = append(jwkSet, keys.ToJWK(previousPub, previousKid))
	}
	return &Service{
		repo:         r,
		cfg:          cfg,
		schema:       schema,
		issuer:       tokens.NewIssuer(signingKey, currentKid, accessTTL, refreshTTL),
		verifier:     tokens.NewVerifier(&signingKey.PublicKey, currentKid, previousPub, previousKid),
		jwkSet:       jwkSet,
		enabled:      enabledComponents,
		sharedSecret: webhookSharedSecret,
		sharedHeader: webhookSharedHeader,
	}
}

// SetIDVerifier 由 module 的后台发现循环在 OIDC 发现成功后调用一次
// （允许晚于 New 若干秒——Casdoor 可能比本组件启动得晚）。
func (s *Service) SetIDVerifier(v *casdoor.IDTokenVerifier) { s.idVerifier.Store(v) }

// SetUserReader 由 module 在构造后调用一次：f 每次投递时调用，返回当前的 Casdoor
// 管理会话（后台登录成功之前返回 nil）。
func (s *Service) SetUserReader(f func() UserReader) { s.users = f }

// JWKS 供 GET /.well-known/jwks.json 直接序列化。
func (s *Service) JWKS() []keys.JWK { return s.jwkSet }

// EnabledComponents 供 GET /api/tenant/features。
func (s *Service) EnabledComponents() []string { return s.enabled }

// WebhookSharedSecretHeader 供 HTTP 层校验时读：密钥值来自 WEBHOOK_SHARED_SECRET，
// header 名是 module 包的固定常量（启动对账建 webhook 时用的也是它）。
func (s *Service) WebhookSharedSecretHeader() string { return s.sharedHeader }
func (s *Service) WebhookSharedSecretValid(v string) bool {
	// 常数时间比较：这个端点对同一网络里的任何容器都可达，逐字节提前返回的比较
	// 会把"猜对了前几位"泄露成响应时间差。
	return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(s.sharedSecret)) == 1
}

// TokenPair 是签发/刷新接口共用的响应形状。
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// ExchangeToken 是 POST /api/iam/token 的核心：验 Casdoor 身份 token →
// 现问 infra-authz 的 claims → 签应用 token + refresh token。
func (s *Service) ExchangeToken(ctx context.Context, casdoorIDToken string) (*TokenPair, error) {
	v := s.idVerifier.Load()
	if v == nil {
		return nil, fmt.Errorf("%w: Casdoor 验证器尚未就绪", ErrUnavailable)
	}
	sub, err := v.Verify(casdoorIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, err.Error())
	}
	return s.issueFor(ctx, sub)
}

// RefreshToken 是 POST /api/iam/token/refresh 的核心：验旧 refresh token →
// 现问 claims 签新应用 token（刷新时角色天然最新）→ 轮换 refresh token。
//
// ⚠️ 先问 claims、后轮换：轮换会撤销旧 refresh token。先轮换的话，infra-authz
// 一次抖动（ResolveClaims 失败、回 503）就把调用方手里唯一的 refresh token
// 烧掉了，它重试时撞上重放检测（401，并撤销这个人名下全部 refresh token）——
// 一次依赖抖动把在线用户全部踢下线。现在问 claims 失败时什么都没改，重试照常。
func (s *Service) RefreshToken(ctx context.Context, oldRefreshToken string) (*TokenPair, error) {
	sub, oldJTI, err := s.verifier.VerifyRefreshToken(oldRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, err.Error())
	}

	accessToken, expiresIn, err := s.signAccessTokenFor(ctx, sub)
	if err != nil {
		return nil, err
	}

	newRefreshToken, newJTI, newExpiresAt, err := s.issuer.SignRefreshToken(sub)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RotateRefreshToken(ctx, oldJTI, newJTI, sub, newExpiresAt); err != nil {
		if errors.Is(err, repo.ErrRefreshTokenInvalid) {
			return nil, fmt.Errorf("%w: refresh token 已失效", ErrUnauthenticated)
		}
		return nil, err
	}
	return &TokenPair{AccessToken: accessToken, RefreshToken: newRefreshToken, ExpiresIn: expiresIn}, nil
}

// Logout 作废一个 refresh token——幂等（对已作废的 token 重复调用同样成功）。sub 由调用方（http 层）从已验签的应用 token 里
// 取——只能作废"自己"的 refresh token，不能凭一个 refresh token 字符串
// 单方面作废别人的会话（service.go 顶部没有额外校验的原因：这条防线在
// repo.RevokeRefreshToken 的 SQL WHERE 条件里，sub 不匹配时 UPDATE
// 影响 0 行，等同空操作，语义上仍然是"幂等的登出"）。
func (s *Service) Logout(ctx context.Context, refreshToken, callerSub string) error {
	// refresh token 本身可能已经过期/格式错误——登出的意图无论如何都该
	// 达成"这个 token 以后肯定用不了"，所以验签失败时不报错，直接按
	// "没有可撤销的东西"处理，返回成功（登出是幂等的）。
	_, jti, err := s.verifier.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil
	}
	return s.repo.RevokeRefreshToken(ctx, jti, callerSub)
}

// issueFor 是"给一个 sub 现问 claims + 签一对全新 token（非刷新场景）"
// 的共用逻辑——登录（ExchangeToken）用，"新登录"与"刷新"的差别只在
// refresh token 是全新登记还是轮换。
func (s *Service) issueFor(ctx context.Context, sub string) (*TokenPair, error) {
	accessToken, expiresIn, err := s.signAccessTokenFor(ctx, sub)
	if err != nil {
		return nil, err
	}
	refreshToken, jti, expiresAt, err := s.issuer.SignRefreshToken(sub)
	if err != nil {
		return nil, err
	}
	if err := s.repo.IssueRefreshToken(ctx, jti, sub, expiresAt); err != nil {
		return nil, err
	}
	return &TokenPair{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: expiresIn}, nil
}

// signAccessTokenFor 现问 infra-authz 的 ResolveClaims 再签一个应用
// token。⚠️ 这里用 besdk.SystemClient——不是绕过用户数据权限的那类误用
// （SystemClient 的禁令针对的是"该转发调用者身份去查调用者自己该看到的数据"，
// 而这里恰恰没有"调用者身份"可转发：这一刻调用者手上要么还没有任何
// 应用身份（登录/刷新的意义就是把它签出来），要么正在被刷新，ctx 里从
// 不存在一个已验签的 besdk.Claims（本组件的 REST 面除 /api/iam/logout
// 外全部是 besdk.Public，见 assembly.yaml）。ResolveClaims 本身也没有
// 按"谁在问"做任何数据范围过滤——它就是一个 sub -> claims 的纯查询。
func (s *Service) signAccessTokenFor(ctx context.Context, sub string) (accessToken string, expiresIn int, err error) {
	conn, err := besdk.SystemClient(s.cfg, "infra/authz", "grpc")
	if err != nil {
		return "", 0, fmt.Errorf("拨号 infra-authz 失败: %w", err)
	}
	defer conn.Close()

	resp, err := authzv1.NewAuthzServiceClient(conn).ResolveClaims(ctx, &authzv1.ResolveClaimsRequest{Sub: sub})
	if err != nil {
		return "", 0, fmt.Errorf("%w: ResolveClaims 失败: %s", ErrDependencyUnavailable, err.Error())
	}

	return s.issuer.SignAccessToken(tokens.Claims{
		Sub: sub, Roles: resp.Roles, DeptPath: resp.DeptPath, OrgID: resp.OrgId,
	})
}

// ── Webhook ──────────────────────────────────────────────────────────

// HandleWebhookDelivery 登记一次投递（去重）并宽容解析 payload——校验
// 共享密钥这一步已经在 http 层做完（那一步是"是不是 Casdoor 发的"，
// 严格；这一步是"这条事件长什么样"，宽容：Casdoor 的投递保证与 payload
// 形状至今没有完全核实，见 docs/design.md 的未决问题）。
//
// dedupKey 由调用方（http 层）算好传入——算法本身（有没有稳定投递 ID、
// 退化到内容哈希）是协议细节，不属于这一层的编排逻辑。action 从
// payload 自己解析出来，不要求调用方提前知道 Casdoor 的字段名。
//
// ⚠️ 解析（这个函数）与登记+发布（RecordDeliveryAndPublish）分成两段：
// 解析不需要数据库，先做完再决定 status/errMsg 与要不要发事件；登记
// 与发布必须在同一个事务里（Outbox Pattern），交给
// repo 层的 RecordDeliveryAndPublish 一次做完。
func (s *Service) HandleWebhookDelivery(ctx context.Context, dedupKey string, rawPayload []byte) error {
	var payload webhookUserPayload
	status, errMsg := "PROCESSED", ""
	var publish func(tx *sql.Tx) error

	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		status, errMsg = "ERROR", "解析 payload 失败: "+err.Error()
	} else if payload.Sub() == "" {
		status, errMsg = "IGNORED", "payload 里找不到用户标识"
	} else if subject, ok := payload.EventSubject(payload.Action); !ok {
		status, errMsg = "IGNORED", "无法从 action 推出事件类型: "+payload.Action
	} else {
		ev, buildErr := buildUserEvent(subject, payload)
		if buildErr != nil {
			status, errMsg = "ERROR", buildErr.Error()
		} else {
			publish = func(tx *sql.Tx) error { return besdk.PublishOutbox(tx, s.schema, ev) }
		}
	}

	_, err := s.repo.RecordDeliveryAndPublish(ctx, dedupKey, payload.Action, rawPayload, status, errMsg, publish)
	return err
}

// ── 密钥元数据（启动时登记，供 ListSigningKeys 排查用）──────────────

func (s *Service) RegisterSigningKey(ctx context.Context, kid, alg string) error {
	return s.repo.UpsertSigningKey(ctx, kid, alg)
}

func (s *Service) ListSigningKeys(ctx context.Context) ([]repo.SigningKey, error) {
	return s.repo.ListSigningKeys(ctx)
}

// ── 踢人（事件消费者用）──────────────────────────────────────────────

func (s *Service) RevokeAllRefreshTokensForSub(ctx context.Context, sub string) error {
	return s.repo.RevokeAllRefreshTokensForSub(ctx, sub)
}
