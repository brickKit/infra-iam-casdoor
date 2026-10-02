package module

import (
	"context"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/bootstrap"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/service"
)

// webhookName 是本组件在 Casdoor 里建的用户事件 webhook 的名字（启动对账按它找）。
const webhookName = "brickkit-user-events"

// registerSigningKeys 把当前（与轮换期的上一把）签名公钥的 kid 登记进
// signing_keys，供排查用。失败只记日志、不阻断启动：签发与验签不读这张表。
func registerSigningKeys(ctx context.Context, svc *service.Service, cfg settings, logger *slog.Logger) {
	kids := []string{cfg.currentKid}
	if cfg.previousPub != nil {
		kids = append(kids, cfg.previousKid)
	}
	for _, kid := range kids {
		if err := svc.RegisterSigningKey(ctx, kid, "RS256"); err != nil && ctx.Err() == nil {
			logger.Error("登记签名密钥元数据失败", "kid", kid, "error", err)
		}
	}
}

// connectCasdoorAdmin 在后台登录 Casdoor 管理 API，成功后交给 gRPC BatchGetUsers
// 使用（在此之前它回 Unavailable），再跑启动对账（组织、应用、webhook）。登录失败、
// 或对账途中 Casdoor 不可达，都整轮重来（对账每一步先查再建，重跑安全）；对账被
// Casdoor 拒绝或写库失败要人处理，记一条 Error、不再重试（重试也是同样的结果）。
func connectCasdoorAdmin(ctx context.Context, cfg settings, r *repo.Repo,
	holder *atomic.Pointer[casdoor.AdminClient], logger *slog.Logger) {
	retryUntilOK(ctx, time.Second, func(ctx context.Context) error {
		c, err := casdoor.NewAdminClient(ctx, cfg.casdoorBaseURL, cfg.casdoorAdminUsername, cfg.casdoorAdminPassword)
		if err != nil {
			return err
		}
		holder.Store(c)
		err = bootstrap.Run(ctx, c, r, bootstrap.Config{
			OrgName: cfg.casdoorOrgName,
			AppName: cfg.casdoorAppName,
			// 前端登录回调地址属于前端的部署，不在这里写死；应用已存在时不改它。
			AppRedirectURIs:        []string{},
			WebhookName:            webhookName,
			WebhookCallbackURL:     cfg.webhookCallbackURL,
			WebhookSharedHeader:    webhookSharedSecretHeader,
			WebhookSharedSecretVal: cfg.webhookSharedSecret,
		})
		switch {
		case err == nil || ctx.Err() != nil:
			return nil
		case casdoor.IsUnreachable(err):
			return err // 整轮重来；onFail 记 Warn
		default:
			logger.Error("启动对账失败，需要人处理（不再重试；新用户登录或用户事件投递可能受影响）", "error", err)
			return nil
		}
	}, func(err error, next time.Duration) {
		logCasdoorFailure(logger, "连接 Casdoor 管理 API 或启动对账失败，稍后重试（登录成功之前 gRPC BatchGetUsers 回 Unavailable）", err, next)
	})
}

// discoverIDTokenVerifier 在后台做 OIDC 发现（重试直到成功）——成功一次之后
// keyfunc 自己的后台协程接管 JWKS 的持续刷新，这个循环就退出了。成功之前
// POST /api/iam/token 回 503。
func discoverIDTokenVerifier(ctx context.Context, casdoorBaseURL string, svc *service.Service, logger *slog.Logger) {
	retryUntilOK(ctx, time.Second, func(ctx context.Context) error {
		issuer, jwksURI, err := casdoor.DiscoverOIDC(ctx, casdoorBaseURL)
		if err != nil {
			return err
		}
		// ⚠️ 不能把发现文档给出的 jwks_uri 原样拿去连。Casdoor 的 origin 是部署级
		// 全局唯一值，发现文档会被两类调用方消费——本组件（容器，只能用
		// CASDOOR_BASE_URL 那种地址够到 Casdoor）与宿主机上的 curl / 集成测试——
		// 两者需要的 host:port 往往不同，origin 只能二选一。所以把 jwks_uri 的
		// host 换成 CASDOOR_BASE_URL 的（刚用它拉到了发现文档，天然可达），只留
		// 路径；issuer 不换（它是签名里的身份声明，不是网络地址）。
		v, err := casdoor.NewIDTokenVerifier(ctx, rebaseHost(jwksURI, casdoorBaseURL), issuer)
		if err != nil {
			return err
		}
		svc.SetIDVerifier(v)
		return nil
	}, func(err error, next time.Duration) {
		// 发现文档与 JWKS 都是普通 HTTP 读：失败就是 Casdoor 暂时不在，Warn。
		logger.Warn("初始化 Casdoor id_token 验证器失败，稍后重试（在此之前 POST /api/iam/token 回 503）",
			"error", err, "retry_in", next)
	})
}

// logCasdoorFailure：Casdoor 暂时不可达 → Warn（后台会重试，不需要人）；
// Casdoor 明确拒绝（口令错等）→ Error（要人去改配置）。
func logCasdoorFailure(logger *slog.Logger, msg string, err error, next time.Duration) {
	if casdoor.IsUnreachable(err) {
		logger.Warn(msg, "error", err, "retry_in", next)
		return
	}
	logger.Error(msg, "error", err, "retry_in", next)
}

// rebaseHost 把 rawURL 的 scheme+host 换成 baseURL 的（只留 rawURL 的
// path/query），解析失败时原样返回 rawURL——宁可让调用方按老路径失败
// 重试，也不要因为这一步解析出错就 panic 或吞掉错误。
func rebaseHost(rawURL, baseURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return rawURL
	}
	u.Scheme, u.Host = b.Scheme, b.Host
	return u.String()
}
