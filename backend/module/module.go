// Package module 是 infra-iam-casdoor 唯一的装配入口（全局约束 §K、
// 设计书 §12.5.1、§13.3 铁律七）。单跑与合并走同一个 New 函数；模块
// 只交回零件，谁去 Listen、谁开池、谁 init OTel、谁装信号处理器，全归
// 调用方。
package module

import (
	"context"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	iamv1 "github.com/brickKit/infra-iam-casdoor/gen/infra/iam/v1"
	"google.golang.org/grpc"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/bootstrap"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/consumer"
	grpcapi "github.com/brickKit/infra-iam-casdoor/v2/backend/internal/grpc"
	httpapi "github.com/brickKit/infra-iam-casdoor/v2/backend/internal/http"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/service"
)

const webhookSharedSecretHeader = "X-Shared-Secret"

// New 构造 infra-iam-casdoor 模块。签名一个字都不许改（§12.5.1）。
func New(ctx context.Context, rt *besdk.Runtime) (*besdk.Module, error) {
	// ⚠️ 配置只从 rt.Config 来，模块里零 os.Getenv（进外壳后成员共用一个进程环境）。
	cfg, err := loadSettings(rt.Config)
	if err != nil {
		return nil, err
	}

	// ⚠️ 池从 rt.DB 来，不许自己 sql.Open。
	r := repo.New(rt.DB, cfg.role, cfg.schema)
	svc := service.New(r, rt.Config, cfg.schema, cfg.signingKey, cfg.currentKid, cfg.previousPub, cfg.previousKid,
		cfg.accessTTL, cfg.refreshTTL, cfg.enabledComponents, cfg.webhookSharedSecret, webhookSharedSecretHeader)

	// HTTP：engine 必须用 besdk.NewGinEngine，它已挂好 OTel / request-id /
	// error→status / PII 脱敏日志 / RED 指标 / /healthz / /metrics。
	eng := besdk.NewGinEngine(rt)
	httpapi.RegisterRoutes(eng, svc)

	// adminClientHolder 由 Start() 登录成功后填入，gRPC handler 每次调用
	// 时才 Load()——见 grpc.go 顶部注释，RegisterGRPC 与 Start() 是并发
	// 起步的两件事，构造这一刻登录多半还没完成。
	var adminClientHolder atomic.Pointer[casdoor.AdminClient]

	return &besdk.Module{
		HTTPHandler: eng,

		// ⚠️ gRPC 一个不省，而且由调用方在 extraPorts["grpc"] 上 Listen
		// （§1.5 原则一）。
		RegisterGRPC: func(gs *grpc.Server) {
			iamv1.RegisterIamServiceServer(gs, grpcapi.New(&adminClientHolder, cfg.enabledComponents))
		},

		// Start 做三件事：① 登记签名密钥元数据 + 登录 Casdoor 管理 API +
		// 跑一遍自举对账（都是一次性的，失败只记日志——本组件启动不该
		// 因为 Casdoor 暂时不可达而整体失败，已登录用户不受影响）；
		// ② 起一个后台循环，重试 OIDC 发现直到成功（Casdoor 可能比本
		// 组件启动得晚，这是唯一需要"重试直到成功"而不是"失败一次就
		// 放弃"的部分，因为它直接决定 POST /api/iam/token 这个最核心
		// 接口能不能用）；③ 起 Outbox 推送 + 事件消费两个常驻循环。
		Start: func(ctx context.Context) error {
			if err := svc.RegisterSigningKey(ctx, cfg.currentKid, "RS256"); err != nil {
				rt.Logger.Error("登记当前签名密钥元数据失败", "error", err)
			}
			if cfg.previousPub != nil {
				if err := svc.RegisterSigningKey(ctx, cfg.previousKid, "RS256"); err != nil {
					rt.Logger.Error("登记上一把签名密钥元数据失败", "error", err)
				}
			}

			adminClient, err := casdoor.NewAdminClient(ctx, cfg.casdoorBaseURL, cfg.casdoorAdminUsername, cfg.casdoorAdminPassword)
			if err != nil {
				rt.Logger.Error("登录 Casdoor 管理 API 失败，本轮跳过自举，gRPC BatchGetUsers 暂不可用", "error", err)
			} else {
				adminClientHolder.Store(adminClient)
				bootstrap.Run(ctx, adminClient, r, bootstrap.Config{
					OrgName:                cfg.casdoorOrgName,
					AppName:                cfg.casdoorAppName,
					AppRedirectURIs:        []string{}, // 阶段三没有前端，先不写死回调地址（阶段四补）
					WebhookName:            "brickkit-user-events",
					WebhookCallbackURL:     cfg.webhookCallbackURL,
					WebhookSharedHeader:    webhookSharedSecretHeader,
					WebhookSharedSecretVal: cfg.webhookSharedSecret,
				}, rt.Logger)
			}

			go discoverIDTokenVerifier(ctx, cfg.casdoorBaseURL, svc, rt.Logger)

			errCh := make(chan error, 2)
			go func() { errCh <- besdk.StartOutboxPump(ctx, rt.DB, cfg.schema, rt.NATS, rt.Logger) }()
			go func() { errCh <- consumer.Start(ctx, rt.DB, cfg.role, cfg.schema, rt.NATS, rt.Logger) }()

			select {
			case <-ctx.Done():
				return nil
			case err := <-errCh:
				return err // ⚠️ 返回 error，不许 log.Fatal：一个模块退进程 = 整组组件一起没了
			}
		},
		Stop: func(ctx context.Context) error { return nil }, // 后台循环靠 ctx 退出
	}, nil
}

// discoverIDTokenVerifier 重试直到 OIDC 发现成功——成功一次之后
// keyfunc 自己的后台刷新协程接管 JWKS 的持续更新，这个循环就退出了
// （不是一个永久轮询，是"等它第一次可用"）。指数退避封顶 30 秒，Casdoor
// 慢启动几秒到几十秒都能追上，也不会在它长时间不可达时疯狂重试。
func discoverIDTokenVerifier(ctx context.Context, casdoorBaseURL string, svc *service.Service, logger *slog.Logger) {
	backoff := time.Second
	for {
		issuer, jwksURI, err := casdoor.DiscoverOIDC(ctx, casdoorBaseURL)
		if err == nil {
			// ⚠️ 真机踩出来的坑：不能把发现文档给出的 jwks_uri 原样拿去连。
			// Casdoor 的 origin 配置是**部署级全局唯一值**，同一份发现文档
			// 会被至少两类调用方消费——本组件（brickkit 管理的容器，只能
			// 用 casdoorBaseUrl 那种地址够到 Casdoor）与人在宿主机上直接
			// 测试用的 curl/集成测试（只能用宿主机能解析的地址）——两者
			// 需要的 host:port 往往不同，origin 只能二选一。把 jwks_uri
			// 的 host 部分强制换成 casdoorBaseUrl 自己的（本组件已经用它
			// 成功拉到了这份发现文档，天然可达），只留发现文档给出的路径
			// ——issuer 字符串本身不换（它是签名里的身份声明，不是网络
			// 地址，不需要能连得上）。
			jwksURI = rebaseHost(jwksURI, casdoorBaseURL)
			v, verr := casdoor.NewIDTokenVerifier(ctx, jwksURI, issuer)
			if verr == nil {
				svc.SetIDVerifier(v)
				return
			}
			err = verr
		}
		logger.Error("初始化 Casdoor id_token 验证器失败，将重试（POST /api/iam/token 在此之前会返回 503）",
			"error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
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
