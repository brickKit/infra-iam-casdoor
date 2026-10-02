// Package module 是 infra-iam-casdoor 唯一的装配入口。单跑与进外壳走同一个
// New 函数；模块
// 只交回零件，谁去 Listen、谁开池、谁 init OTel、谁装信号处理器，全归
// 调用方。
package module

import (
	"context"
	"sync/atomic"

	besdk "github.com/brickKit/be-sdk-go"
	iamv1 "github.com/brickKit/infra-iam-casdoor/gen/infra/iam/v1"
	"google.golang.org/grpc"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/casdoor"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/consumer"
	grpcapi "github.com/brickKit/infra-iam-casdoor/v2/backend/internal/grpc"
	httpapi "github.com/brickKit/infra-iam-casdoor/v2/backend/internal/http"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/partition"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/service"
)

const webhookSharedSecretHeader = "X-Shared-Secret"

// New 构造 infra-iam-casdoor 模块。签名一个字都不许改：外壳按这个签名登记成员。
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
	// webhook 投递回读用户当前状态用的也是这条会话（R61）。⚠️ 没登录时必须返回
	// nil 接口，不能把 nil 的 *AdminClient 装进接口（那是一个非 nil 的接口值）。
	svc.SetUserReader(func() service.UserReader {
		if c := adminClientHolder.Load(); c != nil {
			return c
		}
		return nil
	})

	return &besdk.Module{
		HTTPHandler: eng,

		// ⚠️ gRPC 一个不省，而且由调用方在 extraPorts["grpc"] 上 Listen
		// （每个声明的端口都必须真的在听）。
		RegisterGRPC: func(gs *grpc.Server) {
			iamv1.RegisterIamServiceServer(gs, grpcapi.New(&adminClientHolder, cfg.enabledComponents))
		},

		// Start：登记签名密钥元数据；后台连 Casdoor 管理 API 并跑一遍自举对账、
		// 后台做 OIDC 发现（两者都重试直到成功——Casdoor 可能比本组件起得晚，
		// 暂时不可达不该让本组件启动失败）；起 Outbox 推送、事件消费、分区维护三个
		// 常驻循环。
		Start: func(ctx context.Context) error {
			registerSigningKeys(ctx, svc, cfg, rt.Logger)
			go connectCasdoorAdmin(ctx, cfg, r, &adminClientHolder, rt.Logger)
			go discoverIDTokenVerifier(ctx, cfg.casdoorBaseURL, svc, rt.Logger)

			errCh := make(chan error, 3)
			go func() { errCh <- besdk.StartOutboxPump(ctx, rt.DB, cfg.schema, rt.NATS, rt.Logger) }()
			go func() { errCh <- consumer.Start(ctx, rt.DB, cfg.role, cfg.schema, rt.NATS, rt.Logger) }()
			go func() { errCh <- partition.Start(ctx, rt.DB, cfg.role, cfg.schema, rt.Logger) }()

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
