// Package grpc 实现 infra.iam.v1.IamService——本组件仅有的两个同步读
// 接口（设计计划 §3：账密校验/MFA/token 签发刷新登出全部不在这份契约
// 里，那些走 REST 或浏览器直连 Casdoor）。
package grpc

import (
	"context"
	"fmt"
	"sync/atomic"

	iamv1 "github.com/brickKit/infra-iam-casdoor/gen/infra/iam/v1"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/casdoor"
)

// server 持有一个指向 Casdoor 管理会话的原子指针，而不是直接持有会话
// 本身——RegisterGRPC（拨号+挂载）与 Start()（真正登录 Casdoor）是并发
// 跑的两件事（standalone.go：serveExtraPort 与 mod.Start 在各自的
// goroutine 里同时起步），gRPC server 构造那一刻登录可能还没完成。
// 每次调用时才 Load()，比"构造时传一个可能还是 nil 的裸指针"更安全。
//
// ⚠️ 另一个已知简化：Casdoor 的管理 API 是会话 cookie 认证，理论上可能
// 过期（多久过期未核实）；本组件目前没有做"401 时自动重新登录"的重试
// 逻辑——会话一旦过期，BatchGetUsers 会开始报错，直到组件重启换一条
// 新会话。这与已登录用户的应用 token 刷新（服务的是完全不同的一条
// 会话）无关，只影响这一个内部只读查询接口，可接受的初版范围，需要时
// 再补重连。
type server struct {
	iamv1.UnimplementedIamServiceServer
	admin   *atomic.Pointer[casdoor.AdminClient]
	enabled []string
}

func New(admin *atomic.Pointer[casdoor.AdminClient], enabledComponents []string) iamv1.IamServiceServer {
	return &server{admin: admin, enabled: enabledComponents}
}

// BatchGetUsers 逐个回源 Casdoor 查（§3.8 的 batchGet 惯例：省掉查不到
// 的那一个，不报错——同 infra-authz 的 BatchGetRoles）。⚠️ 本组件不落
// 一张 users 影子表，每次都是真实的 Casdoor API 调用（设计计划 §2 末尾：
// "那等于把 slot:iam 的可替换性又焊死一次"）；Casdoor 没有暴露批量按
// UUID 查用户的接口，这里的"批量"体现在**调用方**只需要一次 gRPC 往返
// （防的是调用方的 N+1，不是本组件到 Casdoor 之间的 N+1——那一段是
// admin 会话走内网，成本与用户体验无关）。
func (s *server) BatchGetUsers(ctx context.Context, req *iamv1.BatchGetUsersRequest) (*iamv1.BatchGetUsersResponse, error) {
	admin := s.admin.Load()
	if admin == nil {
		return nil, fmt.Errorf("Casdoor 管理会话尚未就绪")
	}
	users := make([]*iamv1.User, 0, len(req.Subs))
	for _, sub := range req.Subs {
		u, err := admin.GetUserBySub(ctx, sub)
		if err != nil || u == nil {
			continue
		}
		pu := &iamv1.User{
			Sub: u.ID, DisplayName: u.DisplayName, Email: u.Email, Phone: u.Phone,
		}
		if u.Dingtalk != "" {
			pu.ImAccounts = append(pu.ImAccounts, &iamv1.ImAccount{Channel: "dingtalk", AccountId: u.Dingtalk})
		}
		users = append(users, pu)
	}
	return &iamv1.BatchGetUsersResponse{Users: users}, nil
}

// GetTenantFeatures 是 gRPC 版的 features 清单，内容与 GET
// /api/tenant/features 完全一致（同一份 enabled 切片）。
func (s *server) GetTenantFeatures(ctx context.Context, _ *iamv1.GetTenantFeaturesRequest) (*iamv1.GetTenantFeaturesResponse, error) {
	return &iamv1.GetTenantFeaturesResponse{EnabledComponents: s.enabled}, nil
}
