package service

import (
	"context"
	"net"
	"testing"
	"time"

	besdk "github.com/brickKit/be-sdk-go"
	"google.golang.org/grpc"

	authzv1 "github.com/brickKit/infra-authz/gen/infra/authz/v1"

	"github.com/brickKit/infra-iam-casdoor/v2/backend/internal/repo"
)

// fakeAuthz 是 infra-authz 的替身：一个真的在听的 gRPC 服务，ResolveClaims 对任何 sub
// 都回同一组角色。刷新路径先问 claims 再轮换，没有它，刷新在问 claims 那一步就回 503，
// 测不到轮换与撤销。
type fakeAuthz struct {
	authzv1.UnimplementedAuthzServiceServer
}

func (fakeAuthz) ResolveClaims(_ context.Context, req *authzv1.ResolveClaimsRequest) (*authzv1.ResolveClaimsResponse, error) {
	return &authzv1.ResolveClaimsResponse{Roles: []string{"test_role"}, DeptPath: "/1/", OrgId: "1"}, nil
}

// startFakeAuthz 起替身，返回 INFRA_AUTHZ_GRPC_ENDPOINT 的值（与平台注入的形状一样带 http://）。
func startFakeAuthz(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authzv1.RegisterAuthzServiceServer(gs, fakeAuthz{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return "http://" + lis.Addr().String()
}

// newServiceWithAuthz 构造一个连真实 Postgres、拨替身 authz 的 Service，refresh token
// 有效期由调用方给（会话期限的测试要用秒级的有效期）。
func newServiceWithAuthz(t *testing.T, refreshTTL time.Duration) (*Service, *repo.Repo) {
	t.Helper()
	db := testDB(t)
	cfg := besdk.NewConfig(map[string]string{"INFRA_AUTHZ_GRPC_ENDPOINT": startFakeAuthz(t)})
	r := repo.New(db, "infra_iam_casdoor_rw", "infra_iam_casdoor")
	svc := New(r, cfg, "infra_iam_casdoor", testSigningKey(t), "test-kid", nil, "",
		10*time.Minute, refreshTTL, []string{"mdm/customer"},
		"shared-secret-for-test", "X-Shared-Secret")
	forTest(svc)
	return svc, r
}
