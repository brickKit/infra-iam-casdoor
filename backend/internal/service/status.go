package service

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ToStatus 把本层的哨兵错误翻成 gRPC status——HTTP 层的
// grpcCodeToHTTPStatus（be-sdk-go gin.go）再把它翻成 HTTP 状态码，两条
// 对外接口共用同一套业务错误类型（同 infra-authz 的判据）。
//
// ⚠️ ErrUnauthenticated 映射到 Unauthenticated（HTTP 401），不是
// PermissionDenied（HTTP 403）——这两个语义不同：401 说"你没有证明你是
// 谁"，403 说"你已经证明了但没有权限"。本组件的 REST 面全部是 Public/
// Authenticated（没有具体权限键），发生错误的地方全部属于前者。
func ToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrDependencyUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
