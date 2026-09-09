package service

import "errors"

// ── 哨兵错误。HTTP 与 gRPC 两层通过 ToStatus 统一映射（同 infra-authz
// 等既有组件的判据）。────────────────────────────────────────────────

// ErrUnauthenticated：调用方给的凭据（Casdoor 身份 token / refresh
// token）验签失败、格式不对，或已经不再有效。
var ErrUnauthenticated = errors.New("凭据无效")

// ErrUnavailable：本组件自己的某个前置条件还没就绪——目前只有一种情况，
// Casdoor 的 OIDC 发现/JWKS 验证器还没能成功初始化过一次（module.go 的
// 后台重试循环还在跑）。这与"凭据无效"是完全不同的原因，不能合并成
// 同一个错误码，否则运维排查时会把"Casdoor 还没起来"误判成"这个 token
// 真的是假的"。
var ErrUnavailable = errors.New("依赖尚未就绪")

// ErrDependencyUnavailable：调用 infra-authz 的 ResolveClaims 失败
// （网络问题、infra-authz 本身挂了）。设计计划 §5 明文的 fail-closed
// 决策：签发这一步不留 claims 兜底缓存，宁可让这次登录/刷新失败，也
// 不要签出一个带着过期角色的 token。
var ErrDependencyUnavailable = errors.New("依赖服务不可用")
