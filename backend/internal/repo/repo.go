// Package repo 是 infra-iam-casdoor 的数据访问层：refresh_tokens 的
// 存取/轮换、signing_keys 的元数据登记、webhook_deliveries 的去重、
// user_event_versions 的每人事件版本号、bootstrap_state 的幂等标记。
//
// ⚠️ 没有 users/roles 相关的表——用户主数据在 Casdoor，角色在
// infra-authz，本组件只存"自己签发过什么"。
package repo

import (
	"database/sql"
	"errors"
	"fmt"
)

// ── 哨兵错误。grpc/http 两层通过 service.ToStatus 统一映射（同 infra-authz）──

var ErrNotFound = errors.New("not found")
var ErrInvalidArgument = errors.New("参数不合法")

// ErrRefreshTokenInvalid：refresh token 不存在、已撤销、已过期，或曾被
// 轮换掉后又被重放——四种情况对前端是同一种后果（刷新失败 → 登出），调用方不需要区分，统一映射成 401（同一个错误类型，同一个
// HTTP/gRPC 状态码，见 status.go）。
var ErrRefreshTokenInvalid = errors.New("refresh token 无效")

// ErrSubjectDisabled：这个人最近一次投递处理时在 Casdoor 里是停用、删除或已经不在的，
// 不再给他登记新会话（service 层翻成 401）。
var ErrSubjectDisabled = errors.New("用户在 Casdoor 里已停用")

type Repo struct {
	db     *sql.DB
	role   string
	schema string
}

func New(db *sql.DB, role, schema string) *Repo {
	return &Repo{db: db, role: role, schema: schema}
}

func wrap(action string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func mapConstraintErr(err error, notFoundMsg string) error {
	switch {
	case isForeignKeyViolation(err):
		return fmt.Errorf("%w: %s", ErrNotFound, notFoundMsg)
	case isUniqueViolation(err):
		return fmt.Errorf("%w: 已存在", ErrInvalidArgument)
	default:
		return err
	}
}
