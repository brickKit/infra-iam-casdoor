// Package consumer 消费唯一一条订阅：infra.authz.user_role.changed.v1
// （设计计划 §4）——只在"踢人"（change_type: kicked）时作废该用户的
// refresh token，普通的角色增减/到期不触碰 refresh token（下次刷新
// 自然拿到新角色，设计计划 §4 的明文警告）。
package consumer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	besdk "github.com/brickKit/be-sdk-go"
	"github.com/nats-io/nats.go"

	"github.com/brickKit/infra-iam-casdoor/backend/internal/repo"
)

const subjectUserRoleChanged = "infra.authz.user_role.changed.v1"

func Start(ctx context.Context, db *sql.DB, role, schema string, nc *nats.Conn, logger *slog.Logger) error {
	return besdk.Consume(ctx, nc, db, role, schema, subjectUserRoleChanged, userRoleChangedHandler(logger))
}

// userRoleChangedPayload 字段照抄 infra-authz 已经真实发布的契约
// （contracts/events/authz.events.json）。
type userRoleChangedPayload struct {
	Sub        string `json:"sub"`
	RoleCode   string `json:"role_code"`
	ChangeType string `json:"change_type"` // granted / revoked / expired / kicked
}

// userRoleChangedHandler 用 RevokeAllRefreshTokensForSubTx（不是
// RevokeAllRefreshTokensForSub）——besdk.Consume 给的 tx 已经在一个
// 事务里（inbox 去重记录也在这个事务里），复用同一个 tx 而不是让
// repo 层再开一个独立事务，"撤销 token"与"记录这条事件已处理"才是
// 原子的（见 refreshtokens.go 的详细注释）。
func userRoleChangedHandler(logger *slog.Logger) func(context.Context, *sql.Tx, besdk.Event) error {
	return func(ctx context.Context, tx *sql.Tx, ev besdk.Event) error {
		var p userRoleChangedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return fmt.Errorf("解析 %s payload: %w", ev.Subject, err)
		}
		if p.ChangeType != "kicked" {
			// 普通角色增减/到期：不动 refresh token，下次刷新自然拿到
			// 新角色（设计计划 §4 的明文要求）。
			return nil
		}
		if p.Sub == "" {
			logger.Warn("收到 kicked 事件但 sub 为空，跳过", "aggregate_id", ev.AggregateID)
			return nil
		}
		return repo.RevokeAllRefreshTokensForSubTx(ctx, tx, p.Sub)
	}
}
