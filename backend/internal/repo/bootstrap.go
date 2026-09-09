package repo

import (
	"context"
	"database/sql"
	"encoding/json"

	besdk "github.com/brickKit/be-sdk-go"
)

// BootstrapStep 是 bootstrap_state 一行的读出结果。Done 为 false 表示
// 这一步还没做过或还没确认过——调用方（bootstrap 包）据此决定要不要
// 重新跑一遍这一步的 Casdoor 管理 API 调用（设计计划 §9 第 5 条：
// "每次启动都对账"，每一步都要能安全重跑）。
type BootstrapStep struct {
	Done   bool
	Detail json.RawMessage
}

// GetBootstrapStep 读一步的状态。这一步从未出现过时返回 Done=false、
// Detail=nil，不是错误——bootstrap_state 只登记"发生过的步骤"。
func (r *Repo) GetBootstrapStep(ctx context.Context, step string) (BootstrapStep, error) {
	var out BootstrapStep
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		var doneAt sql.NullTime
		var detail []byte
		row := tx.QueryRowContext(ctx,
			`SELECT done_at, detail FROM bootstrap_state WHERE step = $1`, step)
		switch err := row.Scan(&doneAt, &detail); {
		case err == sql.ErrNoRows:
			return nil
		case err != nil:
			return err
		}
		out.Done = doneAt.Valid
		out.Detail = detail
		return nil
	})
	return out, wrap("读自举步骤状态", err)
}

// MarkBootstrapStepDone 幂等地把一步标记完成，并记下这一步产生的可复用
// 信息（如建好的 Casdoor 应用 client_id/client_secret）。多次调用是安全
// 的——每次都是整行覆盖，不是"只在第一次写入"。
func (r *Repo) MarkBootstrapStepDone(ctx context.Context, step string, detail json.RawMessage) error {
	if detail == nil {
		detail = json.RawMessage(`{}`)
	}
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO bootstrap_state (step, done_at, detail) VALUES ($1, now(), $2)
			 ON CONFLICT (step) DO UPDATE SET done_at = now(), detail = $2, updated_at = now()`,
			step, []byte(detail))
		return err
	})
	return wrap("登记自举步骤完成", err)
}
