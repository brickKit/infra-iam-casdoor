package repo

import (
	"context"
	"database/sql"

	besdk "github.com/brickKit/be-sdk-go"
)

type SigningKey struct {
	Kid string
	Alg string
}

// UpsertSigningKey 幂等登记一把签名密钥的元数据——启动时对
// appTokenSigningKeyPem/appTokenPreviousPublicKeyPem 各算一次 kid（公钥
// JWK thumbprint）后调用（设计计划 §3.3、§9 第 1b 条）。kid 是确定性
// 推导出来的（同一把钥匙每次启动都算出同一个 kid），ON CONFLICT DO
// NOTHING 保证重复调用不覆盖 not_before——它记的是"第一次被观测到"的
// 时间，不是"最近一次启动"的时间。
//
// ⚠️ 私钥本身不落库（设计计划 §2 明文警告）：这张表只有 kid/alg 两个
// 业务字段，没有任何跟私钥材料相关的列。
func (r *Repo) UpsertSigningKey(ctx context.Context, kid, alg string) error {
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO signing_keys (kid, alg) VALUES ($1, $2)
			 ON CONFLICT (kid) DO NOTHING`, kid, alg)
		return err
	})
	return wrap("登记签名密钥元数据", err)
}

// ListSigningKeys 供管理/排查用：这个部署历史上出现过哪些 kid。
func (r *Repo) ListSigningKeys(ctx context.Context) ([]SigningKey, error) {
	var out []SigningKey
	err := besdk.WithTx(ctx, r.db, r.role, r.schema, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT kid, alg FROM signing_keys ORDER BY not_before`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SigningKey
			if err := rows.Scan(&k.Kid, &k.Alg); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, wrap("列出签名密钥元数据", err)
}
