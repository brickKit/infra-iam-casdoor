package iam

import (
	"context"
	"encoding/json"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/events"
)

// accountStream is the account status: a watermark source of the authorization member (security 03's internal
// sources, D64), so it answers the member's pulls and its batch reads and snapshots (P9.13, P9.30). An account is never
// deleted: an ID that is not one is purged (never existed).
var accountStream = events.Stream{Name: StreamAccount, Partitions: 4,
	Watermark: &events.Watermark{Operation: OpAccountPull, Pullers: []string{Authz}},
	Records:   &events.Records{Operation: OpAccountRead, Readers: []string{Authz}, Read: readAccounts, Page: pageAccounts}}

// readAccounts answers every ID with the status record that went out last: the same bytes as its event.
func readAccounts(ctx context.Context, tx db.Tx, ids []string) ([]events.ReadResult, error) {
	rows, err := tx.Query(ctx, `SELECT principal::text, security_version, status_record FROM iam_account
		WHERE principal::text = ANY($1) AND status_record IS NOT NULL`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]events.ReadResult{}
	for rows.Next() {
		var r events.ReadResult
		var raw []byte
		if err := rows.Scan(&r.ID, &r.Version, &raw); err != nil {
			return nil, err
		}
		r.State, r.Data = events.Exists, json.RawMessage(raw)
		found[r.ID] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]events.ReadResult, len(ids))
	for i, id := range ids {
		if r, ok := found[id]; ok {
			out[i] = r
		} else {
			out[i] = events.ReadResult{ID: id, State: events.Purged}
		}
	}
	return out, nil
}

// pageAccounts is the snapshot: the accounts whose status went out, by principal (its text, bytes ascending).
func pageAccounts(ctx context.Context, tx db.Tx, after string, limit int) ([]events.Record, error) {
	rows, err := tx.Query(ctx, `SELECT principal::text, security_version, status_record FROM iam_account
		WHERE status_record IS NOT NULL AND principal::text > $1 ORDER BY principal::text COLLATE "C" LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []events.Record
	for rows.Next() {
		var r events.Record
		var raw []byte
		if err := rows.Scan(&r.ID, &r.Version, &raw); err != nil {
			return nil, err
		}
		r.Data = json.RawMessage(raw)
		out = append(out, r)
	}
	return out, rows.Err()
}
