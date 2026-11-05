//go:build integration

package iam

import (
	"context"
	"strconv"
	"time"

	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// replay is item 4's T9c (be-protocol P12.19-P12.21, assembly protocol 15's 6.3): the recovery tool replays this
// member's evidence. An account restored to before its changes gets them again as recorded: a disablement (the
// security version up, the status out), a forced logout, a re-enable; a record again is reflected; an account that is
// gone is dangling; a credential tightening is not replayed (6.7 voids the credentials instead).
func (r *iamRun) replay() {
	t := r.t
	m, err := calls.NewMember(nil)
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	m.SetTLS(r.w.TLS(t, "ops/recover"))
	conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
	require.NoError(t, err)
	client := evidence.ReplayClient{Conn: conn}
	p := ids.New().String()
	_, err = r.admin.Exec(r.ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', 'https://replay.test', $2, $3)", p, ids.New().String(), itOrg+"/test.it.replay")
	require.NoError(t, err)
	record := func(category, phase, object string, change map[string]any) []byte {
		rec := map[string]any{"record_type": evidence.RecordType, "schema": "1.0", "id": ids.New().String(),
			"recorder": map[string]any{"component": ID, "instance": "i"}, "category": category, "phase": phase,
			"subject": object, "object": map[string]any{"type": AccountType, "id": object, "version": "1"},
			"change": change, "at": "2026-11-05T10:00:00.000000Z"}
		if phase != "intent" {
			rec["position"] = map[string]any{"epoch": "1.1", "commit_seq": 1}
		}
		s, err := evidence.Seal(rec)
		require.NoError(t, err)
		return s.Record
	}
	replay := func(raw []byte) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
		defer cancel()
		out, _, err := client.Replay(ctx, raw, "r1")
		require.NoError(t, err)
		return out
	}
	account := func() (status string, version int64) {
		require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT status, security_version FROM "+itSchema+".iam_account WHERE principal = $1",
			p).Scan(&status, &version))
		return
	}
	_, v0 := account()

	disable := record("account_status", "effective", p, map[string]any{"status": "disabled", "source": "adapter"})
	assert.Equal(t, evidence.Applied, replay(disable))
	status, v := account()
	assert.Equal(t, "disabled", status)
	assert.Equal(t, v0+1, v, "the security version up, as the change did")
	assert.Equal(t, evidence.AlreadyReflected, replay(disable))
	assert.Equal(t, evidence.Applied, replay(record("session_revocation", "intent", p, map[string]any{"kind": "forced_logout"})),
		"an intent whose conclusion is not in the store: applied after the effective ones")
	_, v = account()
	assert.Equal(t, v0+2, v)
	assert.Equal(t, evidence.Applied, replay(record("account_reenable", "general", p, map[string]any{"status": "active",
		"source": "adapter"})))
	status, _ = account()
	assert.Equal(t, "active", status)
	assert.Equal(t, evidence.Dangling, replay(record("account_status", "effective", ids.New().String(),
		map[string]any{"status": "frozen", "source": "adapter"})))
	assert.Equal(t, evidence.Unsupported, replay(record("credential_tightening", "effective", p,
		map[string]any{"kind": "password", "source": "adapter"})))
}
