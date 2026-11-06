//go:build integration

package iam

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
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
// gone is dangling; a credential tightening is checked against Casdoor, not replayed (6.7).
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
	var disabled map[string]any
	require.NoError(t, json.Unmarshal(disable, &disabled))
	assert.Equal(t, disabled["id"], r.lastStatus(p)["evidence"],
		"a replayed status names the original evidence record: the signal_ref is the same across the recovery")
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
	// a freeze (T13e's drill: its replay answered an internal error, the status's value is security_frozen)
	assert.Equal(t, evidence.Applied, replay(record("account_status", "effective", p, map[string]any{"status": "security_frozen",
		"source": "adapter"})))
	status, _ = account()
	assert.Equal(t, "security_frozen", status)
	assert.Equal(t, evidence.Dangling, replay(record("account_status", "effective", ids.New().String(),
		map[string]any{"status": "security_frozen", "source": "adapter"})))
	r.credentialChecks(record, replay)
}

// credentialChecks is 6.7 with Casdoor outside the recovery group (A141; be-protocol P12.20): a credential tightening
// is not replayed but checked against Casdoor: a password changed by this member holds when Casdoor's last password
// change is not earlier than the record; a reset of the second factors holds when Casdoor has none now or changed
// since; a change seen in Casdoor holds when Casdoor has not gone back past what was seen. Not so, or no such account,
// for review.
func (r *iamRun) credentialChecks(record func(category, phase, object string, change map[string]any) []byte,
	replay func([]byte) string) {
	t := r.t
	ca := casdoorAdmin(t)
	const name = "test.it.credcheck"
	pw, pw2 := "It-Cred-1-"+ids.New().String()[24:], "It-Cred-2-"+ids.New().String()[24:]
	r.secrets = append(r.secrets, pw, pw2)
	throwawayUser(t, ca, name, pw)
	p := ids.New().String()
	_, err := r.admin.Exec(r.ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', 'https://replay.test', $2, $3)", p, ids.New().String(), itOrg+"/"+name)
	require.NoError(t, err)
	at := func(rec []byte, when time.Time) []byte { // the record again, recorded at another time
		const was = `"at":"2026-11-05T10:00:00.000000Z"`
		require.Contains(t, string(rec), was)
		return []byte(strings.Replace(string(rec), was, `"at":"`+when.UTC().Format("2006-01-02T15:04:05.000000Z")+`"`, 1))
	}
	before := time.Now().Add(-time.Minute)
	resp, err := ca.PostForm(itCasdoor+"/api/set-password", url.Values{"userOwner": {itOrg}, "userName": {name},
		"newPassword": {pw2}})
	require.NoError(t, err)
	resp.Body.Close()
	password := record("credential_tightening", "effective", p, map[string]any{"kind": "password", "source": "adapter"})
	assert.Equal(t, evidence.Consistent, replay(at(password, before)), "Casdoor's password changed after the record")
	assert.Equal(t, evidence.Inconsistent, replay(at(password, time.Now().Add(time.Hour))),
		"Casdoor's last password change is earlier than the record: Casdoor went back")
	factors := record("credential_tightening", "intent", p, map[string]any{"kind": "second_factor", "source": "adapter"})
	assert.Equal(t, evidence.Consistent, replay(at(factors, time.Now().Add(time.Hour))), "no second factor in Casdoor")
	casdoorUser(r, ca, name, func(u map[string]any) { u["email"], u["mfaEmailEnabled"] = name+"@example.test", true })
	assert.Equal(t, evidence.Inconsistent, replay(at(factors, time.Now().Add(time.Hour))),
		"a second factor in Casdoor, not changed since the reset")
	assert.Equal(t, evidence.Consistent, replay(at(factors, before)), "a factor added after the reset")
	updated, _ := casdoorUser(r, ca, name, nil)["updatedTime"].(string)
	require.NotEmpty(t, updated)
	assert.Equal(t, evidence.Consistent, replay(record("credential_tightening_in_product", "general", p,
		map[string]any{"kind": "second_factor", "product_updated": updated})), "Casdoor as seen, or later")
	assert.Equal(t, evidence.Inconsistent, replay(record("credential_tightening_in_product", "general", p,
		map[string]any{"kind": "password", "product_updated": time.Now().Add(time.Hour).Format(time.RFC3339)})),
		"Casdoor older than what was seen")
	assert.Equal(t, evidence.Inconsistent, replay(record("credential_tightening", "effective", ids.New().String(),
		map[string]any{"kind": "password", "source": "adapter"})), "no such account here")
}
