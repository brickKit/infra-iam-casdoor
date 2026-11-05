//go:build integration

package iam

import (
	"net/http"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recovery is item 4's T9c for a full recovery's 6.6 (assembly protocol 15; be-protocol P1.23): the sessions from
// before a recovery end. A full recovery advances the deployment's recovery generation (step 4): a session created
// before ends at its next exchange (reason recovery); a member started after the advance ends every such session at
// once, writes each to the ended stream the edge reads, and ends the same people's sessions in Casdoor; while the
// recovery runs, no token is issued at all. It runs last: it ends every session.
func (r *iamRun) recovery() {
	t, ctx := r.t, r.ctx
	alice, _ := browserLogin(t, "test.alice", r.password, "")
	bob, _ := browserLogin(t, "test.bob", r.password, "")
	r.secrets = append(r.secrets, alice.Value, bob.Value)
	_, err := r.exchange(alice, true)
	require.NoError(t, err, "precondition: a live session")
	_, err = r.exchange(bob, true)
	require.NoError(t, err)
	ca := casdoorAdmin(t)
	require.Positive(t, casdoorSessions(r, ca, "test.bob"), "precondition: a Casdoor session")

	_, err = r.admin.Exec(ctx, "UPDATE "+itSchema+".be_recovery_generation SET generation = generation + 1") // step 4
	require.NoError(t, err)
	_, err = r.exchange(alice, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "a session from before the recovery: %v", err)
	assert.Equal(t, "recovery", r.endReason(alice))
	assert.Equal(t, "", r.endReason(bob), "not used yet: still open in the database")

	r.restart(map[string]string{"RECOVERY_PHASE": "frozen"})
	assert.Equal(t, "", r.endReason(bob), "frozen: the database may be under restore, nothing is written")
	r.restart(map[string]string{"RECOVERY_PHASE": "replaying"})
	assert.Equal(t, "recovery", r.endReason(bob), "the member started after the advance ends it")
	// the edge's cursor is of the epoch before the recovery: it is told to reset (it drops every cached token, protocol
	// 15's 6.6: Alice's end is covered by that), then reads the ends of the new epoch by position
	page := r.ended(r.cursor)
	assert.True(t, page.GetReset_(), "the recovery's new epoch resets the edge")
	seen, cursor := map[string]bool{}, page.GetNext()
	require.Eventually(t, func() bool {
		page := r.ended(cursor)
		for _, d := range page.GetSessionDigests() {
			seen[d] = true
		}
		cursor = page.GetNext()
		return seen[digest(bob)]
	}, time.Minute, 200*time.Millisecond, "the sweep's end in the ended stream") // the stopped member's forwarding
	// lease of the partition runs out first (be-sdk-go does not give it up on a graceful stop: up to its lease and a poll)
	assert.Zero(t, casdoorSessions(r, ca, "test.bob"), "the same person's sessions in Casdoor")
	_, err = r.exchange(bob, true)
	assert.ErrorContains(t, err, errs.ReasonMaintenance, "no token while the recovery runs (the caller's side wraps it as "+
		"a dependency unavailable)")
	assert.Contains(t, r.logs.String(), `"event":"sessions_ended_by_recovery"`)
}

// endReason is a session's end reason ("" while it is live).
func (r *iamRun) endReason(c *http.Cookie) string {
	var reason *string
	require.NoError(r.t, r.admin.QueryRow(r.ctx, "SELECT end_reason FROM "+itSchema+".iam_session WHERE id_hash = $1",
		digest(c)).Scan(&reason))
	if reason == nil {
		return ""
	}
	return *reason
}
