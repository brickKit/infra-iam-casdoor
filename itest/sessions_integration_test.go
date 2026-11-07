//go:build integration

package itest

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// edgeSessions: the edge's SessionService over mTLS (P8.28), and a polling exchange that does not renew (protocol 20).
func (r *iamRun) edgeSessions() {
	t, ctx := r.t, r.ctx
	r.edge = r.sessions(core.Edge)
	start := r.ended(nil)
	assert.True(t, start.GetReset_(), "no cursor: start at the end")
	ex, err := r.exchange(r.session, true)
	require.NoError(t, err)
	assert.EqualValues(t, 1, r.verify(ex.GetAccessToken(), r.alice.Principal).SecurityVersion)
	assert.Equal(t, r.alice.Principal, ex.GetPrincipal(), "the browser login and the exchange agree on the principal")
	assert.LessOrEqual(t, ex.GetExpiresAtMs(), ex.GetSessionUntilMs(), "the token ends no later than the session")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = r.sessions("erp/sales").Exchange(cctx, &sessionpb.ExchangeRequest{SessionDigest: digest(r.session)})
	cancel()
	assert.True(t, errs.Is(err, "be", errs.ReasonPermissionDenied), "only the edge may exchange: %v", err)
	_, err = r.exchange(&http.Cookie{Value: "forged"}, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)

	seen := func() time.Time {
		var at time.Time
		require.NoError(t, r.admin.QueryRow(ctx, "SELECT last_seen FROM "+itSchema+".iam_session WHERE id_hash = $1",
			digest(r.session)).Scan(&at))
		return at
	}
	_, err = r.admin.Exec(ctx, "UPDATE "+itSchema+".iam_session SET last_seen = now() - interval '10 minutes' WHERE id_hash = $1", digest(r.session))
	require.NoError(t, err)
	before := seen()
	_, err = r.exchange(r.session, false)
	require.NoError(t, err)
	assert.Equal(t, before, seen(), "renew_idle false")
	_, err = r.exchange(r.session, true)
	require.NoError(t, err)
	assert.True(t, seen().After(before.Add(9*time.Minute)), "renew_idle true")
}

// passwordChange: the password change through the member (protocol 20, UI22's identity side), on a throwaway user.
func (r *iamRun) passwordChange() {
	t, ctx := r.t, r.ctx
	ca := casdoorAdmin(t)
	first, second := "It-Pass-1-"+ids.New().String()[24:], "It-Pass-2-"+ids.New().String()[24:]
	r.secrets = append(r.secrets, first, second)
	throwawayUser(t, ca, itThrowaway, first)
	keep, _ := browserLogin(t, itThrowaway, first, "")
	r.secrets = append(r.secrets, keep.Value)
	kept, err := r.exchange(keep, true)
	require.NoError(t, err)
	r.throwaway = kept.GetPrincipal()
	statuses := func() (n int) {
		require.NoError(t, r.admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_outbox WHERE stream = $1 AND record_id = $2",
			core.StreamAccount, r.throwaway).Scan(&n))
		return n
	}
	assert.Equal(t, 1, statuses(), "a new account's status goes out when it is bound")
	other, _ := browserLogin(t, itThrowaway, first, "")
	assert.Equal(t, 1, statuses(), "a later login sends nothing")
	r.cursor = r.ended(nil).GetNext()
	resp, b := send(t, "POST", itBase+"/api/iam/password", map[string]string{"old_password": "wrong", "new_password": second}, keep)
	assert.Equal(t, 400, resp.StatusCode, string(b))
	assert.EqualValues(t, 1, r.version(r.throwaway), "a refused change changes nothing")
	resp, b = send(t, "POST", itBase+"/api/iam/password", map[string]string{"old_password": first, "new_password": second}, keep)
	require.Equal(t, 204, resp.StatusCode, string(b))
	assert.EqualValues(t, 2, r.version(r.throwaway))
	// the refused change's intent is cancelled; the change's intent concludes effective (item 4 T6b)
	pw := r.evidence(r.throwaway, "credential_tightening", "effective", 1)
	assert.Len(t, pw["cancelled"], 1, "the refused change")
	assert.Equal(t, "password", pw["effective"][0]["change"].(map[string]any)["kind"])
	_, err = r.exchange(other, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "the other session ended: %v", err)
	kept, err = r.exchange(keep, true)
	require.NoError(t, err, "the session that made the change goes on")
	assert.EqualValues(t, 2, r.verify(kept.GetAccessToken(), r.throwaway).SecurityVersion, "with a token of the new version")
	r.endedSince(digest(other)) // the edge reads the other session's end, not the kept one
	var statusRows int
	require.NoError(t, r.admin.QueryRow(ctx, "SELECT count(*), max(payload::text)::bytea FROM "+itSchema+".be_outbox "+
		"WHERE stream = $1 AND record_id = $2", core.StreamAccount, r.throwaway).Scan(&statusRows, &r.payload))
	assert.Equal(t, 2, statusRows, "the account's status went out when it was bound and when it changed")
	assert.Contains(t, string(r.payload), `"security_version":2`)
	_, newPasswordWorks := casdoorSubjectOK(t, itThrowaway, second)
	assert.True(t, newPasswordWorks, "Casdoor has the new password")
}

// idleAndLogout: the idle timeout ends a session; a second login, then logout; the edge reads both ends.
func (r *iamRun) idleAndLogout() {
	t, ctx := r.t, r.ctx
	_, err := r.admin.Exec(ctx, "UPDATE "+itSchema+".iam_session SET last_seen = now() - interval '31 minutes' WHERE id_hash = $1", digest(r.session))
	require.NoError(t, err)
	_, err = r.exchange(r.session, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)
	var reason string
	require.NoError(t, r.admin.QueryRow(ctx, "SELECT end_reason FROM "+itSchema+".iam_session WHERE id_hash = $1",
		digest(r.session)).Scan(&reason))
	assert.Equal(t, "idle", reason)
	r.endedSince(digest(r.session))

	second, to := browserLogin(t, "test.alice", r.password, "")
	assert.Equal(t, "/home", to, "without return_to: IAM_AFTER_LOGIN_URL")
	resp, _ := send(t, "POST", itBase+"/api/iam/logout", nil, second)
	assert.Equal(t, 204, resp.StatusCode)
	assert.True(t, strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0"), "the browser forgets the cookie")
	_, err = r.exchange(second, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "a logged-out session gives no token: %v", err)
	r.endedSince(digest(second))
}
