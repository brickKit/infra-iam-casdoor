//go:build integration

package iam

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// op calls a protected account route with a token of principal (the test deployment's issuer).
func (r *iamRun) op(principal, method, path string, body any) (int, map[string]any) {
	r.t.Helper()
	b, err := json.Marshal(body)
	require.NoError(r.t, err)
	req, err := http.NewRequest(method, itBase+path, bytes.NewReader(b))
	require.NoError(r.t, err)
	req.Header.Set("Authorization", r.w.Bearer(principal))
	req.Header.Set("Content-Type", "application/json")
	resp, err := noFollow.Do(req)
	require.NoError(r.t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// lastStatus is the account's last status record sent (be.security.account_status).
func (r *iamRun) lastStatus(principal string) map[string]any {
	var raw string
	require.NoError(r.t, r.admin.QueryRow(r.ctx, "SELECT convert_from(payload, 'UTF8') FROM "+itSchema+".be_outbox WHERE stream = $1 AND "+
		"record_id = $2 ORDER BY seq DESC NULLS FIRST LIMIT 1", StreamAccount, principal).Scan(&raw))
	var rec map[string]any
	require.NoError(r.t, json.Unmarshal([]byte(raw), &rec))
	return rec
}

// evidence waits until the evidence store keeps a record of a category about a principal in a phase, and returns
// the records of that category by phase (item 4 T6b: assembly protocol 15's evidence table).
func (r *iamRun) evidence(principal, category, phase string, at int) map[string][]map[string]any {
	r.t.Helper()
	var out map[string][]map[string]any
	ok := assert.Eventually(r.t, func() bool {
		out = map[string][]map[string]any{}
		for _, raw := range r.w.Evidence() {
			var rec map[string]any
			if json.Unmarshal(raw, &rec) != nil || rec["subject"] != principal || rec["category"] != category {
				continue
			}
			out[rec["phase"].(string)] = append(out[rec["phase"].(string)], rec)
		}
		return len(out[phase]) >= at
	}, 10*time.Second, 100*time.Millisecond, "%s %s %s (at least %d)", principal, category, phase, at)
	if !ok {
		r.t.FailNow()
	}
	return out
}

// casdoorSessions lists the Casdoor sessions of a user (any application).
func casdoorSessions(r *iamRun, ca *http.Client, name string) int {
	_, b := sendWith(r.t, ca, "GET", itCasdoor+"/api/get-sessions?owner="+itOrg, nil)
	var out struct {
		Data []struct{ Name string }
	}
	require.NoError(r.t, json.Unmarshal(b, &out), string(b))
	n := 0
	for _, s := range out.Data {
		if s.Name == name {
			n++
		}
	}
	return n
}

// accountOperations: an administrator's operations on an account (security 03's tightening-only operations, security
// 08's admin accounts, A134): the authorization member is asked first; disabling and freezing reach Casdoor after this
// member, enabling before it; an admin's account waits for a confirmation, which goes into the status record; a
// forced logout ends this member's and Casdoor's sessions; a reset of the second factors is one security change, not
// counted again by the comparison; the comparison leaves an account this member changed within a minute alone.
func (r *iamRun) accountOperations() {
	t := r.t
	ca := casdoorAdmin(t)
	const name = "test.it.accounts"
	pw := "It-Acc-1-" + ids.New().String()[24:]
	r.secrets = append(r.secrets, pw)
	throwawayUser(t, ca, name, pw)
	session, _ := browserLogin(t, name, pw, "")
	r.secrets = append(r.secrets, session.Value)
	ex, err := r.exchange(session, true)
	require.NoError(t, err)
	p := ex.GetPrincipal()
	require.NoError(t, r.pullAsAuthz(), "the baseline")
	v := r.version(p)
	path := func(action string) string { return "/api/iam/accounts/" + p + "/" + action }
	signIn := func() int {
		resp, _ := send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": name, "password": pw})
		return resp.StatusCode
	}

	// seeing an account is not changing it
	r.w.Grant(sectest.Bob, sdkauthz.Segment{ResourceType: Account, Operation: OpAccountView,
		Atoms: map[string]sdkauthz.Atom{AccountDim: {Kind: "all"}}, ReadFields: []string{"principal", "status"},
		Valid: sdkauthz.Window{From: "2026-01-01T00:00:00Z"}})
	var code int
	var out map[string]any
	viewed := func(who string) func() bool { // the member takes the new view at its next verification
		return func() bool { code, out = r.op(who, "GET", "/api/iam/accounts/"+p, nil); return code == 200 }
	}
	require.Eventually(t, viewed(sectest.Bob), 10*time.Second, 100*time.Millisecond, "%d %v", code, out)
	assert.Equal(t, "active", out["status"])
	code, out = r.op(sectest.Bob, "POST", path("disable"), map[string]any{})
	assert.Equal(t, 403, code, "%v", out)
	r.w.GrantAll(sectest.Alice, Definitions())
	require.Eventually(t, viewed(sectest.Alice), 10*time.Second, 100*time.Millisecond, "%d %v", code, out)
	// the same user under another issuer (the throwaway's name: a broken rule touches no seed account)
	elsewhere := ids.New().String()
	_, err = r.admin.Exec(r.ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', 'https://another-casdoor.test', $2, $3)", elsewhere, ids.New().String(), itOrg+"/"+name)
	require.NoError(t, err)
	code, out = r.op(sectest.Alice, "POST", "/api/iam/accounts/"+elsewhere+"/disable", map[string]any{})
	assert.Equal(t, 404, code, "another Casdoor's account is not this member's to change: %v", out)

	// a user's account disabled: asked first, this member, then Casdoor
	before := len(r.w.AccountChecks())
	code, out = r.op(sectest.Alice, "POST", path("disable"), map[string]any{})
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "disabled", out["status"])
	assert.EqualValues(t, v+1, r.version(p))
	checks := r.w.AccountChecks()
	require.Len(t, checks, before+1, "the authorization member was asked once")
	c := checks[before]
	assert.Equal(t, p, c.GetAccount())
	assert.Equal(t, "disabled", c.GetTargetState())
	assert.Equal(t, v, c.GetSecurityVersion(), "the version the change is made on")
	assert.Equal(t, sectest.Alice, c.GetRequester())
	assert.False(t, c.GetSecondPerson(), "a fresh view: one person")
	assert.Equal(t, true, casdoorUser(r, ca, name, nil)["isForbidden"], "forbidden in Casdoor")
	_, err = r.exchange(session, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "the session ended: %v", err)
	assert.Equal(t, 401, signIn())
	st, ev := r.statusOf(p)
	assert.Equal(t, "disabled", st)
	assert.Equal(t, []string{"adapter"}, ev)
	recs := r.evidence(p, "account_status", "effective", 1) // the intent before, the conclusion with the change
	require.Len(t, recs["intent"], 1)
	assert.Equal(t, recs["intent"][0]["id"], recs["effective"][0]["id"])
	assert.Equal(t, "disabled", recs["effective"][0]["change"].(map[string]any)["status"])
	assert.NotNil(t, recs["effective"][0]["position"])
	// the comparison right after it is no rollback, and the same request again changes nothing
	require.NoError(t, r.pullAsAuthz())
	code, out = r.op(sectest.Alice, "POST", path("disable"), map[string]any{})
	require.Equal(t, 200, code, "%v", out)
	_, ev = r.statusOf(p)
	assert.Equal(t, []string{"adapter"}, ev)
	assert.EqualValues(t, v+1, r.version(p))

	// an admin's account: the authorization member asks for a confirmation; refused is refused; with one, enabled
	// (Casdoor first), and the confirmation goes out in the status record, once
	confirmation := ids.New().String()
	r.w.AccountCheck(func(in *authzv3.CheckAccountChangeRequest) *authzv3.CheckAccountChangeResponse {
		switch in.GetConfirmation() {
		case confirmation:
			return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, Administrator: true}
		case "":
			return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED,
				Reason: "an authorization admin's account", Administrator: true}
		}
		return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED,
			Reason: "the confirmation does not bind this account", Administrator: true}
	})
	defer r.w.AccountCheck(nil)
	code, out = r.op(sectest.Alice, "POST", path("enable"), map[string]any{})
	require.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "CONFIRMATION_REQUIRED", out["reason"])
	assert.Equal(t, true, out["administrator"])
	code, out = r.op(sectest.Alice, "POST", path("enable"), map[string]any{"confirmation": ids.New().String()})
	assert.Equal(t, 403, code, "%v", out)
	unprovable := ids.New().String() // its confirmer cannot be proven now (CP92): processing, nothing changes
	r.w.AccountCheck(func(in *authzv3.CheckAccountChangeRequest) *authzv3.CheckAccountChangeResponse {
		return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE,
			Reason: "the confirmer's eligibility cannot be proven now", Administrator: true}
	})
	code, out = r.op(sectest.Alice, "POST", path("enable"), map[string]any{"confirmation": unprovable})
	assert.Equal(t, 202, code, "%v", out)
	assert.Equal(t, "processing", out["outcome"])
	assert.Equal(t, "ADMIN_AVAILABILITY_UNPROVABLE", out["reason"])
	r.w.AccountCheck(func(in *authzv3.CheckAccountChangeRequest) *authzv3.CheckAccountChangeResponse {
		switch in.GetConfirmation() {
		case confirmation:
			return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED, Administrator: true}
		}
		return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_REFUSED, Administrator: true}
	})
	assert.Equal(t, true, casdoorUser(r, ca, name, nil)["isForbidden"], "nothing changed in Casdoor")
	assert.EqualValues(t, v+1, r.version(p), "nothing changed here")
	code, out = r.op(sectest.Alice, "POST", path("enable"), map[string]any{"confirmation": confirmation})
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "active", out["status"])
	assert.EqualValues(t, v+2, r.version(p))
	assert.Equal(t, false, casdoorUser(r, ca, name, nil)["isForbidden"])
	assert.Equal(t, confirmation, r.lastStatus(p)["confirmation"])
	reenable := r.evidence(p, "account_reenable", "general", 1)["general"][0]
	assert.Equal(t, confirmation, reenable["change"].(map[string]any)["confirmation"], "the re-enable's evidence")
	assert.Contains(t, r.logs.String(), `"event":"admin_account_status"`, "an admin's account status change is a severe alert")
	assert.Equal(t, 200, signIn())
	require.NoError(t, r.pullAsAuthz())
	st, ev = r.statusOf(p)
	assert.Equal(t, "active", st, "the comparison takes it as it is")
	assert.Equal(t, []string{"adapter", "adapter"}, ev)

	// a forced logout: this member's sessions and Casdoor's end; the status goes out without the old confirmation
	session, _ = browserLogin(t, name, pw, "")
	r.secrets = append(r.secrets, session.Value)
	require.Positive(t, casdoorSessions(r, ca, name), "precondition: a Casdoor session")
	code, out = r.op(sectest.Alice, "POST", path("logout"), map[string]any{})
	require.Equal(t, 200, code, "%v", out)
	assert.EqualValues(t, v+3, r.version(p))
	_, err = r.exchange(session, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)
	assert.Zero(t, casdoorSessions(r, ca, name), "Casdoor's sessions ended")
	r.evidence(p, "session_revocation", "effective", 1)
	_, carried := r.lastStatus(p)["confirmation"]
	assert.False(t, carried, "a confirmation belongs to the change it confirmed")

	// a reset of the second factors: Casdoor's removed, one security change, not counted again by the comparison
	casdoorUser(r, ca, name, func(u map[string]any) { u["email"], u["mfaEmailEnabled"] = name+"@example.test", true })
	require.NoError(t, r.pullAsAuthz())
	require.EqualValues(t, v+4, r.version(p), "precondition: the second factor added in Casdoor counted once")
	code, out = r.op(sectest.Alice, "POST", path("reset-second-factor"), map[string]any{})
	require.Equal(t, 200, code, "%v", out)
	assert.EqualValues(t, v+5, r.version(p))
	assert.Equal(t, false, casdoorUser(r, ca, name, nil)["mfaEmailEnabled"])
	require.NoError(t, r.pullAsAuthz())
	assert.EqualValues(t, v+5, r.version(p), "not counted twice")
	reset := r.evidence(p, "credential_tightening", "effective", 1)
	assert.Equal(t, "second_factor", reset["effective"][0]["change"].(map[string]any)["kind"])
	product := r.evidence(p, "credential_tightening_in_product", "general", 1)
	assert.Len(t, product["general"], 1, "the factor added in Casdoor is one record; the reset is not counted there again")

	// frozen; a console re-enable within a minute of this member's own change is compared at a later run, then
	// forbidden again (the member's writes in flight are never taken for a rollback)
	r.w.AccountCheck(nil)
	aged := func() { // this member's last status change is old: the comparison compares the status again
		_, err := r.admin.Exec(r.ctx, "UPDATE "+itSchema+".iam_account SET local_change_at = now() - interval '2 minutes' WHERE principal = $1", p)
		require.NoError(t, err)
	}
	rollbacks := func() int {
		_, ev := r.statusOf(p)
		n := 0
		for _, e := range ev {
			if e == "rollback" {
				n++
			}
		}
		return n
	}
	aged()
	code, out = r.op(sectest.Alice, "POST", path("freeze"), map[string]any{})
	require.Equal(t, 200, code, "%v", out)
	assert.Equal(t, "security_frozen", out["status"])
	assert.Equal(t, "security_frozen", r.lastStatus(p)["status"])
	casdoorUser(r, ca, name, func(u map[string]any) { u["isForbidden"] = false })
	require.NoError(t, r.pullAsAuthz())
	assert.Zero(t, rollbacks(), "left alone within a minute of the freeze")
	aged()
	require.NoError(t, r.pullAsAuthz())
	assert.Equal(t, 1, rollbacks())
	assert.Equal(t, true, casdoorUser(r, ca, name, nil)["isForbidden"])

	// the account changed while the authorization member was asked about an enable: Casdoor allowed it already, this
	// member refuses (CHANGE_REVISION_STALE) and stays frozen; the fence keeps the comparison off it for a minute,
	// then it is forbidden again: a failure in between never leaves Casdoor more open than this member
	aged()
	r.w.AccountCheck(func(*authzv3.CheckAccountChangeRequest) *authzv3.CheckAccountChangeResponse {
		_, err := r.admin.Exec(r.ctx, "UPDATE "+itSchema+".iam_account SET security_version = security_version + 1 WHERE principal = $1", p)
		require.NoError(t, err)
		return &authzv3.CheckAccountChangeResponse{Verdict: authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED}
	})
	code, out = r.op(sectest.Alice, "POST", path("enable"), map[string]any{})
	assert.Equal(t, "CHANGE_REVISION_STALE", out["reason"], "%d %v", code, out)
	r.w.AccountCheck(nil)
	st, _ = r.statusOf(p)
	assert.Equal(t, "security_frozen", st)
	require.Equal(t, false, casdoorUser(r, ca, name, nil)["isForbidden"], "precondition: allowed in Casdoor before this member")
	assert.Equal(t, 401, signIn(), "this member refuses it meanwhile")
	require.NoError(t, r.pullAsAuthz())
	assert.Equal(t, 1, rollbacks(), "the enable in flight is fenced")
	aged()
	require.NoError(t, r.pullAsAuthz())
	assert.Equal(t, 2, rollbacks())
	assert.Equal(t, true, casdoorUser(r, ca, name, nil)["isForbidden"])
}
