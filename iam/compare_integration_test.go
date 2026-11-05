//go:build integration

package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// pullAsAuthz pulls the account stream as the authorization member does (echo only): before the echo the member
// compares every bound account with Casdoor (P9.16, security 03). The request is built from the registered
// descriptor (the SDK's source messages are internal to it).
func (r *iamRun) pullAsAuthz() error {
	desc := func(name string) protoreflect.MessageDescriptor {
		d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
		require.NoError(r.t, err)
		return d.(protoreflect.MessageDescriptor)
	}
	req, resp := dynamicpb.NewMessage(desc("be.source.v1.PullRequest")), dynamicpb.NewMessage(desc("be.source.v1.PullResponse"))
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	req.Set(req.Descriptor().Fields().ByName("stream"), protoreflect.ValueOfString(StreamAccount))
	req.Set(req.Descriptor().Fields().ByName("nonce"), protoreflect.ValueOfString(hex.EncodeToString(b)))
	m, err := calls.NewMember(nil)
	require.NoError(r.t, err)
	defer m.Close()
	m.SetTLS(r.w.TLS(r.t, Authz))
	conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
	require.NoError(r.t, err)
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	return conn.Invoke(ctx, "/be.source.v1.WatermarkService/Pull", req, resp, calls.Idempotent())
}

// casdoorUser edits a Casdoor user as its console does (the built-in admin): the user read, changed, written back.
func casdoorUser(r *iamRun, ca *http.Client, name string, change func(map[string]any)) map[string]any {
	_, got := sendWith(r.t, ca, "GET", itCasdoor+"/api/get-user?id="+itOrg+"/"+name, nil)
	var u struct{ Data map[string]any }
	require.NoError(r.t, json.Unmarshal(got, &u))
	require.NotNil(r.t, u.Data)
	if change == nil {
		return u.Data
	}
	change(u.Data)
	_, b := sendWith(r.t, ca, "POST", itCasdoor+"/api/update-user?id="+url.QueryEscape(itOrg+"/"+name), u.Data)
	require.Contains(r.t, string(b), `"ok"`, string(b))
	return u.Data
}

func (r *iamRun) statusOf(principal string) (status string, evidence []string) {
	require.NoError(r.t, r.admin.QueryRow(r.ctx, "SELECT status FROM "+itSchema+".iam_account WHERE principal = $1",
		principal).Scan(&status))
	rows, err := r.admin.Query(r.ctx, "SELECT source FROM "+itSchema+".iam_status_evidence WHERE principal = $1 ORDER BY recorded_at",
		principal)
	require.NoError(r.t, err)
	defer rows.Close()
	for rows.Next() {
		var s string
		require.NoError(r.t, rows.Scan(&s))
		evidence = append(evidence, s)
	}
	return status, evidence
}

// comparison: what changes in Casdoor itself becomes this member's facts at the next comparison (security 03, AT37,
// AT49): a console disablement takes effect with evidence; a console re-enable is a rollback, forbidden again; a
// password or second-factor change there is a security change; the member's own password change is not counted twice.
func (r *iamRun) comparison() {
	t := r.t
	ca := casdoorAdmin(t)
	const name, other = "test.it.compare", "test.it.compare2"
	pw, pw2 := "It-Cmp-1-"+ids.New().String()[24:], "It-Cmp-2-"+ids.New().String()[24:]
	r.secrets = append(r.secrets, pw, pw2)
	throwawayUser(t, ca, name, pw)
	throwawayUser(t, ca, other, pw)
	session, _ := browserLogin(t, name, pw, "")
	ex, err := r.exchange(session, true)
	require.NoError(t, err)
	p := ex.GetPrincipal()
	// the same subject bound under another issuer is another identity: this Casdoor's state is not compared with it
	sub, _ := casdoorSubject(t, name, pw)
	elsewhere := ids.New().String()
	_, err = r.admin.Exec(r.ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', 'https://another-casdoor.test', $2, 'brickkit/"+name+"')", elsewhere, sub)
	require.NoError(t, err)
	require.NoError(t, r.pullAsAuthz(), "the first comparison takes Casdoor's state as the baseline")
	assert.EqualValues(t, 1, r.version(p), "a baseline is no change")

	// a console disablement takes effect: one version up, the session ended, the status out, the evidence kept
	casdoorUser(r, ca, name, func(u map[string]any) { u["isForbidden"] = true })
	require.NoError(t, r.pullAsAuthz())
	assert.EqualValues(t, 2, r.version(p))
	st, ev := r.statusOf(p)
	assert.Equal(t, "disabled", st)
	assert.Equal(t, []string{"console"}, ev)
	console := r.evidence(p, "account_status", "effective", 1)
	require.Len(t, console["intent"], 1, "the intent before the comparison's transaction")
	assert.Equal(t, "console", console["effective"][0]["change"].(map[string]any)["source"])
	_, err = r.exchange(session, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "the session ended: %v", err)
	st, _ = r.statusOf(elsewhere)
	assert.Equal(t, "active", st, "another issuer's account with the same subject is not this Casdoor's")
	var last string
	require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT convert_from(payload, 'UTF8') FROM "+itSchema+".be_outbox WHERE stream = $1 AND "+
		"record_id = $2 ORDER BY seq DESC NULLS FIRST LIMIT 1", StreamAccount, p).Scan(&last))
	assert.Contains(t, last, `"status":"disabled"`)

	// a console re-enable (or a product rollback) is no enable: forbidden there again, the evidence says so
	casdoorUser(r, ca, name, func(u map[string]any) { u["isForbidden"] = false })
	resp, _ := send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": name, "password": pw})
	assert.Equal(t, 401, resp.StatusCode, "Casdoor lets it in again, this member does not (before the next comparison)")
	require.NoError(t, r.pullAsAuthz())
	assert.Equal(t, true, casdoorUser(r, ca, name, nil)["isForbidden"], "forbidden in Casdoor again")
	st, ev = r.statusOf(p)
	assert.Equal(t, "disabled", st)
	assert.Equal(t, []string{"console", "rollback"}, ev)
	rolled := r.evidence(p, "account_status", "general", 1)["general"][0]
	assert.Equal(t, "rollback", rolled["change"].(map[string]any)["source"], "an enable seen in Casdoor is recorded too")
	assert.EqualValues(t, 2, r.version(p), "the status did not change here")
	resp, _ = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": name, "password": pw})
	assert.Equal(t, 401, resp.StatusCode, "a disabled account does not sign in")

	// a password changed in Casdoor itself, and a change of the second factors, are security changes
	s2, _ := browserLogin(t, other, pw, "")
	ex, err = r.exchange(s2, true)
	require.NoError(t, err)
	q := ex.GetPrincipal()
	require.NoError(t, r.pullAsAuthz())
	form := url.Values{"userOwner": {itOrg}, "userName": {other}, "newPassword": {pw2}}
	resp, err = ca.PostForm(itCasdoor+"/api/set-password", form)
	require.NoError(t, err)
	resp.Body.Close()
	time.Sleep(1100 * time.Millisecond) // Casdoor's times have one-second precision
	require.NoError(t, r.pullAsAuthz())
	assert.EqualValues(t, 2, r.version(q), "the password changed in Casdoor")
	inProduct := r.evidence(q, "credential_tightening_in_product", "general", 1)["general"][0]
	assert.Equal(t, "password", inProduct["change"].(map[string]any)["kind"])
	_, err = r.exchange(s2, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)
	casdoorUser(r, ca, other, func(u map[string]any) { u["email"], u["mfaEmailEnabled"] = other+"@example.test", true })
	require.NoError(t, r.pullAsAuthz())
	assert.EqualValues(t, 3, r.version(q), "the second factors changed in Casdoor")

	// the member's own password change is not counted again by the next comparison
	s3, _ := browserLogin(t, other, pw2, "")
	r.secrets = append(r.secrets, s3.Value)
	resp, b := send(t, "POST", itBase+"/api/iam/password", map[string]string{"old_password": pw2, "new_password": pw}, s3)
	require.Equal(t, 204, resp.StatusCode, string(b))
	assert.EqualValues(t, 4, r.version(q))
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, r.pullAsAuthz())
	assert.EqualValues(t, 4, r.version(q), "not counted twice")
	_, err = r.exchange(s3, true)
	assert.NoError(t, err, "the session that changed it goes on")
}
