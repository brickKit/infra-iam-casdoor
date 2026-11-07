//go:build integration

package itest

import (
	"github.com/brickKit/be-sdk-go/v3/identity"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// tokens: Casdoor's own ID token is no access token (TI04); the development exchange (A101); the binding (TI11).
func (r *iamRun) tokens() {
	t := r.t
	_, aliceIDToken := casdoorSubject(t, "test.alice", r.password)
	_, err := r.verifier.Verify(aliceIDToken)
	var te *identity.TokenError
	require.ErrorAs(t, err, &te, "the provider's ID token is refused")
	t.Logf("Casdoor's ID token refused at %q", te.Problem)

	resp, b := send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": r.password})
	require.Equal(t, 200, resp.StatusCode, string(b))
	r.alice = r.check(b)
	assert.LessOrEqual(t, r.alice.ExpiresIn, 300)
	assert.NotEqual(t, r.otherIssuers, r.alice.Principal, "the same subject of another issuer is not taken over (TI11)")
	u, _ := r.verifier.Verify(r.alice.AccessToken)
	assert.EqualValues(t, 1, u.SecurityVersion, "be_sv: a new account is at 1")
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": r.password})
	assert.Equal(t, r.alice.Principal, r.check(b).Principal, "the same user is the same principal")
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.bob", "password": r.password})
	assert.Equal(t, r.bobBefore, r.check(b).Principal, "an account bound before the issuer was kept keeps its principal")
	resp, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": "wrong"})
	assert.Equal(t, 401, resp.StatusCode, string(b))

	// UI04: the session's token is not on the user surface any more
	var to string
	r.session, to = browserLogin(t, "test.alice", r.password, "/orders")
	assert.Equal(t, "/orders", to)
	resp, _ = send(t, "POST", itBase+"/api/iam/session/token", nil, r.session)
	assert.Equal(t, 501, resp.StatusCode, "no such route")
	r.secrets = append(r.secrets, r.session.Value)
}
