package iam

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/mergesafety"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPEM(t *testing.T) string {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// testModule is the token half of the module, with keys that tests can rotate.
func testModule(t *testing.T, cur, next *string) *Module {
	return &Module{issuer: "https://iam.test/", audience: "be:deployment:0190f3a1-0000-7000-8000-00000000d001",
		ttl: DefaultTokenTTL, keys: &keyRing{current: func() string { return *cur }, next: func() string { return *next },
			warn: func(err error) { t.Log(err) }}}
}

// jwksServer serves the module's key set, as /api/iam/jwks does.
func jwksServer(t *testing.T, m *Module) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, set, err := m.keys.keys()
		require.NoError(t, err)
		out := []map[string]string{}
		for _, k := range set {
			out = append(out, k.jwk())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	}))
	t.Cleanup(s.Close)
	return s
}

// TestTokensPassTheSDKsVerification: what the member signs is what every component accepts (protocol P8.1, P8.2):
// the SDK's own verifier, keys fetched from the member's JWKS.
func TestTokensPassTheSDKsVerification(t *testing.T) {
	cur, next := newPEM(t), ""
	m := testModule(t, &cur, &next)
	srv := jwksServer(t, m)
	ks, err := identity.NewKeySet(context.Background(), srv.URL)
	require.NoError(t, err)
	v := &identity.Verifier{Issuer: m.issuer, Audience: m.audience, Keys: ks}
	const alice = "0190f3a1-0000-7000-8000-0000000000a1"
	tok, exp, err := m.issue(alice, time.Now(), time.Time{})
	require.NoError(t, err)
	u, err := v.Verify(tok)
	require.NoError(t, err)
	assert.Equal(t, alice, u.Subject)
	assert.WithinDuration(t, time.Now().Add(DefaultTokenTTL), exp, 2*time.Second)

	header, _ := jsonPart(t, tok, 0)
	assert.Equal(t, "at+jwt", header["typ"])
	assert.Equal(t, "EdDSA", header["alg"])
	claims, _ := jsonPart(t, tok, 1)
	for _, k := range []string{"role", "roles", "groups", "department"} {
		assert.NotContains(t, claims, k, "authorization comes from the view only")
	}

	// a session ending sooner bounds the token
	soon := time.Now().Add(time.Minute)
	_, exp, err = m.issue(alice, time.Now(), soon)
	require.NoError(t, err)
	assert.Equal(t, soon.Unix(), exp.Unix())
}

// TestKeyRotation: the standby key is published before it signs; after the switch, tokens of the old key verify as
// long as it stays published as the standby.
func TestKeyRotation(t *testing.T) {
	oldKey, newKey := newPEM(t), newPEM(t)
	cur, next := oldKey, newKey
	m := testModule(t, &cur, &next)
	_, set, err := m.keys.keys()
	require.NoError(t, err)
	assert.Len(t, set, 2, "the standby key is published ahead")
	oldTok, _, err := m.issue("0190f3a1-0000-7000-8000-0000000000a1", time.Now(), time.Time{})
	require.NoError(t, err)

	cur, next = newKey, oldKey // the switch: the old key stays published until its tokens expire
	srv := jwksServer(t, m)
	ks, err := identity.NewKeySet(context.Background(), srv.URL)
	require.NoError(t, err)
	v := &identity.Verifier{Issuer: m.issuer, Audience: m.audience, Keys: ks}
	newTok, _, err := m.issue("0190f3a1-0000-7000-8000-0000000000a1", time.Now(), time.Time{})
	require.NoError(t, err)
	_, err = v.Verify(oldTok)
	assert.NoError(t, err)
	_, err = v.Verify(newTok)
	assert.NoError(t, err)

	next = "not a key" // a broken standby is left out, the current key keeps signing
	_, set, err = m.keys.keys()
	require.NoError(t, err)
	assert.Len(t, set, 1)
	cur = "not a key"
	_, _, err = m.issue("0190f3a1-0000-7000-8000-0000000000a1", time.Now(), time.Time{})
	assert.Error(t, err, "a current key that does not parse signs nothing")
}

func TestReturnToStaysOnThisSite(t *testing.T) {
	m := &Module{after: "/"}
	for in, want := range map[string]string{"/orders?x=1": "/orders?x=1", "": "/", "https://evil.test/": "/",
		"//evil.test/": "/", "/\\evil.test": "/", "javascript:alert(1)": "/"} {
		assert.Equal(t, want, m.returnTo(in), in)
	}
}

func TestPKCE(t *testing.T) {
	v, c := pkce()
	assert.Len(t, v, 43)
	assert.Equal(t, hashOf(v), c, "S256: base64url(SHA-256(verifier))")
	assert.NotEqual(t, randomToken(), randomToken())
}

// TestTheModuleIsMergeSafe: the module is compiled into the Go infra shell.
func TestTheModuleIsMergeSafe(t *testing.T) {
	findings, err := mergesafety.CheckDir(".")
	require.NoError(t, err)
	for _, f := range findings {
		t.Errorf("%v", f)
	}
}

func jsonPart(t *testing.T, tok string, i int) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	raw, err := b64decode(parts[i])
	require.NoError(t, err)
	var m map[string]any
	return m, json.Unmarshal(raw, &m)
}
