//go:build integration

package iam

// The member end to end against a real Casdoor and PostgreSQL (prepared by scripts/dev_setup.py): the development
// exchange, the browser login with PKCE, the session's token, logout and the idle timeout; every token is checked by
// the SDK's own verifier with the keys of the member's JWKS. Needs IAM_IT_PG_PASSWORD (the postgres superuser of
// be-postgres), IAM_IT_CLIENT_SECRET, IAM_IT_DEV_CLIENT_SECRET, IAM_IT_TEST_PASSWORD and IAM_IT_KEY_FILE; a missing
// one fails, never skips. Run: go test -tags integration ./iam/

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	itPort      = "8200" // the redirect URI registered for be-iam is on it
	itBase      = "http://localhost:" + itPort
	itCasdoor   = "http://localhost:8000"
	itSchema    = "iam_it"
	itDB        = "brickkit_test_db"
	itDeploy    = "0190f3a1-0000-7000-8000-00000000d001"
	itClient    = "be-iam-client"
	itDevClient = "be-iam-dev-client"
)

func need(t *testing.T, name string) string {
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set (see the header of this file)", name)
	}
	return v
}

// noFollow is a client that shows redirects instead of following them.
var noFollow = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

func send(t *testing.T, method, u string, body any, cookies ...*http.Cookie) (*http.Response, []byte) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, r)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noFollow.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

type tokenOut struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Principal   string
}

func TestEndToEndAgainstCasdoor(t *testing.T) {
	pgPassword, password := need(t, "IAM_IT_PG_PASSWORD"), need(t, "IAM_IT_TEST_PASSWORD")
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres:"+url.QueryEscape(pgPassword)+"@localhost:5432/"+itDB+"?sslmode=disable")
	require.NoError(t, err)
	defer admin.Close(ctx)
	_, err = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+itSchema+" CASCADE; CREATE SCHEMA "+itSchema)
	require.NoError(t, err)

	env := map[string]string{"COMPONENT_ID": ID, "COMPONENT_VERSION": Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword,
		"DEPLOYMENT_ID": itDeploy, "IAM_TOKEN_ISSUER": itBase, "IAM_SIGNING_KEY_FILE": need(t, "IAM_IT_KEY_FILE"),
		"IAM_CALLBACK_URL": itBase + "/api/iam/callback", "IAM_COOKIE_SECURE": "false", "IAM_AFTER_LOGIN_URL": "/home",
		"IAM_SESSION_IDLE": "30m",
		"CASDOOR_URL":      itCasdoor, "CASDOOR_PUBLIC_URL": itCasdoor, "CASDOOR_CLIENT_ID": itClient,
		"CASDOOR_CLIENT_SECRET": need(t, "IAM_IT_CLIENT_SECRET"), "IAM_DEV_EXCHANGE": "true",
		"IAM_DEV_CLIENT_ID": itDevClient, "IAM_DEV_CLIENT_SECRET": need(t, "IAM_IT_DEV_CLIENT_SECRET")}
	run := func(args ...string) (int, *bytes.Buffer) {
		var out bytes.Buffer
		ctx, cancel := context.WithCancel(ctx)
		done := make(chan int, 1)
		go func() {
			done <- launcher.Run(ctx, Definition(), launcher.Options{Args: args, Stdout: &out, Stderr: &out,
				Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}})
		}()
		if len(args) > 0 { // migrate runs to its end
			code := <-done
			cancel()
			return code, &out
		}
		t.Cleanup(func() { cancel(); <-done })
		ready := assert.Eventually(t, func() bool {
			r, err := http.Get(itBase + "/readyz")
			if err == nil {
				r.Body.Close()
			}
			return err == nil && r.StatusCode == 200
		}, 10*time.Second, 50*time.Millisecond)
		if !ready {
			t.Fatal(out.String())
		}
		return 0, &out
	}
	code, out := run("migrate")
	require.Equal(t, launcher.ExitOK, code, out.String())
	_, logs := run()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})

	ks, err := identity.NewKeySet(ctx, itBase+"/api/iam/jwks")
	require.NoError(t, err)
	verifier := &identity.Verifier{Issuer: itBase, Audience: "be:deployment:" + itDeploy, Keys: ks}
	check := func(b []byte) tokenOut {
		var tk tokenOut
		require.NoError(t, json.Unmarshal(b, &tk), string(b))
		u, err := verifier.Verify(tk.AccessToken)
		require.NoError(t, err)
		require.Equal(t, tk.Principal, u.Subject)
		return tk
	}

	// the development exchange (A101): a real user's password for a token; the principal is stable
	resp, b := send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": password})
	require.Equal(t, 200, resp.StatusCode, string(b))
	alice := check(b)
	assert.LessOrEqual(t, alice.ExpiresIn, 300)
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": password})
	assert.Equal(t, alice.Principal, check(b).Principal, "the same user is the same principal")
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.bob", "password": password})
	assert.NotEqual(t, alice.Principal, check(b).Principal)
	resp, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": "wrong"})
	assert.Equal(t, 401, resp.StatusCode, string(b))
	assert.NotContains(t, logs.String(), password, "a password never reaches the logs")

	// the browser login: the member's redirect to Casdoor, Casdoor's login (what the browser does there), the callback
	resp, _ = send(t, "GET", itBase+"/api/iam/login?return_to=/orders", nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	authz, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := authz.Query()
	assert.Equal(t, itCasdoor, authz.Scheme+"://"+authz.Host)
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	casdoorLogin := url.Values{"clientId": {itClient}, "responseType": {"code"}, "redirectUri": {q.Get("redirect_uri")},
		"type": {"code"}, "scope": {q.Get("scope")}, "state": {q.Get("state")}, "code_challenge_method": {"S256"},
		"code_challenge": {q.Get("code_challenge")}}
	resp, b = send(t, "POST", itCasdoor+"/api/login?"+casdoorLogin.Encode(), map[string]string{"application": "be-iam",
		"organization": "brickkit", "username": "test.alice", "password": password, "type": "code"})
	require.Equal(t, 200, resp.StatusCode)
	var cl struct{ Status, Msg, Data string }
	require.NoError(t, json.Unmarshal(b, &cl))
	require.Equal(t, "ok", cl.Status, cl.Msg)

	callback := itBase + "/api/iam/callback?" + url.Values{"code": {cl.Data}, "state": {q.Get("state")}}.Encode()
	resp, b = send(t, "GET", callback, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, string(b))
	assert.Equal(t, "/orders", resp.Header.Get("Location"))
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			session = c
		}
	}
	require.NotNil(t, session)
	assert.True(t, session.HttpOnly && session.SameSite == http.SameSiteLaxMode)
	resp, _ = send(t, "GET", callback, nil)
	assert.Equal(t, 400, resp.StatusCode, "a state is used once")

	resp, b = send(t, "POST", itBase+"/api/iam/session/token", nil, session)
	require.Equal(t, 200, resp.StatusCode, string(b))
	assert.Equal(t, alice.Principal, check(b).Principal, "the browser login and the exchange agree on the principal")
	resp, _ = send(t, "POST", itBase+"/api/iam/session/token", nil, &http.Cookie{Name: CookieName, Value: "forged"})
	assert.Equal(t, 401, resp.StatusCode)

	// the idle timeout ends the session
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".iam_session SET last_seen = now() - interval '31 minutes'")
	require.NoError(t, err)
	resp, b = send(t, "POST", itBase+"/api/iam/session/token", nil, session)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Contains(t, string(b), "SESSION_ENDED")
	var reason string
	require.NoError(t, admin.QueryRow(ctx, "SELECT end_reason FROM "+itSchema+".iam_session").Scan(&reason))
	assert.Equal(t, "idle", reason)

	// a second login, then logout
	resp, _ = send(t, "GET", itBase+"/api/iam/login", nil)
	q2, _ := url.Parse(resp.Header.Get("Location"))
	q = q2.Query()
	casdoorLogin.Set("state", q.Get("state"))
	casdoorLogin.Set("code_challenge", q.Get("code_challenge"))
	_, b = send(t, "POST", itCasdoor+"/api/login?"+casdoorLogin.Encode(), map[string]string{"application": "be-iam",
		"organization": "brickkit", "username": "test.alice", "password": password, "type": "code"})
	require.NoError(t, json.Unmarshal(b, &cl))
	resp, _ = send(t, "GET", itBase+"/api/iam/callback?"+url.Values{"code": {cl.Data}, "state": {q.Get("state")}}.Encode(), nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/home", resp.Header.Get("Location"), "without return_to: IAM_AFTER_LOGIN_URL")
	session = resp.Cookies()[0]
	resp, _ = send(t, "POST", itBase+"/api/iam/logout", nil, session)
	assert.Equal(t, 204, resp.StatusCode)
	assert.True(t, strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0"), "the browser forgets the cookie")
	resp, _ = send(t, "POST", itBase+"/api/iam/session/token", nil, session)
	assert.Equal(t, 401, resp.StatusCode, "a logged-out session gives no token")
}
