//go:build integration

package itest

// The member end to end against a real Casdoor, PostgreSQL and the bus (prepared by scripts/dev_setup.py): the
// development exchange, the binding by issuer and subject, the browser login with PKCE, the edge's SessionService over
// mTLS (Exchange, Ended), the password change, the idle timeout and logout; every token is checked by the SDK's own
// verifier with the keys of the member's JWKS. The service identities and the authorization member are the SDK's
// test deployment (sectest). Needs IAM_IT_PG_PASSWORD (the postgres superuser of be-postgres), IAM_IT_BUS_URL,
// IAM_IT_CLIENT_SECRET, IAM_IT_DEV_CLIENT_SECRET, IAM_IT_TEST_PASSWORD, IAM_IT_CASDOOR_ADMIN_PASSWORD (a throwaway
// user is made for the password change and deleted) and IAM_IT_KEY_FILE; a missing one fails, never skips. Port 9200
// (the system surface) must be free. Run: go test -tags integration ./iam/

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
	iam "github.com/brickKit/infra-iam-casdoor/v3/iam"
	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	"github.com/jackc/pgx/v5"

	iamlogin "github.com/brickKit/infra-iam-casdoor/v3/internal/login"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	itPort      = "8200" // the redirect URI registered for be-iam is on it
	itBase      = "http://localhost:" + itPort
	itCasdoor   = "http://localhost:8000"
	itSchema    = "iam_it"
	itDB        = "brickkit_test_db"
	itClient    = "be-iam-client"
	itDevClient = "be-iam-dev-client"
	itOrg       = "brickkit"
	itThrowaway = "test.it.password" // made and deleted by this test
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

func sendWith(t *testing.T, c *http.Client, method, u string, body any, cookies ...*http.Cookie) (*http.Response, []byte) {
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
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func send(t *testing.T, method, u string, body any, cookies ...*http.Cookie) (*http.Response, []byte) {
	return sendWith(t, noFollow, method, u, body, cookies...)
}

type tokenOut struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Principal   string
}

// casdoorSubject is Casdoor's own subject for a user, from an ID token of the development client's password grant;
// the ID token itself is returned too (TI04).
func casdoorSubject(t *testing.T, user, password string) (sub, idToken string) {
	form := url.Values{"grant_type": {"password"}, "client_id": {itDevClient}, "client_secret": {need(t, "IAM_IT_DEV_CLIENT_SECRET")},
		"username": {user}, "password": {password}, "scope": {"openid"}}
	resp, err := http.PostForm(itCasdoor+"/api/login/oauth/access_token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.IDToken, "precondition: Casdoor gave an ID token for %s", user)
	parts := strings.Split(out.IDToken, ".")
	claims, err := base64URL(parts[1])
	require.NoError(t, err)
	var c struct{ Sub string }
	require.NoError(t, json.Unmarshal(claims, &c))
	return c.Sub, out.IDToken
}

// casdoorAdmin is a client logged in to Casdoor as the built-in admin (for the throwaway user).
func casdoorAdmin(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 10 * time.Second, Jar: jar}
	_, b := sendWith(t, c, "POST", itCasdoor+"/api/login", map[string]string{"application": "app-built-in",
		"organization": "built-in", "username": "admin", "password": need(t, "IAM_IT_CASDOOR_ADMIN_PASSWORD"), "type": "login"})
	var out struct{ Status, Msg string }
	require.NoError(t, json.Unmarshal(b, &out))
	require.Equal(t, "ok", out.Status, out.Msg)
	return c
}

// browserLogin does what a browser does: the member's redirect, Casdoor's login form, the callback; it returns the
// session cookie and the redirect after the login.
func browserLogin(t *testing.T, user, password, returnTo string) (*http.Cookie, string) {
	u := itBase + "/api/iam/login"
	if returnTo != "" {
		u += "?return_to=" + url.QueryEscape(returnTo)
	}
	resp, _ := send(t, "GET", u, nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	authz, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := authz.Query()
	assert.Equal(t, itCasdoor, authz.Scheme+"://"+authz.Host)
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	login := url.Values{"clientId": {itClient}, "responseType": {"code"}, "redirectUri": {q.Get("redirect_uri")},
		"type": {"code"}, "scope": {q.Get("scope")}, "state": {q.Get("state")}, "code_challenge_method": {"S256"},
		"code_challenge": {q.Get("code_challenge")}}
	resp, b := send(t, "POST", itCasdoor+"/api/login?"+login.Encode(), map[string]string{"application": "be-iam",
		"organization": itOrg, "username": user, "password": password, "type": "code"})
	require.Equal(t, 200, resp.StatusCode)
	var cl struct{ Status, Msg, Data string }
	require.NoError(t, json.Unmarshal(b, &cl))
	require.Equal(t, "ok", cl.Status, cl.Msg)
	callback := itBase + "/api/iam/callback?" + url.Values{"code": {cl.Data}, "state": {q.Get("state")}}.Encode()
	resp, b = send(t, "GET", callback, nil)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode, string(b))
	location := resp.Header.Get("Location")
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == iamlogin.CookieName {
			session = c
		}
	}
	require.NotNil(t, session)
	assert.True(t, session.HttpOnly && session.SameSite == http.SameSiteLaxMode)
	resp, _ = send(t, "GET", callback, nil)
	assert.Equal(t, 400, resp.StatusCode, "a state is used once")
	return session, location
}

func base64URL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func digest(c *http.Cookie) string {
	sum := sha256.Sum256([]byte(c.Value))
	return hex.EncodeToString(sum[:])
}

func TestEndToEndAgainstCasdoor(t *testing.T) {
	r := startIAM(t)
	r.tokens()
	r.edgeSessions()
	r.passwordChange()
	r.accountReads()
	r.idleAndLogout()
	r.comparison()
	r.accountOperations()
	r.replay()
	r.recovery()
	for _, secret := range r.secrets {
		assert.NotContains(t, r.logs.String(), secret, "no password or session cookie in the logs")
	}
}

// throwawayUser makes a Casdoor user for one test and deletes it when the test ends.
func throwawayUser(t *testing.T, ca *http.Client, name, password string) {
	_, b := sendWith(t, ca, "POST", itCasdoor+"/api/add-user", map[string]any{"owner": itOrg, "name": name,
		"createdTime": "2026-11-03T00:00:00Z", "displayName": "e2e", "type": "normal-user", "password": password,
		"signupApplication": "be-iam"})
	require.Contains(t, string(b), `"ok"`, string(b))
	t.Cleanup(func() {
		_, got := sendWith(t, ca, "GET", itCasdoor+"/api/get-user?id="+itOrg+"/"+name, nil)
		var u struct{ Data json.RawMessage }
		if json.Unmarshal(got, &u) == nil && string(u.Data) != "null" {
			sendWith(t, ca, "POST", itCasdoor+"/api/delete-user", u.Data)
		}
	})
}

// casdoorSubjectOK reports whether Casdoor accepts the password (the development client's password grant).
func casdoorSubjectOK(t *testing.T, user, password string) (string, bool) {
	form := url.Values{"grant_type": {"password"}, "client_id": {itDevClient}, "client_secret": {need(t, "IAM_IT_DEV_CLIENT_SECRET")},
		"username": {user}, "password": {password}, "scope": {"openid"}}
	resp, err := http.PostForm(itCasdoor+"/api/login/oauth/access_token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.IDToken, out.IDToken != ""
}

// iamRun is one run of the member against Casdoor, shared by the phases of TestEndToEndAgainstCasdoor.
type iamRun struct {
	t            *testing.T
	ctx          context.Context
	admin        *pgx.Conn
	w            *sectest.World
	password     string
	logs         *bytes.Buffer
	verifier     *identity.Verifier
	alice        tokenOut
	bobBefore    string
	otherIssuers string
	session      *http.Cookie // Alice's browser session
	edge         sessionpb.SessionServiceClient
	cursor       *sessionpb.Cursor // the edge's position in the ended stream
	throwaway    string            // the throwaway account's principal (passwordChange)
	payload      []byte            // its last status event
	secrets      []string          // never in the logs
	env          map[string]string // the member's environment (restart changes it)
	stop         func()            // stops the running member
}

// startIAM migrates and starts the member on a fresh schema, with an account bound before the issuer was kept and
// one bound under another issuer (TI11, before the start).
func startIAM(t *testing.T) *iamRun {
	r := &iamRun{t: t, ctx: context.Background(), password: need(t, "IAM_IT_TEST_PASSWORD")}
	pgPassword := need(t, "IAM_IT_PG_PASSWORD")
	var err error
	r.admin, err = pgx.Connect(r.ctx, "postgres://postgres:"+url.QueryEscape(pgPassword)+"@localhost:5432/"+itDB+"?sslmode=disable")
	require.NoError(t, err)
	t.Cleanup(func() { r.admin.Close(r.ctx) })
	_, err = r.admin.Exec(r.ctx, "DROP SCHEMA IF EXISTS "+itSchema+" CASCADE; CREATE SCHEMA "+itSchema)
	require.NoError(t, err)

	r.w = sectest.New(t)
	env := map[string]string{"COMPONENT_ID": core.ID, "COMPONENT_VERSION": core.Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "BUS_URL": need(t, "IAM_IT_BUS_URL"),
		"IMPLEMENTATION_INSTANCE": "iam-it-1",
		"IAM_TOKEN_ISSUER":        itBase, "IAM_SIGNING_KEY_FILE": need(t, "IAM_IT_KEY_FILE"),
		"IAM_CALLBACK_URL": itBase + "/api/iam/callback", "IAM_COOKIE_SECURE": "false", "IAM_AFTER_LOGIN_URL": "/home",
		"IAM_SESSION_IDLE": "30m", "IAM_PULL_INTERVAL": "1h", // the comparison runs when a test pulls (comparison)
		"CASDOOR_URL": itCasdoor, "CASDOOR_PUBLIC_URL": itCasdoor, "CASDOOR_CLIENT_ID": itClient,
		"CASDOOR_CLIENT_SECRET": need(t, "IAM_IT_CLIENT_SECRET"), "IAM_DEV_EXCHANGE": "true",
		"IAM_DEV_CLIENT_ID": itDevClient, "IAM_DEV_CLIENT_SECRET": need(t, "IAM_IT_DEV_CLIENT_SECRET")}
	maps.Copy(env, r.w.Env(t, core.ID)) // DEPLOYMENT_ID, the authorization member, the service identity
	r.env, r.logs = env, &bytes.Buffer{}
	var out bytes.Buffer
	code := launcher.Run(r.ctx, iam.Definition(), launcher.Options{Args: []string{"migrate"}, Stdout: &out, Stderr: &out,
		Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}})
	require.Equal(t, launcher.ExitOK, code, out.String())

	bobSub, _ := casdoorSubject(t, "test.bob", r.password)
	aliceSub, _ := casdoorSubject(t, "test.alice", r.password)
	r.bobBefore, r.otherIssuers = ids.New().String(), ids.New().String()
	_, err = r.admin.Exec(r.ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', '', $2, 'brickkit/test.bob'), ($3, 'casdoor', 'https://another-casdoor.test', $4, 'brickkit/test.alice')",
		r.bobBefore, bobSub, r.otherIssuers, aliceSub)
	require.NoError(t, err)

	r.serve()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(r.logs.String())
		}
	})
	ks, err := identity.NewKeySet(r.ctx, itBase+"/api/iam/jwks")
	require.NoError(t, err)
	r.verifier = &identity.Verifier{Issuer: itBase, Audience: "be:deployment:" + r.w.Deployment, Keys: ks}
	r.secrets = []string{r.password}
	return r
}

func (r *iamRun) verify(tok, principal string) identity.User {
	u, err := r.verifier.Verify(tok)
	require.NoError(r.t, err)
	require.Equal(r.t, principal, u.Subject)
	return u
}

func (r *iamRun) check(b []byte) tokenOut {
	var tk tokenOut
	require.NoError(r.t, json.Unmarshal(b, &tk), string(b))
	r.verify(tk.AccessToken, tk.Principal)
	return tk
}

// serve starts the member on r.env until the test ends or restart stops it; its logs go to r.logs.
func (r *iamRun) serve() {
	t, env := r.t, r.env
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan int, 1)
	go func() {
		done <- launcher.Run(ctx, iam.Definition(), launcher.Options{Stdout: r.logs, Stderr: r.logs,
			Env: config.Env{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, Read: os.ReadFile}})
	}()
	var once sync.Once
	r.stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(r.stop)
	ready := assert.Eventually(t, func() bool {
		resp, err := http.Get(itBase + "/readyz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	}, 15*time.Second, 50*time.Millisecond)
	if !ready {
		t.Fatal(r.logs.String())
	}
}

// restart stops the member and starts it again with extra in its environment (a phase of a full recovery).
func (r *iamRun) restart(extra map[string]string) {
	r.stop()
	env := maps.Clone(r.env)
	maps.Copy(env, extra)
	r.env = env
	r.serve()
}

func (r *iamRun) sessions(component string) sessionpb.SessionServiceClient {
	m, err := calls.NewMember(nil)
	require.NoError(r.t, err)
	r.t.Cleanup(func() { m.Close() })
	m.SetTLS(r.w.TLS(r.t, component))
	conn, err := m.GRPC(core.ID, "localhost:"+strconv.Itoa(iam.GRPCPort))
	require.NoError(r.t, err)
	return sessionpb.NewSessionServiceClient(conn)
}

func (r *iamRun) exchange(c *http.Cookie, renew bool) (*sessionpb.ExchangeResponse, error) {
	cctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	return r.edge.Exchange(cctx, &sessionpb.ExchangeRequest{SessionDigest: digest(c), RenewIdle: renew})
}

func (r *iamRun) ended(after *sessionpb.Cursor) *sessionpb.EndedResponse {
	cctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	out, err := r.edge.Ended(cctx, &sessionpb.EndedRequest{After: after})
	require.NoError(r.t, err)
	return out
}

// endedSince reads like the edge, page after page, until want has appeared (an end gets its position when it is
// numbered after its commit, P6.5); what was read must be exactly want.
func (r *iamRun) endedSince(want ...string) {
	var got []string
	cursor := r.cursor
	require.Eventually(r.t, func() bool {
		page := r.ended(cursor)
		require.False(r.t, page.GetReset_())
		got, cursor = append(got, page.GetSessionDigests()...), page.GetNext()
		return len(got) >= len(want)
	}, 10*time.Second, 200*time.Millisecond, "the ends were numbered")
	assert.Equal(r.t, want, got)
	r.cursor = cursor
}

func (r *iamRun) version(principal string) (v int64) {
	require.NoError(r.t, r.admin.QueryRow(r.ctx, "SELECT security_version FROM "+itSchema+".iam_account WHERE principal = $1",
		principal).Scan(&v))
	return v
}

func (r *iamRun) accounts(component string) projection.RecordClient {
	m, err := calls.NewMember(nil)
	require.NoError(r.t, err)
	r.t.Cleanup(func() { m.Close() })
	m.SetTLS(r.w.TLS(r.t, component))
	conn, err := m.GRPC(core.ID, "localhost:"+strconv.Itoa(iam.GRPCPort))
	require.NoError(r.t, err)
	return projection.RecordClient{Conn: conn, Stream: core.StreamAccount}
}
