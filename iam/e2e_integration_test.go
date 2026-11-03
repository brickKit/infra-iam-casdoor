//go:build integration

package iam

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
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/canon"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/brickKit/be-sdk-go/v3/projection"
	"github.com/brickKit/be-sdk-go/v3/records"
	"github.com/brickKit/be-sdk-go/v3/sectest"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
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
		if c.Name == CookieName {
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
	pgPassword, password := need(t, "IAM_IT_PG_PASSWORD"), need(t, "IAM_IT_TEST_PASSWORD")
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres:"+url.QueryEscape(pgPassword)+"@localhost:5432/"+itDB+"?sslmode=disable")
	require.NoError(t, err)
	defer admin.Close(ctx)
	_, err = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+itSchema+" CASCADE; CREATE SCHEMA "+itSchema)
	require.NoError(t, err)

	w := sectest.New(t)
	env := map[string]string{"COMPONENT_ID": ID, "COMPONENT_VERSION": Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "BUS_URL": need(t, "IAM_IT_BUS_URL"),
		"IMPLEMENTATION_INSTANCE": "iam-it-1",
		"IAM_TOKEN_ISSUER":        itBase, "IAM_SIGNING_KEY_FILE": need(t, "IAM_IT_KEY_FILE"),
		"IAM_CALLBACK_URL": itBase + "/api/iam/callback", "IAM_COOKIE_SECURE": "false", "IAM_AFTER_LOGIN_URL": "/home",
		"IAM_SESSION_IDLE": "30m",
		"CASDOOR_URL":      itCasdoor, "CASDOOR_PUBLIC_URL": itCasdoor, "CASDOOR_CLIENT_ID": itClient,
		"CASDOOR_CLIENT_SECRET": need(t, "IAM_IT_CLIENT_SECRET"), "IAM_DEV_EXCHANGE": "true",
		"IAM_DEV_CLIENT_ID": itDevClient, "IAM_DEV_CLIENT_SECRET": need(t, "IAM_IT_DEV_CLIENT_SECRET")}
	maps.Copy(env, w.Env(t, ID)) // DEPLOYMENT_ID, the authorization member, the service identity
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
		}, 15*time.Second, 50*time.Millisecond)
		if !ready {
			t.Fatal(out.String())
		}
		return 0, &out
	}
	code, out := run("migrate")
	require.Equal(t, launcher.ExitOK, code, out.String())

	// TI11, before the member starts: an account bound before the issuer was kept (Bob's) is adopted by the
	// configured issuer; Alice's subject bound under another issuer is another account, never taken over
	bobSub, _ := casdoorSubject(t, "test.bob", password)
	aliceSub, aliceIDToken := casdoorSubject(t, "test.alice", password)
	bobBefore, otherIssuers := ids.New().String(), ids.New().String()
	_, err = admin.Exec(ctx, "INSERT INTO "+itSchema+".iam_account (principal, provider, issuer, provider_subject, username) "+
		"VALUES ($1, 'casdoor', '', $2, 'brickkit/test.bob'), ($3, 'casdoor', 'https://another-casdoor.test', $4, 'brickkit/test.alice')",
		bobBefore, bobSub, otherIssuers, aliceSub)
	require.NoError(t, err)

	_, logs := run()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	ks, err := identity.NewKeySet(ctx, itBase+"/api/iam/jwks")
	require.NoError(t, err)
	verifier := &identity.Verifier{Issuer: itBase, Audience: "be:deployment:" + w.Deployment, Keys: ks}
	verify := func(tok, principal string) identity.User {
		u, err := verifier.Verify(tok)
		require.NoError(t, err)
		require.Equal(t, principal, u.Subject)
		return u
	}
	check := func(b []byte) tokenOut {
		var tk tokenOut
		require.NoError(t, json.Unmarshal(b, &tk), string(b))
		verify(tk.AccessToken, tk.Principal)
		return tk
	}

	// TI04: Casdoor's own ID token is not an access token of this deployment
	_, err = verifier.Verify(aliceIDToken)
	var te *identity.TokenError
	require.ErrorAs(t, err, &te, "the provider's ID token is refused")
	t.Logf("Casdoor's ID token refused at %q", te.Problem)

	// the development exchange (A101): a real user's password for a token; the principal is stable
	resp, b := send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": password})
	require.Equal(t, 200, resp.StatusCode, string(b))
	alice := check(b)
	assert.LessOrEqual(t, alice.ExpiresIn, 300)
	assert.NotEqual(t, otherIssuers, alice.Principal, "the same subject of another issuer is not taken over (TI11)")
	u, _ := verifier.Verify(alice.AccessToken)
	assert.EqualValues(t, 1, u.SecurityVersion, "be_sv: a new account is at 1")
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": password})
	assert.Equal(t, alice.Principal, check(b).Principal, "the same user is the same principal")
	_, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.bob", "password": password})
	assert.Equal(t, bobBefore, check(b).Principal, "an account bound before the issuer was kept keeps its principal")
	resp, b = send(t, "POST", itBase+"/api/iam/dev/token", map[string]string{"username": "test.alice", "password": "wrong"})
	assert.Equal(t, 401, resp.StatusCode, string(b))

	// UI04: the session's token is not on the user surface any more
	session, to := browserLogin(t, "test.alice", password, "/orders")
	assert.Equal(t, "/orders", to)
	resp, _ = send(t, "POST", itBase+"/api/iam/session/token", nil, session)
	assert.Equal(t, 501, resp.StatusCode, "no such route")

	// the edge's SessionService over mTLS (P8.28)
	sessions := func(component string) sessionpb.SessionServiceClient {
		m, err := calls.NewMember(nil)
		require.NoError(t, err)
		t.Cleanup(func() { m.Close() })
		m.SetTLS(w.TLS(t, component))
		conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
		require.NoError(t, err)
		return sessionpb.NewSessionServiceClient(conn)
	}
	edge := sessions(Edge)
	exchange := func(c *http.Cookie, renew bool) (*sessionpb.ExchangeResponse, error) {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return edge.Exchange(cctx, &sessionpb.ExchangeRequest{SessionDigest: digest(c), RenewIdle: renew})
	}
	ended := func(after *sessionpb.Cursor) *sessionpb.EndedResponse {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, err := edge.Ended(cctx, &sessionpb.EndedRequest{After: after})
		require.NoError(t, err)
		return out
	}
	start := ended(nil)
	assert.True(t, start.GetReset_(), "no cursor: start at the end")
	// endedSince reads like the edge, page after page, until want has appeared (an end gets its position when it is
	// numbered after its commit, P6.5); what was read must be exactly want
	endedSince := func(cursor *sessionpb.Cursor, want ...string) *sessionpb.Cursor {
		var got []string
		require.Eventually(t, func() bool {
			page := ended(cursor)
			require.False(t, page.GetReset_())
			got, cursor = append(got, page.GetSessionDigests()...), page.GetNext()
			return len(got) >= len(want)
		}, 10*time.Second, 200*time.Millisecond, "the ends were numbered")
		assert.Equal(t, want, got)
		return cursor
	}

	ex, err := exchange(session, true)
	require.NoError(t, err)
	assert.EqualValues(t, 1, verify(ex.GetAccessToken(), alice.Principal).SecurityVersion)
	assert.Equal(t, alice.Principal, ex.GetPrincipal(), "the browser login and the exchange agree on the principal")
	assert.LessOrEqual(t, ex.GetExpiresAtMs(), ex.GetSessionUntilMs(), "the token ends no later than the session")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = sessions("erp/sales").Exchange(cctx, &sessionpb.ExchangeRequest{SessionDigest: digest(session)})
	cancel()
	assert.True(t, errs.Is(err, "be", errs.ReasonPermissionDenied), "only the edge may exchange: %v", err)
	_, err = exchange(&http.Cookie{Value: "forged"}, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)

	// a polling request's exchange does not renew the idle time (protocol 20)
	seen := func() time.Time {
		var at time.Time
		require.NoError(t, admin.QueryRow(ctx, "SELECT last_seen FROM "+itSchema+".iam_session WHERE id_hash = $1",
			digest(session)).Scan(&at))
		return at
	}
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".iam_session SET last_seen = now() - interval '10 minutes' WHERE id_hash = $1", digest(session))
	require.NoError(t, err)
	before := seen()
	_, err = exchange(session, false)
	require.NoError(t, err)
	assert.Equal(t, before, seen(), "renew_idle false")
	_, err = exchange(session, true)
	require.NoError(t, err)
	assert.True(t, seen().After(before.Add(9*time.Minute)), "renew_idle true")

	// the password change through the member (protocol 20, UI22's identity side), on a throwaway user
	ca := casdoorAdmin(t)
	first, second := "It-Pass-1-"+ids.New().String()[24:], "It-Pass-2-"+ids.New().String()[24:]
	_, b = sendWith(t, ca, "POST", itCasdoor+"/api/add-user", map[string]any{"owner": itOrg, "name": itThrowaway,
		"createdTime": "2026-11-03T00:00:00Z", "displayName": "e2e", "type": "normal-user", "password": first,
		"signupApplication": "be-iam"})
	require.Contains(t, string(b), `"ok"`, string(b))
	t.Cleanup(func() {
		_, got := sendWith(t, ca, "GET", itCasdoor+"/api/get-user?id="+itOrg+"/"+itThrowaway, nil)
		var u struct{ Data json.RawMessage }
		if json.Unmarshal(got, &u) == nil && string(u.Data) != "null" {
			sendWith(t, ca, "POST", itCasdoor+"/api/delete-user", u.Data)
		}
	})
	keep, _ := browserLogin(t, itThrowaway, first, "")
	kept, err := exchange(keep, true)
	require.NoError(t, err)
	throwaway := kept.GetPrincipal()
	statuses := func() (n int) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT count(*) FROM "+itSchema+".be_outbox WHERE stream = $1 AND record_id = $2",
			StreamAccount, throwaway).Scan(&n))
		return n
	}
	assert.Equal(t, 1, statuses(), "a new account's status goes out when it is bound")
	other, _ := browserLogin(t, itThrowaway, first, "")
	assert.Equal(t, 1, statuses(), "a later login sends nothing")
	version := func() (v int64) {
		require.NoError(t, admin.QueryRow(ctx, "SELECT security_version FROM "+itSchema+".iam_account WHERE principal = $1",
			throwaway).Scan(&v))
		return v
	}
	cursor := ended(nil).GetNext()
	resp, b = send(t, "POST", itBase+"/api/iam/password", map[string]string{"old_password": "wrong", "new_password": second}, keep)
	assert.Equal(t, 400, resp.StatusCode, string(b))
	assert.EqualValues(t, 1, version(), "a refused change changes nothing")
	resp, b = send(t, "POST", itBase+"/api/iam/password", map[string]string{"old_password": first, "new_password": second}, keep)
	require.Equal(t, 204, resp.StatusCode, string(b))
	assert.EqualValues(t, 2, version())
	_, err = exchange(other, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "the other session ended: %v", err)
	kept, err = exchange(keep, true)
	require.NoError(t, err, "the session that made the change goes on")
	assert.EqualValues(t, 2, verify(kept.GetAccessToken(), throwaway).SecurityVersion, "with a token of the new version")
	cursor = endedSince(cursor, digest(other)) // the edge reads the other session's end, not the kept one
	var statusRows int
	var payload []byte
	require.NoError(t, admin.QueryRow(ctx, "SELECT count(*), max(payload::text)::bytea FROM "+itSchema+".be_outbox "+
		"WHERE stream = $1 AND record_id = $2", StreamAccount, throwaway).Scan(&statusRows, &payload))
	assert.Equal(t, 2, statusRows, "the account's status went out when it was bound and when it changed")
	assert.Contains(t, string(payload), `"security_version":2`)
	_, newPasswordWorks := casdoorSubjectOK(t, itThrowaway, second)
	assert.True(t, newPasswordWorks, "Casdoor has the new password")

	// the authorization member reads the account status (P9.30-P9.33): every account, the same bytes as the event
	accounts := func(component string) projection.RecordClient {
		m, err := calls.NewMember(nil)
		require.NoError(t, err)
		t.Cleanup(func() { m.Close() })
		m.SetTLS(w.TLS(t, component))
		conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
		require.NoError(t, err)
		return projection.RecordClient{Conn: conn, Stream: StreamAccount}
	}
	reader := accounts(Authz)
	nobody := ids.New().String()
	read, from, err := reader.Read(ctx, []string{alice.Principal, bobBefore, throwaway, otherIssuers, nobody})
	require.NoError(t, err)
	assert.True(t, from.Primary)
	assert.Equal(t, "iam-it-1", from.Impl)
	got := map[string]string{}
	for _, r := range read {
		got[r.ID] = r.State
		if r.State != projection.Exists {
			continue
		}
		rec, err := records.Open("be.security.account_status", r.Data,
			canon.DigestBytes("be.security.account_status", records.Major, r.Data))
		require.NoError(t, err, "a be.security.account_status record")
		assert.Equal(t, strconv.FormatInt(r.Version, 10), fmt.Sprint(rec["security_version"]),
			"the record's version is its security version")
	}
	assert.Equal(t, map[string]string{alice.Principal: projection.Exists, bobBefore: projection.Exists,
		throwaway: projection.Exists, otherIssuers: projection.Exists, nobody: projection.Purged}, got,
		"bound accounts, and the ones from before whose status went out at start")
	assert.EqualValues(t, 2, read[2].Version, "the throwaway account after its password change")
	assert.JSONEq(t, string(payload), string(read[2].Data), "the read answers with what the event carried")
	var snapshot []string
	for cursor := ""; ; {
		page, next, _, err := reader.Snapshot(ctx, cursor)
		require.NoError(t, err)
		for _, r := range page {
			snapshot = append(snapshot, r.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	assert.Subset(t, snapshot, []string{alice.Principal, bobBefore, throwaway, otherIssuers})
	_, _, err = accounts(Edge).Read(ctx, []string{alice.Principal})
	assert.True(t, errs.Is(err, "be", errs.ReasonPermissionDenied), "only the authorization member reads: %v", err)

	// the idle timeout ends a session; the edge reads it
	_, err = admin.Exec(ctx, "UPDATE "+itSchema+".iam_session SET last_seen = now() - interval '31 minutes' WHERE id_hash = $1", digest(session))
	require.NoError(t, err)
	_, err = exchange(session, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "%v", err)
	var reason string
	require.NoError(t, admin.QueryRow(ctx, "SELECT end_reason FROM "+itSchema+".iam_session WHERE id_hash = $1",
		digest(session)).Scan(&reason))
	assert.Equal(t, "idle", reason)
	cursor = endedSince(cursor, digest(session))

	// a second login, then logout
	second2, to := browserLogin(t, "test.alice", password, "")
	assert.Equal(t, "/home", to, "without return_to: IAM_AFTER_LOGIN_URL")
	resp, _ = send(t, "POST", itBase+"/api/iam/logout", nil, second2)
	assert.Equal(t, 204, resp.StatusCode)
	assert.True(t, strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0"), "the browser forgets the cookie")
	_, err = exchange(second2, true)
	assert.True(t, errs.Is(err, "be", errs.ReasonSessionEnded), "a logged-out session gives no token: %v", err)
	endedSince(cursor, digest(second2))

	for _, secret := range []string{password, first, second, session.Value, keep.Value} {
		assert.NotContains(t, logs.String(), secret, "no password or session cookie in the logs")
	}
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
