//go:build integration

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
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
	env := map[string]string{"COMPONENT_ID": ID, "COMPONENT_VERSION": Version, "PORT": itPort, "STOP_DRAIN_DELAY": "50ms",
		"PG_HOST": "localhost", "PG_DATABASE": itDB, "PG_USER": "postgres", "PG_PASSWORD": pgPassword, "PG_SCHEMA": itSchema,
		"PG_OWNER_USER": "postgres", "PG_OWNER_PASSWORD": pgPassword, "BUS_URL": need(t, "IAM_IT_BUS_URL"),
		"IMPLEMENTATION_INSTANCE": "iam-it-1",
		"IAM_TOKEN_ISSUER":        itBase, "IAM_SIGNING_KEY_FILE": need(t, "IAM_IT_KEY_FILE"),
		"IAM_CALLBACK_URL": itBase + "/api/iam/callback", "IAM_COOKIE_SECURE": "false", "IAM_AFTER_LOGIN_URL": "/home",
		"IAM_SESSION_IDLE": "30m", "IAM_PULL_INTERVAL": "1h", // the comparison runs when a test pulls (comparison)
		"CASDOOR_URL": itCasdoor, "CASDOOR_PUBLIC_URL": itCasdoor, "CASDOOR_CLIENT_ID": itClient,
		"CASDOOR_CLIENT_SECRET": need(t, "IAM_IT_CLIENT_SECRET"), "IAM_DEV_EXCHANGE": "true",
		"IAM_DEV_CLIENT_ID": itDevClient, "IAM_DEV_CLIENT_SECRET": need(t, "IAM_IT_DEV_CLIENT_SECRET")}
	maps.Copy(env, r.w.Env(t, ID)) // DEPLOYMENT_ID, the authorization member, the service identity
	r.env, r.logs = env, &bytes.Buffer{}
	var out bytes.Buffer
	code := launcher.Run(r.ctx, Definition(), launcher.Options{Args: []string{"migrate"}, Stdout: &out, Stderr: &out,
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

// serve starts the member on r.env until the test ends or restart stops it; its logs go to r.logs.
func (r *iamRun) serve() {
	t, env := r.t, r.env
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan int, 1)
	go func() {
		done <- launcher.Run(ctx, Definition(), launcher.Options{Stdout: r.logs, Stderr: r.logs,
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
	conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
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

// edgeSessions: the edge's SessionService over mTLS (P8.28), and a polling exchange that does not renew (protocol 20).
func (r *iamRun) edgeSessions() {
	t, ctx := r.t, r.ctx
	r.edge = r.sessions(Edge)
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
			StreamAccount, r.throwaway).Scan(&n))
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
		"WHERE stream = $1 AND record_id = $2", StreamAccount, r.throwaway).Scan(&statusRows, &r.payload))
	assert.Equal(t, 2, statusRows, "the account's status went out when it was bound and when it changed")
	assert.Contains(t, string(r.payload), `"security_version":2`)
	_, newPasswordWorks := casdoorSubjectOK(t, itThrowaway, second)
	assert.True(t, newPasswordWorks, "Casdoor has the new password")
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
	conn, err := m.GRPC(ID, "localhost:"+strconv.Itoa(GRPCPort))
	require.NoError(r.t, err)
	return projection.RecordClient{Conn: conn, Stream: StreamAccount}
}

// accountReads: the authorization member reads the account status (P9.30-P9.33): every account, the same bytes as
// the event.
func (r *iamRun) accountReads() {
	t, ctx := r.t, r.ctx
	reader := r.accounts(Authz)
	nobody := ids.New().String()
	read, from, err := reader.Read(ctx, []string{r.alice.Principal, r.bobBefore, r.throwaway, r.otherIssuers, nobody})
	require.NoError(t, err)
	assert.True(t, from.Primary)
	assert.Equal(t, "iam-it-1", from.Impl)
	got := map[string]string{}
	for _, rd := range read {
		got[rd.ID] = rd.State
		if rd.State != projection.Exists {
			continue
		}
		rec, err := records.Open("be.security.account_status", rd.Data,
			canon.DigestBytes("be.security.account_status", records.Major, rd.Data))
		require.NoError(t, err, "a be.security.account_status record")
		assert.Equal(t, strconv.FormatInt(rd.Version, 10), fmt.Sprint(rec["security_version"]),
			"the record's version is its security version")
	}
	assert.Equal(t, map[string]string{r.alice.Principal: projection.Exists, r.bobBefore: projection.Exists,
		r.throwaway: projection.Exists, r.otherIssuers: projection.Exists, nobody: projection.Purged}, got,
		"bound accounts, and the ones from before whose status went out at start")
	assert.EqualValues(t, 2, read[2].Version, "the throwaway account after its password change")
	assert.JSONEq(t, string(r.payload), string(read[2].Data), "the read answers with what the event carried")
	var snapshot []string
	for cursor := ""; ; {
		page, next, _, err := reader.Snapshot(ctx, cursor)
		require.NoError(t, err)
		for _, rd := range page {
			snapshot = append(snapshot, rd.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	assert.Subset(t, snapshot, []string{r.alice.Principal, r.bobBefore, r.throwaway, r.otherIssuers})
	_, _, err = r.accounts(Edge).Read(ctx, []string{r.alice.Principal})
	assert.True(t, errs.Is(err, "be", errs.ReasonPermissionDenied), "only the authorization member reads: %v", err)
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
