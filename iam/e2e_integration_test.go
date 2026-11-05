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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

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
