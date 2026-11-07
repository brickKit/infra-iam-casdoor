package login

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"time"

	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	keys "github.com/brickKit/infra-iam-casdoor/v3/internal/keys"
	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	jwt "github.com/golang-jwt/jwt/v5"
)

// CookieName is the browser session's cookie: a random secret, HttpOnly, SameSite=Lax (protocol 20).
const CookieName = "be_session"

// signedIn binds the verified Casdoor user and refuses an account this member has disabled or frozen: Casdoor may
// still let it in (a console re-enable or a product rollback, until the next comparison forbids it there again).
func signedIn(m *core.Base, ctx context.Context, id provider.ProviderUser) (core.AccountRow, error) {
	a, err := m.Store.Principal(ctx, m.Casdoor.Issuer, id)
	if err == nil && a.Status != "active" {
		m.RT.Logger.Warn("a sign-in of an account disabled here was refused", "principal", a.Principal, "status", a.Status)
		return a, errs.New(errs.ReasonTokenInvalid, "the account cannot sign in")
	}
	return a, err
}

// returnTo keeps only a path on this site: anything else would make the login an open redirect.
func returnTo(m *core.Base, q string) string {
	if strings.HasPrefix(q, "/") && !strings.HasPrefix(q, "//") && !strings.Contains(q, "\\") {
		return q
	}
	return m.After
}

func Login(m *core.Base, c *httpx.Context) error {
	state := provider.RandomToken()
	verifier, challenge := provider.Pkce()
	if err := m.Store.Begin(c.Ctx(), provider.HashOf(state), verifier, returnTo(m, c.Query("return_to"))); err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, m.Casdoor.AuthorizeURL(state, challenge))
}

func Callback(m *core.Base, c *httpx.Context) error {
	if e := c.Query("error"); e != "" {
		return errs.New(errs.ReasonTokenInvalid, "the identity provider ended the login").With("provider_error", e)
	}
	verifier, returnTo, err := m.Store.Take(c.Ctx(), provider.HashOf(c.Query("state")))
	if err == core.ErrNoLogin {
		return errs.New(errs.ReasonRequestInvalid, "the login is unknown or expired; start again")
	} else if err != nil {
		return err
	}
	id, err := m.Casdoor.Code(c.Ctx(), c.Query("code"), verifier)
	if err != nil {
		return err
	}
	a, err := signedIn(m, c.Ctx(), id)
	if err != nil {
		return err
	}
	secret := provider.RandomToken()
	if err := m.Store.Open(c.Ctx(), provider.HashOf(secret), a.Principal); err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{Name: CookieName, Value: secret, Path: "/", HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteLaxMode})
	return c.Redirect(http.StatusSeeOther, returnTo)
}

func Session(m *core.Base, c *httpx.Context) string {
	ck, err := c.Request().Cookie(CookieName)
	if err != nil || ck.Value == "" {
		return ""
	}
	return provider.HashOf(ck.Value)
}

func answerToken(m *core.Base, c *httpx.Context, a core.AccountRow, until time.Time) error {
	now := time.Now()
	tok, exp, err := Issue(m, a.Principal, a.SecurityVersion, now, until)
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_in": int(exp.Sub(now).Seconds()), "principal": a.Principal})
}

func Logout(m *core.Base, c *httpx.Context) error {
	if h := Session(m, c); h != "" {
		if err := m.Store.End(c.Ctx(), h, "logout"); err != nil {
			return err
		}
	}
	c.SetCookie(&http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteLaxMode})
	return c.NoContent(http.StatusNoContent)
}

// Jwks publishes the current and the standby key (RFC 7517); components fetch it from IAM_JWKS_URL (P8.2).
func Jwks(m *core.Base, c *httpx.Context) error {
	_, set, err := m.Keys.Keys()
	if err != nil {
		return err
	}
	out := make([]map[string]string, len(set))
	for i, k := range set {
		out[i] = k.Jwk()
	}
	return c.JSON(200, map[string]any{"keys": out})
}

// DevToken exchanges a user's password for an access token through Casdoor's development client (A101). Seeds and
// automated tests get real tokens this way; it does not exist unless IAM_DEV_EXCHANGE is on.
func DevToken(m *core.Base, c *httpx.Context) error {
	var in struct{ Username, Password string }
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Username == "" || in.Password == "" {
		return errs.New(errs.ReasonRequestInvalid, "username and password are required")
	}
	id, err := m.Casdoor.Password(c.Ctx(), in.Username, in.Password)
	if err != nil {
		return err
	}
	a, err := signedIn(m, c.Ctx(), id)
	if err != nil {
		return err
	}
	return answerToken(m, c, a, time.Time{})
}

// Issue signs an access token for a principal at the account's security version (protocol P8.1: typ at+jwt, a kid,
// EdDSA; iss, aud, sub, iat, nbf, exp and be_sv, P8.27; no role or department claims, authorization comes from the
// view only). The lifetime never runs past until when until is set (a session's end).
func Issue(m *core.Base, principal string, securityVersion int64, now time.Time, until time.Time) (string, time.Time, error) {
	key, _, err := m.Keys.Keys()
	if err != nil {
		return "", time.Time{}, err
	}
	exp := now.Add(m.TTL)
	if !until.IsZero() && until.Before(exp) {
		exp = until
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": m.Issuer, "aud": m.Audience, "sub": principal, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": exp.Unix(), "jti": keys.B64(jti), "be_sv": securityVersion})
	t.Header["typ"] = "at+jwt"
	t.Header["kid"] = key.Kid
	s, err := t.SignedString(key.Priv)
	return s, exp, err
}
