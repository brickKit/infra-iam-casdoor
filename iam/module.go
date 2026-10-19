package iam

import (
	"net/http"
	"strings"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/runtime"
)

// CookieName is the browser session's cookie: a random secret, HttpOnly, SameSite=Lax (protocol 20).
const CookieName = "be_session"

// Module is the identity member.
type Module struct {
	rt       *runtime.Runtime
	store    store
	casdoor  *casdoor
	keys     *keyRing
	issuer   string
	audience string
	ttl      time.Duration
	idle     time.Duration
	absolute time.Duration
	secure   bool
	after    string
	dev      bool
	ended    errs.Declared
}

// New builds the module from its runtime.
func New(rt *runtime.Runtime) (*Module, error) {
	cfg := rt.Config
	if cfg.String("DEPLOYMENT_ID") == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: the tokens' audience is be:deployment:<DEPLOYMENT_ID>")
	}
	cd, _ := rt.HTTPAt("casdoor", cfg.String("CASDOOR_URL"))
	m := &Module{rt: rt, store: store{db: rt.DB}, issuer: cfg.String("IAM_TOKEN_ISSUER"),
		audience: "be:deployment:" + cfg.String("DEPLOYMENT_ID"), ttl: cfg.Duration("IAM_ACCESS_TOKEN_TTL"),
		idle: cfg.Duration("IAM_SESSION_IDLE"), absolute: cfg.Duration("IAM_SESSION_ABSOLUTE"),
		secure: cfg.Bool("IAM_COOKIE_SECURE"), after: cfg.String("IAM_AFTER_LOGIN_URL"), dev: cfg.Bool("IAM_DEV_EXCHANGE"),
		ended: errs.Define(ID, "SESSION_ENDED", errs.Unauthenticated, 401, errs.RetryNo,
			"The session has ended; log in again")}
	issuerOfIDTokens := cfg.String("CASDOOR_ISSUER")
	if issuerOfIDTokens == "" {
		issuerOfIDTokens = cfg.String("CASDOOR_PUBLIC_URL")
	}
	secret := func(name string) func() string {
		return func() string {
			if s := cfg.Secret(name); s != nil {
				return s.Value()
			}
			return ""
		}
	}
	m.casdoor = &casdoor{http: cd, publicURL: strings.TrimRight(cfg.String("CASDOOR_PUBLIC_URL"), "/"),
		issuer: issuerOfIDTokens, clientID: cfg.String("CASDOOR_CLIENT_ID"), callback: cfg.String("IAM_CALLBACK_URL"),
		secret: secret("CASDOOR_CLIENT_SECRET"), devClientID: cfg.String("IAM_DEV_CLIENT_ID"),
		devSecret: secret("IAM_DEV_CLIENT_SECRET")}
	m.keys = &keyRing{current: secret("IAM_SIGNING_KEY"), next: secret("IAM_SIGNING_KEY_NEXT"),
		warn: func(err error) { rt.Logger.Error("a signing key could not be read", "error", err.Error()) }}
	if _, _, err := m.keys.keys(); err != nil {
		return nil, err // a member that cannot sign is not started
	}
	if m.dev {
		if m.casdoor.devClientID == "" || m.casdoor.devSecret() == "" {
			return nil, errs.New(errs.ReasonRequestInvalid, "IAM_DEV_EXCHANGE needs IAM_DEV_CLIENT_ID and IAM_DEV_CLIENT_SECRET")
		}
		rt.Logger.Warn("the development token exchange is on (IAM_DEV_EXCHANGE): never in a production deployment (A101)")
	}
	return m, nil
}

// Routes registers the login, the session's token, the logout, the public keys and, in development deployments,
// the password exchange. They are all public: they are how a credential is obtained in the first place.
func (m *Module) Routes(r *httpx.Routes) error {
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/login", Public: true, Handle: m.login})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/callback", Public: true, Handle: m.callback})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/session/token", Public: true, Handle: m.sessionToken})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/logout", Public: true, Handle: m.logout})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/jwks", Public: true, Handle: m.jwks})
	if m.dev {
		r.Add(httpx.Route{Method: "POST", Path: "/api/iam/dev/token", Public: true, Handle: m.devToken})
	}
	return nil
}

// returnTo keeps only a path on this site: anything else would make the login an open redirect.
func (m *Module) returnTo(q string) string {
	if strings.HasPrefix(q, "/") && !strings.HasPrefix(q, "//") && !strings.Contains(q, "\\") {
		return q
	}
	return m.after
}

func (m *Module) login(c *httpx.Context) error {
	state := randomToken()
	verifier, challenge := pkce()
	if err := m.store.begin(c.Ctx(), hashOf(state), verifier, m.returnTo(c.Query("return_to"))); err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, m.casdoor.authorizeURL(state, challenge))
}

func (m *Module) callback(c *httpx.Context) error {
	if e := c.Query("error"); e != "" {
		return errs.New(errs.ReasonTokenInvalid, "the identity provider ended the login").With("provider_error", e)
	}
	verifier, returnTo, err := m.store.take(c.Ctx(), hashOf(c.Query("state")))
	if err == errNoLogin {
		return errs.New(errs.ReasonRequestInvalid, "the login is unknown or expired; start again")
	} else if err != nil {
		return err
	}
	id, err := m.casdoor.code(c.Ctx(), c.Query("code"), verifier)
	if err != nil {
		return err
	}
	principal, err := m.store.principal(c.Ctx(), id)
	if err != nil {
		return err
	}
	secret := randomToken()
	if err := m.store.open(c.Ctx(), hashOf(secret), principal); err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{Name: CookieName, Value: secret, Path: "/", HttpOnly: true, Secure: m.secure,
		SameSite: http.SameSiteLaxMode})
	return c.Redirect(http.StatusSeeOther, returnTo)
}

func (m *Module) session(c *httpx.Context) string {
	ck, err := c.Request().Cookie(CookieName)
	if err != nil || ck.Value == "" {
		return ""
	}
	return hashOf(ck.Value)
}

// sessionToken is the edge's exchange: a live session's cookie for a short access token (protocol 20, D61).
func (m *Module) sessionToken(c *httpx.Context) error {
	h := m.session(c)
	if h == "" {
		return m.ended.New("no live session")
	}
	principal, until, ok, err := m.store.use(c.Ctx(), h, m.idle, m.absolute)
	if err != nil {
		return err
	}
	if !ok {
		return m.ended.New("no live session")
	}
	return m.answerToken(c, principal, until)
}

func (m *Module) answerToken(c *httpx.Context, principal string, until time.Time) error {
	now := time.Now()
	tok, exp, err := m.issue(principal, now, until)
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_in": int(exp.Sub(now).Seconds()), "principal": principal})
}

func (m *Module) logout(c *httpx.Context) error {
	if h := m.session(c); h != "" {
		if err := m.store.end(c.Ctx(), h, "logout"); err != nil {
			return err
		}
	}
	c.SetCookie(&http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: m.secure,
		SameSite: http.SameSiteLaxMode})
	return c.NoContent(http.StatusNoContent)
}

// jwks publishes the current and the standby key (RFC 7517); components fetch it from IAM_JWKS_URL (P8.2).
func (m *Module) jwks(c *httpx.Context) error {
	_, set, err := m.keys.keys()
	if err != nil {
		return err
	}
	out := make([]map[string]string, len(set))
	for i, k := range set {
		out[i] = k.jwk()
	}
	return c.JSON(200, map[string]any{"keys": out})
}

// devToken exchanges a user's password for an access token through Casdoor's development client (A101). Seeds and
// automated tests get real tokens this way; it does not exist unless IAM_DEV_EXCHANGE is on.
func (m *Module) devToken(c *httpx.Context) error {
	var in struct{ Username, Password string }
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	if in.Username == "" || in.Password == "" {
		return errs.New(errs.ReasonRequestInvalid, "username and password are required")
	}
	id, err := m.casdoor.password(c.Ctx(), in.Username, in.Password)
	if err != nil {
		return err
	}
	principal, err := m.store.principal(c.Ctx(), id)
	if err != nil {
		return err
	}
	return m.answerToken(c, principal, time.Time{})
}
