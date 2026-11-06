package iam

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	"github.com/brickKit/be-sdk-go/v3/work"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
)

// CookieName is the browser session's cookie: a random secret, HttpOnly, SameSite=Lax (protocol 20).
const CookieName = "be_session"

// Module is the identity member.
type Module struct {
	rt       *runtime.Runtime
	store    store
	impl     string // IMPLEMENTATION_INSTANCE: the ended stream's cursors name it
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
	pullEach time.Duration // P_pull
	tight    time.Duration // T_tight
	authz    authzv3.AccountServiceClient
}

// New builds the module from its runtime.
func New(rt *runtime.Runtime) (*Module, error) {
	cfg := rt.Config
	if cfg.String("DEPLOYMENT_ID") == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: the tokens' audience is be:deployment:<DEPLOYMENT_ID>")
	}
	cd, _ := rt.HTTPAt("casdoor", cfg.String("CASDOOR_URL"))
	m := &Module{rt: rt, store: store{db: rt.DB, events: rt.Events, deployment: cfg.String("DEPLOYMENT_ID"), ev: rt.Evidence},
		impl: cfg.String("IMPLEMENTATION_INSTANCE"), issuer: cfg.String("IAM_TOKEN_ISSUER"),
		audience: "be:deployment:" + cfg.String("DEPLOYMENT_ID"), ttl: cfg.Duration("IAM_ACCESS_TOKEN_TTL"),
		idle: cfg.Duration("IAM_SESSION_IDLE"), absolute: cfg.Duration("IAM_SESSION_ABSOLUTE"),
		secure: cfg.Bool("IAM_COOKIE_SECURE"), after: cfg.String("IAM_AFTER_LOGIN_URL"), dev: cfg.Bool("IAM_DEV_EXCHANGE"),
		pullEach: cfg.Duration("IAM_PULL_INTERVAL"), tight: cfg.Duration("IAM_T_TIGHT")}
	if m.pullEach <= 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, "IAM_PULL_INTERVAL must be positive")
	}
	// the authorization member's system surface: an account's status change is asked there first (A134)
	conn, ok := rt.GRPCAt(Authz, cfg.String("AUTHZ_GRPC_URL"))
	if !ok {
		return nil, errs.New(errs.ReasonRequestInvalid, "AUTHZ_GRPC_URL cannot be dialled: account status changes are asked there")
	}
	m.authz = authzv3.NewAccountServiceClient(conn)
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

// signedIn binds the verified Casdoor user and refuses an account this member has disabled or frozen: Casdoor may
// still let it in (a console re-enable or a product rollback, until the next comparison forbids it there again).
func (m *Module) signedIn(ctx context.Context, id providerUser) (account, error) {
	a, err := m.store.principal(ctx, m.casdoor.issuer, id)
	if err == nil && a.status != "active" {
		m.rt.Logger.Warn("a sign-in of an account disabled here was refused", "principal", a.principal, "status", a.status)
		return a, errs.New(errs.ReasonTokenInvalid, "the account cannot sign in")
	}
	return a, err
}

// Jobs declares the periodic comparison with Casdoor (security 03's P_pull).
func (m *Module) Jobs(j *work.Jobs) error {
	j.Add(work.Job{Name: JobPull, Kind: work.Singleton, Effect: work.IdempotentExternal, Interval: m.pullEach,
		MaxAttempts: work.Unlimited, Timeout: 2 * time.Minute, Handle: m.pull})
	return nil
}

// Start gives the accounts bound before the issuer was kept the configured Casdoor's issuer (store.adopt), and ends
// the sessions from before a full recovery (protocol 15, 6.6). The SDK does not start a module while frozen (the
// database may be under restore then, be-protocol P1.23).
func (m *Module) Start(ctx context.Context) error {
	if err := m.store.adopt(ctx, m.casdoor.issuer); err != nil {
		return err
	}
	return m.endSessionsBeforeRecovery(ctx)
}

// productCallLimit bounds one call to Casdoor made outside a request (the start's: no request deadline to inherit).
const productCallLimit = 10 * time.Second

// endSessionsBeforeRecovery ends this platform's sessions from before a full recovery, then this platform's client
// sessions in Casdoor of the same people (protocol 15, 6.6 when the identity product is outside the recovery group:
// the people's sessions in other applications stay). A product call that fails is logged for the operator; the
// platform's sessions are ended either way.
func (m *Module) endSessionsBeforeRecovery(ctx context.Context) error {
	people, err := m.store.endBeforeRecovery(ctx)
	if err != nil || len(people) == 0 {
		return err
	}
	failed := 0
	for _, u := range people {
		cctx, cancel := context.WithTimeout(ctx, productCallLimit)
		err := m.casdoor.endSessions(cctx, u)
		cancel()
		if err != nil {
			failed++
			m.rt.Logger.Warn("a full recovery could not end a person's sessions in Casdoor", "username", u, "error", err.Error())
		}
	}
	m.rt.Logger.Warn("a full recovery ended the sessions from before it", "event", "sessions_ended_by_recovery",
		"people", len(people), "product_failures", failed)
	return nil
}

// Routes registers the login, the logout, the password change, the public keys and, in development deployments, the
// password exchange: public, they are how a credential is obtained in the first place, and the session cookie
// protects the others; and the account operations, protected (accountops.go). The session's token is not among them: only the edge exchanges, on the system surface
// (Services), so a page's script never reads a token (protocol 20 UI04).
func (m *Module) Routes(r *httpx.Routes) error {
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/login", Public: true, Handle: m.login})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/callback", Public: true, Handle: m.callback})
	// ending one's session and changing one's password stay open while the deployment is open read-only (P1.23)
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/logout", Public: true, ReadOnlyOpen: true, Handle: m.logout})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/password", Public: true, ReadOnlyOpen: true, Handle: m.changePassword})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/jwks", Public: true, Handle: m.jwks})
	if m.dev {
		r.Add(httpx.Route{Method: "POST", Path: "/api/iam/dev/token", Public: true, ReadOnlyOpen: true, Handle: m.devToken})
	}
	m.routesForAccounts(r)
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
	a, err := m.signedIn(c.Ctx(), id)
	if err != nil {
		return err
	}
	secret := randomToken()
	if err := m.store.open(c.Ctx(), hashOf(secret), a.principal); err != nil {
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

func (m *Module) answerToken(c *httpx.Context, a account, until time.Time) error {
	now := time.Now()
	tok, exp, err := m.issue(a.principal, a.securityVersion, now, until)
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_in": int(exp.Sub(now).Seconds()), "principal": a.principal})
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
	a, err := m.signedIn(c.Ctx(), id)
	if err != nil {
		return err
	}
	return m.answerToken(c, a, time.Time{})
}
