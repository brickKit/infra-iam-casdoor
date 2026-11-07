package iam

import (
	"context"
	"strings"
	"time"

	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/grpcx"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/runtime"
	"github.com/brickKit/be-sdk-go/v3/sessionpb"
	"github.com/brickKit/be-sdk-go/v3/work"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	accounts "github.com/brickKit/infra-iam-casdoor/v3/internal/accounts"
	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	keys "github.com/brickKit/infra-iam-casdoor/v3/internal/keys"
	login "github.com/brickKit/infra-iam-casdoor/v3/internal/login"
	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"
	reconcile "github.com/brickKit/infra-iam-casdoor/v3/internal/reconcile"
	replay "github.com/brickKit/infra-iam-casdoor/v3/internal/replay"
	sessions "github.com/brickKit/infra-iam-casdoor/v3/internal/sessions"
)

// Module is the identity component as the launcher and the shells run it: it only assembles the business modules
// under internal/ (their map is internal/AGENTS.md).
type Module struct {
	b *core.Base
}

// New builds the module: the store, the Casdoor clients, the signing keys and the settings the modules share; a
// deployment without DEPLOYMENT_ID, a pull interval that is not positive, an authorization member that cannot be
// dialled or a member that cannot sign is not started.
func New(rt *runtime.Runtime) (*Module, error) {
	cfg := rt.Config
	if cfg.String("DEPLOYMENT_ID") == "" {
		return nil, errs.New(errs.ReasonRequestInvalid, "DEPLOYMENT_ID is required: the tokens' audience is be:deployment:<DEPLOYMENT_ID>")
	}
	cd, _ := rt.HTTPAt("casdoor", cfg.String("CASDOOR_URL"))
	b := &core.Base{RT: rt, Store: core.Store{Db: rt.DB, Events: rt.Events, Deployment: cfg.String("DEPLOYMENT_ID"), Ev: rt.Evidence},
		Impl: cfg.String("IMPLEMENTATION_INSTANCE"), Issuer: cfg.String("IAM_TOKEN_ISSUER"),
		Audience: "be:deployment:" + cfg.String("DEPLOYMENT_ID"), TTL: cfg.Duration("IAM_ACCESS_TOKEN_TTL"),
		Idle: cfg.Duration("IAM_SESSION_IDLE"), Absolute: cfg.Duration("IAM_SESSION_ABSOLUTE"),
		Secure: cfg.Bool("IAM_COOKIE_SECURE"), After: cfg.String("IAM_AFTER_LOGIN_URL"), Dev: cfg.Bool("IAM_DEV_EXCHANGE"),
		PullEach: cfg.Duration("IAM_PULL_INTERVAL"), Tight: cfg.Duration("IAM_T_TIGHT")}
	if b.PullEach <= 0 {
		return nil, errs.New(errs.ReasonRequestInvalid, "IAM_PULL_INTERVAL must be positive")
	}
	// the authorization member's system surface: an account's status change is asked there first (A134)
	conn, ok := rt.GRPCAt(core.Authz, cfg.String("AUTHZ_GRPC_URL"))
	if !ok {
		return nil, errs.New(errs.ReasonRequestInvalid, "AUTHZ_GRPC_URL cannot be dialled: account status changes are asked there")
	}
	b.Authz = authzv3.NewAccountServiceClient(conn)
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
	b.Casdoor = &provider.Casdoor{HTTP: cd, PublicURL: strings.TrimRight(cfg.String("CASDOOR_PUBLIC_URL"), "/"),
		Issuer: issuerOfIDTokens, ClientID: cfg.String("CASDOOR_CLIENT_ID"), Callback: cfg.String("IAM_CALLBACK_URL"),
		Secret: secret("CASDOOR_CLIENT_SECRET"), DevClientID: cfg.String("IAM_DEV_CLIENT_ID"),
		DevSecret: secret("IAM_DEV_CLIENT_SECRET")}
	b.Keys = &keys.KeyRing{Current: secret("IAM_SIGNING_KEY"), Next: secret("IAM_SIGNING_KEY_NEXT"),
		Warn: func(err error) { rt.Logger.Error("a signing key could not be read", "error", err.Error()) }}
	if _, _, err := b.Keys.Keys(); err != nil {
		return nil, err // a member that cannot sign is not started
	}
	if b.Dev {
		if b.Casdoor.DevClientID == "" || b.Casdoor.DevSecret() == "" {
			return nil, errs.New(errs.ReasonRequestInvalid, "IAM_DEV_EXCHANGE needs IAM_DEV_CLIENT_ID and IAM_DEV_CLIENT_SECRET")
		}
		rt.Logger.Warn("the development token exchange is on (IAM_DEV_EXCHANGE): never in a production deployment (A101)")
	}
	return &Module{b: b}, nil
}

// Jobs declares the background work: the pull of Casdoor's accounts (reconcile).
func (m *Module) Jobs(j *work.Jobs) error {
	j.Add(work.Job{Name: reconcile.JobPull, Kind: work.Singleton, Effect: work.IdempotentExternal, Interval: m.b.PullEach,
		MaxAttempts: work.Unlimited, Timeout: 2 * time.Minute, Handle: func(ctx context.Context, r *work.Run) error {
			return reconcile.Pull(m.b, ctx, r)
		}})
	return nil
}

// Start adopts the accounts bound before the issuer was recorded and ends the sessions a full recovery left behind.
func (m *Module) Start(ctx context.Context) error {
	if err := m.b.Store.Adopt(ctx, m.b.Casdoor.Issuer); err != nil {
		return err
	}
	return sessions.EndSessionsBeforeRecovery(m.b, ctx)
}

// Routes registers the user surface: the browser's login flow, the password, the keys, the accounts' operations.
func (m *Module) Routes(r *httpx.Routes) error {
	h := m.handler
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/login", Public: true, Handle: h(login.Login)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/callback", Public: true, Handle: h(login.Callback)})
	// ending one's session and changing one's password stay open while the deployment is open read-only (P1.23)
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/logout", Public: true, ReadOnlyOpen: true, Handle: h(login.Logout)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/password", Public: true, ReadOnlyOpen: true, Handle: h(sessions.ChangePassword)})
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/jwks", Public: true, Handle: h(login.Jwks)})
	if m.b.Dev {
		r.Add(httpx.Route{Method: "POST", Path: "/api/iam/dev/token", Public: true, ReadOnlyOpen: true, Handle: h(login.DevToken)})
	}
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/accounts/:principal", Operation: core.OpAccountView, Handle: h(accounts.AccountHTTP)})
	status := func(op, target string) httpx.Handler {
		return func(c *httpx.Context) error { return accounts.StatusHTTP(m.b, c, op, target) }
	}
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/disable", Operation: core.OpDisable, Handle: status(core.OpDisable, "disabled")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/freeze", Operation: core.OpFreeze, Handle: status(core.OpFreeze, "security_frozen")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/enable", Operation: core.OpEnable, Handle: status(core.OpEnable, "active")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/logout", Operation: core.OpForceLogout, Handle: h(accounts.ForceLogoutHTTP)})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/reset-second-factor", Operation: core.OpResetFactors,
		Handle: h(accounts.ResetFactorsHTTP)})
	return nil
}

// Services registers the session methods on the system surface (be.session.v1, P8.28), callable by infra/edge only.
func (m *Module) Services(s *grpcx.Services) error {
	s.Register(&sessionpb.SessionService_ServiceDesc, sessions.NewSessions(m.b), map[string]grpcx.Method{
		"Exchange": {Operation: core.OpExchange, Callers: []string{core.Edge}},
		"Ended":    {Operation: core.OpEnded, Callers: []string{core.Edge}},
	})
	return nil
}

// Replays registers the replay of this member's evidence after a full recovery (evidence.Replayer).
func (m *Module) Replays(r *evidence.Replays) error {
	r.Add("account_status", m.b.Store.ReplayStatus)
	r.Add("account_reenable", m.b.Store.ReplayStatus)
	r.Add("session_revocation", m.b.Store.ReplayLogout)
	check := func(ctx context.Context, rec evidence.Replayed) (bool, string, error) {
		return replay.CheckCredential(m.b, ctx, rec)
	}
	r.Check("credential_tightening", check)
	r.Check("credential_tightening_in_product", check)
	return nil
}

// handler adapts a module's handler, which takes the shared base first, to what the SDK registers.
func (m *Module) handler(f func(*core.Base, *httpx.Context) error) httpx.Handler {
	return func(c *httpx.Context) error { return f(m.b, c) }
}
