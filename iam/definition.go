// Package iam is the identity member in front of Casdoor (boundary card infra/iam-casdoor): browser login by
// authorization code with PKCE and a server-side session, access tokens it signs itself for the platform principal
// with the account's security version, the edge's session methods (be.session.v1, be-protocol P8.28), the password
// change, its public keys, and in development and test deployments only an exchange of a user's password for a token
// (A101). The pull of changes made in Casdoor itself, the deactivation and the watermark come with foundations item 3.
package iam

import (
	"embed"
	"io/fs"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/component"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/runtime"
)

// Identity of the component.
const (
	ID      = "infra/iam-casdoor"
	Version = "3.0.21"
)

// GRPCPort is the system surface's port (registry/ports.tsv).
const GRPCPort = 9200

// The streams (be-protocol P8.27, P8.28): the ended sessions the edge reads by position (one partition, the name and
// type every identity member uses), and the account status the authorization member takes as an internal source.
const (
	StreamEnded   = "be.session.ended"
	TypeEnded     = "be.session.ended.v1"
	StreamAccount = "infra.iam.account_status"
	TypeAccount   = "infra.iam.account_status_changed.v1"
)

// The system methods' operations and their callers: the edge exchanges and reads the ended sessions; the
// authorization member pulls and reads the account status, a watermark source (P9.13, P9.30).
const (
	Sessions   = "infra.iam.session"
	OpExchange = "infra.iam.session.exchange"
	OpEnded    = "infra.iam.session.ended"
	Edge       = "infra/edge"

	Accounts      = "infra.iam.account_status"
	OpAccountPull = "infra.iam.account_status.pull"
	OpAccountRead = "infra.iam.account_status.read"
	Authz         = "infra/authz"
)

// Definitions are the resources and operations: only the system methods have operations; the routes are public (a
// credential is obtained through them in the first place) and protect themselves with the session cookie.
func Definitions() *sdkauthz.Definitions {
	return &sdkauthz.Definitions{Component: ID,
		Resources: []sdkauthz.Resource{
			{Type: Sessions, ViewOperation: OpEnded, Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{}},
			{Type: Accounts, ViewOperation: OpAccountRead, Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{}}},
		Operations: []sdkauthz.Operation{
			{Key: OpExchange, ResourceType: Sessions, Purpose: "action", RiskClass: "low"},
			{Key: OpEnded, ResourceType: Sessions, Purpose: "read", RiskClass: "low"},
			{Key: OpAccountPull, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
			{Key: OpAccountRead, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
		}}
}

// Starting values (protocol 20).
const (
	DefaultTokenTTL = 5 * time.Minute
	DefaultIdle     = 30 * time.Minute
	DefaultAbsolute = 12 * time.Hour
	LoginTTL        = 10 * time.Minute
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func migrations() fs.FS {
	sub, _ := fs.Sub(migrationFiles, "migrations")
	return sub
}

// Keys are the component's own configuration keys.
func Keys() []config.Key {
	return []config.Key{
		// what the tokens carry and how they are signed
		{Name: "IAM_TOKEN_ISSUER", Type: config.String, Required: true},              // the iss of the tokens: every component's IAM_ISSUER
		{Name: "IAM_SIGNING_KEY", Type: config.String, Required: true, Secret: true}, // PEM, Ed25519 (PKCS #8)
		{Name: "IAM_SIGNING_KEY_NEXT", Type: config.String, Secret: true},            // the standby key, published ahead
		{Name: "IAM_ACCESS_TOKEN_TTL", Type: config.Duration, Default: DefaultTokenTTL},
		// the browser session
		{Name: "IAM_CALLBACK_URL", Type: config.String, Required: true}, // the redirect URI registered in Casdoor
		{Name: "IAM_AFTER_LOGIN_URL", Type: config.String, Default: "/"},
		{Name: "IAM_COOKIE_SECURE", Type: config.Boolean, Default: true},
		{Name: "IAM_SESSION_IDLE", Type: config.Duration, Default: DefaultIdle},
		{Name: "IAM_SESSION_ABSOLUTE", Type: config.Duration, Default: DefaultAbsolute},
		// Casdoor: the back channel, the browser's address, the application and the issuer of its ID tokens
		{Name: "CASDOOR_URL", Type: config.String, Required: true},
		{Name: "CASDOOR_PUBLIC_URL", Type: config.String, Required: true},
		{Name: "CASDOOR_ISSUER", Type: config.String}, // default CASDOOR_PUBLIC_URL
		{Name: "CASDOOR_CLIENT_ID", Type: config.String, Required: true},
		{Name: "CASDOOR_CLIENT_SECRET", Type: config.String, Required: true, Secret: true},
		// A101: development and test deployments only; the go-live check confirms it is off
		// P_pull (security 03): how often every bound account is compared with Casdoor, besides before every echo
		{Name: "IAM_PULL_INTERVAL", Type: config.Duration, Default: DefaultPullInterval},
		{Name: "IAM_DEV_EXCHANGE", Type: config.Boolean, Default: false},
		{Name: "IAM_DEV_CLIENT_ID", Type: config.String},
		{Name: "IAM_DEV_CLIENT_SECRET", Type: config.String, Secret: true},
	}
}

// Definition is the component as the launcher and the shells take it.
func Definition() component.Definition {
	ref := &pullRef{} // the account stream's step before the echo reaches the module through it
	return component.Definition{ID: ID, Version: Version, Keys: Keys(), Migrations: migrations(), GRPCPort: GRPCPort,
		Streams: []events.Stream{{Name: StreamEnded, Partitions: 1}, accountStream(ref)},
		Authz:   Definitions(),
		New: func(rt *runtime.Runtime) (component.Module, error) {
			m, err := New(rt)
			if err == nil {
				ref.set(m.reconcile)
			}
			return m, err
		}}
}
