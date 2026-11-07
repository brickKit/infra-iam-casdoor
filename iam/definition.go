// Package iam is the identity member in front of Casdoor (boundary card infra/iam-casdoor): browser login by
// authorization code with PKCE and a server-side session, access tokens it signs itself for the platform principal
// with the account's security version, the edge's session methods (be.session.v1, be-protocol P8.28), the password
// change, its public keys, and in development and test deployments only an exchange of a user's password for a token
// (A101). The pull of changes made in Casdoor itself, the deactivation and the watermark come with foundations item 3.
package iam

import (
	"context"
	"embed"
	"io/fs"

	accounts "github.com/brickKit/infra-iam-casdoor/v3/internal/accounts"
	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	reconcile "github.com/brickKit/infra-iam-casdoor/v3/internal/reconcile"

	"github.com/brickKit/be-sdk-go/v3/component"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/runtime"
)

// GRPCPort is the system surface's port (registry/ports.tsv).
const GRPCPort = 9200

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
		{Name: "IAM_ACCESS_TOKEN_TTL", Type: config.Duration, Default: core.DefaultTokenTTL},
		// the browser session
		{Name: "IAM_CALLBACK_URL", Type: config.String, Required: true}, // the redirect URI registered in Casdoor
		{Name: "IAM_AFTER_LOGIN_URL", Type: config.String, Default: "/"},
		{Name: "IAM_COOKIE_SECURE", Type: config.Boolean, Default: true},
		{Name: "IAM_SESSION_IDLE", Type: config.Duration, Default: core.DefaultIdle},
		{Name: "IAM_SESSION_ABSOLUTE", Type: config.Duration, Default: core.DefaultAbsolute},
		// Casdoor: the back channel, the browser's address, the application and the issuer of its ID tokens
		{Name: "CASDOOR_URL", Type: config.String, Required: true},
		{Name: "CASDOOR_PUBLIC_URL", Type: config.String, Required: true},
		{Name: "CASDOOR_ISSUER", Type: config.String}, // default CASDOOR_PUBLIC_URL
		{Name: "CASDOOR_CLIENT_ID", Type: config.String, Required: true},
		{Name: "CASDOOR_CLIENT_SECRET", Type: config.String, Required: true, Secret: true},
		// P_pull (security 03): how often every bound account is compared with Casdoor, besides before every echo
		{Name: "IAM_PULL_INTERVAL", Type: config.Duration, Default: reconcile.DefaultPullInterval},
		// T_tight (security 03): beyond it, a disablement or freeze decided on a stale view needs a second person
		{Name: "IAM_T_TIGHT", Type: config.Duration, Default: core.DefaultTight},
		// A101: development and test deployments only; the go-live check confirms it is off
		{Name: "IAM_DEV_EXCHANGE", Type: config.Boolean, Default: false},
		{Name: "IAM_DEV_CLIENT_ID", Type: config.String},
		{Name: "IAM_DEV_CLIENT_SECRET", Type: config.String, Secret: true},
	}
}

// Definition is the component as the launcher and the shells take it.
func Definition() component.Definition {
	ref := &reconcile.PullRef{} // the account stream's step before the echo reaches the module through it
	return component.Definition{ID: core.ID, Version: core.Version, Keys: Keys(), Migrations: migrations(), GRPCPort: GRPCPort,
		Streams: []events.Stream{{Name: core.StreamEnded, Partitions: 1}, accounts.AccountStream(ref)}, Evidence: true, Resend: core.OpResend, Replay: core.OpReplay, Recovery: core.OpRecover,
		Authz: core.Definitions(),
		New: func(rt *runtime.Runtime) (component.Module, error) {
			m, err := New(rt)
			if err == nil {
				ref.Set(func(ctx context.Context) error { return reconcile.Reconcile(m.b, ctx) })
			}
			return m, err
		}}
}
