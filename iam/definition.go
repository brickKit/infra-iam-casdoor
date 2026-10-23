// Package iam is the identity member in front of Casdoor (boundary card infra/iam-casdoor): browser login by
// authorization code with PKCE and a server-side session, access tokens it signs itself for the platform principal,
// its public keys, and in development and test deployments only an exchange of a user's password for a token (A101).
// Step 5 of the representative deployment experiment: the change pull, events and the edge plugin come later.
package iam

import (
	"embed"
	"io/fs"
	"time"

	"github.com/brickKit/be-sdk-go/v3/component"
	"github.com/brickKit/be-sdk-go/v3/config"
	"github.com/brickKit/be-sdk-go/v3/runtime"
)

// Identity of the component.
const (
	ID      = "infra/iam-casdoor"
	Version = "3.0.6"
)

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
		{Name: "IAM_DEV_EXCHANGE", Type: config.Boolean, Default: false},
		{Name: "IAM_DEV_CLIENT_ID", Type: config.String},
		{Name: "IAM_DEV_CLIENT_SECRET", Type: config.String, Secret: true},
	}
}

// Definition is the component as the launcher and the shells take it.
func Definition() component.Definition {
	return component.Definition{ID: ID, Version: Version, Keys: Keys(), Migrations: migrations(),
		New: func(rt *runtime.Runtime) (component.Module, error) { return New(rt) }}
}
