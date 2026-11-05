package iam

import (
	"os"
	"testing"

	"github.com/brickKit/be-sdk-go/v3/launcher"
	"github.com/stretchr/testify/assert"
)

// ownKeys are the descriptions of the member's own keys in component.yaml.
var ownKeys = map[string]string{
	"CASDOOR_CLIENT_ID":    "the login application's client ID (authorization code)",
	"CASDOOR_ISSUER":       "the iss of Casdoor's ID tokens (its origin setting); default CASDOOR_PUBLIC_URL",
	"CASDOOR_PUBLIC_URL":   "Casdoor as the browser reaches it (the login page)",
	"CASDOOR_URL":          "Casdoor on the back channel (token exchange, keys), e.g. http://be-casdoor:8000",
	"IAM_ACCESS_TOKEN_TTL": "a duration (e.g. 2s, 500ms); default 5m (protocol 20)",
	"IAM_AFTER_LOGIN_URL":  "where the browser goes after a login without return_to; default /",
	"IAM_CALLBACK_URL":     "the redirect URI registered for the application in Casdoor: <this member's public URL>/api/iam/callback",
	"IAM_COOKIE_SECURE":    "the session cookie is Secure; default true (false only for plain-HTTP development)",
	"IAM_DEV_CLIENT_ID":    "the development client with the password grant (IAM_DEV_EXCHANGE)",
	"IAM_PULL_INTERVAL":    "a duration (e.g. 2s, 500ms); default 1m: P_pull, how often every bound account is compared with Casdoor (security 03), besides before every echo",
	"IAM_DEV_EXCHANGE":     "development and test deployments only (A101): POST /api/iam/dev/token exchanges a user's password for a token; default false, and the go-live check confirms it is off",
	"IAM_SESSION_ABSOLUTE": "a duration (e.g. 2s, 500ms); default 12h (protocol 20)",
	"IAM_SESSION_IDLE":     "a duration (e.g. 2s, 500ms); default 30m (protocol 20)",
	"IAM_SIGNING_KEY":      "the current signing key: PEM, Ed25519 (PKCS #8); usually IAM_SIGNING_KEY_FILE, re-read on rotation",
	"IAM_T_TIGHT":          "a duration (e.g. 2s, 500ms); default 1h: T_tight (security 03), beyond which a disablement or freeze decided on a stale view needs a second person",
	"IAM_SIGNING_KEY_NEXT": "the standby key, published in the JWKS before it signs; after a switch, the old key, until its tokens expire",
	"IAM_TOKEN_ISSUER":     "the iss of the tokens this member signs; every component's IAM_ISSUER equals it",
}

// TestTheManifestDeclaresWhatTheSDKReads: component.yaml's configSchema is exactly the keys the SDK reads.
func TestTheManifestDeclaresWhatTheSDKReads(t *testing.T) {
	raw, err := os.ReadFile("../component.yaml")
	assert.NoError(t, err)
	if p := launcher.ManifestProblems(raw, Definition(), ownKeys); len(p) > 0 {
		t.Errorf("component.yaml's configSchema differs from what the SDK reads:\n%v\nthe block:\n%s", p,
			launcher.ConfigSchemaYAML(Definition(), ownKeys))
	}
}

// TestTheManifestListsThePublishedEvents: component.yaml's events.publishes is exactly the event contracts.
func TestTheManifestListsThePublishedEvents(t *testing.T) {
	raw, err := os.ReadFile("../component.yaml")
	assert.NoError(t, err)
	assert.Empty(t, launcher.EventProblems(raw, os.DirFS("../contract/events")))
}
