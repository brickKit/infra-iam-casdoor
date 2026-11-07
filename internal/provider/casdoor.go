package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	keys "github.com/brickKit/infra-iam-casdoor/v3/internal/keys"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/golang-jwt/jwt/v5"
)

// Casdoor is the OIDC client side towards Casdoor: the browser's authorization request with PKCE, the code and (in
// development) password exchanges on the back channel, and the ID token's verification against Casdoor's keys. Every
// back-channel call goes through the SDK's call policy (deadline, retries, breaker).
type Casdoor struct {
	HTTP               *calls.HTTP   `json:"-"`
	PublicURL, Issuer  string        `json:"-"`
	ClientID, Callback string        `json:"-"`
	Secret             func() string `json:"-"`
	DevClientID        string        `json:"-"`
	DevSecret          func() string `json:"-"`

	mu      sync.Mutex
	keys    keyfunc.Keyfunc
	fetched time.Time
}

// keysRefetchAfter bounds how often an unknown kid fetches Casdoor's keys again.
const keysRefetchAfter = 30 * time.Second

// ProviderUser is what a verified ID token says about the user.
type ProviderUser struct {
	Subject  string // Casdoor's stable user id
	Username string // owner/name
}

// Pkce returns a code verifier and its S256 challenge (RFC 7636).
func Pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = keys.B64(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, keys.B64(sum[:])
}

// RandomToken is 256 random bits, URL safe: states and session secrets.
func RandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return keys.B64(b)
}

// HashOf is what the tables keep of a secret (a session cookie, a login's state): its SHA-256 in lowercase hex, the
// form the edge sends as a session digest (be-protocol P8.28).
func HashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// AuthorizeURL is where the browser goes to log in.
func (c *Casdoor) AuthorizeURL(state, challenge string) string {
	q := url.Values{"client_id": {c.ClientID}, "response_type": {"code"}, "redirect_uri": {c.Callback},
		"scope": {"openid profile"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return c.PublicURL + "/login/oauth/authorize?" + q.Encode()
}

type tokenAnswer struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchange posts to Casdoor's token endpoint and verifies the ID token of the answer.
func (c *Casdoor) exchange(ctx context.Context, body map[string]string, clientID string) (ProviderUser, error) {
	var ans tokenAnswer
	err := c.HTTP.Do(ctx, calls.Request{Method: "POST", Path: "/api/login/oauth/access_token", Body: body}, &ans)
	var refused *calls.StatusError
	if errors.As(err, &refused) && (refused.Status == 400 || refused.Status == 401) {
		// RFC 6749 5.2: a refused grant is 400 (401 for the client) with an error member
		if json.Unmarshal(refused.Body, &ans) == nil && ans.Error != "" {
			err = nil
		}
	}
	if err != nil {
		return ProviderUser{}, err
	}
	if ans.Error != "" || ans.IDToken == "" {
		// Casdoor answers a refused grant with 200 and an error member; the description never goes to the user
		return ProviderUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider refused the login").
			With("provider_error", ans.Error)
	}
	return c.verify(ctx, ans.IDToken, clientID)
}

// Code exchanges an authorization code with its PKCE verifier.
func (c *Casdoor) Code(ctx context.Context, code, verifier string) (ProviderUser, error) {
	return c.exchange(ctx, map[string]string{"grant_type": "authorization_code", "client_id": c.ClientID,
		"client_secret": c.Secret(), "code": code, "code_verifier": verifier, "redirect_uri": c.Callback}, c.ClientID)
}

// Password exchanges a user's password with the development client (A101: development and test deployments only).
func (c *Casdoor) Password(ctx context.Context, username, password string) (ProviderUser, error) {
	return c.exchange(ctx, map[string]string{"grant_type": "password", "client_id": c.DevClientID,
		"client_secret": c.DevSecret(), "username": username, "password": password, "scope": "openid"}, c.DevClientID)
}

// SetPassword changes a user's password in Casdoor with the login application's credentials; Casdoor still checks
// the old password (experiment 16-03), and a wrong one counts toward its lockout. Casdoor answers 200 with status
// "error" when it refuses.
func (c *Casdoor) SetPassword(ctx context.Context, username, oldPassword, newPassword string) error {
	owner, name, ok := strings.Cut(username, "/")
	if !ok {
		return errs.From(fmt.Errorf("casdoor: the account's user name %q is not owner/name", username))
	}
	var ans struct{ Status, Msg string }
	// everything in the form body: neither the passwords nor the client secret travel in the URL
	err := c.HTTP.Do(ctx, calls.Request{Method: "POST", Path: "/api/set-password", Form: url.Values{
		"clientId": {c.ClientID}, "clientSecret": {c.Secret()}, "userOwner": {owner}, "userName": {name},
		"oldPassword": {oldPassword}, "newPassword": {newPassword}}}, &ans)
	if err != nil {
		return err
	}
	if ans.Status != "ok" {
		// the message (which may say how many attempts are left) is logged by the caller, never sent
		return errs.New(errs.ReasonRequestInvalid, "the password could not be changed").With("field", "old_password").
			With("provider_error", ans.Msg)
	}
	return nil
}

// verify checks an ID token: Casdoor's signature, its issuer, the audience (the client it was issued to), the
// lifetime; it returns the subject.
func (c *Casdoor) verify(ctx context.Context, raw, audience string) (ProviderUser, error) {
	parse := func(kf keyfunc.Keyfunc) (*jwt.Token, error) {
		return jwt.Parse(raw, kf.Keyfunc, jwt.WithIssuer(c.Issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"RS256", "RS512", "ES256", "EdDSA"}), jwt.WithLeeway(60*time.Second))
	}
	kf, err := c.keyfunc(ctx, false)
	if err != nil {
		return ProviderUser{}, err
	}
	t, err := parse(kf)
	if errors.Is(err, keyfunc.ErrKeyfunc) || errors.Is(err, jwt.ErrTokenUnverifiable) {
		if kf, err = c.keyfunc(ctx, true); err != nil { // Casdoor may have rotated its keys
			return ProviderUser{}, err
		}
		t, err = parse(kf)
	}
	if err != nil {
		return ProviderUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider's ID token did not verify").
			With("cause", err.Error())
	}
	claims := t.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)
	owner, _ := claims["owner"].(string)
	name, _ := claims["name"].(string)
	if sub == "" {
		return ProviderUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider's ID token has no subject")
	}
	return ProviderUser{Subject: sub, Username: owner + "/" + name}, nil
}

// keyfunc returns Casdoor's keys, fetched on first use and again (at most every keysRefetchAfter) when asked.
func (c *Casdoor) keyfunc(ctx context.Context, refetch bool) (keyfunc.Keyfunc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && (!refetch || time.Since(c.fetched) < keysRefetchAfter) {
		return c.keys, nil
	}
	var set json.RawMessage
	if err := c.HTTP.Do(ctx, calls.Request{Method: "GET", Path: "/.well-known/jwks"}, &set); err != nil {
		if c.keys != nil {
			return c.keys, nil // keep the keys we have
		}
		return nil, fmt.Errorf("the identity provider's keys: %w", err)
	}
	kf, err := keyfunc.NewJWKSetJSON(set)
	if err != nil {
		return nil, fmt.Errorf("the identity provider's keys: %w", err)
	}
	c.keys, c.fetched = kf, time.Now()
	return kf, nil
}

// productCallLimit bounds one call to Casdoor made outside a request (the start's: no request deadline to inherit).
const ProductCallLimit = 10 * time.Second
