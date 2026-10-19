package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/golang-jwt/jwt/v5"
)

// casdoor is the OIDC client side towards Casdoor: the browser's authorization request with PKCE, the code and (in
// development) password exchanges on the back channel, and the ID token's verification against Casdoor's keys. Every
// back-channel call goes through the SDK's call policy (deadline, retries, breaker).
type casdoor struct {
	http               *calls.HTTP
	publicURL, issuer  string
	clientID, callback string
	secret             func() string
	devClientID        string
	devSecret          func() string

	mu      sync.Mutex
	keys    keyfunc.Keyfunc
	fetched time.Time
}

// keysRefetchAfter bounds how often an unknown kid fetches Casdoor's keys again.
const keysRefetchAfter = 30 * time.Second

// providerUser is what a verified ID token says about the user.
type providerUser struct {
	Subject  string // Casdoor's stable user id
	Username string // owner/name
}

// pkce returns a code verifier and its S256 challenge (RFC 7636).
func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = b64(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64(sum[:])
}

// randomToken is 256 random bits, URL safe: states and session secrets.
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64(b)
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

// authorizeURL is where the browser goes to log in.
func (c *casdoor) authorizeURL(state, challenge string) string {
	q := url.Values{"client_id": {c.clientID}, "response_type": {"code"}, "redirect_uri": {c.callback},
		"scope": {"openid profile"}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return c.publicURL + "/login/oauth/authorize?" + q.Encode()
}

type tokenAnswer struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchange posts to Casdoor's token endpoint and verifies the ID token of the answer.
func (c *casdoor) exchange(ctx context.Context, body map[string]string, clientID string) (providerUser, error) {
	var ans tokenAnswer
	err := c.http.Do(ctx, calls.Request{Method: "POST", Path: "/api/login/oauth/access_token", Body: body}, &ans)
	var refused *calls.StatusError
	if errors.As(err, &refused) && (refused.Status == 400 || refused.Status == 401) {
		// RFC 6749 5.2: a refused grant is 400 (401 for the client) with an error member
		if json.Unmarshal(refused.Body, &ans) == nil && ans.Error != "" {
			err = nil
		}
	}
	if err != nil {
		return providerUser{}, err
	}
	if ans.Error != "" || ans.IDToken == "" {
		// Casdoor answers a refused grant with 200 and an error member; the description never goes to the user
		return providerUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider refused the login").
			With("provider_error", ans.Error)
	}
	return c.verify(ctx, ans.IDToken, clientID)
}

// code exchanges an authorization code with its PKCE verifier.
func (c *casdoor) code(ctx context.Context, code, verifier string) (providerUser, error) {
	return c.exchange(ctx, map[string]string{"grant_type": "authorization_code", "client_id": c.clientID,
		"client_secret": c.secret(), "code": code, "code_verifier": verifier, "redirect_uri": c.callback}, c.clientID)
}

// password exchanges a user's password with the development client (A101: development and test deployments only).
func (c *casdoor) password(ctx context.Context, username, password string) (providerUser, error) {
	return c.exchange(ctx, map[string]string{"grant_type": "password", "client_id": c.devClientID,
		"client_secret": c.devSecret(), "username": username, "password": password, "scope": "openid"}, c.devClientID)
}

// verify checks an ID token: Casdoor's signature, its issuer, the audience (the client it was issued to), the
// lifetime; it returns the subject.
func (c *casdoor) verify(ctx context.Context, raw, audience string) (providerUser, error) {
	parse := func(kf keyfunc.Keyfunc) (*jwt.Token, error) {
		return jwt.Parse(raw, kf.Keyfunc, jwt.WithIssuer(c.issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"RS256", "RS512", "ES256", "EdDSA"}), jwt.WithLeeway(60*time.Second))
	}
	kf, err := c.keyfunc(ctx, false)
	if err != nil {
		return providerUser{}, err
	}
	t, err := parse(kf)
	if errors.Is(err, keyfunc.ErrKeyfunc) || errors.Is(err, jwt.ErrTokenUnverifiable) {
		if kf, err = c.keyfunc(ctx, true); err != nil { // Casdoor may have rotated its keys
			return providerUser{}, err
		}
		t, err = parse(kf)
	}
	if err != nil {
		return providerUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider's ID token did not verify").
			With("cause", err.Error())
	}
	claims := t.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)
	owner, _ := claims["owner"].(string)
	name, _ := claims["name"].(string)
	if sub == "" {
		return providerUser{}, errs.New(errs.ReasonTokenInvalid, "the identity provider's ID token has no subject")
	}
	return providerUser{Subject: sub, Username: owner + "/" + name}, nil
}

// keyfunc returns Casdoor's keys, fetched on first use and again (at most every keysRefetchAfter) when asked.
func (c *casdoor) keyfunc(ctx context.Context, refetch bool) (keyfunc.Keyfunc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && (!refetch || time.Since(c.fetched) < keysRefetchAfter) {
		return c.keys, nil
	}
	var set json.RawMessage
	if err := c.http.Do(ctx, calls.Request{Method: "GET", Path: "/.well-known/jwks"}, &set); err != nil {
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
