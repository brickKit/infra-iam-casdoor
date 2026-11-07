package core

import (
	"time"

	"github.com/brickKit/be-sdk-go/v3/runtime"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	keys "github.com/brickKit/infra-iam-casdoor/v3/internal/keys"
	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"
)

// Base is what every module works with: the component's runtime; the store of sessions and accounts; the Casdoor
// clients and the signing keys; the tokens' issuer, audience and lifetimes; the session cookie's settings; the
// development exchange; the pull interval and the tightening window; the authorization member's account service.
type Base struct {
	RT       *runtime.Runtime
	Store    Store
	Impl     string // IMPLEMENTATION_INSTANCE: the ended stream's cursors name it
	Casdoor  *provider.Casdoor
	Keys     *keys.KeyRing
	Issuer   string
	Audience string
	TTL      time.Duration
	Idle     time.Duration
	Absolute time.Duration
	Secure   bool
	After    string
	Dev      bool
	PullEach time.Duration // P_pull
	Tight    time.Duration // T_tight
	Authz    authzv3.AccountServiceClient
}
