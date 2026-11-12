package core

import (
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
)

// Identity of the component.
const (
	ID      = "infra/iam-casdoor"
	Version = "3.0.50"
)

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
	// OpResend is the redelivery of this member's streams (be-protocol P6.38: every component with streams serves it;
	// any component of the deployment may call it).
	OpResend = "infra.iam.account_status.resend"
	// OpReplay is the replay of this member's evidence in a full recovery (be-protocol P12.19: the recovery tool only).
	OpReplay = "infra.iam.account_status.replay"
	// OpRecover is a full recovery's checks (be-protocol chapter 14: the recovery tool only).
	OpRecover = "infra.iam.account_status.recover"
	Authz     = "infra/authz"
)

// The account operations of the user surface (security 03's tightening-only operations, security 08's admin
// accounts, A134): an account is one record, its principal the dimension AccountDim. Disabling, freezing and the
// forced logout only reduce access; enabling and the reset of the second factors do not.
const (
	Account        = "infra.iam.account"
	AccountDim     = "account"
	OpAccountView  = "infra.iam.account.read"
	OpDisable      = "infra.iam.account.disable"
	OpFreeze       = "infra.iam.account.freeze"
	OpEnable       = "infra.iam.account.enable"
	OpForceLogout  = "infra.iam.account.logout"
	OpResetFactors = "infra.iam.account.reset_second_factor"
)

// Definitions are the resources and operations: the system methods, and the account operations an administrator
// does on the user surface; the login routes are public (a credential is obtained through them in the first place)
// and protect themselves with the session cookie.
func Definitions() *sdkauthz.Definitions {
	ordinary := sdkauthz.Field{Class: sdkauthz.Ordinary}
	manage := func(key string, tightening bool) sdkauthz.Operation {
		return sdkauthz.Operation{Key: key, ResourceType: Account, Purpose: "manage", RiskClass: "high",
			SideEffects: []string{"security_change"}, Audit: true, TighteningOnly: tightening}
	}
	return &sdkauthz.Definitions{Component: ID,
		Resources: []sdkauthz.Resource{
			{Type: Sessions, ViewOperation: OpEnded, Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{}},
			{Type: Accounts, ViewOperation: OpAccountRead, Dimensions: map[string]sdkauthz.Dimension{}, Fields: map[string]sdkauthz.Field{}},
			{Type: Account, ViewOperation: OpAccountView,
				Dimensions: map[string]sdkauthz.Dimension{AccountDim: {Kind: sdkauthz.Principal, Column: "principal", PrincipalRole: "account"}},
				Fields: map[string]sdkauthz.Field{"principal": ordinary, "username": ordinary, "status": ordinary,
					"security_mark": ordinary, "security_version": ordinary}}},
		Operations: []sdkauthz.Operation{
			{Key: OpAccountView, ResourceType: Account, Purpose: "read", RiskClass: "low"},
			manage(OpDisable, true), manage(OpFreeze, true), manage(OpForceLogout, true),
			manage(OpEnable, false), manage(OpResetFactors, false),
			{Key: OpExchange, ResourceType: Sessions, Purpose: "action", RiskClass: "low"},
			{Key: OpEnded, ResourceType: Sessions, Purpose: "read", RiskClass: "low"},
			{Key: OpAccountPull, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
			{Key: OpAccountRead, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
			{Key: OpResend, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
			{Key: OpReplay, ResourceType: Accounts, Purpose: "action", RiskClass: "high", SideEffects: []string{"business_write"}},
			{Key: OpRecover, ResourceType: Accounts, Purpose: "read", RiskClass: "low"},
		}}
}

// Starting values (protocol 20).
const (
	DefaultTokenTTL = 5 * time.Minute
	DefaultIdle     = 30 * time.Minute
	DefaultAbsolute = 12 * time.Hour
	LoginTTL        = 10 * time.Minute
	DefaultTight    = time.Hour // security 03's T_tight
)
