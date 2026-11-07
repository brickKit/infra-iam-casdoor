package accounts

import (
	"context"
	"net/http"
	"time"

	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
)

// The account operations (security 03's tightening-only operations, security 08's admin accounts, A134). A status
// change asks the authorization member first (CheckAccountChange: an admin's account is protected; beyond T_tight on
// a stale view this member asks for a second person), then is made in an order that never leaves Casdoor more open
// than this member: a disablement or freeze here first, then forbidden in Casdoor (if that fails, the comparison
// forbids it again); an enable fenced here, allowed in Casdoor, then active here (if this fails, the comparison
// forbids it again). The confirmation goes out in the status record of the change it confirmed.

// target checks the operation on the account (not visible: 404) and reads it; another Casdoor's account is not this
// member's to change.
func targetOf(m *core.Base, c *httpx.Context, op string) (context.Context, string, core.Managed, error) {
	s, _ := sdkauthz.From(c.Ctx())
	p := c.Param("principal")
	ctx, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{core.AccountDim: {State: "value", Value: p}})
	if err != nil {
		return ctx, "", core.Managed{}, err
	}
	a, err := m.Store.ManagedAccount(ctx, p)
	if err == nil && a.Issuer != m.Casdoor.Issuer {
		err = errs.New(errs.ReasonNotFound, "no account of this Casdoor")
	}
	u, _ := identity.UserFrom(ctx)
	return ctx, u.Subject, a, err
}

func answerAccount(m *core.Base, c *httpx.Context, a core.Managed) error {
	out := map[string]any{"principal": a.Principal, "username": a.Username, "status": a.Status,
		"security_version": a.SecurityVersion}
	if a.Mark != "none" {
		out["security_mark"] = a.Mark
	}
	return c.JSON(http.StatusOK, out)
}

func AccountHTTP(m *core.Base, c *httpx.Context) error {
	ctx, _, a, err := targetOf(m, c, core.OpAccountView)
	if err != nil {
		return err
	}
	_ = ctx
	return answerAccount(m, c, a)
}

// StatusHTTP disables, freezes or enables an account.
func StatusHTTP(m *core.Base, c *httpx.Context, op, target string) error {
	var in struct {
		SecurityMark string `json:"security_mark"`
		Confirmation string `json:"confirmation"`
	}
	if err := c.BindJSON(&in); err != nil {
		return err
	}
	mark := in.SecurityMark
	switch {
	case mark == "":
		mark = "none"
	case target != "disabled" || (mark != "compromised" && mark != "suspicious"):
		return errs.New(errs.ReasonRequestInvalid, "security_mark is compromised or suspicious, on a disablement only").
			With("field", "security_mark")
	}
	ctx, requester, a, err := targetOf(m, c, op)
	if err != nil {
		return err
	}
	if a.Status == target && (target != "disabled" || a.Mark == mark) { // already: Casdoor made to agree
		if err := m.Casdoor.SetForbidden(ctx, a.Username, target != "active"); err != nil {
			return err
		}
		return answerAccount(m, c, a)
	}
	since, stale := sdkauthz.StaleBasis(ctx)
	verdict, err := checkChange(m, ctx, a, target, requester, in.Confirmation, secondPerson(since, stale, time.Now(), m.Tight))
	if err != nil {
		return err
	}
	switch verdict.GetVerdict() {
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED:
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED:
		return c.JSON(http.StatusAccepted, map[string]any{"outcome": "awaiting_confirmation", "reason": "CONFIRMATION_REQUIRED",
			"detail": verdict.GetReason(), "administrator": verdict.GetAdministrator(), "target_state": target,
			"security_version": a.SecurityVersion})
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE: // security 03: nothing saved, ask again later
		return c.JSON(http.StatusAccepted, map[string]any{"outcome": "processing", "reason": "ADMIN_AVAILABILITY_UNPROVABLE",
			"detail": verdict.GetReason(), "administrator": verdict.GetAdministrator()})
	default:
		return errs.New(errs.ReasonPermissionDenied, "the authorization member refused the change: "+verdict.GetReason())
	}
	if verdict.GetAdministrator() {
		m.RT.Logger.Error("an authorization admin's account status is changed", "event", "admin_account_status",
			"principal", a.Principal, "status", target, "requested_by", requester)
	}
	confirmation := in.Confirmation
	change := map[string]any{"status": target, "requested_by": requester, "source": "adapter"}
	if mark != "none" {
		change["security_mark"] = mark
	}
	if confirmation != "" {
		change["confirmation"] = confirmation
	}
	var p *evidence.Pending
	step := core.EvidenceStep(func(ctx context.Context, tx db.Tx) (string, error) { // a re-enable: a general record (T6b)
		return m.Store.GeneralID(ctx, tx, "account_reenable", a.Principal, a.SecurityVersion, change)
	})
	if target != "active" { // a disablement or freeze: its intent before this member's change
		p = m.Store.Intent(ctx, "account_status", a.Principal, a.SecurityVersion, change)
		step = core.Concluded(p)
	}
	done := false
	defer func() { core.Settle(ctx, p, done) }()
	if target == "active" {
		if err := m.Store.Fence(ctx, a.Principal); err != nil {
			return err
		}
		if err := m.Casdoor.SetForbidden(ctx, a.Username, false); err != nil {
			return err
		}
	}
	version, err := m.Store.SetStatus(ctx, a.Principal, target, mark, confirmation, requester, a.SecurityVersion, core.ReasonFor(target), step)
	if err != nil {
		return err
	}
	done = true
	a.Status, a.Mark, a.SecurityVersion = target, mark, version
	if target != "active" {
		if err := m.Casdoor.SetForbidden(ctx, a.Username, true); err != nil {
			m.RT.Logger.Warn("disabled here, not yet forbidden in Casdoor: the comparison forbids it", "principal", a.Principal,
				"error", err.Error())
			return err // the same request again makes Casdoor agree
		}
	}
	return answerAccount(m, c, a)
}

// secondPerson: security 03's table for a tightening decided on the shard's last view (P8.29): within T_tight one
// person, beyond it a second. The view's last full renewal stands for the source's watermark (conservative: the
// watermark is never newer than the view that carried it).
func secondPerson(since time.Time, stale bool, now time.Time, tight time.Duration) bool {
	return stale && now.Sub(since) > tight
}

// checkChange asks the authorization member whether the change needs a confirmation (A134).
func checkChange(m *core.Base, ctx context.Context, a core.Managed, target, requester, confirmation string,
	second bool) (*authzv3.CheckAccountChangeResponse, error) {
	return m.Authz.CheckAccountChange(ctx, &authzv3.CheckAccountChangeRequest{Account: a.Principal, TargetState: target,
		SecurityVersion: a.SecurityVersion, Requester: requester, Confirmation: confirmation, SecondPerson: second},
		calls.Idempotent())
}

// ForceLogoutHTTP ends every session of an account here (its version up: tokens issued before are stale) and in
// Casdoor. If Casdoor cannot be reached, the request fails after this member's part: the same request again ends
// Casdoor's.
func ForceLogoutHTTP(m *core.Base, c *httpx.Context) error {
	ctx, _, a, err := targetOf(m, c, core.OpForceLogout)
	if err != nil {
		return err
	}
	p := m.Store.Intent(ctx, "session_revocation", a.Principal, a.SecurityVersion, map[string]any{"kind": "forced_logout"})
	done := false
	defer func() { core.Settle(ctx, p, done) }()
	if a.SecurityVersion, err = m.Store.SecurityChange(ctx, a.Principal, "forced", "", core.Effective(p)); err != nil {
		return err
	}
	done = true
	if err := m.Casdoor.EndSessions(ctx, a.Username); err != nil {
		return err
	}
	return answerAccount(m, c, a)
}

// ResetFactorsHTTP removes an account's second factors in Casdoor, then makes it one security change here and takes
// Casdoor's new state as the comparison's baseline (not counted again). If this member fails after Casdoor, the
// comparison finds the change and counts it then.
func ResetFactorsHTTP(m *core.Base, c *httpx.Context) error {
	ctx, _, a, err := targetOf(m, c, core.OpResetFactors)
	if err != nil {
		return err
	}
	p := m.Store.Intent(ctx, "credential_tightening", a.Principal, a.SecurityVersion, map[string]any{"kind": "second_factor",
		"source": "adapter"})
	done := false
	defer func() { core.Settle(ctx, p, done) }()
	if err := m.Casdoor.DeleteFactors(ctx, a.Username); err != nil {
		return err
	}
	u, err := m.Casdoor.ProductUser(ctx, a.Username)
	if err != nil {
		return err
	}
	if a.SecurityVersion, err = m.Store.ResetFactors(ctx, a.Principal, u.SecondFactors(), core.Effective(p)); err != nil {
		return err
	}
	done = true
	return answerAccount(m, c, a)
}
