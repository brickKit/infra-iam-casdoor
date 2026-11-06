package iam

import (
	"context"
	"errors"
	"net/http"
	"time"

	sdkauthz "github.com/brickKit/be-sdk-go/v3/authz"
	"github.com/brickKit/be-sdk-go/v3/calls"
	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/httpx"
	"github.com/brickKit/be-sdk-go/v3/identity"
	"github.com/brickKit/be-sdk-go/v3/ids"
	authzv3 "github.com/brickKit/contract-infra-authz/v3/gen/go/be/authz/v3"
	"github.com/jackc/pgx/v5"
)

// The account operations (security 03's tightening-only operations, security 08's admin accounts, A134). A status
// change asks the authorization member first (CheckAccountChange: an admin's account is protected; beyond T_tight on
// a stale view this member asks for a second person), then is made in an order that never leaves Casdoor more open
// than this member: a disablement or freeze here first, then forbidden in Casdoor (if that fails, the comparison
// forbids it again); an enable fenced here, allowed in Casdoor, then active here (if this fails, the comparison
// forbids it again). The confirmation goes out in the status record of the change it confirmed.

// managed is an account as the operations see it.
type managed struct {
	account
	mark   string
	issuer string
}

// routesForAccounts registers the account operations.
func (m *Module) routesForAccounts(r *httpx.Routes) {
	r.Add(httpx.Route{Method: "GET", Path: "/api/iam/accounts/:principal", Operation: OpAccountView, Handle: m.accountHTTP})
	status := func(op, target string) func(*httpx.Context) error {
		return func(c *httpx.Context) error { return m.statusHTTP(c, op, target) }
	}
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/disable", Operation: OpDisable, Handle: status(OpDisable, "disabled")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/freeze", Operation: OpFreeze, Handle: status(OpFreeze, "security_frozen")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/enable", Operation: OpEnable, Handle: status(OpEnable, "active")})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/logout", Operation: OpForceLogout, Handle: m.forceLogoutHTTP})
	r.Add(httpx.Route{Method: "POST", Path: "/api/iam/accounts/:principal/reset-second-factor", Operation: OpResetFactors,
		Handle: m.resetFactorsHTTP})
}

// target checks the operation on the account (not visible: 404) and reads it; another Casdoor's account is not this
// member's to change.
func (m *Module) target(c *httpx.Context, op string) (context.Context, string, managed, error) {
	s, _ := sdkauthz.From(c.Ctx())
	p := c.Param("principal")
	ctx, _, err := s.Check(c.Ctx(), op, sdkauthz.Facts{AccountDim: {State: "value", Value: p}})
	if err != nil {
		return ctx, "", managed{}, err
	}
	a, err := m.store.managed(ctx, p)
	if err == nil && a.issuer != m.casdoor.issuer {
		err = errs.New(errs.ReasonNotFound, "no account of this Casdoor")
	}
	u, _ := identity.UserFrom(ctx)
	return ctx, u.Subject, a, err
}

func (m *Module) answerAccount(c *httpx.Context, a managed) error {
	out := map[string]any{"principal": a.principal, "username": a.username, "status": a.status,
		"security_version": a.securityVersion}
	if a.mark != "none" {
		out["security_mark"] = a.mark
	}
	return c.JSON(http.StatusOK, out)
}

func (m *Module) accountHTTP(c *httpx.Context) error {
	ctx, _, a, err := m.target(c, OpAccountView)
	if err != nil {
		return err
	}
	_ = ctx
	return m.answerAccount(c, a)
}

// statusHTTP disables, freezes or enables an account.
func (m *Module) statusHTTP(c *httpx.Context, op, target string) error {
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
	ctx, requester, a, err := m.target(c, op)
	if err != nil {
		return err
	}
	if a.status == target && (target != "disabled" || a.mark == mark) { // already: Casdoor made to agree
		if err := m.casdoor.setForbidden(ctx, a.username, target != "active"); err != nil {
			return err
		}
		return m.answerAccount(c, a)
	}
	since, stale := sdkauthz.StaleBasis(ctx)
	verdict, err := m.checkChange(ctx, a, target, requester, in.Confirmation, secondPerson(since, stale, time.Now(), m.tight))
	if err != nil {
		return err
	}
	switch verdict.GetVerdict() {
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_ALLOWED:
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_CONFIRMATION_REQUIRED:
		return c.JSON(http.StatusAccepted, map[string]any{"outcome": "awaiting_confirmation", "reason": "CONFIRMATION_REQUIRED",
			"detail": verdict.GetReason(), "administrator": verdict.GetAdministrator(), "target_state": target,
			"security_version": a.securityVersion})
	case authzv3.AccountChangeVerdict_ACCOUNT_CHANGE_VERDICT_UNPROVABLE: // security 03: nothing saved, ask again later
		return c.JSON(http.StatusAccepted, map[string]any{"outcome": "processing", "reason": "ADMIN_AVAILABILITY_UNPROVABLE",
			"detail": verdict.GetReason(), "administrator": verdict.GetAdministrator()})
	default:
		return errs.New(errs.ReasonPermissionDenied, "the authorization member refused the change: "+verdict.GetReason())
	}
	if verdict.GetAdministrator() {
		m.rt.Logger.Error("an authorization admin's account status is changed", "event", "admin_account_status",
			"principal", a.principal, "status", target, "requested_by", requester)
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
	step := evidenceStep(func(ctx context.Context, tx db.Tx) (string, error) { // a re-enable: a general record (T6b)
		return m.store.generalID(ctx, tx, "account_reenable", a.principal, a.securityVersion, change)
	})
	if target != "active" { // a disablement or freeze: its intent before this member's change
		p = m.store.intent(ctx, "account_status", a.principal, a.securityVersion, change)
		step = concluded(p)
	}
	done := false
	defer func() { settle(ctx, p, done) }()
	if target == "active" {
		if err := m.store.fence(ctx, a.principal); err != nil {
			return err
		}
		if err := m.casdoor.setForbidden(ctx, a.username, false); err != nil {
			return err
		}
	}
	version, err := m.store.setStatus(ctx, a.principal, target, mark, confirmation, requester, a.securityVersion, reasonFor(target), step)
	if err != nil {
		return err
	}
	done = true
	a.status, a.mark, a.securityVersion = target, mark, version
	if target != "active" {
		if err := m.casdoor.setForbidden(ctx, a.username, true); err != nil {
			m.rt.Logger.Warn("disabled here, not yet forbidden in Casdoor: the comparison forbids it", "principal", a.principal,
				"error", err.Error())
			return err // the same request again makes Casdoor agree
		}
	}
	return m.answerAccount(c, a)
}

func reasonFor(target string) string {
	switch target {
	case "disabled":
		return "disabled"
	case "security_frozen":
		return "frozen"
	}
	return "revoked" // an enable: a disabled account has no live session
}

// secondPerson: security 03's table for a tightening decided on the shard's last view (P8.29): within T_tight one
// person, beyond it a second. The view's last full renewal stands for the source's watermark (conservative: the
// watermark is never newer than the view that carried it).
func secondPerson(since time.Time, stale bool, now time.Time, tight time.Duration) bool {
	return stale && now.Sub(since) > tight
}

// checkChange asks the authorization member whether the change needs a confirmation (A134).
func (m *Module) checkChange(ctx context.Context, a managed, target, requester, confirmation string,
	second bool) (*authzv3.CheckAccountChangeResponse, error) {
	return m.authz.CheckAccountChange(ctx, &authzv3.CheckAccountChangeRequest{Account: a.principal, TargetState: target,
		SecurityVersion: a.securityVersion, Requester: requester, Confirmation: confirmation, SecondPerson: second},
		calls.Idempotent())
}

// forceLogoutHTTP ends every session of an account here (its version up: tokens issued before are stale) and in
// Casdoor. If Casdoor cannot be reached, the request fails after this member's part: the same request again ends
// Casdoor's.
func (m *Module) forceLogoutHTTP(c *httpx.Context) error {
	ctx, _, a, err := m.target(c, OpForceLogout)
	if err != nil {
		return err
	}
	p := m.store.intent(ctx, "session_revocation", a.principal, a.securityVersion, map[string]any{"kind": "forced_logout"})
	done := false
	defer func() { settle(ctx, p, done) }()
	if a.securityVersion, err = m.store.securityChange(ctx, a.principal, "forced", "", effective(p)); err != nil {
		return err
	}
	done = true
	if err := m.casdoor.endSessions(ctx, a.username); err != nil {
		return err
	}
	return m.answerAccount(c, a)
}

// resetFactorsHTTP removes an account's second factors in Casdoor, then makes it one security change here and takes
// Casdoor's new state as the comparison's baseline (not counted again). If this member fails after Casdoor, the
// comparison finds the change and counts it then.
func (m *Module) resetFactorsHTTP(c *httpx.Context) error {
	ctx, _, a, err := m.target(c, OpResetFactors)
	if err != nil {
		return err
	}
	p := m.store.intent(ctx, "credential_tightening", a.principal, a.securityVersion, map[string]any{"kind": "second_factor",
		"source": "adapter"})
	done := false
	defer func() { settle(ctx, p, done) }()
	if err := m.casdoor.deleteFactors(ctx, a.username); err != nil {
		return err
	}
	u, err := m.casdoor.productUser(ctx, a.username)
	if err != nil {
		return err
	}
	if a.securityVersion, err = m.store.resetFactors(ctx, a.principal, u.secondFactors(), effective(p)); err != nil {
		return err
	}
	done = true
	return m.answerAccount(c, a)
}

// managed reads an account for the operations.
func (s store) managed(ctx context.Context, principal string) (managed, error) {
	a := managed{account: account{principal: principal}}
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT username, security_version, status, security_mark, issuer FROM iam_account
			WHERE principal = $1::text::uuid`, principal).Scan(&a.username, &a.securityVersion, &a.status, &a.mark, &a.issuer)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = errs.New(errs.ReasonNotFound, "no such account")
	}
	return a, err
}

// fence marks a status change in flight towards Casdoor: the comparison leaves the account alone for InFlight.
func (s store) fence(ctx context.Context, principal string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE iam_account SET local_change_at = now() WHERE principal = $1", principal)
		return err
	})
}

// setStatus is a status change made here on a request: on the version the authorization member was asked about
// (another change since: CHANGE_REVISION_STALE, ask again), one security change carrying the confirmation, with the
// evidence of who asked; the status record names the evidence record (09a).
func (s store) setStatus(ctx context.Context, principal, status, mark, confirmation, requester string, on int64,
	reason string, step evidenceStep) (int64, error) {
	var version int64
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var now int64
		if err := tx.QueryRow(ctx, "SELECT security_version FROM iam_account WHERE principal = $1 FOR UPDATE", principal).
			Scan(&now); err != nil {
			return err
		}
		if now != on {
			return errs.New(errs.ReasonChangeRevisionStale, "the account changed since: ask again")
		}
		if _, err := tx.Exec(ctx, `UPDATE iam_account SET status = $2, security_mark = $3, local_change_at = now()
			WHERE principal = $1`, principal, status, mark); err != nil {
			return err
		}
		evidenceID, err := step(ctx, tx) // the evidence first, in the same transaction: the status record names it
		if err != nil {
			return err
		}
		if version, err = s.changeEv(ctx, tx, principal, reason, "", confirmation, evidenceID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO iam_status_evidence (id, principal, status, source, security_version, requested_by,
			confirmation) VALUES ($1, $2, $3, 'adapter', $4, $5::text::uuid, NULLIF($6, '')::uuid)`, ids.New(), principal, status,
			version, requester, confirmation)
		return err
	})
	return version, err
}

// resetFactors is the reset's security change here, with Casdoor's new second-factor state as the baseline.
func (s store) resetFactors(ctx context.Context, principal, digest string, after func(context.Context, db.Tx) error) (int64, error) {
	var version int64
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if version, err = s.change(ctx, tx, principal, "second_factor", ""); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE iam_account SET product_mfa = $2 WHERE principal = $1 AND product_mfa IS NOT NULL",
			principal, digest); err != nil {
			return err
		}
		return run(ctx, tx, after)
	})
	return version, err
}
