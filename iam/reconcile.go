package iam

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/work"
	"github.com/jackc/pgx/v5"
)

// The full comparison with Casdoor (security 03, "身份成员由外部产品承载时"): Casdoor gives no reliable change
// sequence, so every account bound here is compared with the user as Casdoor has it now, every P_pull and before every
// echo of the account status stream (P9.16). What changed in Casdoor itself becomes this member's own facts:
//   - forbidden or deleted there while active here: disabled (a console disablement takes effect: it only reduces
//     access), with this member's evidence and the product coordinate;
//   - allowed there while disabled or frozen here: a product rollback or a console re-enable, never an enable (only
//     this member re-enables): forbidden again, with an error;
//   - the password changed or the second factors changed there: a security change.
// Each change is one version up, the sessions ended, the account status out, in one transaction per account.

// DefaultPullInterval is P_pull (security 03's starting value).
const DefaultPullInterval = time.Minute

// JobPull is the periodic comparison.
const JobPull = "pull-casdoor"

// pullRef lets the account stream's step before the echo reach the module, which exists only after the definition:
// one per definition, never process-wide.
type pullRef struct {
	mu  sync.RWMutex
	run func(ctx context.Context) error
}

func (p *pullRef) set(run func(ctx context.Context) error) { p.mu.Lock(); p.run = run; p.mu.Unlock() }

func (p *pullRef) before(ctx context.Context) error {
	p.mu.RLock()
	run := p.run
	p.mu.RUnlock()
	if run == nil {
		return errors.New("the identity member is not started yet")
	}
	return run(ctx)
}

type bound struct{ principal, subject, username string }

// reconcile compares every bound account with Casdoor; an error leaves the rest for the next run (the pull before
// an echo then writes no echo: the watermark does not pass what was not compared).
func (m *Module) reconcile(ctx context.Context) error {
	var accounts []bound
	if err := m.rt.DB.BackgroundTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// only this Casdoor's accounts: the same subject under another issuer is another identity (TI11)
		rows, err := tx.Query(ctx, `SELECT principal::text, provider_subject, username FROM iam_account
			WHERE provider = 'casdoor' AND issuer = $1 ORDER BY username`, m.casdoor.issuer)
		if err != nil {
			return err
		}
		accounts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (bound, error) {
			var b bound
			return b, r.Scan(&b.principal, &b.subject, &b.username)
		})
		return err
	}); err != nil {
		return err
	}
	byOwner := map[string][]bound{}
	for _, a := range accounts {
		owner, _, _ := cut(a.username)
		byOwner[owner] = append(byOwner[owner], a)
	}
	var failed error
	for owner, list := range byOwner {
		users, err := m.casdoor.users(ctx, owner)
		if err != nil {
			return err
		}
		byID := map[string]productUser{}
		for _, u := range users {
			byID[u.ID] = u
		}
		for _, a := range list {
			u, ok := byID[a.subject]
			if !ok {
				u = productUser{ID: a.subject, IsDeleted: true} // gone from Casdoor: it signs in no more
			}
			rollback, err := m.store.compare(ctx, a.principal, u, m.rt.Logger)
			if err != nil {
				return err
			}
			if rollback {
				if err := m.casdoor.setForbidden(ctx, a.username, true); err != nil {
					failed = errors.Join(failed, err) // compared again at the next run, still enabled there
				}
			}
		}
	}
	return failed
}

func cut(username string) (owner, name string, ok bool) {
	for i := range username {
		if username[i] == '/' {
			return username[:i], username[i+1:], true
		}
	}
	return "", username, false
}

// pull is the periodic job.
func (m *Module) pull(ctx context.Context, _ *work.Run) error { return m.reconcile(ctx) }

// compare applies one Casdoor user to its account under the account's row lock; rollback: forbid it there again.
func (s store) compare(ctx context.Context, principal string, u productUser, log interface {
	Warn(string, ...any)
	Error(string, ...any)
}) (rollback bool, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rollback = false
		var status string
		var forbidden *bool
		var passwordAt, mfa *string
		if err := tx.QueryRow(ctx, `SELECT status, product_forbidden, product_password_at, product_mfa FROM iam_account
			WHERE principal = $1 FOR UPDATE`, principal).Scan(&status, &forbidden, &passwordAt, &mfa); err != nil {
			return err
		}
		first := forbidden == nil
		reason, next := "", status
		switch {
		case status == "active" && u.off():
			reason, next = "disabled", "disabled"
			log.Warn("an account was disabled in Casdoor itself: it takes effect here", "event", "account_disabled_in_product",
				"principal", principal, "product_updated", u.UpdatedTime)
		case status != "active" && !u.off():
			rollback = true
			log.Error("an account disabled here is allowed in Casdoor (a product rollback or a console re-enable): it is "+
				"forbidden there again; only this member re-enables", "event", "account_enabled_in_product",
				"principal", principal, "product_updated", u.UpdatedTime)
			if err := evidence(ctx, tx, principal, status, "rollback", u.UpdatedTime); err != nil {
				return err
			}
		case !first && passwordAt != nil && *passwordAt != u.LastChangePasswordTime:
			reason = "password"
		case !first && mfa != nil && *mfa != u.secondFactors():
			reason = "second_factor"
		}
		if _, err := tx.Exec(ctx, `UPDATE iam_account SET product_forbidden = $2, product_password_at = $3, product_mfa = $4,
			product_updated = $5, product_seen_at = now(), status = $6 WHERE principal = $1`, principal, u.off(),
			u.LastChangePasswordTime, u.secondFactors(), u.UpdatedTime, next); err != nil {
			return err
		}
		if reason == "" {
			return nil
		}
		version, err := s.change(ctx, tx, principal, reason, "")
		if err != nil {
			return err
		}
		if reason == "disabled" {
			return evidence(ctx, tx, principal, next, "console", u.UpdatedTime, version)
		}
		return nil
	})
	return rollback, err
}

// evidence records a status this member made or saw, with the product coordinate (protocol 15, kept here until the
// evidence store of foundations item 4); the version is the account's at that moment (the current one when absent).
func evidence(ctx context.Context, tx db.Tx, principal, status, source, coordinate string, version ...int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO iam_status_evidence (id, principal, status, source, product_updated, security_version)
		SELECT $1, principal, $3, $4, $5, coalesce($6, security_version) FROM iam_account WHERE principal = $2`,
		ids.New(), principal, status, source, nullable(coordinate), optional(version))
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func optional(v []int64) any {
	if len(v) == 0 {
		return nil
	}
	return v[0]
}

// baselinePassword records a password time this member caused, when the comparison has a baseline at all.
func (s store) baselinePassword(ctx context.Context, principal, at string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE iam_account SET product_password_at = $2 WHERE principal = $1
			AND product_password_at IS NOT NULL`, principal, at)
		return err
	})
}
