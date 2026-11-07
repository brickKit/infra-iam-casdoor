package reconcile

import (
	"context"
	"errors"
	"sync"
	"time"

	core "github.com/brickKit/infra-iam-casdoor/v3/internal/core"
	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"

	"github.com/brickKit/be-sdk-go/v3/db"
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

// PullRef lets the account stream's step before the echo reach the module, which exists only after the definition:
// one per definition, never process-wide.
type PullRef struct {
	mu  sync.RWMutex
	run func(ctx context.Context) error
}

func (p *PullRef) Set(run func(ctx context.Context) error) { p.mu.Lock(); p.run = run; p.mu.Unlock() }

func (p *PullRef) Before(ctx context.Context) error {
	p.mu.RLock()
	run := p.run
	p.mu.RUnlock()
	if run == nil {
		return errors.New("the identity member is not started yet")
	}
	return run(ctx)
}

type bound struct{ principal, subject, username string }

// Reconcile compares every bound account with Casdoor; an error leaves the rest for the next run (the pull before
// an echo then writes no echo: the watermark does not pass what was not compared).
func Reconcile(m *core.Base, ctx context.Context) error {
	var accounts []bound
	var readAt time.Time // before anything is read from Casdoor, on the database's clock (local_change_at's)
	if err := m.RT.DB.BackgroundTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&readAt); err != nil {
			return err
		}
		// only this Casdoor's accounts: the same subject under another issuer is another identity (TI11)
		rows, err := tx.Query(ctx, `SELECT principal::text, provider_subject, username FROM iam_account
			WHERE provider = 'casdoor' AND issuer = $1 ORDER BY username`, m.Casdoor.Issuer)
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
		owner, _, _ := provider.Cut(a.username)
		byOwner[owner] = append(byOwner[owner], a)
	}
	var failed error
	for owner, list := range byOwner {
		users, err := m.Casdoor.Users(ctx, owner)
		if err != nil {
			return err
		}
		byID := map[string]provider.ProductUser{}
		for _, u := range users {
			byID[u.ID] = u
		}
		for _, a := range list {
			u, ok := byID[a.subject]
			if !ok {
				u = provider.ProductUser{ID: a.subject, IsDeleted: true} // gone from Casdoor: it signs in no more
			}
			// a console disablement is a tightening: its intent before the comparison's transaction, read without a lock
			// first; the transaction concludes it only if the change is still there under the row lock (item 4 T6b)
			p, err := m.Store.ConsoleIntent(ctx, a.principal, u)
			if err != nil {
				return err
			}
			rollback, concluded, err := m.Store.Compare(ctx, a.principal, u, readAt, m.RT.Logger, p)
			core.Settle(ctx, p, concluded)
			if err != nil {
				return err
			}
			if rollback {
				if err := m.Casdoor.SetForbidden(ctx, a.username, true); err != nil {
					failed = errors.Join(failed, err) // compared again at the next run, still enabled there
				}
			}
		}
	}
	return failed
}

// Pull is the periodic job.
func Pull(m *core.Base, ctx context.Context, _ *work.Run) error { return Reconcile(m, ctx) }
