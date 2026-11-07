package core

import (
	"context"
	"strconv"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/evidence"
)

// The evidence this member records (assembly protocol 15's evidence table; be-protocol P12.15-P12.18): a status or
// credential tightening and a forced logout in two phases (the intent before the change, the conclusion in its
// transaction, cancelled when it did not take place); a re-enable, a re-enable seen in Casdoor (rolled back) and a
// credential change seen in Casdoor as general records in the transaction that records them.

// AccountType is the object type of an account's evidence.
const AccountType = "infra.iam.account"

// Intent writes a tightening's intent; nil when the member writes no evidence (no database).
func (s Store) Intent(ctx context.Context, category, principal string, version int64, change map[string]any) *evidence.Pending {
	if s.Ev == nil {
		return nil
	}
	p, err := s.Ev.Intent(ctx, category, principal, evidence.Object{Type: AccountType, ID: principal,
		Version: strconv.FormatInt(version, 10)}, change)
	if err != nil {
		return nil // the intent could not be sealed: the change goes on; the writer logged it (evidence_intent_unsealed)
	}
	return p
}

// Effective is the conclusion to run in the change's transaction (nil without an intent).
func Effective(p *evidence.Pending) func(context.Context, db.Tx) error {
	if p == nil {
		return nil
	}
	return p.Effective
}

// Settle writes cancelled when the change whose intent p is did not take place.
func Settle(ctx context.Context, p *evidence.Pending, done bool) {
	if p != nil && !done {
		_ = p.Cancelled(ctx)
	}
}

// general records a change that needs no intent, in the caller's transaction.
func (s Store) general(ctx context.Context, tx db.Tx, category, principal string, version int64, change map[string]any) error {
	_, err := s.GeneralID(ctx, tx, category, principal, version, change)
	return err
}

// GeneralID is general returning the record's identity ("" when this member writes no evidence).
func (s Store) GeneralID(ctx context.Context, tx db.Tx, category, principal string, version int64, change map[string]any) (string, error) {
	if s.Ev == nil {
		return "", nil
	}
	return s.Ev.General(ctx, tx, category, principal, evidence.Object{Type: AccountType, ID: principal,
		Version: strconv.FormatInt(version, 10)}, change)
}

// EvidenceStep writes a status change's evidence in its transaction and names the record (empty: none).
type EvidenceStep func(context.Context, db.Tx) (string, error)

// Concluded is the step of a tightening whose intent p is: its conclusion, named by the intent's identity.
func Concluded(p *evidence.Pending) EvidenceStep {
	return func(ctx context.Context, tx db.Tx) (string, error) {
		if p == nil {
			return "", nil
		}
		return p.ID, p.Effective(ctx, tx)
	}
}

func run(ctx context.Context, tx db.Tx, after func(context.Context, db.Tx) error) error {
	if after == nil {
		return nil
	}
	return after(ctx, tx)
}
