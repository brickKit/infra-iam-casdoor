package iam

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

// intent writes a tightening's intent; nil when the member writes no evidence (no database).
func (s store) intent(ctx context.Context, category, principal string, version int64, change map[string]any) *evidence.Pending {
	if s.ev == nil {
		return nil
	}
	p, err := s.ev.Intent(ctx, category, principal, evidence.Object{Type: AccountType, ID: principal,
		Version: strconv.FormatInt(version, 10)}, change)
	if err != nil {
		return nil // the intent could not be sealed: the change goes on, its absence is logged by the writer
	}
	return p
}

// effective is the conclusion to run in the change's transaction (nil without an intent).
func effective(p *evidence.Pending) func(context.Context, db.Tx) error {
	if p == nil {
		return nil
	}
	return p.Effective
}

// settle writes cancelled when the change whose intent p is did not take place.
func settle(ctx context.Context, p *evidence.Pending, done bool) {
	if p != nil && !done {
		_ = p.Cancelled(ctx)
	}
}

// general records a change that needs no intent, in the caller's transaction.
func (s store) general(ctx context.Context, tx db.Tx, category, principal string, version int64, change map[string]any) error {
	if s.ev == nil {
		return nil
	}
	_, err := s.ev.General(ctx, tx, category, principal, evidence.Object{Type: AccountType, ID: principal,
		Version: strconv.FormatInt(version, 10)}, change)
	return err
}

func run(ctx context.Context, tx db.Tx, after func(context.Context, db.Tx) error) error {
	if after == nil {
		return nil
	}
	return after(ctx, tx)
}
