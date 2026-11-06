package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// The replay of this member's evidence in a full recovery's step 6 (assembly protocol 15, 6.3; be-protocol
// P12.19-P12.21): an account's status (a disablement, a freeze, a console disablement, a rollback, a re-enable) and a
// forced logout are applied again here as recorded, without the business preconditions (the authorization member's
// check, the requester's rights): they held when the change was made. Only the account must exist. Casdoor is not
// called in the transaction: the comparison with Casdoor (P_pull) forbids or allows it there again, as for any
// status this member holds. The credential tightenings (a password changed here, the second factors reset here, a
// credential change seen in Casdoor) cannot be made again: Casdoor is outside the recovery group (A141), so 6.7 checks
// them against Casdoor instead (be-protocol P12.20, checkCredential).

// Replays registers the replay of the account status and the forced logout, and the check of the credential
// tightenings (evidence.Replayer).
func (m *Module) Replays(r *evidence.Replays) error {
	r.Add("account_status", m.store.replayStatus)
	r.Add("account_reenable", m.store.replayStatus)
	r.Add("session_revocation", m.store.replayLogout)
	r.Check("credential_tightening", m.checkCredential)
	r.Check("credential_tightening_in_product", m.checkCredential)
	return nil
}

// clockSkew is the clock offset declared between this member and Casdoor (assembly protocol 15's parameters: 2 s).
const clockSkew = 2 * time.Second

// checkCredential is 6.7 with Casdoor outside the recovery group: whether a credential tightening still holds in
// Casdoor. A password changed here holds when Casdoor's last password change is not earlier than the record; a reset
// of the second factors holds when Casdoor has none now or has changed since; a change seen in Casdoor holds when
// Casdoor is not older than what was seen. Casdoor's times have one-second precision, so the record's time is taken
// less the declared skew. Not so: Casdoor went back on its own, for review.
func (m *Module) checkCredential(ctx context.Context, rec evidence.Replayed) (bool, string, error) {
	username, err := m.store.usernameOf(ctx, rec.Object.ID)
	if err != nil {
		return false, "", err
	}
	if username == "" {
		return false, "no such account here", nil
	}
	u, err := m.casdoor.productUser(ctx, username)
	if err != nil {
		return false, "", err
	}
	kind, _ := rec.Change["kind"].(string)
	since := rec.At.Add(-clockSkew)
	if rec.Category == "credential_tightening_in_product" {
		seen, _ := rec.Change["product_updated"].(string)
		if !notBefore(u.UpdatedTime, parseProductTime(seen)) {
			return false, fmt.Sprintf("Casdoor's user was updated at %q, before the change seen at %q", u.UpdatedTime, seen), nil
		}
		return true, "", nil
	}
	switch kind {
	case "password":
		if !notBefore(u.LastChangePasswordTime, since) {
			return false, fmt.Sprintf("Casdoor's last password change %q is before the record", u.LastChangePasswordTime), nil
		}
	case "second_factor":
		if u.hasFactors() && !notBefore(u.UpdatedTime, since) {
			return false, fmt.Sprintf("Casdoor has second factors, unchanged since %q, before the reset", u.UpdatedTime), nil
		}
	default:
		return false, fmt.Sprintf("a credential tightening of kind %q", kind), nil
	}
	return true, "", nil
}

// parseProductTime reads one of Casdoor's times (RFC 3339); a time that does not parse is the zero time.
func parseProductTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// notBefore: Casdoor's time is set and not before t (a time that does not parse is not).
func notBefore(product string, t time.Time) bool {
	p := parseProductTime(product)
	return !p.IsZero() && !p.Before(t)
}

// usernameOf is the account's Casdoor username; empty when this member has no such account.
func (s store) usernameOf(ctx context.Context, principal string) (string, error) {
	var username string
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, "SELECT username FROM iam_account WHERE principal = $1::text::uuid", principal).Scan(&username)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return username, err
}

// replayStatus sets the account to the recorded status, the security version up and its sessions ended as the
// change did; a status the account already has is left as it is.
func (s store) replayStatus(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	status, _ := rec.Change["status"].(string)
	if status != "active" && status != "disabled" && status != "security_frozen" { // the account's statuses (09a)
		return fmt.Errorf("the record carries no account status (%q)", status)
	}
	mark, _ := rec.Change["security_mark"].(string)
	if mark == "" {
		mark = "none"
	}
	cur, err := s.lockAccount(ctx, tx, rec.Object.ID)
	if err != nil {
		return err
	}
	if cur == status {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE iam_account SET status = $2, security_mark = $3, local_change_at = now()
		WHERE principal = $1`, rec.Object.ID, status, mark); err != nil {
		return err
	}
	version, err := s.changeEv(ctx, tx, rec.Object.ID, reasonFor(status), "", "", rec.ID) // the original record named
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO iam_status_evidence (id, principal, status, source, security_version)
		VALUES ($1, $2, $3, 'adapter', $4)`, ids.New(), rec.Object.ID, status, version)
	return err
}

// replayLogout ends the account's sessions as the forced logout did, the security version up.
func (s store) replayLogout(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	if _, err := s.lockAccount(ctx, tx, rec.Object.ID); err != nil {
		return err
	}
	_, err := s.change(ctx, tx, rec.Object.ID, "forced", "")
	return err
}

// lockAccount locks an account's row and returns its status; an account that is gone is dangling.
func (s store) lockAccount(ctx context.Context, tx db.Tx, principal string) (string, error) {
	var status string
	err := tx.QueryRow(ctx, "SELECT status FROM iam_account WHERE principal = $1 FOR UPDATE", principal).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("account %s: %w", principal, evidence.ErrDangling)
	}
	return status, err
}
