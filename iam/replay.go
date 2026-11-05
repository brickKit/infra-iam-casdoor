package iam

import (
	"context"
	"errors"
	"fmt"

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
// status this member holds. The credential tightenings are not replayed (protocol 15: 6.7 voids the credentials
// instead), nor the credential changes made in Casdoor.

// Replays registers the replay of the account status and the forced logout (evidence.Replayer).
func (m *Module) Replays(r *evidence.Replays) error {
	r.Add("account_status", m.store.replayStatus)
	r.Add("account_reenable", m.store.replayStatus)
	r.Add("session_revocation", m.store.replayLogout)
	return nil
}

// replayStatus sets the account to the recorded status, the security version up and its sessions ended as the
// change did; a status the account already has is left as it is.
func (s store) replayStatus(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	status, _ := rec.Change["status"].(string)
	if status != "active" && status != "disabled" && status != "frozen" {
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
	version, err := s.changeWith(ctx, tx, rec.Object.ID, reasonFor(status), "", "")
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
