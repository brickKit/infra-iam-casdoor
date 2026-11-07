package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	provider "github.com/brickKit/infra-iam-casdoor/v3/internal/provider"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/errs"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/records"
	"github.com/jackc/pgx/v5"
)

// Store is the member's tables: logins in flight, accounts bound to Casdoor subjects, browser sessions. Every end of
// a session is written to the stream be.session.ended in the transaction that ends it (be-protocol P8.28), and every
// security change of an account to infra.iam.account_status with its new version (P8.27).
type Store struct {
	Db         *db.DB           `json:"-"`
	Events     *events.Producer `json:"-"`
	Deployment string           `json:"-"`
	Ev         *evidence.Writer `json:"-"` // the evidence (evidence.go); nil without a database
}

var ErrNoLogin = errors.New("no such login in flight")

// account is a bound account as the sessions need it.
type AccountRow struct {
	Principal       string `json:"-"`
	Username        string `json:"-"` // owner/name in Casdoor
	SecurityVersion int64  `json:"-"`
	Status          string `json:"-"` // active, disabled, security_frozen (security 09a)
}

// Begin saves a login in flight and forgets the ones older than LoginTTL.
func (s Store) Begin(ctx context.Context, stateHash, verifier, returnTo string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM iam_login WHERE created_at < now() - make_interval(secs => $1)",
			LoginTTL.Seconds()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO iam_login (state_hash, verifier, return_to) VALUES ($1, $2, $3)",
			stateHash, verifier, returnTo)
		return err
	})
}

// Take consumes a login in flight: a state is used once.
func (s Store) Take(ctx context.Context, stateHash string) (verifier, returnTo string, err error) {
	err = s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `DELETE FROM iam_login WHERE state_hash = $1
			AND created_at >= now() - make_interval(secs => $2) RETURNING verifier, return_to`,
			stateHash, LoginTTL.Seconds()).Scan(&verifier, &returnTo)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNoLogin
	}
	return verifier, returnTo, err
}

// Adopt gives the accounts bound before the issuer was kept the configured Casdoor's issuer: they came from it (the
// controlled exact mapping that keeps their principals, security 02 TI11); and sends the status of the accounts
// whose status never went out (bound before it did), so the authorization member's projection has every account.
func (s Store) Adopt(ctx context.Context, issuer string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE iam_account SET issuer = $1 WHERE issuer = ''", issuer); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT principal::text, security_version FROM iam_account WHERE status_record IS NULL")
		if err != nil {
			return err
		}
		type pending struct {
			principal string
			version   int64
		}
		todo, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
			var p pending
			return p, r.Scan(&p.principal, &p.version)
		})
		if err != nil {
			return err
		}
		for _, p := range todo {
			if err := s.status(ctx, tx, p.principal, p.version); err != nil {
				return err
			}
		}
		return nil
	})
}

// Principal returns the account bound to Casdoor's issuer and subject, binding a new principal on first sight (its
// status goes out in the same transaction). The same subject of another issuer, or the same e-mail or login name, is
// another account: nothing is taken over.
// A disabled or frozen account is answered as it is: the caller refuses it (signedIn).
func (s Store) Principal(ctx context.Context, issuer string, id provider.ProviderUser) (AccountRow, error) {
	a := AccountRow{Username: id.Username}
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var bound bool
		if err := tx.QueryRow(ctx, `INSERT INTO iam_account (principal, provider, issuer, provider_subject, username)
			VALUES ($1, 'casdoor', $2, $3, $4)
			ON CONFLICT (provider, issuer, provider_subject) DO UPDATE SET username = EXCLUDED.username
			RETURNING principal::text, security_version, status, xmax = 0`, ids.New(), issuer, id.Subject, id.Username).
			Scan(&a.Principal, &a.SecurityVersion, &a.Status, &bound); err != nil {
			return err
		}
		if !bound {
			return nil
		}
		return s.status(ctx, tx, a.Principal, a.SecurityVersion)
	})
	return a, err
}

// Open starts a session for a principal.
func (s Store) Open(ctx context.Context, idHash, principal string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iam_session (id_hash, principal, recovery_generation)
			VALUES ($1, $2, (SELECT generation FROM be_recovery_generation))`, idHash, principal)
		return err
	})
}

// Use returns a live session's account and the instant the session ends at the latest (the absolute timeout, or the
// idle one from now), renewing the idle time unless renew is false (a polling request's exchange, protocol 20). The
// session row's lock serialises the session's uses. A session past either timeout, or created before the deployment's
// last full recovery (protocol 15, 6.6), is ended with that reason (and written to the ended stream); ok=false for
// every session that is not live.
func (s Store) Use(ctx context.Context, idHash string, idle, absolute time.Duration, renew bool) (a AccountRow,
	until time.Time, ok bool, err error) {
	err = s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var created, seen time.Time
		err := tx.QueryRow(ctx, `UPDATE iam_session SET last_seen = CASE WHEN $4 THEN now() ELSE last_seen END
			WHERE id_hash = $1 AND ended_at IS NULL AND last_seen >= now() - make_interval(secs => $2)
				AND created_at >= now() - make_interval(secs => $3)
				AND recovery_generation >= (SELECT generation FROM be_recovery_generation)
			RETURNING principal::text, created_at, last_seen`, idHash, idle.Seconds(), absolute.Seconds(), renew).
			Scan(&a.Principal, &created, &seen)
		if errors.Is(err, pgx.ErrNoRows) {
			var ended string
			err = tx.QueryRow(ctx, `UPDATE iam_session SET ended_at = now(),
					end_reason = CASE WHEN recovery_generation < (SELECT generation FROM be_recovery_generation) THEN 'recovery'
						WHEN created_at < now() - make_interval(secs => $2) THEN 'absolute' ELSE 'idle' END
				WHERE id_hash = $1 AND ended_at IS NULL RETURNING id_hash`, idHash, absolute.Seconds()).Scan(&ended)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // unknown or already ended
			}
			if err != nil {
				return err
			}
			return s.ended(ctx, tx, ended)
		}
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT username, security_version FROM iam_account WHERE principal = $1",
			a.Principal).Scan(&a.Username, &a.SecurityVersion); err != nil {
			return err
		}
		ok = true
		until = created.Add(absolute)
		if i := seen.Add(idle); i.Before(until) {
			until = i
		}
		return nil
	})
	return a, until, ok, err
}

// End ends a session.
func (s Store) End(ctx context.Context, idHash, reason string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var ended string
		err := tx.QueryRow(ctx, `UPDATE iam_session SET ended_at = now(), end_reason = $2
			WHERE id_hash = $1 AND ended_at IS NULL RETURNING id_hash`, idHash, reason).Scan(&ended)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.ended(ctx, tx, ended)
	})
}

// EndBeforeRecovery ends every live session created before the deployment's current recovery generation (protocol
// 15, 6.6: a full recovery ends the sessions from before it), each written to the ended stream; it answers the
// accounts whose sessions ended. Nothing to do unless a full recovery advanced the generation.
func (s Store) EndBeforeRecovery(ctx context.Context) (usernames []string, err error) {
	err = s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		usernames = nil
		rows, err := tx.Query(ctx, `UPDATE iam_session SET ended_at = now(), end_reason = 'recovery'
			WHERE ended_at IS NULL AND recovery_generation < (SELECT generation FROM be_recovery_generation)
			RETURNING id_hash, principal::text`)
		if err != nil {
			return err
		}
		type ended struct{ idHash, principal string }
		all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ended, error) {
			var e ended
			return e, r.Scan(&e.idHash, &e.principal)
		})
		if err != nil {
			return err
		}
		people := map[string]bool{}
		for _, e := range all {
			if err := s.ended(ctx, tx, e.idHash); err != nil {
				return err
			}
			people[e.principal] = true
		}
		if len(people) == 0 {
			return nil
		}
		ps := make([]string, 0, len(people))
		for p := range people {
			ps = append(ps, p)
		}
		rows, err = tx.Query(ctx, "SELECT username FROM iam_account WHERE principal::text = ANY($1) ORDER BY username", ps)
		if err != nil {
			return err
		}
		usernames, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return usernames, err
}

// SecurityChange is a security change of an account made here (a password change, a forced logout, a reset of the
// second factors): its version goes up by one, every live session but keep ends with reason, and the account's status
// goes out with the new version, all in one transaction (P8.27). keep is the session that made the change ("" for
// none): its next exchange gets a token of the new version.
func (s Store) SecurityChange(ctx context.Context, principal, reason, keep string, after func(context.Context, db.Tx) error) (int64, error) {
	var version int64
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if version, err = s.change(ctx, tx, principal, reason, keep); err != nil {
			return err
		}
		return run(ctx, tx, after) // the evidence's conclusion, in the same transaction
	})
	return version, err
}

// change is a security change inside the caller's transaction: the version up, the sessions but keep ended with
// reason, the status (as the row now has it) out.
func (s Store) change(ctx context.Context, tx db.Tx, principal, reason, keep string) (int64, error) {
	return s.changeWith(ctx, tx, principal, reason, keep, "")
}

// changeWith is change carrying a confirmation in the status record (a protected status change, A134); every other
// security change sends none, so a confirmation goes out with the change it confirmed only.
func (s Store) changeWith(ctx context.Context, tx db.Tx, principal, reason, keep, confirmation string) (int64, error) {
	return s.changeEv(ctx, tx, principal, reason, keep, confirmation, "")
}

// changeEv is changeWith naming the evidence record that made a status change (09a's account_status.evidence): the
// status record carries it, and only the change it made.
func (s Store) changeEv(ctx context.Context, tx db.Tx, principal, reason, keep, confirmation, evidenceID string) (int64, error) {
	var version int64
	if err := tx.QueryRow(ctx, `UPDATE iam_account SET security_version = security_version + 1,
		status_confirmation = NULLIF($2, '')::uuid, status_evidence = NULLIF($3, '')::uuid WHERE principal = $1
		RETURNING security_version`, principal, confirmation, evidenceID).Scan(&version); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `UPDATE iam_session SET ended_at = now(), end_reason = $2
		WHERE principal = $1 AND ended_at IS NULL AND id_hash <> $3 RETURNING id_hash`, principal, reason, keep)
	if err != nil {
		return 0, err
	}
	ended, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	for _, h := range ended {
		if err := s.ended(ctx, tx, h); err != nil {
			return 0, err
		}
	}
	return version, s.status(ctx, tx, principal, version)
}

// ended writes a session's end to the stream the edge reads by position.
func (s Store) ended(ctx context.Context, tx db.Tx, idHash string) error {
	_, err := s.Events.Emit(ctx, tx, StreamEnded, events.Event{Type: TypeEnded, RecordID: idHash, Version: 1,
		Projection: events.Full, Data: map[string]string{"session_digest": idHash}})
	return err
}

// status writes the account's status record (be.security.account_status, security 09a) with its security version;
// the version is also the record's revision in this member's database.
func (s Store) status(ctx context.Context, tx db.Tx, principal string, version int64) error {
	var status, mark string
	var confirmation, evidenceID *string
	if err := tx.QueryRow(ctx, `SELECT status, security_mark, status_confirmation::text, status_evidence::text FROM iam_account
		WHERE principal = $1`, principal).Scan(&status, &mark, &confirmation, &evidenceID); err != nil {
		return err
	}
	rec := map[string]any{
		"record_type": "be.security.account_status", "schema": "1.0", "deployment": s.Deployment, "authority": ID,
		"id": principal, "revision": map[string]any{"domain": StreamAccount, "value": strconv.FormatInt(version, 10)},
		"account": map[string]any{"deployment": s.Deployment, "kind": "user", "id": principal},
		"status":  status, "security_version": version}
	if mark != "none" {
		rec["security_mark"] = mark
	}
	if confirmation != nil {
		rec["confirmation"] = *confirmation
	}
	if evidenceID != nil {
		rec["evidence"] = *evidenceID
	}
	raw, digest, err := records.Seal("be.security.account_status", rec)
	if err != nil {
		return err
	}
	if _, err := records.Open("be.security.account_status", raw, digest); err != nil {
		return err // the record this member sends passes its own schema (be-protocol schemas/security)
	}
	if _, err := tx.Exec(ctx, "UPDATE iam_account SET status_record = $2 WHERE principal = $1", principal, raw); err != nil {
		return err // what the batch read and the snapshot answer with (P9.30)
	}
	_, err = s.Events.Emit(ctx, tx, StreamAccount, events.Event{Type: TypeAccount, RecordID: principal,
		Version: version, Projection: events.Full, Data: json.RawMessage(raw), Subjects: []string{principal}})
	return err
}

// UsernameOf is the account's Casdoor username; empty when this member has no such account.
func (s Store) UsernameOf(ctx context.Context, principal string) (string, error) {
	var username string
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, "SELECT username FROM iam_account WHERE principal = $1::text::uuid", principal).Scan(&username)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return username, err
}

// ReplayStatus sets the account to the recorded status, the security version up and its sessions ended as the
// change did; a status the account already has is left as it is.
func (s Store) ReplayStatus(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
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
	version, err := s.changeEv(ctx, tx, rec.Object.ID, ReasonFor(status), "", "", rec.ID) // the original record named
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO iam_status_evidence (id, principal, status, source, security_version)
		VALUES ($1, $2, $3, 'adapter', $4)`, ids.New(), rec.Object.ID, status, version)
	return err
}

// ReplayLogout ends the account's sessions as the forced logout did, the security version up.
func (s Store) ReplayLogout(ctx context.Context, tx db.Tx, rec evidence.Replayed) error {
	if _, err := s.lockAccount(ctx, tx, rec.Object.ID); err != nil {
		return err
	}
	_, err := s.change(ctx, tx, rec.Object.ID, "forced", "")
	return err
}

// lockAccount locks an account's row and returns its status; an account that is gone is dangling.
func (s Store) lockAccount(ctx context.Context, tx db.Tx, principal string) (string, error) {
	var status string
	err := tx.QueryRow(ctx, "SELECT status FROM iam_account WHERE principal = $1 FOR UPDATE", principal).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("account %s: %w", principal, evidence.ErrDangling)
	}
	return status, err
}

func ReasonFor(target string) string {
	switch target {
	case "disabled":
		return "disabled"
	case "security_frozen":
		return "frozen"
	}
	return "revoked" // an enable: a disabled account has no live session
}

// InFlight is how long before a comparison's read this member's own status change keeps the account's status out of
// that comparison: Casdoor may not show the change yet (a write in flight, or read before it), and the next run
// compares it. The password and the second factors are compared as always.
const InFlight = time.Minute

// Compare applies one Casdoor user to its account under the account's row lock; rollback: forbid it there again. The
// status of an account this member changed within InFlight before readAt (or since) is left to the next run.
func (s Store) Compare(ctx context.Context, principal string, u provider.ProductUser, readAt time.Time, log interface {
	Warn(string, ...any)
	Error(string, ...any)
}, p *evidence.Pending) (rollback, concluded bool, err error) {
	err = s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		rollback, concluded = false, false
		var status string
		var forbidden *bool
		var passwordAt, mfa *string
		var recent bool
		if err := tx.QueryRow(ctx, `SELECT status, product_forbidden, product_password_at, product_mfa,
				coalesce(local_change_at > $2::timestamptz - make_interval(secs => $3), false)
			FROM iam_account WHERE principal = $1 FOR UPDATE`, principal, readAt, InFlight.Seconds()).
			Scan(&status, &forbidden, &passwordAt, &mfa, &recent); err != nil {
			return err
		}
		first := forbidden == nil
		reason, next := "", status
		switch {
		case !recent && status == "active" && u.Off():
			reason, next = "disabled", "disabled"
			log.Warn("an account was disabled in Casdoor itself: it takes effect here", "event", "account_disabled_in_product",
				"principal", principal, "product_updated", u.UpdatedTime)
		case !recent && status != "active" && !u.Off():
			rollback = true
			log.Error("an account disabled here is allowed in Casdoor (a product rollback or a console re-enable): it is "+
				"forbidden there again; only this member re-enables", "event", "account_enabled_in_product",
				"principal", principal, "product_updated", u.UpdatedTime)
			if err := statusEvidence(ctx, tx, principal, status, "rollback", u.UpdatedTime); err != nil {
				return err
			}
			if err := s.general(ctx, tx, "account_status", principal, 0, map[string]any{"status": status, "source": "rollback",
				"product_updated": u.UpdatedTime}); err != nil { // an enable seen in Casdoor is recorded too
				return err
			}
		case !first && passwordAt != nil && *passwordAt != u.LastChangePasswordTime:
			reason = "password"
		case !first && mfa != nil && *mfa != u.SecondFactors():
			reason = "second_factor"
		}
		if _, err := tx.Exec(ctx, `UPDATE iam_account SET product_forbidden = $2, product_password_at = $3, product_mfa = $4,
			product_updated = $5, product_seen_at = now(), status = $6 WHERE principal = $1`, principal, u.Off(),
			u.LastChangePasswordTime, u.SecondFactors(), u.UpdatedTime, next); err != nil {
			return err
		}
		if reason == "" {
			return nil
		}
		evidenceID := ""
		if reason == "disabled" && p != nil { // the console disablement's intent names the status record (09a)
			evidenceID = p.ID
		}
		version, err := s.changeEv(ctx, tx, principal, reason, "", "", evidenceID)
		if err != nil {
			return err
		}
		if reason == "disabled" {
			if err := statusEvidence(ctx, tx, principal, next, "console", u.UpdatedTime, version); err != nil {
				return err
			}
			if p != nil {
				concluded = true
				return p.Effective(ctx, tx)
			}
			return nil
		}
		// a password or second-factor change made in Casdoor itself (item 4 T6b)
		return s.general(ctx, tx, "credential_tightening_in_product", principal, version-1, map[string]any{"kind": reason,
			"product_updated": u.UpdatedTime})
	})
	if err != nil {
		concluded = false
	}
	return rollback, concluded, err
}

// ConsoleIntent is the intent of a console disablement the comparison is about to take in: an active account that
// Casdoor refuses (read without a lock; the transaction confirms it).
func (s Store) ConsoleIntent(ctx context.Context, principal string, u provider.ProductUser) (*evidence.Pending, error) {
	if s.Ev == nil || !u.Off() {
		return nil, nil
	}
	var status string
	var version int64
	if err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, "SELECT status, security_version FROM iam_account WHERE principal = $1", principal).
			Scan(&status, &version)
	}); err != nil || status != "active" {
		return nil, err
	}
	return s.Intent(ctx, "account_status", principal, version, map[string]any{"status": "disabled", "source": "console",
		"product_updated": u.UpdatedTime}), nil
}

// statusEvidence records a status this member made or saw, with the product coordinate (protocol 15, kept here until the
// evidence store of foundations item 4); the version is the account's at that moment (the current one when absent).
func statusEvidence(ctx context.Context, tx db.Tx, principal, status, source, coordinate string, version ...int64) error {
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

// BaselinePassword records a password time this member caused, when the comparison has a baseline at all.
func (s Store) BaselinePassword(ctx context.Context, principal, at string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE iam_account SET product_password_at = $2 WHERE principal = $1
			AND product_password_at IS NOT NULL`, principal, at)
		return err
	})
}

// Managed is an account as the operations see it.
type Managed struct {
	AccountRow
	Mark   string `json:"-"`
	Issuer string `json:"-"`
}

// managed reads an account for the operations.
func (s Store) ManagedAccount(ctx context.Context, principal string) (Managed, error) {
	a := Managed{AccountRow: AccountRow{Principal: principal}}
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT username, security_version, status, security_mark, issuer FROM iam_account
			WHERE principal = $1::text::uuid`, principal).Scan(&a.Username, &a.SecurityVersion, &a.Status, &a.Mark, &a.Issuer)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = errs.New(errs.ReasonNotFound, "no such account")
	}
	return a, err
}

// Fence marks a status change in flight towards Casdoor: the comparison leaves the account alone for InFlight.
func (s Store) Fence(ctx context.Context, principal string) error {
	return s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE iam_account SET local_change_at = now() WHERE principal = $1", principal)
		return err
	})
}

// SetStatus is a status change made here on a request: on the version the authorization member was asked about
// (another change since: CHANGE_REVISION_STALE, ask again), one security change carrying the confirmation, with the
// evidence of who asked; the status record names the evidence record (09a).
func (s Store) SetStatus(ctx context.Context, principal, status, mark, confirmation, requester string, on int64,
	reason string, step EvidenceStep) (int64, error) {
	var version int64
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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

// ResetFactors is the reset's security change here, with Casdoor's new second-factor state as the baseline.
func (s Store) ResetFactors(ctx context.Context, principal, digest string, after func(context.Context, db.Tx) error) (int64, error) {
	var version int64
	err := s.Db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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
