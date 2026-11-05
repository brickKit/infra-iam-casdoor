package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/events"
	"github.com/brickKit/be-sdk-go/v3/evidence"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/brickKit/be-sdk-go/v3/records"
	"github.com/jackc/pgx/v5"
)

// store is the member's tables: logins in flight, accounts bound to Casdoor subjects, browser sessions. Every end of
// a session is written to the stream be.session.ended in the transaction that ends it (be-protocol P8.28), and every
// security change of an account to infra.iam.account_status with its new version (P8.27).
type store struct {
	db         *db.DB
	events     *events.Producer
	deployment string
	ev         *evidence.Writer // the evidence (evidence.go); nil without a database
}

var errNoLogin = errors.New("no such login in flight")

// account is a bound account as the sessions need it.
type account struct {
	principal       string
	username        string // owner/name in Casdoor
	securityVersion int64
	status          string // active, disabled, security_frozen (security 09a)
}

// begin saves a login in flight and forgets the ones older than LoginTTL.
func (s store) begin(ctx context.Context, stateHash, verifier, returnTo string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM iam_login WHERE created_at < now() - make_interval(secs => $1)",
			LoginTTL.Seconds()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO iam_login (state_hash, verifier, return_to) VALUES ($1, $2, $3)",
			stateHash, verifier, returnTo)
		return err
	})
}

// take consumes a login in flight: a state is used once.
func (s store) take(ctx context.Context, stateHash string) (verifier, returnTo string, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `DELETE FROM iam_login WHERE state_hash = $1
			AND created_at >= now() - make_interval(secs => $2) RETURNING verifier, return_to`,
			stateHash, LoginTTL.Seconds()).Scan(&verifier, &returnTo)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = errNoLogin
	}
	return verifier, returnTo, err
}

// adopt gives the accounts bound before the issuer was kept the configured Casdoor's issuer: they came from it (the
// controlled exact mapping that keeps their principals, security 02 TI11); and sends the status of the accounts
// whose status never went out (bound before it did), so the authorization member's projection has every account.
func (s store) adopt(ctx context.Context, issuer string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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

// principal returns the account bound to Casdoor's issuer and subject, binding a new principal on first sight (its
// status goes out in the same transaction). The same subject of another issuer, or the same e-mail or login name, is
// another account: nothing is taken over.
// A disabled or frozen account is answered as it is: the caller refuses it (signedIn).
func (s store) principal(ctx context.Context, issuer string, id providerUser) (account, error) {
	a := account{username: id.Username}
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var bound bool
		if err := tx.QueryRow(ctx, `INSERT INTO iam_account (principal, provider, issuer, provider_subject, username)
			VALUES ($1, 'casdoor', $2, $3, $4)
			ON CONFLICT (provider, issuer, provider_subject) DO UPDATE SET username = EXCLUDED.username
			RETURNING principal::text, security_version, status, xmax = 0`, ids.New(), issuer, id.Subject, id.Username).
			Scan(&a.principal, &a.securityVersion, &a.status, &bound); err != nil {
			return err
		}
		if !bound {
			return nil
		}
		return s.status(ctx, tx, a.principal, a.securityVersion)
	})
	return a, err
}

// open starts a session for a principal.
func (s store) open(ctx context.Context, idHash, principal string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iam_session (id_hash, principal, recovery_generation)
			VALUES ($1, $2, (SELECT generation FROM be_recovery_generation))`, idHash, principal)
		return err
	})
}

// use returns a live session's account and the instant the session ends at the latest (the absolute timeout, or the
// idle one from now), renewing the idle time unless renew is false (a polling request's exchange, protocol 20). The
// session row's lock serialises the session's uses. A session past either timeout, or created before the deployment's
// last full recovery (protocol 15, 6.6), is ended with that reason (and written to the ended stream); ok=false for
// every session that is not live.
func (s store) use(ctx context.Context, idHash string, idle, absolute time.Duration, renew bool) (a account,
	until time.Time, ok bool, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var created, seen time.Time
		err := tx.QueryRow(ctx, `UPDATE iam_session SET last_seen = CASE WHEN $4 THEN now() ELSE last_seen END
			WHERE id_hash = $1 AND ended_at IS NULL AND last_seen >= now() - make_interval(secs => $2)
				AND created_at >= now() - make_interval(secs => $3)
				AND recovery_generation >= (SELECT generation FROM be_recovery_generation)
			RETURNING principal::text, created_at, last_seen`, idHash, idle.Seconds(), absolute.Seconds(), renew).
			Scan(&a.principal, &created, &seen)
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
			a.principal).Scan(&a.username, &a.securityVersion); err != nil {
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

// end ends a session.
func (s store) end(ctx context.Context, idHash, reason string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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

// endBeforeRecovery ends every live session created before the deployment's current recovery generation (protocol
// 15, 6.6: a full recovery ends the sessions from before it), each written to the ended stream; it answers the
// accounts whose sessions ended. Nothing to do unless a full recovery advanced the generation.
func (s store) endBeforeRecovery(ctx context.Context) (usernames []string, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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

// securityChange is a security change of an account made here (a password change, a forced logout, a reset of the
// second factors): its version goes up by one, every live session but keep ends with reason, and the account's status
// goes out with the new version, all in one transaction (P8.27). keep is the session that made the change ("" for
// none): its next exchange gets a token of the new version.
func (s store) securityChange(ctx context.Context, principal, reason, keep string, after func(context.Context, db.Tx) error) (int64, error) {
	var version int64
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
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
func (s store) change(ctx context.Context, tx db.Tx, principal, reason, keep string) (int64, error) {
	return s.changeWith(ctx, tx, principal, reason, keep, "")
}

// changeWith is change carrying a confirmation in the status record (a protected status change, A134); every other
// security change sends none, so a confirmation goes out with the change it confirmed only.
func (s store) changeWith(ctx context.Context, tx db.Tx, principal, reason, keep, confirmation string) (int64, error) {
	var version int64
	if err := tx.QueryRow(ctx, `UPDATE iam_account SET security_version = security_version + 1,
		status_confirmation = NULLIF($2, '')::uuid WHERE principal = $1 RETURNING security_version`, principal,
		confirmation).Scan(&version); err != nil {
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
func (s store) ended(ctx context.Context, tx db.Tx, idHash string) error {
	_, err := s.events.Emit(ctx, tx, StreamEnded, events.Event{Type: TypeEnded, RecordID: idHash, Version: 1,
		Projection: events.Full, Data: map[string]string{"session_digest": idHash}})
	return err
}

// status writes the account's status record (be.security.account_status, security 09a) with its security version;
// the version is also the record's revision in this member's database.
func (s store) status(ctx context.Context, tx db.Tx, principal string, version int64) error {
	var status, mark string
	var confirmation *string
	if err := tx.QueryRow(ctx, "SELECT status, security_mark, status_confirmation::text FROM iam_account WHERE principal = $1",
		principal).Scan(&status, &mark, &confirmation); err != nil {
		return err
	}
	rec := map[string]any{
		"record_type": "be.security.account_status", "schema": "1.0", "deployment": s.deployment, "authority": ID,
		"id": principal, "revision": map[string]any{"domain": StreamAccount, "value": strconv.FormatInt(version, 10)},
		"account": map[string]any{"deployment": s.deployment, "kind": "user", "id": principal},
		"status":  status, "security_version": version}
	if mark != "none" {
		rec["security_mark"] = mark
	}
	if confirmation != nil {
		rec["confirmation"] = *confirmation
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
	_, err = s.events.Emit(ctx, tx, StreamAccount, events.Event{Type: TypeAccount, RecordID: principal,
		Version: version, Projection: events.Full, Data: json.RawMessage(raw), Subjects: []string{principal}})
	return err
}
