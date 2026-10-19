package iam

import (
	"context"
	"errors"
	"time"

	"github.com/brickKit/be-sdk-go/v3/db"
	"github.com/brickKit/be-sdk-go/v3/ids"
	"github.com/jackc/pgx/v5"
)

// store is the member's tables: logins in flight, accounts bound to Casdoor subjects, browser sessions.
type store struct{ db *db.DB }

var errNoLogin = errors.New("no such login in flight")

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

// principal returns the platform principal bound to a Casdoor subject, binding a new one on first sight.
func (s store) principal(ctx context.Context, id providerUser) (string, error) {
	var p string
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO iam_account (principal, provider, provider_subject, username)
			VALUES ($1, 'casdoor', $2, $3)
			ON CONFLICT (provider, provider_subject) DO UPDATE SET username = EXCLUDED.username
			RETURNING principal::text`, ids.New(), id.Subject, id.Username).Scan(&p)
	})
	return p, err
}

// open starts a session for a principal.
func (s store) open(ctx context.Context, idHash, principal string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO iam_session (id_hash, principal) VALUES ($1, $2)", idHash, principal)
		return err
	})
}

// use renews a live session's idle time and returns its principal and the instant it ends at the latest (the
// absolute timeout, or the idle one from now). A session past either timeout is ended with that reason; ok=false
// for every session that is not live.
func (s store) use(ctx context.Context, idHash string, idle, absolute time.Duration) (principal string, until time.Time, ok bool, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		var created time.Time
		err := tx.QueryRow(ctx, `UPDATE iam_session SET last_seen = now()
			WHERE id_hash = $1 AND ended_at IS NULL AND last_seen >= now() - make_interval(secs => $2)
				AND created_at >= now() - make_interval(secs => $3)
			RETURNING principal::text, created_at`, idHash, idle.Seconds(), absolute.Seconds()).Scan(&principal, &created)
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = tx.Exec(ctx, `UPDATE iam_session SET ended_at = now(),
					end_reason = CASE WHEN created_at < now() - make_interval(secs => $2) THEN 'absolute' ELSE 'idle' END
				WHERE id_hash = $1 AND ended_at IS NULL`, idHash, absolute.Seconds())
			return err
		}
		if err != nil {
			return err
		}
		ok = true
		until = created.Add(absolute)
		if i := time.Now().Add(idle); i.Before(until) {
			until = i
		}
		return nil
	})
	return principal, until, ok, err
}

// end ends a session.
func (s store) end(ctx context.Context, idHash, reason string) error {
	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE iam_session SET ended_at = now(), end_reason = $2 WHERE id_hash = $1 AND ended_at IS NULL",
			idHash, reason)
		return err
	})
}
