-- The account operations (security 03's tightening-only operations, security 08's admin accounts, A134):
-- the confirmation the status change carries goes out in the status record of that change only; the time of this
-- member's last own status change (or of one in flight towards Casdoor) keeps the comparison from taking its own
-- write for a console change or a rollback.
ALTER TABLE iam_account ADD COLUMN status_confirmation uuid;
ALTER TABLE iam_account ADD COLUMN local_change_at timestamptz;

-- The evidence of a status this member made on a request: who asked, with which confirmation.
ALTER TABLE iam_status_evidence ADD COLUMN requested_by uuid;
ALTER TABLE iam_status_evidence ADD COLUMN confirmation uuid;

ALTER TABLE iam_session DROP CONSTRAINT iam_session_end_reason_check;
ALTER TABLE iam_session ADD CONSTRAINT iam_session_end_reason_check
    CHECK (end_reason IN ('logout', 'idle', 'absolute', 'disabled', 'frozen', 'revoked', 'password', 'second_factor', 'forced'));
