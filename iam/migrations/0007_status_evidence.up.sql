-- The evidence record that made the account's last status change (security 09a's account_status.evidence): sent in
-- the status record, so the authorization member's identity-side dispositions keep their signal_ref across a full
-- recovery (a replay writes the original record's identity back). Empty for a change without one.
ALTER TABLE iam_account ADD COLUMN status_evidence uuid;
