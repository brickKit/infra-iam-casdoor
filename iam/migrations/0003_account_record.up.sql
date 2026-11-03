-- Foundations item 3 (be-protocol P9.30): the account's status record as it went out, the same bytes the batch read
-- and the snapshot answer with (a record read must carry what the current full-state event carries). NULL only for
-- rows from before: the member fills them at start.
ALTER TABLE iam_account ADD COLUMN status_record bytea;
