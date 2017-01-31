CREATE SEQUENCE metadata_id_sequence START WITH 1 BELONGS_TO_TABLE;

CREATE TABLE secret_metadata (
  name VARCHAR(255) NOT NULL,
--   type VARCHAR(255) NOT NULL
);

ALTER TABLE secret_metadata
  ADD CONSTRAINT secret_metadata_pkey PRIMARY KEY(name);

INSERT INTO secret_metadata (name)
  SELECT DISTINCT(named_secret.name)
  FROM named_secret;

ALTER TABLE named_secret
  ADD COLUMN secret_metadata_name BIGINT NOT NULL;

ALTER TABLE named_secret
  DROP COLUMN name;

ALTER TABLE named_secret
  ADD CONSTRAINT secret_metadata_id_fkey
  FOREIGN KEY(secret_metadata_id)
  REFERENCES secret_metadata(id)
  ON DELETE CASCADE;
