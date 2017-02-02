CREATE SEQUENCE metadata_id_sequence START WITH 1 BELONGS_TO_TABLE;

CREATE TABLE secret_metadata (
  id BIGINT DEFAULT (NEXT VALUE FOR metadata_id_sequence) NOT NULL NULL_TO_DEFAULT SEQUENCE metadata_id_sequence,
  name VARCHAR(255) NOT NULL
  type VARCHAR(31) NOT NULL
);

ALTER TABLE secret_metadata
  ADD CONSTRAINT secret_metadata_pkey PRIMARY KEY(id);

ALTER TABLE secret_metadata
  ADD CONSTRAINT name_unique UNIQUE(name);

INSERT INTO secret_metadata (name, type)
  SELECT DISTINCT(named_secret.name, type)
  FROM named_secret;

ALTER TABLE named_secret
  ADD COLUMN secret_metadata_id BIGINT NOT NULL;

UPDATE named_secret ns
join secret_metadata sm
on ns.name = sm.name
set ns.secret_metadata_id=sm.id;

ALTER TABLE named_secret
  DROP COLUMN name,
  DROP COLUMN type;

ALTER TABLE named_secret
  ADD CONSTRAINT secret_metadata_id_fkey
FOREIGN KEY(secret_metadata_id)
REFERENCES secret_metadata(id)
ON DELETE CASCADE;