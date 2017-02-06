CREATE SEQUENCE metadata_id_sequence START WITH 1 BELONGS_TO_TABLE;

CREATE CACHED TABLE secret_metadata (
  id BIGINT DEFAULT (NEXT VALUE FOR metadata_id_sequence) NOT NULL NULL_TO_DEFAULT SEQUENCE metadata_id_sequence,
  name VARCHAR(255) NOT NULL
);

ALTER TABLE secret_metadata
  ADD CONSTRAINT secret_metadata_pkey PRIMARY KEY(id);

ALTER TABLE secret_metadata
  ADD CONSTRAINT name_unique UNIQUE(name);

INSERT INTO secret_metadata (name)
  SELECT DISTINCT named_secret.name
  FROM named_secret;

ALTER TABLE named_secret
  ADD COLUMN secret_metadata_id BIGINT NOT NULL;

UPDATE named_secret
SET named_secret.secret_metadata_id =
  (SELECT id
    FROM secret_metadata
    WHERE secret_metadata.name = named_secret.name);


ALTER TABLE named_secret
  DROP COLUMN name;

ALTER TABLE named_secret
  ADD CONSTRAINT secret_metadata_id_fkey
  FOREIGN KEY(secret_metadata_id)
  REFERENCES secret_metadata(id)
  ON DELETE CASCADE;