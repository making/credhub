INSERT INTO named_secret (uuid, name, updated_at, encryption_key_uuid, encrypted_value, nonce, type)
  SELECT uuid, name, updated_at, encryption_key_uuid, encrypted_value, nonce, 'certificate_authority' FROM named_certificate_authority;

CREATE CACHED TABLE certificate_authority(
  uuid BINARY(16) NOT NULL PRIMARY KEY,
  certificate VARCHAR(7000),
  certificate_authority_type VARCHAR(255) NOT NULL
) AS SELECT uuid, certificate, type FROM named_certificate_authority;

ALTER TABLE certificate_authority ADD CONSTRAINT named_secret_uuid_fkey
  FOREIGN KEY(uuid)
  REFERENCES named_secret(uuid)
  ON DELETE CASCADE;

DROP TABLE named_certificate_authority;
