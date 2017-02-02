CREATE TABLE `secret_metadata` (
  `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `type` VARCHAR(31) NOT NULL,
  PRIMARY KEY(`id`),
  UNIQUE KEY `secret_metadata_unique_name` (`name`)
) CHARACTER SET utf8 COLLATE utf8_general_ci;

INSERT INTO `secret_metadata` (`name`, `type`)
  SELECT DISTINCT(`name`, `type`)
  FROM `named_secret`;

ALTER TABLE `named_secret`
  ADD COLUMN `secret_metadata_id` BIGINT(20);

UPDATE named_secret ns
  join secret_metadata sm
    on ns.name = sm.name
set ns.secret_metadata_id=sm.id;

ALTER TABLE named_secret
  DROP COLUMN `name`,
  DROP COLUMN `type`;

ALTER TABLE `named_secret` MODIFY COLUMN `secret_metadata_id` BIGINT(20) NOT NULL,
  ADD CONSTRAINT `secret_metadata_id_fkey`
FOREIGN KEY(`secret_metadata_id`)
REFERENCES `secret_metadata`(`id`) ON DELETE CASCADE