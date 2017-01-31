package io.pivotal.security.repository;

import io.pivotal.security.entity.SecretMetadata;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecretMetadataRepository extends JpaRepository<SecretMetadata, String> {
  SecretMetadata findOne(String name);
}
