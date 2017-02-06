package io.pivotal.security.repository;

import io.pivotal.security.entity.SecretMetadata;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecretMetadataRepository extends JpaRepository<SecretMetadata, Long> {
  List<SecretMetadata> findByNameContainingIgnoreCase(String name);

  List<SecretMetadata> findByNameStartingWith(String name);
}
