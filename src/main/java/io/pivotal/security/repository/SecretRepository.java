package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretMetadata;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

public interface SecretRepository extends JpaRepository<NamedSecret, UUID> {
  int SECRET_BATCH_SIZE = 50;

  NamedSecret findFirstBySecretMetadataNameIgnoreCaseOrderByVersionCreatedAtDesc(String name);
  NamedSecret findOneByUuid(UUID uuid);

  List<NamedSecret> deleteBySecretMetadataNameIgnoreCase(String name);
  List<NamedSecret> findAllBySecretMetadataNameIgnoreCase(String name);
  Slice<NamedSecret> findByEncryptionKeyUuidNot(UUID encryptionKeyUuid, Pageable page);

  default List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    return findAll().stream()
        .map(NamedSecret::getName)
        .flatMap(NamedSecret::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }

  default NamedSecret createIfNotExists(NamedSecret namedSecret){
    NamedSecret existing = findFirstBySecretMetadataNameIgnoreCaseOrderByVersionCreatedAtDesc(namedSecret.getName());
    if (existing == null){
      return saveAndFlush(namedSecret);
    }
    return existing;
  }

  List<NamedSecret> findBySecretMetadata(SecretMetadata metadata);
}
