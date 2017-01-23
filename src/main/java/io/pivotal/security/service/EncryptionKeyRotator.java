package io.pivotal.security.service;

import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.domain.Slice;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.stereotype.Component;

import javax.persistence.EntityManager;

@Component
@EnableAsync
public class EncryptionKeyRotator {
  private final SecretEncryptionHelper secretEncryptionHelper;
  private final SecretDataService secretDataService;
  private final CertificateAuthorityDataService certificateAuthorityDataService;
  private final Logger logger;
  private final EntityManager entityManager;

  EncryptionKeyRotator(
      SecretEncryptionHelper secretEncryptionHelper,
      SecretDataService secretDataService,
      CertificateAuthorityDataService certificateAuthorityDataService,
      EntityManager entityManager
  ) {
    this.secretEncryptionHelper = secretEncryptionHelper;
    this.secretDataService = secretDataService;
    this.certificateAuthorityDataService = certificateAuthorityDataService;
    this.logger = LogManager.getLogger(this.getClass());
    this.entityManager = entityManager;
  }

  // Synchronized to ensure that nothing happens until everything has been rotated.
  // This is the naive version!!!
  // Future stories should improve this (performance, error handling, etc.).
  //
  @Async
  public synchronized void rotate() {
    final long start = System.currentTimeMillis();
    logger.info("Started encryption key rotation");

//    Stream<NamedSecret> namedSecretStream = secretDataService.streamAllNotEncryptedByActiveKey();
//    logger.warn("size before: " + namedSecretStream.count());
//    namedSecretStream = secretDataService.streamAllNotEncryptedByActiveKey();
//    try(Stream<NamedSecret> streamedSecretsEncryptedByOldKey = namedSecretStream) {
//      streamedSecretsEncryptedByOldKey.forEach(secret -> {
//        secretEncryptionHelper.rotate(secret);
//        secretDataService.save(secret);
////        entityManager.detach(secret);
//      });
//    } catch (Exception e) {
//
//    }
//    namedSecretStream = secretDataService.streamAllNotEncryptedByActiveKey();
//    logger.warn("size after: " + namedSecretStream.count());

    Slice<NamedSecret> secretsEncryptedByOldKey = secretDataService.findAllNotEncryptedByActiveKey();
    while (secretsEncryptedByOldKey.hasContent()) {
      secretsEncryptedByOldKey.getContent().forEach(secret -> {
        secretEncryptionHelper.rotate(secret);
        secretDataService.save(secret);
      });
      secretsEncryptedByOldKey = secretDataService.findAllNotEncryptedByActiveKey();
    }
//    List<NamedSecret> secretsEncryptedByOldKey = secretDataService.findAllNotEncryptedByActiveKey();
//    for (NamedSecret secret : secretsEncryptedByOldKey) {
//      secretEncryptionHelper.rotate(secret);
//      secretDataService.save(secret);
//    }

//    List<NamedPasswordSecret> passwordsWithParametersEncryptedByOldEncryptionKey = secretDataService.findAllPasswordsWithParametersNotEncryptedByActiveKey();
//    for (NamedPasswordSecret password : passwordsWithParametersEncryptedByOldEncryptionKey) {
//      secretEncryptionHelper.rotatePasswordParameters(password);
//      secretDataService.save(password);
//    }
//
//    List<NamedCertificateAuthority> certificateAuthoritiesEncryptedByOldKey = certificateAuthorityDataService.findAllNotEncryptedByActiveKey();
//    for (NamedCertificateAuthority certificateAuthority : certificateAuthoritiesEncryptedByOldKey) {
//      secretEncryptionHelper.rotate(certificateAuthority);
//      certificateAuthorityDataService.save(certificateAuthority);
//    }
    final long finish = System.currentTimeMillis();
    final long delta = finish - start;
    logger.info("Finished encryption key rotation - took " + delta + " milliseconds.");
  }
}
