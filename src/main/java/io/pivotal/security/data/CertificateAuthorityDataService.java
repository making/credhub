package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertificateAuthorityDataService {
  private final SecretDataService secretDataService;

  @Autowired
  public CertificateAuthorityDataService(SecretDataService secretDataService) {
    this.secretDataService = secretDataService;
  }

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    return secretDataService.save(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecent(String name) {
    NamedSecret mostRecentSecret = secretDataService.findMostRecent(name);
    NamedCertificateAuthority mostRecentCa = null;

    if (isCertificateAuthority(mostRecentSecret)) {
      mostRecentCa = (NamedCertificateAuthority) mostRecentSecret;
    }

    return mostRecentCa;
  }

  public NamedCertificateAuthority findByUuid(String uuid) {
    NamedSecret mostRecentSecret = secretDataService.findByUuid(uuid);
    NamedCertificateAuthority mostRecentCa = null;

    if (isCertificateAuthority(mostRecentSecret)) {
      mostRecentCa = (NamedCertificateAuthority) mostRecentSecret;
    }

    return mostRecentCa;
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return secretDataService.findAllByName(name)
        .stream()
        .filter(CertificateAuthorityDataService::isCertificateAuthority)
        .map(secret -> (NamedCertificateAuthority) secret)
        .collect(Collectors.toList());
  }

  private static boolean isCertificateAuthority(NamedSecret secret) {
    return secret != null && NamedCertificateAuthority.SECRET_TYPE.equals(secret.getSecretType());
  }
}
