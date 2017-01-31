package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.secret.Certificate;

class CertificateView extends SecretView {
  CertificateView(NamedCertificateSecret namedCertificateSecret) {
    super(
        namedCertificateSecret.getVersionCreatedAt(),
        namedCertificateSecret.getUuid(),
        namedCertificateSecret.getSecretName(),
        namedCertificateSecret.getSecretType(),
        new Certificate(namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey())
    );
  }
}
