package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.secret.Certificate;

class CertificateView extends SecretView {
  private final Certificate value;

  CertificateView(NamedCertificateSecret namedCertificateSecret) {
    super(namedCertificateSecret);
    this.value = new Certificate(namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey());
  }

  @Override
  public Certificate getValue() {
    return value;
  }
}
