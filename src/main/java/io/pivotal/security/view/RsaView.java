package io.pivotal.security.view;

import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.secret.RsaKey;

public class RsaView extends SecretView {
  RsaView(NamedRsaSecret namedRsaSecret) {
    super(
        namedRsaSecret.getVersionCreatedAt(),
        namedRsaSecret.getUuid(),
        namedRsaSecret.getSecretName(),
        namedRsaSecret.getSecretType(),
        new RsaKey(namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey())
    );
  }
}
