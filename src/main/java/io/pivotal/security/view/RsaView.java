package io.pivotal.security.view;

import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.secret.RsaKey;

public class RsaView extends SecretView {
  private final RsaKey value;

  RsaView(NamedRsaSecret namedRsaSecret) {
    super(namedRsaSecret);
    this.value = new RsaKey(namedRsaSecret.getPublicKey(), namedRsaSecret.getPrivateKey());
  }

  @Override
  public RsaKey getValue() {
    return value;
  }
}
