package io.pivotal.security.view;

import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.secret.SshKey;

class SshView extends SecretView {
  private final SshKey value;

  SshView(NamedSshSecret namedSshSecret) {
    super(namedSshSecret);
    this.value = new SshKey(namedSshSecret.getPublicKey(), namedSshSecret.getPrivateKey());
  }

  @Override
  SshKey getValue() {
    return value;
  }
}
