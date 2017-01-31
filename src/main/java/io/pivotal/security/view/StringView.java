package io.pivotal.security.view;

import io.pivotal.security.entity.NamedStringSecret;

class StringView extends SecretView {
  StringView(NamedStringSecret namedStringSecret) {
    super(
        namedStringSecret.getVersionCreatedAt(),
        namedStringSecret.getUuid(),
        namedStringSecret.getSecretName(),
        namedStringSecret.getSecretType(),
        namedStringSecret.getValue()
    );
  }
}
