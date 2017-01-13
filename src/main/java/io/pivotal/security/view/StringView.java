package io.pivotal.security.view;

import io.pivotal.security.entity.NamedStringSecret;

class StringView extends SecretView {
  private final String value;

  StringView(NamedStringSecret namedStringSecret) {
    super(namedStringSecret);
    this.value = namedStringSecret.getValue();
  }

  @Override
  public String getValue() {
    return value;
  }
}
