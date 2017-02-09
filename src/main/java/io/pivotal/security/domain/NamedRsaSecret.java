package io.pivotal.security.domain;

import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedRsaSecret extends NamedRsaSshSecret {

  private NamedRsaSecretData delegate;

  public NamedRsaSecret(NamedRsaSecretData delegate){
    super(delegate);
    this.delegate = delegate;
  }

  public int getKeyLength(){
    return delegate.getKeyLength();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }
}
