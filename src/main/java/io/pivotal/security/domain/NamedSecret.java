package io.pivotal.security.domain;

import io.pivotal.security.entity.EncryptedValueContainer;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.view.SecretKind;

import java.time.Instant;
import java.util.UUID;

public abstract class NamedSecret<Z extends NamedSecret>  implements EncryptedValueContainer {

  private NamedSecretData delegate;

  public abstract SecretKind getKind();
  public abstract String getSecretType();
  abstract void copyIntoImpl(Z copy);

  public NamedSecret(NamedSecretData delegate) {
    this.delegate = delegate;
  }

  public UUID getUuid() {
    return delegate.getUuid();
  }

  public Z setUuid(UUID uuid) {
    delegate.setUuid(uuid);
    return (Z) this;
  }

  public String getName() {
    return delegate.getName();
  }

  public void setName(String name) {
    delegate.setName(name);
  }

  public byte[] getEncryptedValue() {
    return delegate.getEncryptedValue();
  }

  public void setEncryptedValue(byte[] encryptedValue) {
    delegate.setEncryptedValue(encryptedValue);
  }

  public byte[] getNonce() {
    return delegate.getNonce();
  }

  public void setNonce(byte[] nonce) {
    delegate.setNonce(nonce);
  }


  public UUID getEncryptionKeyUuid() {
    return delegate.getEncryptionKeyUuid();
  }

  public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    delegate.setEncryptionKeyUuid(encryptionKeyUuid);
  }

  public Instant getVersionCreatedAt() {
    return  delegate.getVersionCreatedAt();
  }

  public Z setVersionCreatedAt(Instant versionCreatedAt) {
    delegate.setVersionCreatedAt(versionCreatedAt);
    return (Z) this;
  }

  public void copyInto(Z copy) {
    copy.setEncryptedValue(getEncryptedValue());
    copy.setNonce(getNonce());
    copy.setEncryptionKeyUuid(getEncryptionKeyUuid());
    copyIntoImpl(copy);
  }
}
