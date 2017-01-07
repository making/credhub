package io.pivotal.security.service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class EncryptionKey {
  private final EncryptionProviderConfiguration encryptionProviderConfiguration;
  private final Key key;

  public EncryptionKey(EncryptionProviderConfiguration encryptionProviderConfiguration, Key key) {
    this.encryptionProviderConfiguration = encryptionProviderConfiguration;
    this.key = key;
  }

  public Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return encryptionProviderConfiguration.getCipher();
  }

  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return encryptionProviderConfiguration.generateParameterSpec(nonce);
  }

  public Key getKey() {
    return key;
  }

  public SecureRandom getSecureRandom() {
    return encryptionProviderConfiguration.getSecureRandom();
  }
}
