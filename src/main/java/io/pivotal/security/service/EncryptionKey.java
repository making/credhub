package io.pivotal.security.service;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class EncryptionKey {
  private final EncryptionProvider encryptionProvider;
  private final Key key;

  public EncryptionKey(EncryptionProvider encryptionProvider, Key key) {
    this.encryptionProvider = encryptionProvider;
    this.key = key;
  }

  public Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return encryptionProvider.getCipher();
  }

  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return encryptionProvider.generateParameterSpec(nonce);
  }

  public Key getKey() {
    return key;
  }

  public SecureRandom getSecureRandom() {
    return encryptionProvider.getSecureRandom();
  }
}
