package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public interface EncryptionProvider {
  Provider getProvider();

  SecureRandom getSecureRandom();

  Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException;

  IvParameterSpec generateParameterSpec(byte[] nonce);

  EncryptionKey createKey(EncryptionKeyMetadata keyMetadata);
}
