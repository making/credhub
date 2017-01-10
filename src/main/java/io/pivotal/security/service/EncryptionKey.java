package io.pivotal.security.service;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

public class EncryptionKey {
  public static final Charset CHARSET = Charset.defaultCharset();
  private final EncryptionConfiguration encryptionConfiguration;
  private final Key key;

  public EncryptionKey(EncryptionConfiguration encryptionConfiguration, Key key) {
    this.encryptionConfiguration = encryptionConfiguration;
    this.key = key;
  }

  public Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return encryptionConfiguration.getCipher();
  }

  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return encryptionConfiguration.generateParameterSpec(nonce);
  }

  public Key getKey() {
    return key;
  }

  public SecureRandom getSecureRandom() {
    return encryptionConfiguration.getSecureRandom();
  }

  public byte[] generateNonce(EncryptionKey encryptionKey) {
    SecureRandom secureRandom = encryptionKey.getSecureRandom();
    byte[] nonce = new byte[NONCE_SIZE];
    secureRandom.nextBytes(nonce);
    return nonce;
  }

  public Encryption encrypt(String value) throws Exception {
    byte[] nonce = generateNonce(this);
    IvParameterSpec parameterSpec = generateParameterSpec(nonce);
    Cipher encryptionCipher = getCipher();

    encryptionCipher.init(Cipher.ENCRYPT_MODE, getKey(), parameterSpec);

    byte[] encrypted = encryptionCipher.doFinal(value.getBytes(CHARSET));

    return new Encryption(encrypted, nonce);
  }

  public String decrypt(byte[] encryptedValue, byte[] nonce) throws Exception {
    Cipher decryptionCipher = getCipher();
    IvParameterSpec ccmParameterSpec = generateParameterSpec(nonce);
    decryptionCipher.init(Cipher.DECRYPT_MODE, getKey(), ccmParameterSpec);

    return new String(decryptionCipher.doFinal(encryptedValue), CHARSET);
  }
}
