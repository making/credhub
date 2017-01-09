package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@SuppressWarnings("unused")
@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dsm")
public class DyadicEncryptionProvider implements EncryptionProvider {
  private List<EncryptionKey> keys;
  @Value("${dsm.encryption-key-name}")
  String encryptionKeyAlias;

  private Provider provider;
  private SecureRandom secureRandom;

  public DyadicEncryptionProvider() throws Exception {
    provider = (Provider) Class.forName("com.dyadicsec.provider.DYCryptoProvider").newInstance();
    Security.addProvider(provider);
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  @Override
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  public Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return Cipher.getInstance(CipherTypes.CCM.toString(), provider);
  }

  @Override
  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    int numBytes = nonce != null ? nonce.length : 0;
    try {
      Constructor constructor = Class.forName("com.dyadicsec.provider.CcmParameterSpec").getConstructor(byte[].class, int.class, byte[].class);
      return (IvParameterSpec) constructor.newInstance(nonce, numBytes, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public EncryptionKey createKey(EncryptionKeyMetadata keyMetadata) {
    return null;
  }

  private void initializeKeys() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null);
    secureRandom = new SecureRandom();

    if (!keyStore.containsAlias(encryptionKeyAlias)) {
      KeyGenerator aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
      aesKeyGenerator.init(128);

      SecretKey aesKey = aesKeyGenerator.generateKey();
      keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null, null);
    }

    new EncryptionKey(this, keyStore.getKey(encryptionKeyAlias, null));
  }
}
