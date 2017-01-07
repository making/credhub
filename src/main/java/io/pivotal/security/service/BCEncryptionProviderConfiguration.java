package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionProviderConfiguration implements EncryptionProviderConfiguration {
  private final SecureRandom secureRandom;
  private final BouncyCastleProvider provider;

  @Autowired
  BCEncryptionProviderConfiguration(BouncyCastleProvider provider)
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    this.provider = provider;

    KeyStore keyStore = KeyStore.getInstance("BKS", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("SHA1PRNG");
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
    return Cipher.getInstance(CipherTypes.GCM.toString(), provider);
  }

  @Override
  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  @Override
  public EncryptionKey createKey(EncryptionKeyMetadata keyMetadata) {
    String devKey = keyMetadata.getDevKey();
    EncryptionKey encryptionKey = null;

    if (devKey != null) {
      encryptionKey = new EncryptionKey(this, new SecretKeySpec(DatatypeConverter.parseHexBinary(devKey), 0, 16, "AES"));
    }

    return encryptionKey;
  }
}
