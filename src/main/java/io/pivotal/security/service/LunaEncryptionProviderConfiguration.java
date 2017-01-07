package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.constants.CipherTypes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@SuppressWarnings("unused")
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm", matchIfMissing = true)
@Component
public class LunaEncryptionProviderConfiguration implements EncryptionProviderConfiguration {

  @Value("${hsm.partition}")
  String partitionName;

  @Value("${hsm.partition-password}")
  String partitionPassword;

  @Value("${hsm.encryption-key-name}")
  String encryptionKeyAlias;

  private Provider provider;
  private SecureRandom secureRandom;
  private EncryptionKey key;
  private List<EncryptionKey> keys;
  private KeyStore keyStore;
  private KeyGenerator aesKeyGenerator;

  public LunaEncryptionProviderConfiguration() throws Exception {
    provider = (Provider) Class.forName("com.safenetinc.luna.provider.LunaProvider").newInstance();
    Security.addProvider(provider);
  }

  @PostConstruct
  private void initialize() throws Exception {
    Object lunaSlotManager = Class.forName("com.safenetinc.luna.LunaSlotManager").getDeclaredMethod("getInstance").invoke(null);
    lunaSlotManager.getClass().getMethod("login", String.class, String.class).invoke(lunaSlotManager, partitionName, partitionPassword);

    keyStore = KeyStore.getInstance("Luna", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("LunaRNG");
    aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);
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
    String encryptionKeyAlias = keyMetadata.getActiveKeyName();
    EncryptionKey encryptionKey = null;

    if (encryptionKeyAlias != null) {
      try {
        if (!keyStore.containsAlias(encryptionKeyAlias)) {
          SecretKey aesKey = aesKeyGenerator.generateKey();
          keyStore.setKeyEntry(encryptionKeyAlias, aesKey, null, null);
        }

        encryptionKey = new EncryptionKey(this, keyStore.getKey(encryptionKeyAlias, null));
      } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
        throw new RuntimeException(e);
      }
    }

    return encryptionKey;
  }
}
