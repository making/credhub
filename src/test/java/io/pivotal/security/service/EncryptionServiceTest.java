package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionServiceTest {

  private EncryptionService subject;
  private EncryptionKey encryptionKey;

  {
    beforeEach(() -> {
      EncryptionKeysConfiguration encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
      EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();

      keyMetadata.setDevKey("A673ACF01DB091B08133FBC8C0B5F555");
      when(encryptionKeysConfiguration.getKeys()).thenReturn(asList(keyMetadata));

      BCEncryptionProvider bcEncryptionProviderConfiguration = new BCEncryptionProvider(new BouncyCastleProvider());
      encryptionKey = bcEncryptionProviderConfiguration.createKey(keyMetadata);

      subject = new EncryptionService();
    });

    it("should encrypt/decrypt a value", () -> {
      Encryption encryptedValue = subject.encrypt(encryptionKey, "expected-plaintext");

      assertNotNull(encryptedValue.encryptedValue);
      assertNotNull(encryptedValue.nonce);

      assertThat(subject.decrypt(encryptionKey, encryptedValue.encryptedValue, encryptedValue.nonce), equalTo("expected-plaintext"));
    });

    it("should not use the same nonce twice", () -> {
      Encryption encryptedValue1 = subject.encrypt(encryptionKey, "plaintext");
      Encryption encryptedValue2 = subject.encrypt(encryptionKey, "repeat-plaintext");
      Encryption encryptedValue3 = subject.encrypt(encryptionKey, "repeat-plaintext");

      assertThat(encryptedValue1.nonce, not(equalTo(encryptedValue2.nonce)));
      assertThat(encryptedValue1.nonce, not(equalTo(encryptedValue3.nonce)));
      assertThat(encryptedValue2.nonce, not(equalTo(encryptedValue3.nonce)));
    });
  }
}
