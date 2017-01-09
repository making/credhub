package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

@RunWith(Spectrum.class)
public class EncryptionKeyConfigurationServiceTest {
  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private EncryptionProvider encryptionProvider;
  private EncryptionKeyMetadata keyMetadata1;
  private EncryptionKeyMetadata activeKeyMetadata;
  private EncryptionKeyMetadata keyMetadata3;
  private EncryptionKey key1;
  private EncryptionKey activeKey;
  private EncryptionKey key3;
  private EncryptionKeyConfigurationService subject;
  private EncryptionKeyMetadata invalidKeyMetadata;

  {
    beforeEach(() -> {
      encryptionKeysConfiguration = mock(EncryptionKeysConfiguration.class);
      encryptionProvider = mock(EncryptionProvider.class);
    });

    describe("when there are no active keys", () -> {
      itThrowsWithMessage("should throw an exception",
          EncryptionKeyConfigurationService.EncryptionKeyConfigurationException.class,
          "error.invalid_active_key_number",
          () -> {
            when(encryptionKeysConfiguration.getKeys())
                .thenReturn(new ArrayList<>());

            new EncryptionKeyConfigurationService(
                encryptionKeysConfiguration,
                encryptionProvider
            );
          }
      );
    });

    describe("when there are multiple active keys", () -> {
      itThrowsWithMessage("should throw an exception",
          EncryptionKeyConfigurationService.EncryptionKeyConfigurationException.class,
          "error.invalid_active_key_number",
          () -> {
            EncryptionKeyMetadata activeKey1 = new EncryptionKeyMetadata();
            activeKey1.setActive(true);
            EncryptionKeyMetadata activeKey2 = new EncryptionKeyMetadata();
            activeKey2.setActive(true);

            when(encryptionKeysConfiguration.getKeys())
                .thenReturn(asList(activeKey1, activeKey2));

            new EncryptionKeyConfigurationService(
                encryptionKeysConfiguration,
                mock(EncryptionProvider.class)
            );
          }
      );
    });

    describe("when there is exactly 1 active key", () -> {
      beforeEach(() -> {
        keyMetadata1 = new EncryptionKeyMetadata();
        activeKeyMetadata = new EncryptionKeyMetadata();
        activeKeyMetadata.setActive(true);
        keyMetadata3 = new EncryptionKeyMetadata();
        invalidKeyMetadata = new EncryptionKeyMetadata();

        when(encryptionKeysConfiguration.getKeys())
            .thenReturn(asList(keyMetadata1, activeKeyMetadata, keyMetadata3, invalidKeyMetadata));

        key1 = mock(EncryptionKey.class);
        activeKey = mock(EncryptionKey.class);
        key3 = mock(EncryptionKey.class);

        when(encryptionProvider.createKey(keyMetadata1))
            .thenReturn(key1);
        when(encryptionProvider.createKey(activeKeyMetadata))
            .thenReturn(activeKey);
        when(encryptionProvider.createKey(keyMetadata3))
            .thenReturn(key3);
        when(encryptionProvider.createKey(invalidKeyMetadata))
            .thenReturn(null);

        subject = new EncryptionKeyConfigurationService(
            encryptionKeysConfiguration,
            encryptionProvider
        );
      });

      describe("#getEncryptionKeys", () -> {
        it("should return a list of EncryptionKeys based on the provider, omitting null keys", () -> {
          List<EncryptionKey> encryptionKeys = subject.getEncryptionKeys();

          assertThat(encryptionKeys.size(), equalTo(3));
          assertThat(encryptionKeys, containsInAnyOrder(key1, activeKey, key3));
        });
      });

      describe("#getActiveKey", () -> {
        it("should return the active key", () -> {
          assertThat(subject.getActiveKey(), equalTo(activeKey));
        });
      });

      describe("when the active key is null", () -> {
        itThrowsWithMessage(
            "should throw an exception",
            EncryptionKeyConfigurationService.EncryptionKeyConfigurationException.class,
            "error.invalid_active_key",
            () -> {
              EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
              keyMetadata.setActive(true);

              when(encryptionKeysConfiguration.getKeys())
                  .thenReturn(asList(keyMetadata));

              when(encryptionProvider.createKey(any(EncryptionKeyMetadata.class)))
                  .thenReturn(null);

              new EncryptionKeyConfigurationService(
                  encryptionKeysConfiguration,
                  encryptionProvider
              );
          }
        );
      });
    });
  }
}
