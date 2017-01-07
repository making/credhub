package io.pivotal.security.service;

import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import org.springframework.stereotype.Service;

import static java.util.stream.Collectors.partitioningBy;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class EncryptionKeyConfigurationService {
  private final EncryptionKey activeKey;
  private final List<EncryptionKey> encryptionKeys;

  EncryptionKeyConfigurationService(
      EncryptionKeysConfiguration encryptionKeysConfiguration,
      EncryptionProviderConfiguration encryptionProviderConfiguration
  ) {
    List<EncryptionKeyMetadata> keyMetadatas = encryptionKeysConfiguration.getKeys();
    Map<Boolean, List<EncryptionKeyMetadata>> partitionedKeys = keyMetadatas
        .stream()
        .collect(partitioningBy(EncryptionKeyMetadata::isActive));

    List<EncryptionKeyMetadata> activeKeyList = partitionedKeys.get(true);
    List<EncryptionKeyMetadata> inactiveKeyList = partitionedKeys.get(false);

    if (activeKeyList.size() != 1) {
      throw new EncryptionKeyConfigurationException("error.invalid_active_key_number");
    }

    activeKey = encryptionProviderConfiguration.createKey(activeKeyList.get(0));

    if (activeKey == null) {
      throw new EncryptionKeyConfigurationException("error.invalid_active_key");
    }

    encryptionKeys = inactiveKeyList
        .stream()
        .map(encryptionProviderConfiguration::createKey)
        .filter(keyMetadata -> keyMetadata != null)
        .collect(Collectors.toList());

    encryptionKeys.add(activeKey);
  }

  public List<EncryptionKey> getEncryptionKeys() {
    return encryptionKeys;
  }

  public EncryptionKey getActiveKey() {
    return activeKey;
  }

  class EncryptionKeyConfigurationException extends RuntimeException {
    EncryptionKeyConfigurationException(String message) {
      super(message);
    }
  }
}
