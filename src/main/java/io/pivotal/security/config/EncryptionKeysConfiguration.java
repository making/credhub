package io.pivotal.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties("encryption")
public class EncryptionKeysConfiguration {
  private List<EncryptionKeyMetadata> keys = new ArrayList<>();

  public List<EncryptionKeyMetadata> getKeys() { return keys; }
}
