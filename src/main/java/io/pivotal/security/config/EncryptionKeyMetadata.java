package io.pivotal.security.config;

public class EncryptionKeyMetadata {
  private String devKey;
  private String activeKeyName;
  private boolean active;

  public String getDevKey() {
    return devKey;
  }

  public void setDevKey(String devKey) {
    this.devKey = devKey;
  }

  public String getActiveKeyName() {
    return activeKeyName;
  }

  public void setActiveKeyName(String activeKeyName) {
    this.activeKeyName = activeKeyName;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }
}
