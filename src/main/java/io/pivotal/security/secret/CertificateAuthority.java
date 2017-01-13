package io.pivotal.security.secret;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateAuthority implements Secret {
  private final String certificateAuthorityType;
  private final String certificate;
  private final String privateKey;

  public CertificateAuthority(String certificateAuthorityType, String certificate, String privateKey) {
    this.certificateAuthorityType = certificateAuthorityType;
    this.certificate = certificate;
    this.privateKey = privateKey;
  }

  @JsonIgnore
  public String getCertificateAuthorityType() {
    return certificateAuthorityType;
  }

  @JsonProperty("certificate")
  public String getCertificate() {
    return certificate;
  }

  @JsonProperty("private_key")
  public String getPrivateKey() {
    return privateKey;
  }
}
