package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CertificateAuthority")
@DiscriminatorValue(NamedCertificateAuthority.TABLE_TYPE)
public class NamedCertificateAuthority extends NamedSecret<NamedCertificateAuthority> {
  public static final String SECRET_TYPE = "root";
  static final String TABLE_TYPE = "root";

  @Column(length = 255)
  private String certificateAuthorityType;

  @Column(length = 7000)
  private String certificate;

  @SuppressWarnings("unused")
  public NamedCertificateAuthority() {
  }

  public NamedCertificateAuthority(String name) {
    super(name);
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.CERTIFICATE_AUTHORITY;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  public String getCertificate() {
    return certificate;
  }

  public NamedCertificateAuthority setCertificate(String certificate) {
    this.certificate = certificate;
    return this;
  }

  public String getCertificateAuthorityType() {
    return certificateAuthorityType;
  }

  public NamedCertificateAuthority setCertificateAuthorityType(String type) {
    this.certificateAuthorityType = type;
    return this;
  }

  public String getPrivateKey() {
    return SecretEncryptionHelperProvider.getInstance().retrieveClearTextValue(this);
  }

  public NamedCertificateAuthority setPrivateKey(String privateKey) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedValue(this, privateKey);
    return this;
  }

  @Override
  void copyIntoImpl(NamedCertificateAuthority copy) {
    copy.setCertificate(certificate);
    copy.setCertificateAuthorityType(certificateAuthorityType);
  }
}
