package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.CertificateSecret;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class CertificateSetRequestTranslator implements SecretSetterRequestTranslator {

  @Override
  public CertificateSecret createSecretFromJson(DocumentContext parsed) throws ValidationException {
    String ca = parsed.read("$.certificate.ca");
    String pub = parsed.read("$.certificate.public");
    String priv = parsed.read("$.certificate.private");
    ca = StringUtils.isEmpty(ca) ? null : ca;
    pub = StringUtils.isEmpty(pub) ? null : pub;
    priv = StringUtils.isEmpty(priv) ? null : priv;
    if (ca == null && pub == null && priv == null) {
      throw new ValidationException("error.missing_certificate_credentials");
    }
    return new CertificateSecret(ca, pub, priv);
  }
}
