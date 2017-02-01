package io.pivotal.security.service;


import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import io.pivotal.security.view.SecretKindFromString;
import io.pivotal.security.view.SecretView;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
public class SecretStorageService {
  private SecretDataService secretDataService;

  @Autowired
  public SecretStorageService(SecretDataService secretDataService) {
    this.secretDataService = secretDataService;
  }

  public SecretView storeSecret(String secretPath,
                                SecretKindMappingFactory namedSecretHandler,
                                DocumentContext parsed,
                                NamedSecret existingNamedSecret,
                                boolean overwrite, boolean regenerate) throws ParameterizedValidationException, NoSuchAlgorithmException{

      String requestedSecretType = parsed.read("$.type");
      final SecretKind secretKind = (existingNamedSecret != null ?
        existingNamedSecret.getKind() :
        SecretKindFromString.fromString(requestedSecretType));

      if (existingNamedSecret != null && requestedSecretType != null && !existingNamedSecret.getSecretType().equals(requestedSecretType))
        throw new ParameterizedValidationException("error.type_mismatch");

      secretPath = existingNamedSecret == null ? secretPath : existingNamedSecret.getName();

      NamedSecret storedNamedSecret;
      if (!overwrite && !regenerate){
        storedNamedSecret = secretKind.lift(namedSecretHandler.make(secretPath, parsed)).apply(existingNamedSecret);
        storedNamedSecret = secretDataService.createIfNotExists(storedNamedSecret);
      }
      else if (overwrite || regenerate ||existingNamedSecret == null) {
          storedNamedSecret = secretKind.lift(namedSecretHandler.make(secretPath, parsed)).apply(existingNamedSecret);
          storedNamedSecret = secretDataService.createOrReplace(storedNamedSecret);

      } else {
        // To catch invalid parameters, validate request even though we throw away the result.
        // We need to apply it to null or Hibernate may decide to createOrReplace the record.
        // As above, the unit tests won't catch (all) issues :( , but there is an integration test to cover it.
        storedNamedSecret = existingNamedSecret;
        secretKind.lift(namedSecretHandler.make(secretPath, parsed)).apply(null);
      }

      return SecretView.fromEntity(storedNamedSecret);
  }



}
