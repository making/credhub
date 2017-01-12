package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {
  private SecretEncryptionHelper secretEncryptionHelper;
  private SecretDataService secretDataService;

  private NamedSecret passwordSecretUnsaved1;
  private NamedSecret certificateAuthority;
  private NamedSecret passwordSecretUnsaved2;
  private NamedSecret certificateSecret;

  private NamedPasswordSecret passwordWithOldParameters1;
  private NamedPasswordSecret passwordWithOldParameters2;


  {
    beforeEach(() -> {
      secretEncryptionHelper = mock(SecretEncryptionHelper.class);
      secretDataService = mock(SecretDataService.class);

      certificateSecret = new NamedCertificateSecret();
      certificateAuthority = new NamedCertificateAuthority();
      passwordSecretUnsaved1 = new NamedPasswordSecret();
      passwordSecretUnsaved2 = new NamedPasswordSecret();

      when(secretDataService.findAllNotEncryptedByActiveKey())
          .thenReturn(asList(certificateSecret, certificateAuthority, passwordSecretUnsaved1, passwordSecretUnsaved2));

      // This loveliness (not) enforces the right order of operations, since we need to ensure that
      // we fetch passwords with params that need to be rotated only after we've rotated the secrets.
      // If not, we will re-persist the old encryption key UUID for password secrets.
      passwordWithOldParameters1 = null;
      passwordWithOldParameters2 = null;

      when(secretDataService.save(passwordSecretUnsaved1))
          .thenAnswer(invocation -> {
            passwordWithOldParameters1 = new NamedPasswordSecret();
            return passwordWithOldParameters1;
          });
      when(secretDataService.save(passwordSecretUnsaved2))
          .thenAnswer(invocation -> {
            passwordWithOldParameters2 = new NamedPasswordSecret();
            return passwordWithOldParameters2;
          });

      when(secretDataService.findAllPasswordsWithParametersNotEncryptedByActiveKey())
          .thenAnswer(invocation -> (
            asList(passwordWithOldParameters1, passwordWithOldParameters2)
          ));

      new EncryptionKeyRotator(secretEncryptionHelper, secretDataService);
    });

    it("should rotate all the secrets and params that were encrypted with an old key", () -> {
      verify(secretEncryptionHelper, times(4)).rotate(any(NamedSecret.class));
      verify(secretEncryptionHelper, times(2)).rotate(any(NamedPasswordSecret.class));

      verify(secretEncryptionHelper).rotate(certificateSecret);
      verify(secretEncryptionHelper).rotate(certificateAuthority);
      verify(secretEncryptionHelper).rotate(passwordSecretUnsaved1);
      verify(secretEncryptionHelper).rotate(passwordSecretUnsaved2);

      verify(secretEncryptionHelper).rotate(passwordWithOldParameters1);
      verify(secretEncryptionHelper).rotate(passwordWithOldParameters2);
    });

    it("should save all the secrets and params that were encrypted with an old key", () -> {
      verify(secretDataService, times(6)).save(any(NamedSecret.class));

      verify(secretDataService).save(certificateSecret);
      verify(secretDataService).save(certificateAuthority);
      verify(secretDataService).save(passwordSecretUnsaved1);
      verify(secretDataService).save(passwordSecretUnsaved2);

      verify(secretDataService).save(passwordWithOldParameters1);
      verify(secretDataService).save(passwordWithOldParameters2);
    });
  }
}
