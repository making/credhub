package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedPasswordSecret;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateAuthorityDataServiceTest {
  private CertificateAuthorityDataService subject;
  private SecretDataService secretDataService;

  {
    beforeEach(() -> {
      secretDataService = mock(SecretDataService.class);
      subject = new CertificateAuthorityDataService(secretDataService);
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority();
        UUID uuid = UUID.randomUUID();

        when(secretDataService.save(certificateAuthority)).thenAnswer(
            invocation -> invocation.getArgumentAt(0, NamedCertificateAuthority.class)
            .setUuid(uuid)
        );

        certificateAuthority = subject.save(certificateAuthority);

        verify(secretDataService, times(1)).save(certificateAuthority);
        assertThat(certificateAuthority.getUuid(), equalTo(uuid));
      });
    });

    describe("#findMostRecent", () -> {
      describe("when the CA does not exist", () -> {
        it("should return null", () -> {
          when(secretDataService.findMostRecent("fake-ca")).thenReturn(null);

          assertThat(subject.findMostRecent("fake-ca"), equalTo(null));
        });
      });

      describe("when the match is a CA", () -> {
        it("should return the most recent record", () -> {
          NamedCertificateAuthority mostRecentCA = new NamedCertificateAuthority("fake-ca");
          when(secretDataService.findMostRecent("fake-ca")).thenReturn(mostRecentCA);

          assertThat(subject.findMostRecent("fake-ca"), equalTo(mostRecentCA));
        });
      });

      describe("when the match is a different type", () -> {
        it("should return null", () -> {
          NamedPasswordSecret mostRecentSecret = new NamedPasswordSecret("not-a-ca ");
          when(secretDataService.findMostRecent("not-a-ca")).thenReturn(mostRecentSecret);

          assertThat(subject.findMostRecent("not-a-ca"), equalTo(null));

        });
      });
    });

    describe("#findAllByName", () -> {
      describe("when there are no secrets with that name", () -> {
        it("should return an empty list", () -> {
          when(secretDataService.findAllByName("no-matches")).thenReturn(new ArrayList<>());

          assertThat(subject.findAllByName("no-matches").size(), equalTo(0));
        });
      });

      describe("when the name is really for CAs", () -> {
        it("should return all CAs with that name", () -> {
          NamedCertificateAuthority namedCertificateAuthority1 = new NamedCertificateAuthority("ca-match");
          NamedCertificateAuthority namedCertificateAuthority2 = new NamedCertificateAuthority("ca-match");

          when(secretDataService.findAllByName("ca-match"))
              .thenReturn(asList(namedCertificateAuthority1, namedCertificateAuthority2));

          assertThat(subject.findAllByName("ca-match").size(), equalTo(2));
          assertThat(subject.findAllByName("ca-match"), containsInAnyOrder(namedCertificateAuthority1, namedCertificateAuthority2));
        });
      });

      describe("when the name is for a different type", () -> {
        it("should return an empty list", () -> {
          NamedPasswordSecret secret1 = new NamedPasswordSecret("ca-match");
          NamedPasswordSecret secret2 = new NamedPasswordSecret("ca-match");

          when(secretDataService.findAllByName("bad-match"))
              .thenReturn(asList(secret1, secret2));

          assertThat(subject.findAllByName("bad-match").size(), equalTo(0));
        });
      });
    });

    describe("#findByUuid", () -> {
      describe("when there is no match with that UUID", () -> {
        it("should return null", () -> {
          String uuid = UUID.randomUUID().toString();
          when(secretDataService.findByUuid(uuid)).thenReturn(null);

          assertThat(subject.findByUuid(uuid), equalTo(null));
        });
      });

      describe("when the match with that UUID is a CA", () -> {
        it("should return null", () -> {
          String uuid = UUID.randomUUID().toString();
          NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority();
          when(secretDataService.findByUuid(uuid)).thenReturn(certificateAuthority);

          assertThat(subject.findByUuid(uuid), equalTo(certificateAuthority));
        });
      });

      describe("when the match with that UUID is not a CA", () -> {
        it("should return null", () -> {
          String uuid = UUID.randomUUID().toString();
          NamedPasswordSecret passwordSecret = new NamedPasswordSecret();
          when(secretDataService.findByUuid(uuid)).thenReturn(passwordSecret);

          assertThat(subject.findByUuid(uuid), equalTo(null));
        });
      });
    });
  }
}
