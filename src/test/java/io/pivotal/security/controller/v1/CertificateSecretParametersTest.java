package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(Spectrum.class)
public class CertificateSecretParametersTest {

  // Make sure self-signed works
    // make sure however we detect self-signed is secure (check signature?)
    // make sure a regenerated self-signed cert is self-signed
  // These tests don't test a CA, they only test self-signed
    // Make sure a regenerated cert is resigned by the original ca
  // We don't test duration carrying over from the original cert
  // These tests don't tests regenerating a CA itself (future story #137497811)


  /**
   * Subject Name: O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa
   * Duration: 30 days
   * Key Length: 4096
   * Alternative Names: SolarSystem
   * Extended Key Usage: server_auth, client_auth
   * Key Usage: digital_signature
   */
  public static final String BIG_TEST_CERT = "-----BEGIN CERTIFICATE-----\n" +
      "MIIEbzCCA1egAwIBAgIUYE3pB+BUaAP0YHeofpCmI/xCkmYwDQYJKoZIhvcNAQEL\n" +
      "BQAwDjEMMAoGA1UEAwwDZm9vMB4XDTE3MDIwMzAxNDMzNloXDTE3MDMwNTAxNDMz\n" +
      "NlowfDERMA8GA1UECgwIdGVzdC1vcmcxEDAOBgNVBAgMB0p1cGl0ZXIxETAPBgNV\n" +
      "BAYTCE1pbGt5V2F5MRkwFwYDVQQDDBB0ZXN0LWNvbW1vbi1uYW1lMRYwFAYDVQQL\n" +
      "DA10ZXN0LW9yZy11bml0MQ8wDQYDVQQHDAZFdXJvcGEwggIiMA0GCSqGSIb3DQEB\n" +
      "AQUAA4ICDwAwggIKAoICAQCk+byx2uL5QNAQqdeEWoD0NfuXdbtf/j7orjK7TjCn\n" +
      "djM21HLnIq96hZ+/Vxg30oxjRqAMKDUIj8OTrisorgcgpLNV7NwklPG9A0gv7xdk\n" +
      "YvxhnEnyrztZYiS8sx98YDwjQpJDeA45QX6+/9k8qmXf7XRQRRTqhkG8jpkk0vvj\n" +
      "hvwwTAma+0xALWfVBnhLJz82snJI+ezM9OuwO53iOkziNHNxtuc5sq/AjuDf48O4\n" +
      "HOtxdB27WniL0T3+4Ng8ZRAgMmlSrQdFn6x/Us32VTVLTD4x1s9H4HL3c8LZJaoD\n" +
      "CEKIwFRn2lSko4b4PAUGHZ0KpfeTlur0uR464s4PHh+EV1DOm/R/1/HIQgKanr5B\n" +
      "FzLONAqFPPCMB/hTPli+Q6nez+Q2alpyxEz/QTCTNROKl+opVWJW6gAPMXAkpqc2\n" +
      "bx0O7fRwwF9evVcQ1BZdfWaG3iGqO60o0y7lEAmvlOwnw0JjSta2NDlR0nNp9frx\n" +
      "85USPdMoSBoaAGb+BehbvFsVoRTToxCo0YwCDcGjgacR4oCu5zTZd0KUVlGJ0vpu\n" +
      "OJiUALyYSD/6mN8ZIfPa/rR8PF5ju3JzGd/AEh0F8gfgardLrNHre904/0HwBqvc\n" +
      "ShdSS0XHjA7nTLAyARgLU/E0TIL9DH63tWrB2W+m7vBMkU0fuY5c40QIalT/iGbj\n" +
      "8QIDAQABo1cwVTAWBgNVHREEDzANggtTb2xhclN5c3RlbTAOBgNVHQ8BAf8EBAMC\n" +
      "B4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw\n" +
      "DQYJKoZIhvcNAQELBQADggEBAF6cvPlK7kuoC/EBmTF4OdTrqzKYa4bm47hn0e7V\n" +
      "3fmgt5YJl/HM/wQI5Dw37y5SjtCScvZUJQ7N+vKQ06bPJHea8f3+XwgsM0JpUhkV\n" +
      "djZR9L5LrJdwmhk4arbMLMKeFwB1Xir72trL1DreI/Kzsow0LbMhllLWPyRHmAhr\n" +
      "Kqu/WgGim6m3lVgZdx4o6cguGry+ceiunCwCFL36CL1AdvYL8ZnUlQDT1hNp3anE\n" +
      "QTHPRc0mETzHET0uL+9UpaUxglRPzuxVhyIYimXSiPQlk8K43gmXM8QKi85eo8xD\n" +
      "W5kgC9Eel5YQcs5wUS/1aW72x2D+7DeGxLjFwm0Sy9S8hfI=\n" +
      "-----END CERTIFICATE-----";

  /**
   * Subject Name: CN=foo.example.com
   * Duration: 1 year
   * Key Length: 2048
   */
  public static final String SIMPLE_TEST_CERT = "-----BEGIN CERTIFICATE-----\n" +
    "MIIC0jCCAbqgAwIBAgIUW6HcroJaHBMF2VK/6z13iBnNxeAwDQYJKoZIhvcNAQEL\n" +
    "BQAwGjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMB4XDTE3MDIwNjIwMDAyN1oX\n" +
    "DTE4MDIwNjIwMDAyN1owGjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMIIBIjAN\n" +
    "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyy+c0ZPNPmGBzkiC+XzMJkbgJFK7\n" +
    "2BNgLpzI1AmqFBMBs7dSfxypS7qTfAEUQ1HMY2S9/odhslEUIyBVPguonk++WvGw\n" +
    "w6P49d3GPK6beyrw+FobBkVWJ64qRZIUJlRanFzs1yGnRJ2omHgJ03sTYiL4t8wt\n" +
    "Cm9po3gp7QwGXQ2Ol1QEadH095WBdwkN0Wo7WF/4+Fz7cACCBZNQoSYmT3uREH9S\n" +
    "iVur6H4WLsPEs5QBV+o9204qVZh0er+/LEwzuqZD97gppLVdYk673R2Kje4Gc6mz\n" +
    "Y61oKlQzSQXPsA1Sx7dOUgMGtzhRrFgUE1WzvTqiDVQB9dEsn1JILJWA7wIDAQAB\n" +
    "oxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQANE8zWwdjCEmOw\n" +
    "+wbqVR3RyL1P2T0eQI1ML/epxVNLRoAKihs2ypKFLpLC9P7mucsHxl4FY/pzXOJo\n" +
    "i0PEG/ZCapRunC3XVwxGUZos2ytPIebyshlp4eRTyuch7ei3aTO2cLrLsgWZxyxc\n" +
    "i5JveF8PvPZkOR5qzq6P7dMpQde3nL8/kLRwp7aSE8OAKoeyhEDCy+e9lPh9+Q/g\n" +
    "36dvhRfyD3PUifLC1A6usOedplxEJpf5hNlyVljTXRZXRijltHIxsp2vf8vzSLO4\n" +
    "zam9Ke7B5YU8lRd5PlyFXDp+vEJ4HaX8FMtUthLvvDQ7l9UOR7r2rf3hfggxC7/s\n" +
    "s2smQYqB\n" +
    "-----END CERTIFICATE-----";

  private CertificateSecretParameters certificateSecretParameters;

  {
    describe("when not given a certificate string", () -> {
      it("constructs DN string correctly from parameters", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .setCountry("My Country")
            .setState("My State")
            .setOrganization("My Organization")
            .setOrganizationUnit("My Organization Unit")
            .setCommonName("My Common Name")
            .setLocality("My Locality");

        assertThat(
            params.getDN().toString(),
            equalTo("O=My Organization,ST=My State,C=My Country,CN=My Common Name,OU=My Organization Unit,L=My Locality")
        );
      });

      it("can add alternative names", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .addAlternativeNames("alternative-name-1", "alternative-name-2");

        ASN1Sequence sequence = ASN1Sequence.getInstance(params.getAlternativeNames());
        assertThat(sequence.getObjectAt(0), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-1")));
        assertThat(sequence.getObjectAt(1), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-2")));
      });

      it("can add extended key usages", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .addExtendedKeyUsage("server_auth", "client_auth", "code_signing", "email_protection", "time_stamping");

        ExtendedKeyUsage extendedKeyUsages = ExtendedKeyUsage.getInstance(params.getExtendedKeyUsage());
        assertThat(extendedKeyUsages.getUsages()[0], equalTo(KeyPurposeId.id_kp_serverAuth));
        assertThat(extendedKeyUsages.getUsages()[1], equalTo(KeyPurposeId.id_kp_clientAuth));
        assertThat(extendedKeyUsages.getUsages()[2], equalTo(KeyPurposeId.id_kp_codeSigning));
        assertThat(extendedKeyUsages.getUsages()[3], equalTo(KeyPurposeId.id_kp_emailProtection));
        assertThat(extendedKeyUsages.getUsages()[4], equalTo(KeyPurposeId.id_kp_timeStamping));
      });

      it("validates extended key usages", () -> {
        try {
          new CertificateSecretParameters().
              setCountry("My Country")
              .addExtendedKeyUsage("client_auth", "server_off");
          fail();
        } catch (ParameterizedValidationException pve) {
          assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_extended_key_usage"));
          assertThat(pve.getParameters()[0], equalTo("server_off"));
        }
      });

      it("can add key usages", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .setCountry("My Country")
            .addKeyUsage(
                "digital_signature",
                "non_repudiation",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
                "key_cert_sign",
                "crl_sign",
                "encipher_only",
                "decipher_only"
            );

        KeyUsage keyUsages = KeyUsage.getInstance(params.getKeyUsage());
        assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));

        params = new CertificateSecretParameters()
            .setCountry("My Country")
            .addKeyUsage("digital_signature", "non_repudiation", "decipher_only");

        keyUsages = KeyUsage.getInstance(params.getKeyUsage());
        assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));
      });

      it("validates key usages", () -> {
        try {
          new CertificateSecretParameters()
              .setCountry("My Country")
              .addKeyUsage("key_agreement", "digital_sinnature");
          fail();
        } catch (ParameterizedValidationException pve) {
          assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_key_usage"));
          assertThat(pve.getParameters()[0], equalTo("digital_sinnature"));
        }
      });

      it("sets default duration to 365 days", () -> {
        assertThat(new CertificateSecretParameters().getDurationDays(), equalTo(365));
      });

      it("sets default key length to 2048 bits", () -> {
        assertThat(new CertificateSecretParameters().getKeyLength(), equalTo(2048));
      });

      itThrowsWithMessage("when duration is less than 1", ParameterizedValidationException.class, "error.invalid_duration", () -> {
        new CertificateSecretParameters()
            .setCommonName("foo")
            .setDurationDays(0)
            .validate();
      });

      itThrowsWithMessage("when duration is greater than 3650", ParameterizedValidationException.class, "error.invalid_duration", () -> {
        new CertificateSecretParameters()
            .setCommonName("foo")
            .setDurationDays(3651)
            .validate();
      });

      itThrowsWithMessage("when all of DN parameters are empty", ParameterizedValidationException.class, "error.missing_certificate_parameters", () -> {
        new CertificateSecretParameters()
            .setOrganization("")
            .setState("")
            .setCountry("")
            .setCommonName("")
            .setOrganizationUnit("")
            .setLocality("").validate();
      });

      describe("when key lengths are invalid", () -> {
        itThrowsWithMessage("when key length is less than 2048", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(1024)
              .validate();
        });

        itThrowsWithMessage("when key length is between 2048 and 3072", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(2222)
              .validate();
        });

        itThrowsWithMessage("when key length is greater than 4096", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(9192)
              .validate();
        });
      });
    });

    describe("when given a certificate string", () -> {
      describe("when it is a self-signed certificate", () -> {
        beforeEach(() -> {
          Security.addProvider(new BouncyCastleProvider());
          certificateSecretParameters = new CertificateSecretParameters(BIG_TEST_CERT, "my-name", "my-name");
        });

        afterEach(() -> {
          Security.removeProvider("BC");
        });

        it("should correctly parse the DN name", () -> {
          assertThat(certificateSecretParameters.getDN().toString(),
              equalTo("O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa"));
        });

        it("should set the certificate's key length", () -> {
          assertThat(certificateSecretParameters.getKeyLength(), equalTo(4096));
        });

        it("sets alternative names", () -> {
          assertThat(
            certificateSecretParameters.getAlternativeNames(),
              equalTo(new GeneralNames(new GeneralName(GeneralName.dNSName, "SolarSystem")))
          );
        });

        it("sets extended key usage", () -> {
          assertThat(
              asList(certificateSecretParameters.getExtendedKeyUsage().getUsages()),
              containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth)
          );
        });

        it("sets key usage", () -> {
          assertThat(
            certificateSecretParameters.getKeyUsage().hasUsages(KeyUsage.digitalSignature),
              equalTo(true)
          );
        });

        it("sets duration", () -> {
          assertThat(
            certificateSecretParameters.getDurationDays(),
              equalTo(30)
          );
        });

        it("sets self-sign", () -> {
          assertThat(
            certificateSecretParameters.getSelfSign(),
              equalTo(true)
          );
        });

        it("sets CA name", () -> {
          assertThat(
            certificateSecretParameters.getCaName(),
              equalTo("my-name")
          );
        });

        describe("when given a very simple certificate", () -> {
          beforeEach(() -> {
            certificateSecretParameters = new CertificateSecretParameters(SIMPLE_TEST_CERT, "another-name", "another-name");
          });

          it("should correctly parse the DN name", () -> {
            assertThat(certificateSecretParameters.getDN().toString(),
              equalTo("CN=foo.example.com"));
          });

          it("should set the certificate's key length", () -> {
            assertThat(certificateSecretParameters.getKeyLength(), equalTo(2048));
          });

          it("has no alternative names", () -> {
            assertThat(
              certificateSecretParameters.getAlternativeNames(),
              equalTo(null)
            );
          });

          it("has no extended key usages", () -> {
            assertThat(
              certificateSecretParameters.getExtendedKeyUsage(),
              equalTo(null)
            );
          });

          it("has no key usages", () -> {
            assertThat(
              certificateSecretParameters.getKeyUsage(),
              equalTo(null)
            );
          });

          it("sets duration", () -> {
            assertThat(
              certificateSecretParameters.getDurationDays(),
              equalTo(360)
            );
          });

          it("sets self-sign", () -> {
            assertThat(
              certificateSecretParameters.getSelfSign(),
              equalTo(true)
            );
          });

          it("sets CA name", () -> {
            assertThat(
              certificateSecretParameters.getCaName(),
              equalTo("my-name")
            );
          });
        });
      });
    });
  }
}
