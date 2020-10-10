package com.sinch.rtc.examples.hms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.sinch.rtc.examples.ReferenceData;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.*;

/**
 * This test examplifies how to validate a JWT token provided to you by Sinch as part of the Huawei
 * HMS/HPK OAuth flow.
 *
 * <p>The JWT token specified in the examples below is what will be provided by Sinch, to your
 * server, in an OAuth access token request using grant_type=client_credentials and
 * client_assertion_type=urn:bietf:params:oauth:client-assertion-type:jwt-bearer.
 */
public class HmsOAuthJwtClientAssertionTest {

  private final CredentialsProvider credentialsProvider;

  public HmsOAuthJwtClientAssertionTest() {
    credentialsProvider = new CredentialsProvider();
  }

  @Test
  public void testValidateReferenceToken() {

    // Add mapping for your Sinch Application Key and Secret.
    credentialsProvider.add(ReferenceData.APPLICATION_KEY, ReferenceData.APPLICATION_SECRET);

    HmsOAuthFlowTokenValidator validator = new HmsOAuthFlowTokenValidator(credentialsProvider);

    // (This token is pre-generated based input as specified in ReferenceData)
    final String clientAssertionJwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrZGZ2MS0yMDE4MDEwMiIsInNpbmNoOnJ0YzphcHBsaWNhdGlvbl9rZXkiOiJhMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQifQ.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MDgwL3NpbmNoL3J0Yy9wdXNoL29hdXRoMi92MS9odWF3ZWktaG1zL3Rva2VuIiwiZXhwIjoxNTE0ODY1ODQ1LCJpYXQiOjE1MTQ4NjIyNDUsImlzcyI6Ii8vcnRjLnNpbmNoLmNvbS9hcHBsaWNhdGlvbnMvYTMyZTVhOGQtZjdkOC00MTFjLTk2NDUtOTAzOGU4ZGQwNTFkIiwibm9uY2UiOiI2YjQzOGJkYS0yZDVjLTRlOGMtOTJiMC0zOWYyMGE5NGIzNGUiLCJzY29wZSI6Imh0dHBzOi8vcHVzaC1hcGkuY2xvdWQuaHVhd2VpLmNvbSIsInNpbmNoOnJ0YzphcHBsaWNhdGlvbl9rZXkiOiJhMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQiLCJzdWIiOiIxMjM0NTY3ODkifQ.xOoYQZZ9W1EZE96BdsRbxzqIPdkVhXhAO5XE9ZD5WI8";

    TokenValidationResult result = validator.Validate(clientAssertionJwt, ReferenceData.NOW);

    assertTrue(result.isValid());
    assertEquals(ReferenceData.APPLICATION_KEY, result.getSinchApplicationKey());
    assertEquals(ReferenceData.HMS_APP_ID, result.getHmsApplicationId());
  }

  @Test
  public void testValidateReferenceToken_invalidApplicationSecret() {

    // Add mapping for your Sinch Application Key, but a different secret than the JWT has been
    // signed with (this is negative test case).
    credentialsProvider.add(ReferenceData.APPLICATION_KEY, Base64(RandomBytes(32)));

    HmsOAuthFlowTokenValidator validator = new HmsOAuthFlowTokenValidator(credentialsProvider);

    // (This token is pre-generated based input as specified in ReferenceData)
    final String clientAssertionJwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrZGZ2MS0yMDE4MDEwMiIsInNpbmNoOnJ0YzphcHBsaWNhdGlvbl9rZXkiOiJhMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQifQ.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo4MDgwL3NpbmNoL3J0Yy9wdXNoL29hdXRoMi92MS9odWF3ZWktaG1zL3Rva2VuIiwiZXhwIjoxNTE0ODY1ODQ1LCJpYXQiOjE1MTQ4NjIyNDUsImlzcyI6Ii8vcnRjLnNpbmNoLmNvbS9hcHBsaWNhdGlvbnMvYTMyZTVhOGQtZjdkOC00MTFjLTk2NDUtOTAzOGU4ZGQwNTFkIiwibm9uY2UiOiI2YjQzOGJkYS0yZDVjLTRlOGMtOTJiMC0zOWYyMGE5NGIzNGUiLCJzY29wZSI6Imh0dHBzOi8vcHVzaC1hcGkuY2xvdWQuaHVhd2VpLmNvbSIsInNpbmNoOnJ0YzphcHBsaWNhdGlvbl9rZXkiOiJhMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQiLCJzdWIiOiIxMjM0NTY3ODkifQ.xOoYQZZ9W1EZE96BdsRbxzqIPdkVhXhAO5XE9ZD5WI8";

    TokenValidationResult result = validator.Validate(clientAssertionJwt, ReferenceData.NOW);

    assertFalse(result.isValid());
  }

  private class CredentialsProvider implements SinchApplicationCredentialsResolver {
    // Map Sinch Application Key to Sinch Application Secret.
    private final Map<String, String> credentials;

    public CredentialsProvider() {
      this.credentials = new HashMap<String, String>();
    }

    public void add(String applicationKey, String applicationSecret) {
      credentials.put(applicationKey, applicationSecret);
    }

    public String resolveSinchApplicationSecret(String applicationKey) {
      return credentials.get(applicationKey);
    }
  }

  private static byte[] RandomBytes(int length) {
    byte[] buffer = new byte[length];
    new SecureRandom().nextBytes(buffer);
    return buffer;
  }

  private static String Base64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }
}
