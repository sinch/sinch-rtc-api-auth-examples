package com.sinch.rtc.examples.ocra.auth;

import static org.junit.Assert.assertEquals;

import com.sinch.rtc.examples.ReferenceData;
import java.time.OffsetDateTime;
import org.junit.*;

public class UserRegistrationTokenTest {

  @Test
  public void testReferenceToken() {

    OffsetDateTime now = ReferenceData.NOW;
    // Let JWT be valid for 10 minutes.
    OffsetDateTime tokenExpireAt = now.plusSeconds(600);

    UserRegistrationToken token =
        new UserRegistrationToken(
            ReferenceData.APPLICATION_KEY,
            ReferenceData.APPLICATION_SECRET,
            ReferenceData.EXTERNAL_USER_ID,
            ReferenceData.JWT_NONCE,
            now,
            tokenExpireAt);

    final String expected =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6ImhrZGZ2MS0yMDE4MDEwMiJ9.eyJleHAiOjE1MTQ4NjI4NDUsImlhdCI6MTUxNDg2MjI0NSwiaXNzIjoiLy9ydGMuc2luY2guY29tL2FwcGxpY2F0aW9ucy9hMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQiLCJub25jZSI6IjZiNDM4YmRhLTJkNWMtNGU4Yy05MmIwLTM5ZjIwYTk0YjM0ZSIsInN1YiI6Ii8vcnRjLnNpbmNoLmNvbS9hcHBsaWNhdGlvbnMvYTMyZTVhOGQtZjdkOC00MTFjLTk2NDUtOTAzOGU4ZGQwNTFkL3VzZXJzL2ZvbyJ9.10N-QAvRK0-dacox5X5YusK7C0AWb-kZLiNNTKLQw8I";

    assertEquals(expected, token.toJwt());
  }

  @Test
  public void testReferenceToken_InstanceTtl() {

    OffsetDateTime now = ReferenceData.NOW;
    // Let JWT be valid for 10 minutes.
    OffsetDateTime tokenExpireAt = now.plusSeconds(600);
    // Let the User registration be valid for 180 days.
    OffsetDateTime registrationExpiresAt = now.plusDays(180);

    UserRegistrationToken token =
        new UserRegistrationToken(
            ReferenceData.APPLICATION_KEY,
            ReferenceData.APPLICATION_SECRET,
            ReferenceData.EXTERNAL_USER_ID,
            ReferenceData.JWT_NONCE,
            now,
            tokenExpireAt,
            registrationExpiresAt);

    final String expected =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6ImhrZGZ2MS0yMDE4MDEwMiJ9.eyJleHAiOjE1MTQ4NjI4NDUsImlhdCI6MTUxNDg2MjI0NSwiaXNzIjoiLy9ydGMuc2luY2guY29tL2FwcGxpY2F0aW9ucy9hMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQiLCJub25jZSI6IjZiNDM4YmRhLTJkNWMtNGU4Yy05MmIwLTM5ZjIwYTk0YjM0ZSIsInNpbmNoOnJ0YzppbnN0YW5jZTpleHAiOjE1MzA0MTQyNDUsInN1YiI6Ii8vcnRjLnNpbmNoLmNvbS9hcHBsaWNhdGlvbnMvYTMyZTVhOGQtZjdkOC00MTFjLTk2NDUtOTAzOGU4ZGQwNTFkL3VzZXJzL2ZvbyJ9.Z1KlXha3ubMWjMI2z949NkUHmekpe31z0fNx-XiMDuo";

    assertEquals(expected, token.toJwt());
  }
}
