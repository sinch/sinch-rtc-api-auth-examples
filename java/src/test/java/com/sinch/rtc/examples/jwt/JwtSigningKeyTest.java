package com.sinch.rtc.examples.jwt;

import static org.junit.Assert.assertEquals;

import com.sinch.rtc.examples.ReferenceData;
import java.time.OffsetDateTime;
import java.util.Base64;
import org.junit.*;

public class JwtSigningKeyTest {

  @Test
  public void testDeriveSigningKey() {
    OffsetDateTime issuedAt = ReferenceData.NOW;
    byte[] signingKey = JwtSigningKey.deriveSigningKey(ReferenceData.APPLICATION_SECRET, issuedAt);

    assertEquals(32, signingKey.length);
    assertEquals(
        "AZj5EsS8S7wb06xr5jERqPHsraQt3w/+Ih5EfrhisBQ=",
        Base64.getEncoder().encodeToString(signingKey));
  }

  @Test
  public void testKeyId() {
    assertEquals("hkdfv1-20180102", JwtSigningKey.keyId(ReferenceData.NOW));
  }
}
