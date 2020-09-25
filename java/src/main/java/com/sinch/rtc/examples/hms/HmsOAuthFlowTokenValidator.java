// Copyright 2020 Sinch AB

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.sinch.rtc.examples.hms;

import com.sinch.rtc.examples.jwt.JwtSigningKey;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Date;

/**
 * This class can be used to validate a JWT that is passed as an OAuth 2.0 client_assertion by Sinch
 * to your server as part of the Sinch Managed Push OAuth 2.0 Flow for Huawei Push Messages
 * (HMS/HPK).
 *
 * <p>See unit test <i>HmsOAuthJwtClientAssertionTest</i> for example usage.
 */
public class HmsOAuthFlowTokenValidator {

  private final SinchApplicationCredentialsResolver credentialsResolver;

  public HmsOAuthFlowTokenValidator(SinchApplicationCredentialsResolver credentialsResolver) {
    this.credentialsResolver = credentialsResolver;
  }

  /**
   * Validate a JWT that is passed as an OAuth 2.0 client_assertion by Sinch, to your OAuth 2.0
   * Authorization Server token endpoint, as part of the Sinch Managed Push OAuth 2.0 Flow for
   * Huawei Push Messages (HMS/HPK).
   */
  public boolean IsTokenValid(String clientAssertionJwt, OffsetDateTime now) {

    // 1. Use JWT header `kid` and claim `sub` to lookup (your) Sinch Application
    // Secret, which will be used to derive a signing key.
    // 2. Validate the JWT as a whole in terms of signing, `iat`, `exp`, `nonce` etc. Here we do
    // that using the io.jsonwebtoken library.
    // 3. Validate the Sinch specific claims for HMS OAuth flow, i.e. `scope`.

    Jws<Claims> jwt;
    try {

      jwt =
          Jwts.parserBuilder()
              .setSigningKeyResolver(new SinchSigningKeyResolver(this.credentialsResolver))
              .setClock(new FixedClock(now))
              .build()
              .parseClaimsJws(clientAssertionJwt);
    } catch (JwtException e) {
      return false;
    }

    // At this point, the JWT should be considered validated in terms
    // of signature and expiry.

    // If you require it necessary, you should at this point verify
    // that the nonce value from the claim `nonce` is not being
    // reused, but that is outside the scope of this example
    // implementation.

    Claims claims = jwt.getBody();

    return "https://push-api.cloud.huawei.com".equals(claims.get("scope"));
  }

  static class SinchSigningKeyResolver extends SigningKeyResolverAdapter {

    private final SinchApplicationCredentialsResolver credentialsResolver;

    public SinchSigningKeyResolver(SinchApplicationCredentialsResolver credentialsResolver) {
      this.credentialsResolver = credentialsResolver;
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwtHeader, Claims claims) {

      final OffsetDateTime issuedAt = JwtSigningKey.parseIssuedAtFromKeyId(jwtHeader.getKeyId());

      // The claim `sub` is expected to be your Sinch Application
      // Key. The JWT as a whole is still not validated but the `sub`
      // can be used to resolve the expected signing key (Sinch
      // Application Secret).

      String applicationSecretBase64 =
          credentialsResolver.resolveSinchApplicationSecret(claims.getSubject());

      if (applicationSecretBase64 == null) return null;

      byte[] applicationSecret = Base64.getDecoder().decode(applicationSecretBase64);

      return Keys.hmacShaKeyFor(JwtSigningKey.deriveSigningKey(applicationSecret, issuedAt));
    }
  }

  /** Adapter for io.jsonwebtoken.Clock so we can use pass a fixed timestamp in unit tests. */
  static class FixedClock implements Clock {
    private Date now;

    public FixedClock(OffsetDateTime now) {
      this.now = new Date(now.toInstant().toEpochMilli());
    }

    @Override
    public Date now() {
      return now;
    }
  }
}
