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

package com.sinch.rtc.examples.ocra.auth;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.SecretKey;

/**
 * This class can be used to construct and sign a token (in the form of a <a
 * href="https://jwt.io/">JWT</a>) to authorize <i>User</i> registration for <i>Sinch RTC</i>
 * clients.
 *
 * <p>A <a href="https://jwt.io/">JWT</a> to authorize <i>User</i> registration is issued by a
 * <i>Sinch Application</i>, and signed with a signing key that is derived from the <i>Sinch
 * Application Secret</i>.
 *
 * <p>See unit test <i>UserRegistrationTokenTest</i> for example usage.
 */
public class UserRegistrationToken {

  private String applicationKey;
  private byte[] applicationSecret;
  private String userId;
  private String nonce;
  private OffsetDateTime issuedAt;
  private OffsetDateTime expiresAt;
  private OffsetDateTime instanceExpiresAt;

  /**
   * Construct a User registration token.
   *
   * @param applicationKey <i>Sinch Application Key</i>
   * @param applicationSecret <i>Sinch Application Secret</i> (in base64-encoded format)
   * @param userId User ID
   * @param nonce <a href="https://en.wikipedia.org/wiki/Cryptographic_nonce">Cryptographic
   *     nonce</a> (will be used as JWT claim <i>nonce</i>). Should be unique per token.
   * @param issuedAt Time when token is issued/created. Also see JWT claim <a
   *     href="https://tools.ietf.org/html/rfc7519#section-4.1">iat</a>.
   * @param expiresAt Time after which token should be considered expired. Also see JWT claim <a
   *     href="https://tools.ietf.org/html/rfc7519#section-4.1">exp</a>.
   * @param instanceExpiresAt Time after which the User/client registration for which this token
   *     will be authorizing should be considered expired. This may be <code>null</code>, and if it
   *     is <code>null</code> then the <i>User</i>/client registration will be valid forever (or
   *     until the <i>User</i>/client is explicitly blocked). The term <i>instance</i> here refers
   *     to an <i>Instance</i> of a Sinch RTC SDK client that is acting on behalf of a <i>User</i>.
   */
  public UserRegistrationToken(
      String applicationKey,
      String applicationSecret,
      String userId,
      String nonce,
      OffsetDateTime issuedAt,
      OffsetDateTime expiresAt,
      OffsetDateTime instanceExpiresAt) {
    if (null == applicationKey) throw new IllegalArgumentException("applicationKey");
    if (null == applicationSecret) throw new IllegalArgumentException("applicationSecret");
    if (applicationSecret.length() < 1) throw new IllegalArgumentException("applicationSecret");
    if (null == userId) throw new IllegalArgumentException("userId");
    if (null == nonce) throw new IllegalArgumentException("nonce");
    if (null == issuedAt) throw new IllegalArgumentException("issuedAt");
    if (null == expiresAt) throw new IllegalArgumentException("expiresAt");

    this.applicationKey = applicationKey;
    this.applicationSecret = Base64.getDecoder().decode(applicationSecret);
    this.userId = userId;
    this.nonce = nonce;
    this.issuedAt = issuedAt;
    this.expiresAt = expiresAt;
    this.instanceExpiresAt = instanceExpiresAt;
  }

  public UserRegistrationToken(
      String applicationKey,
      String applicationSecret,
      String userId,
      String nonce,
      OffsetDateTime issuedAt,
      OffsetDateTime expiresAt) {
    this(applicationKey, applicationSecret, userId, nonce, issuedAt, expiresAt, null);
  }

  /**
   * Build and sign token and as a JWT.
   *
   * @return A JWT.
   */
  public String toJwt() {
    // NOTE: The reason a TreeMap is used for the JWT claims here is
    // that it maintains ordering of its keys, which means it
    // simplifies comparing the JWT output against expected output in
    // a deterministic manner. I.e it simplifies expected output in
    // unit tests and also simplifies comparison of exact output
    // across different implementations.  Here we also specify header
    // params `alg`, `typ` and `kid` explicitly to ensure presence and
    // order (for the same reason of comparision)

    SignatureAlgorithm alg = SignatureAlgorithm.HS256;

    Map<String, Object> claims = new TreeMap<String, Object>();
    claims.put("iss", "//rtc.sinch.com/applications/" + applicationKey);
    claims.put("sub", "//rtc.sinch.com/applications/" + applicationKey + "/users/" + userId);
    claims.put("iat", issuedAt.toEpochSecond());
    claims.put("exp", expiresAt.toEpochSecond());
    claims.put("nonce", nonce);
    if (instanceExpiresAt != null)
      claims.put("sinch:rtc:instance:exp", instanceExpiresAt.toEpochSecond());

    JwtBuilder builder =
        Jwts.builder()
            .setHeaderParam("alg", alg.getValue())
            .setHeaderParam("typ", "JWT")
            .setHeaderParam("kid", JwtSigningKey.keyId(issuedAt))
            .setClaims(claims);

    SecretKey signingKey =
        Keys.hmacShaKeyFor(JwtSigningKey.deriveSigningKey(applicationSecret, issuedAt));

    return builder.signWith(signingKey, alg).compact();
  }
}
