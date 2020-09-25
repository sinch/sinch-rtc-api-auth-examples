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

package com.sinch.rtc.examples.jwt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** This class is used to derive a <i>JWT</i> signing key from a <i>Sinch Application Secret</i>. */
public class JwtSigningKey {

  private static DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

  public static String formatDate(OffsetDateTime dt) {
    return dt.format(DATE_FORMATTER);
  }

  public static String keyId(OffsetDateTime issuedAt) {
    return "hkdfv1-" + formatDate(issuedAt);
  }

  public static OffsetDateTime parseIssuedAtFromKeyId(String kid) {
    if (!kid.startsWith("hkdfv1-"))
      throw new IllegalArgumentException("Invalid key id ('kid'), expected prefix 'hkdfv1-'");

    LocalDate utcDate = LocalDate.parse(kid.substring("hkdfv1-".length()), DATE_FORMATTER);

    return utcDate.atStartOfDay(ZoneId.of("Z")).toOffsetDateTime();
  }

  /**
   * @param applicationSecret <i>Sinch Application Secret</i> (in base64-encoded format)
   * @param issuedAt Time when signing key is issued/created.
   * @return A derived signing secret key.
   */
  public static byte[] deriveSigningKey(String applicationSecret, OffsetDateTime issuedAt) {
    return deriveSigningKey(Base64.getDecoder().decode(applicationSecret), issuedAt);
  }

  public static byte[] deriveSigningKey(byte[] applicationSecret, OffsetDateTime issuedAt) {
    return hmacSha256(applicationSecret, formatDate(issuedAt));
  }

  private static byte[] hmacSha256(byte[] key, String message) {
    if (null == key || key.length == 0)
      throw new IllegalArgumentException("Invaid input key to HMAC-256");

    if (null == message)
      throw new IllegalArgumentException("Input message to HMAC-256 must not be null");

    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
      mac.init(keySpec);
      return mac.doFinal(message.getBytes("UTF-8"));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (InvalidKeyException e) {
      throw new RuntimeException(e);
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}
