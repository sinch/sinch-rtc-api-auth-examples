package com.sinch.rtc.examples.ocra.auth;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;

public class ReferenceData {
  public static final String APPLICATION_KEY = "a32e5a8d-f7d8-411c-9645-9038e8dd051d";

  public static final byte[] APPLICATION_SECRET =
      Base64.getDecoder().decode("ax8hTTQJF0OPXL32r1LHMA==");

  public static final OffsetDateTime NOW =
      OffsetDateTime.of(2018, 1, 2, 3, 4, 5, 0, ZoneOffset.UTC);

  public static final String EXTERNAL_USER_ID = "foo";

  public static final String JWT_NONCE = "6b438bda-2d5c-4e8c-92b0-39f20a94b34e";
}
