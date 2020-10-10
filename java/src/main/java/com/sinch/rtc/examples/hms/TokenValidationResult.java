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

public final class TokenValidationResult {
  private final boolean valid;
  private final String sinchApplicationKey;
  private final String hmsApplicationId;

  public boolean isValid() {
    return this.valid;
  }

  public String getSinchApplicationKey() {
    return this.sinchApplicationKey;
  }

  public String getHmsApplicationId() {
    return this.hmsApplicationId;
  }

  private TokenValidationResult(String applicationKey, String hmsApplicationId) {
    this.valid = true;
    this.sinchApplicationKey = applicationKey;
    this.hmsApplicationId = hmsApplicationId;
  }

  private TokenValidationResult() {
    this.valid = false;
    this.sinchApplicationKey = null;
    this.hmsApplicationId = null;
  }

  static final TokenValidationResult Valid(String applicationKey, String hmsApplicationId) {
    return new TokenValidationResult(applicationKey, hmsApplicationId);
  }

  static final TokenValidationResult Invalid = new TokenValidationResult();
}
