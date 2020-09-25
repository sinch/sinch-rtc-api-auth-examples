This repository contains examples for:

- Creating JWTs for user/client registration with Sinch Voice & Video SDKs. 
- How to verify client assertions (JWT bearer tokens) used in the Sinch Managed Push Notifications OAuth 2.0 flow.

# Creating JWT for user/client registration

For examples in _Java_, see [java/](./java/) and in particular [UserRegistrationToken.java](./java/src/main/java/com/sinch/rtc/examples/ocra/auth/UserRegistrationToken.java) and [UserRegistrationTokenTest.java](java/src/test/java/com/sinch/rtc/examples/ocra/auth/UserRegistrationTokenTest.java).

For examples in _Python_, see [python/](./python/) and in particular [create-registration-token.py](./python/create-registration-token.py). Also see [python/test.sh](./python/test.sh) for example of an expected output JWT given specific input.

# Validating JWT client assertions used in Sinch Managed Push Notifications OAuth 2.0 flow

For Huawei Push Messages, see [HmsOAuthFlowTokenValidator.java](java/src/main/java/com/sinch/rtc/examples/hms/HmsOAuthFlowTokenValidator.java) and [HmsOAuthJwtClientAssertionTest.java](java/src/test/java/com/sinch/rtc/examples/hms/HmsOAuthJwtClientAssertionTest.java)
