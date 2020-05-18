#!/usr/bin/env python
"""
Construct and sign a token (in the form of a a JWT) to authorize
registration for Sinch RTC clients.
"""
import os
import sys
import argparse
import uuid
import time
import datetime
import json
import base64
import hmac
import hashlib

def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def _new_nonce():
    return str(uuid.uuid4())

def _jwt_base64url_encode(v):
    # JWT RFC 7515 specifies that base64 encoding without padding should be used.
    # https://tools.ietf.org/html/rfc7515#appendix-C
    # https://tools.ietf.org/html/rfc4648#section-3.2
    return base64.urlsafe_b64encode(v).replace(b'=', b'')

def _jwt_json_encode(o):
    # Order JSON dicts to make it easier to compare final encoded JWT
    # string value to other implementations. NOTE: It is not
    # mandatory by the JWT spec to order the payload like this.
    return json.dumps(o, separators=(',', ':'), sort_keys=True)

def _jwt_datetime(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    return int((dt - epoch).total_seconds())

def _jwt_encode(o):
    return _jwt_base64url_encode(_jwt_json_encode(o))

def _jwt_sign_hs256(header, payload, key):
    data = header + "." + payload
    digest = _hmac_sha256(key, data)
    return _jwt_base64url_encode(digest)

def _jwt_signed_token(header, payload, signing_key):
    if(len(signing_key) < 32):
        raise ValueError('Invalid signing key (too short, must be >= 256 bit)')

    h = _jwt_encode(header)
    p = _jwt_encode(payload)
    s = _jwt_sign_hs256(h, p, signing_key)

    return h + "." + p + "." + s

def _derive_signing_key(input_key_material, issued_at):
    date_ymd = issued_at.strftime("%Y%m%d")
    return _hmac_sha256(input_key_material, date_ymd)

def _create_jwt(application_key,
                application_secret,
                user_id,
                nonce,
                issued_at,
                expire_at):

    secret = base64.standard_b64decode(application_secret)
    signing_key = _derive_signing_key(secret, issued_at)

    header = {
        "alg": "HS256",
        "kid": "hkdfv1-" + issued_at.strftime("%Y%m%d")
    }

    payload = {
        "iss": "//rtc.sinch.com/applications/" + application_key,
        "sub": "//rtc.sinch.com/applications/" + application_key + "/users/" + user_id,
        "iat": _jwt_datetime(issued_at),
        "exp": _jwt_datetime(expire_at),
        "nonce": nonce
    }

    return _jwt_signed_token(header, payload, signing_key)

def _main(args):
    if args.now:
        now = datetime.datetime.strptime(args.now, "%Y%m%dT%H%M%SZ")
    else:
        now = datetime.datetime.utcnow()

    token = _create_jwt(args.application_key,
                        args.application_secret,
                        args.user_id,
                        args.nonce,
                        now,
                        now + datetime.timedelta(seconds=args.token_ttl))

    print(token)

    return 0

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--application-key', type=str, required=True, help='Sinch Application Key')
    p.add_argument('--application-secret', type=str, required=True, help="Sinch Application Secret (base64-encoded)")
    p.add_argument('--user-id', type=str, required=True, help='User ID, e.g. \'foo\'')
    p.add_argument('--nonce', type=str, default=_new_nonce(), help='A cryptographic nonce')
    p.add_argument('--now', type=str, help="Simulate current time, in UTC, ISO 8601 basic format. Example value: '20180102T030405Z'. Value is used as `iat`.")
    p.add_argument('--token-ttl', type=int, default=600, help="Token TTL in seconds. Affects `exp`, i.e. `exp` := `iat` + TTL.")

    sys.exit(_main(p.parse_args(sys.argv[1:])))
