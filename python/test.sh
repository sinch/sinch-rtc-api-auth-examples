#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)"

function _assert_eq()
{
    if [ "$1" != "$2" ]; then
        echo "Expected: $1"
        echo "But was: $2"
        exit 1
    fi
}

OUTPUT="$(mktemp)"

set -x
python "${SCRIPT_DIR}/create-registration-token.py" \
       --application-key 'a32e5a8d-f7d8-411c-9645-9038e8dd051d' \
       --application-secret 'ax8hTTQJF0OPXL32r1LHMA==' \
       --user-id 'foo' \
       --nonce '6b438bda-2d5c-4e8c-92b0-39f20a94b34e' \
       --now '20180102T030405Z' \
       > "$OUTPUT"

EXPECTED='eyJhbGciOiJIUzI1NiIsImtpZCI6ImhrZGZ2MS0yMDE4MDEwMiJ9.eyJleHAiOjE1MTQ4NjI4NDUsImlhdCI6MTUxNDg2MjI0NSwiaXNzIjoiLy9ydGMuc2luY2guY29tL2FwcGxpY2F0aW9ucy9hMzJlNWE4ZC1mN2Q4LTQxMWMtOTY0NS05MDM4ZThkZDA1MWQiLCJub25jZSI6IjZiNDM4YmRhLTJkNWMtNGU4Yy05MmIwLTM5ZjIwYTk0YjM0ZSIsInN1YiI6Ii8vcnRjLnNpbmNoLmNvbS9hcHBsaWNhdGlvbnMvYTMyZTVhOGQtZjdkOC00MTFjLTk2NDUtOTAzOGU4ZGQwNTFkL3VzZXJzL2ZvbyJ9.10N-QAvRK0-dacox5X5YusK7C0AWb-kZLiNNTKLQw8I'
set +x

_assert_eq "$EXPECTED" "$(cat "$OUTPUT")" || exit 1
