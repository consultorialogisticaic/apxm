#!/usr/bin/env bash
# Attach a GitHub OIDC proof of origin to an image push-image.sh pushed.
#
#   attest-image.sh ARTIFACT DIGEST
#
# The proof is a token whose audience is <AUDIENCE_PREFIX>:<digest>, attached to the
# image in the registry as an OCI artifact of type application/vnd.hostplane.ci-oidc.v1+jwt.
# The platform's promoter reads it to learn that this repository's main workflow built
# these bytes. Needs `permissions: id-token: write` and the registry credential in the
# runner's Docker configuration, so it runs only on the publishing runner.
#
#   AUDIENCE_PREFIX  the platform's audience prefix (a repository variable, not a secret)
set -euo pipefail

ORAS_VERSION=1.3.6
ORAS_SHA256_AMD64=66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0
ATTESTATION_TYPE=application/vnd.hostplane.ci-oidc.v1+jwt

die() {
  echo "attest-image: $*" >&2
  exit 1
}

[ $# -eq 2 ] || die "usage: attest-image.sh ARTIFACT DIGEST"
artifact=$1
digest=$2
[[ $artifact =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || die "invalid artifact name: $artifact"
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "invalid digest: $digest"
[[ ${AUDIENCE_PREFIX:-} =~ ^[A-Za-z0-9._-]+$ ]] || die "AUDIENCE_PREFIX must be set to the platform's audience prefix"
[[ ${GITHUB_EVENT_NAME:-} == push && ${GITHUB_REF:-} == refs/heads/main ]] \
  || die "attestations are made only from a push to main"
[[ -n ${ACTIONS_ID_TOKEN_REQUEST_URL:-} && -n ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]] \
  || die "the job needs permissions: id-token: write"
[[ $ACTIONS_ID_TOKEN_REQUEST_URL == https://* ]] || die "the token request URL is not https"
# Both go into a curl config file, where a quote, backslash or space would change its meaning.
[[ ${ACTIONS_ID_TOKEN_REQUEST_URL}${ACTIONS_ID_TOKEN_REQUEST_TOKEN} != *[\"\\[:space:]]* ]] \
  || die "the token request URL or credential holds a quote, backslash or space"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

[ "$(uname -m)" = x86_64 ] || die "the pinned oras build is linux amd64 only"
tarball="$scratch/oras.tar.gz"
curl -sSfL --proto '=https' --tlsv1.2 -o "$tarball" \
  "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz"
actual=$(sha256sum "$tarball" | cut -d' ' -f1)
[ "$actual" = "$ORAS_SHA256_AMD64" ] || die "oras tarball sha256 is $actual, expected $ORAS_SHA256_AMD64"
mkdir "$scratch/bin"
tar -xzf "$tarball" -C "$scratch/bin" oras

docker_config=${DOCKER_CONFIG:-$HOME/.docker}/config.json
[ -r "$docker_config" ] || die "no Docker configuration at $docker_config: this job is not on a registry-enabled runner"
registry=$(python3 -I - "$docker_config" <<'PY'
import json, sys
auths = json.load(open(sys.argv[1])).get("auths", {})
if len(auths) != 1:
    sys.exit("the Docker configuration must name exactly one registry")
print(next(iter(auths)))
PY
)

echo "::add-mask::${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" >&2
audience=$(AUDIENCE="${AUDIENCE_PREFIX}:${digest}" python3 -I -c \
  'import os, urllib.parse; print(urllib.parse.quote(os.environ["AUDIENCE"], safe=""))')
response=$(curl -sSf --proto '=https' --tlsv1.2 --config - <<CURL
url = "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}"
header = "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}"
CURL
) || die "the OIDC token request failed"
token=$(printf '%s' "$response" | python3 -I -c \
  'import json, sys; v = json.load(sys.stdin).get("value"); print(v if isinstance(v, str) else "", end="")') \
  || die "the OIDC token response is not JSON"
[ -n "$token" ] || die "the OIDC token response has no value"
echo "::add-mask::${token}" >&2
printf '%s' "$token" >"$scratch/ci-oidc.jwt"

# oras refuses absolute file paths, so it attaches from the directory holding the token.
(cd "$scratch" && ./bin/oras attach --no-tty --artifact-type "$ATTESTATION_TYPE" \
  "$registry/ci/apxm/$artifact@$digest" "ci-oidc.jwt:$ATTESTATION_TYPE" >/dev/null) \
  || die "attaching the attestation to $registry/ci/apxm/$artifact@$digest failed"
echo "attested $artifact@$digest"
