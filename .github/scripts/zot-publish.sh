#!/usr/bin/env bash
# Push one locally built image to the CI registry and attach the proof of origin.
#
#   zot-publish.sh resolve WORKLOAD ARTIFACT
#   zot-publish.sh publish WORKLOAD ARTIFACT LOCAL_IMAGE
#
# The image lands at <registry>/ci/WORKLOAD/ARTIFACT:<commit sha>. The registry
# host and the push credential are the ones the runner already carries in its
# Docker configuration (one registry, one credential, nothing stored in GitHub).
# Tags there are immutable (create only), so a commit that was already pushed,
# for instance a release tag on a commit that main built before, is never pushed
# again: its existing digest is reused and only a fresh proof is attached.
#
# The proof is a GitHub OIDC token for this run whose audience is
# "<HOSTPLANE_OIDC_AUDIENCE_PREFIX>:<digest>", attached to the digest as a
# referrer of artifact type application/vnd.hostplane.ci-oidc.v1+jwt.
#
# resolve prints the digest of the pushed commit, or nothing when there is none.
# publish prints the digest the proof was attached to as its last line (the
# runner's ::add-mask:: command precedes it, so callers read it with tail -n 1).
#
# Environment: GITHUB_SHA and, for publish, ACTIONS_ID_TOKEN_REQUEST_URL,
# ACTIONS_ID_TOKEN_REQUEST_TOKEN (job permission id-token: write) and
# HOSTPLANE_OIDC_AUDIENCE_PREFIX (must equal the promoter's oidc.audience_prefix).
# DOCKER_CONFIG selects the Docker configuration directory (default ~/.docker).
set -euo pipefail

readonly ORAS_VERSION=1.3.6
readonly ORAS_SHA256=66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0
readonly TOKEN_TYPE='application/vnd.hostplane.ci-oidc.v1+jwt'

die() {
  echo "zot-publish: $*" >&2
  exit 1
}

usage() {
  die "usage: zot-publish.sh resolve WORKLOAD ARTIFACT | publish WORKLOAD ARTIFACT LOCAL_IMAGE"
}

mode=${1:-}
workload=${2:-}
artifact=${3:-}
case "$mode" in
  resolve) [ $# -eq 3 ] || usage ;;
  publish) [ $# -eq 4 ] || usage ;;
  *) usage ;;
esac
local_image=${4:-}
name_pattern='^[a-z][a-z0-9-]{0,30}[a-z0-9]$'
[[ $workload =~ $name_pattern ]] || die "invalid workload name: $workload"
[[ $artifact =~ $name_pattern ]] || die "invalid artifact name: $artifact"
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || die "GITHUB_SHA must be a full commit sha"

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
repository="$registry/ci/$workload/$artifact"
reference="$repository:$GITHUB_SHA"

ensure_oras() {
  if command -v oras >/dev/null 2>&1 && [ "$(oras version | sed -n 's/^Version:[[:space:]]*//p')" = "$ORAS_VERSION" ]; then
    return
  fi
  local scratch="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/oras-$ORAS_VERSION"
  mkdir -p "$scratch"
  if [ ! -x "$scratch/oras" ]; then
    curl -fsSL --retry 3 -o "$scratch/oras.tar.gz" \
      "https://github.com/oras-project/oras/releases/download/v$ORAS_VERSION/oras_${ORAS_VERSION}_linux_amd64.tar.gz"
    echo "$ORAS_SHA256  $scratch/oras.tar.gz" | sha256sum --check --status || die "oras archive checksum mismatch"
    tar -xzf "$scratch/oras.tar.gz" -C "$scratch" oras
  fi
  PATH="$scratch:$PATH"
}

# Prints the digest behind the tag, or nothing when the tag does not exist.
resolve() {
  local output
  if output=$(oras manifest fetch --descriptor "$reference" 2>&1); then
    local digest
    digest=$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)["digest"])' <<<"$output") ||
      die "the registry returned an unreadable descriptor for $reference"
    [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "the registry returned an invalid digest for $reference"
    printf '%s\n' "$digest"
  elif [[ $output == *"not found"* ]]; then
    return 0
  else
    die "cannot look up $reference: $output"
  fi
}

attach_proof() {
  local digest=$1
  : "${ACTIONS_ID_TOKEN_REQUEST_URL:?the job needs permissions: id-token: write}"
  : "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?the job needs permissions: id-token: write}"
  : "${HOSTPLANE_OIDC_AUDIENCE_PREFIX:?set the audience prefix the promoter is configured with}"
  local scratch token audience
  scratch=$(mktemp -d)
  audience="$HOSTPLANE_OIDC_AUDIENCE_PREFIX:$digest"
  token=$(curl -fsS --retry 3 -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$audience")" |
    python3 -I -c 'import json, sys; print(json.load(sys.stdin)["value"])')
  [ -n "$token" ] || die "GitHub returned an empty OIDC token"
  echo "::add-mask::$token"
  printf '%s' "$token" >"$scratch/ci-oidc.jwt"
  (cd "$scratch" && oras attach --no-tty --artifact-type "$TOKEN_TYPE" \
    "$repository@$digest" "ci-oidc.jwt:$TOKEN_TYPE" >/dev/null)
  rm -rf "$scratch"
}

ensure_oras
digest=$(resolve)
if [ "$mode" = resolve ]; then
  [ -z "$digest" ] || printf '%s\n' "$digest"
  exit 0
fi

if [ -z "$digest" ]; then
  docker image inspect "$local_image" >/dev/null || die "local image not found: $local_image"
  docker tag "$local_image" "$reference"
  docker push --quiet "$reference" >/dev/null
  digest=$(resolve)
  [ -n "$digest" ] || die "$reference is not in the registry after the push"
fi
attach_proof "$digest"
printf '%s\n' "$digest"
