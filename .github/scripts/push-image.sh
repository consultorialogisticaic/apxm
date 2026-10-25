#!/usr/bin/env bash
# Push one locally built service image to the CI registry and print its digest.
#
#   push-image.sh ARTIFACT LOCAL_IMAGE
#
# The image lands at <registry>/ci/apxm/ARTIFACT:<commit sha>. The registry host and the
# push credential are the ones the runner already carries in its Docker configuration.
#
# These images are consumed by digest only: a deployment that runs one records the
# digest this script prints in its own reviewed configuration, and a digest names its
# bytes whoever pushed the tag. No proof of origin is attached and none is needed, and
# this repository declares no deployment of its own. The tag is immutable: the script
# fails when it already exists instead of reusing it.
set -euo pipefail

die() {
  echo "push-image: $*" >&2
  exit 1
}

[ $# -eq 2 ] || die "usage: push-image.sh ARTIFACT LOCAL_IMAGE"
artifact=$1
local_image=$2
[[ $artifact =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || die "invalid artifact name: $artifact"
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
reference="$registry/ci/apxm/$artifact:$GITHUB_SHA"

docker image inspect "$local_image" >/dev/null || die "local image not found: $local_image"
if docker manifest inspect "$reference" >/dev/null 2>&1; then
  die "$reference already exists: tags are immutable"
fi
docker tag "$local_image" "$reference"
digest=$(docker push "$reference" | sed -n 's/.*digest: \(sha256:[0-9a-f]\{64\}\).*/\1/p' | tail -n 1)
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "the push of $reference reported no digest"
printf '%s\n' "$digest"
