#!/usr/bin/env bash
# Vendored from consultorialogisticaic/hostplane tools/ci/publish.sh at commit d63134c0023b876612aaafffdfac50acc4dee69f (main, PR #24 merged).
# Update by copying a reviewed hostplane commit, never by editing here.
# Publish one CI artifact of a workload and attest it, as the promoter expects.
#
# Run from the consumer's CI job on the workload's publishing pool, for a push event:
#
#   tools/ci/publish.sh [docker build arguments...]
#
# Only a push to RELEASE_BRANCH_REF publishes. On any other ref the script prints "not the
# release branch, skipping publish", writes no output and exits 0. Prod never reuses a
# ci/ tag: a prod release is requested through the promoter's API for a commit dev already
# deployed, and the promoter copies the digests dev recorded into release/**.
# A branch other than the release branch also gets a "::warning::" annotation: a publish job should not reach that ref (the workflow is
# missing its "if: github.ref == <release branch>" gate, or RELEASE_BRANCH_REF is
# wrong), and the annotation makes that visible in the run without failing a run that
# published, and claimed, nothing. Failing would turn every feature-branch push of a
# workflow without the gate red, for a job that has done no harm.
#
# On the release branch the image is always built and pushed by this run to
#   <REGISTRY>/ci/<WORKLOAD>/<ARTIFACT>:<GITHUB_SHA>
# and the run fails when that tag already exists: the registry credential is shared by
# every job of the pool, so an existing tag proves nothing about who pushed it. The digest
# docker reports must be the one the tag resolves to; only that digest is attested, with
# an OIDC token whose audience is <AUDIENCE_PREFIX>:<digest>, after attestation.py has
# checked that token.
#
# Registry access. On a pool runner that opted in to publish, the runner holds no
# registry credential at all: the pool's setup wrote /etc/hostplane/publish/env (the
# token exchange URL and audience, the registry and the CA), and this script proves the
# job with its GitHub OIDC token, whose audience is the publish audience, to the dev
# promoter's registry token exchange. Docker and oras present it as the password of the
# user "oidc" (an isolated DOCKER_CONFIG in the scratch directory, never the runner's
# own), and the registry's token flow turns it into a short-lived push token for
# ci/<WORKLOAD>/** and nothing else. The OIDC token is minted again right before each
# step that needs it, so a long build never leaves a stale one. Without an exchange
# (HOSTPLANE_PUBLISH_URL unset), a publishing runner's own credential is used, as before.
#
# Inputs (environment):
#   REGISTRY            registry host[:port] (default: HOSTPLANE_PUBLISH_REGISTRY)
#   HOSTPLANE_PUBLISH_URL, HOSTPLANE_PUBLISH_AUDIENCE, HOSTPLANE_PUBLISH_CA,
#   HOSTPLANE_PUBLISH_REGISTRY_CA
#                       the token exchange, from PUBLISH_ENV_FILE (default
#                       /etc/hostplane/publish/env) unless set here
#   WORKLOAD, ARTIFACT  names in the image path
#   AUDIENCE_PREFIX     the promoter's oidc.audience_prefix
#   CI_WORKFLOW         path of the CI workflow file, .github/workflows/<name>.yml
#   ORAS_VERSION        oras release to use, and ORAS_SHA256, the sha256 of its tarball
#   ORAS_TARBALL        optional pre-fetched tarball; still checked against ORAS_SHA256
#   CONTEXT             build context (default .), CONTAINERFILE (default Containerfile)
#   RELEASE_BRANCH_REF  the only ref that publishes (default refs/heads/main)
#   RUNNER_ENVIRONMENT  optional runner_environment claim the attestation must carry
#   OIDC_ISSUER         token issuer (default https://token.actions.githubusercontent.com)
#   JWKS_FILE           optional issuer key set file, instead of fetching it
#   and from GitHub Actions: GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_SHA, GITHUB_REPOSITORY,
#   GITHUB_REPOSITORY_ID, ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN and,
#   when set, GITHUB_OUTPUT (receives image= and digest=).
set -euo pipefail
umask 077

readonly ATTESTATION_TYPE="application/vnd.hostplane.ci-oidc.v1+jwt"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE

fail() {
  printf 'publish: %s\n' "$*" >&2
  exit 1
}

require() {
  local name="$1" pattern="$2" value="${!1:-}"
  [[ -n "${value}" ]] || fail "${name} must be set"
  [[ "${value}" =~ ${pattern} ]] || fail "${name} is not valid: ${value}"
}

# The pool setup writes the exchange coordinates as KEY=VALUE lines; only these keys are
# read, and a value already in the environment wins. The file is never sourced.
load_publish_env() {
  local file="${PUBLISH_ENV_FILE:-/etc/hostplane/publish/env}" key value
  [[ -r "${file}" ]] || return 0
  while IFS='=' read -r key value; do
    case "${key}" in
      HOSTPLANE_PUBLISH_URL | HOSTPLANE_PUBLISH_AUDIENCE | HOSTPLANE_PUBLISH_CA | HOSTPLANE_PUBLISH_REGISTRY | HOSTPLANE_PUBLISH_REGISTRY_CA)
        [[ -n "${!key:-}" ]] || printf -v "${key}" '%s' "${value}" ;;
    esac
  done <"${file}"
}
load_publish_env
REGISTRY="${REGISTRY:-${HOSTPLANE_PUBLISH_REGISTRY:-}}"
PUBLISH_URL="${HOSTPLANE_PUBLISH_URL:-}"
if [[ -n "${PUBLISH_URL}" ]]; then
  require PUBLISH_URL '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/v1/registry-token$'
  PUBLISH_AUDIENCE="${HOSTPLANE_PUBLISH_AUDIENCE:-}"
  require PUBLISH_AUDIENCE '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,62}:publish$'
fi

require REGISTRY '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$'
require WORKLOAD '^[a-z][a-z0-9-]{0,30}[a-z0-9]$'
require ARTIFACT '^[a-z0-9]+([._-][a-z0-9]+)*$'
require AUDIENCE_PREFIX '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$'
require CI_WORKFLOW '^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$'
require ORAS_VERSION '^[0-9]+\.[0-9]+\.[0-9]+$'
require ORAS_SHA256 '^[0-9a-f]{64}$'
require GITHUB_REPOSITORY '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
require GITHUB_REPOSITORY_ID '^[1-9][0-9]{0,19}$'
require GITHUB_SHA '^[0-9a-f]{40}$'
require GITHUB_REF '^refs/(heads|tags)/[A-Za-z0-9._/-]+$'
RELEASE_BRANCH_REF="${RELEASE_BRANCH_REF:-refs/heads/main}"
require RELEASE_BRANCH_REF '^refs/heads/[A-Za-z0-9._/-]+$'
OIDC_ISSUER="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
require OIDC_ISSUER '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$'
[[ "${GITHUB_EVENT_NAME:-}" == "push" ]] || fail "only a push event publishes; this is '${GITHUB_EVENT_NAME:-}'"
if [[ -n "${RUNNER_ENVIRONMENT:-}" ]]; then
  require RUNNER_ENVIRONMENT '^[a-z-]+$'
fi
if [[ -n "${JWKS_FILE:-}" ]]; then
  [[ -f "${JWKS_FILE}" ]] || fail "JWKS_FILE is not a file: ${JWKS_FILE}"
fi
if [[ "${GITHUB_REF}" != "${RELEASE_BRANCH_REF}" ]]; then
  printf 'publish: %s is not the release branch %s, skipping publish\n' "${GITHUB_REF}" "${RELEASE_BRANCH_REF}"
  if [[ "${GITHUB_REF}" != refs/tags/* ]]; then
    printf '::warning::publish reached %s, which is neither the release branch %s nor a tag: gate the publish job with if: github.ref == %s\n' \
      "${GITHUB_REF}" "${RELEASE_BRANCH_REF}" "${RELEASE_BRANCH_REF}"
  fi
  exit 0
fi
CONTEXT="${CONTEXT:-.}"
CONTAINERFILE="${CONTAINERFILE:-Containerfile}"

readonly REPO="${REGISTRY}/ci/${WORKLOAD}/${ARTIFACT}"
readonly IMAGE="${REPO}:${GITHUB_SHA}"

SCRATCH="$(mktemp -d)"
readonly SCRATCH
trap 'rm -rf "${SCRATCH}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Curl's retry policy for the platform's own endpoints: transient failures (timeouts,
# connection refused, 408, 429, 5xx) are retried with a pause, honouring Retry-After.
readonly CURL_RETRY=(--retry 5 --retry-delay 2 --retry-connrefused --retry-max-time 90)

# oras comes from its release tarball, accepted only at the pinned sha256.
install_oras() {
  local tarball="${ORAS_TARBALL:-}" arch
  if [[ -z "${tarball}" ]]; then
    case "$(uname -m)" in
      x86_64 | amd64) arch=amd64 ;;
      aarch64 | arm64) arch=arm64 ;;
      *) fail "no oras build for $(uname -m)" ;;
    esac
    tarball="${SCRATCH}/oras.tar.gz"
    curl -sSfL "${CURL_RETRY[@]}" --proto '=https' --tlsv1.2 -o "${tarball}" \
      "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${arch}.tar.gz"
  fi
  [[ -f "${tarball}" ]] || fail "oras tarball not found: ${tarball}"
  local actual
  actual="$(sha256sum "${tarball}" | cut -d' ' -f1)"
  [[ "${actual}" == "${ORAS_SHA256}" ]] || fail "oras tarball sha256 is ${actual}, expected ${ORAS_SHA256}"
  mkdir -p "${SCRATCH}/bin"
  tar -xzf "${tarball}" -C "${SCRATCH}/bin" oras
  ORAS="${SCRATCH}/bin/oras"
  [[ -x "${ORAS}" ]] || fail "the oras tarball holds no executable oras"
}

# oras does not read certs.d, and its --ca-file replaces the system roots. It talks to
# the registry and to the exchange the registry's token challenge names, which have
# different CAs, so it gets a bundle of both, in the scratch directory. Nothing is
# added to the system roots. Without the exchange the system roots are used.
ORAS_TLS=()
oras_trust() {
  [[ -n "${PUBLISH_URL}" ]] || return 0
  local registry_ca="${HOSTPLANE_PUBLISH_REGISTRY_CA:-}" bundle="${SCRATCH}/oras-ca.pem"
  [[ -r "${HOSTPLANE_PUBLISH_CA:-}" ]] || fail "the exchange CA is not readable: ${HOSTPLANE_PUBLISH_CA:-unset}"
  [[ -r "${registry_ca}" ]] || fail "the registry CA is not readable: ${registry_ca:-unset}"
  cat "${HOSTPLANE_PUBLISH_CA}" "${registry_ca}" >"${bundle}"
  ORAS_TLS=(--ca-file "${bundle}")
}

is_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

# Succeeds when the oras error in file $1 is the registry saying the manifest does not
# exist: oras reports a 404 as "<reference>: not found", or with the registry's error
# code (MANIFEST_UNKNOWN, or NAME_UNKNOWN for a repository nothing was pushed to yet).
# Any other status code, an authentication error, a timeout or anything unrecognised
# is not "not found".
not_found() {
  local text
  text="$(tr '[:upper:]' '[:lower:]' <"$1")"
  if [[ "${text}" =~ status\ code\ ([0-9]+) ]]; then
    [[ "${BASH_REMATCH[1]}" == 404 ]] || return 1
    [[ "${text}" =~ (manifest|name)[\ _]unknown ]]
    return
  fi
  [[ "${text}" =~ :\ not\ found[[:space:]]*$ ]]
}

# Prints the digest a reference resolves to. Returns 1 only when the registry says it
# does not exist; any other failure aborts the run, so a registry that cannot answer is
# never taken for an absent tag.
resolve() {
  local digest errors="${SCRATCH}/resolve.err"
  if ! digest="$("${ORAS}" resolve "${ORAS_TLS[@]}" "$1" 2>"${errors}")"; then
    not_found "${errors}" && return 1
    fail "cannot resolve $1: $(head -c 1000 "${errors}" | tr '\n' ' ')"
  fi
  is_digest "${digest}" || fail "$1 resolves to an unexpected value: ${digest}"
  printf '%s\n' "${digest}"
}

# Asks the Actions token service for an OIDC token for the audience $1 and writes it to
# the file $2. The request credential goes to curl on stdin, not on its command line.
mint_token() {
  local audience_value="$1" out="$2" audience response token
  [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] \
    || fail "the job needs permissions: id-token: write"
  [[ "${ACTIONS_ID_TOKEN_REQUEST_URL}" == https://* ]] || fail "the token request URL is not https"
  # Both go into a curl config file, where a quote or backslash would change its meaning.
  [[ "${ACTIONS_ID_TOKEN_REQUEST_URL}${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" != *[\"\\[:space:]]* ]] \
    || fail "the token request URL or credential holds a quote, backslash or space"
  echo "::add-mask::${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" >&2
  audience="$(AUDIENCE="${audience_value}" python3 -I -c \
    'import os, urllib.parse; print(urllib.parse.quote(os.environ["AUDIENCE"], safe=""))')"
  response="$(curl -sSf "${CURL_RETRY[@]}" --proto '=https' --tlsv1.2 --config - <<EOF
url = "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}"
header = "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}"
EOF
  )" || fail "the OIDC token request failed"
  token="$(printf '%s' "${response}" | python3 -I -c \
    'import json, sys; v = json.load(sys.stdin).get("value"); print(v if isinstance(v, str) else "", end="")')" \
    || fail "the OIDC token response is not JSON"
  [[ -n "${token}" ]] || fail "the OIDC token response has no value"
  echo "::add-mask::${token}" >&2
  printf '%s' "${token}" >"${out}"
}

# With the token exchange: mints a publish-audience OIDC token, proves the exchange
# grants this workload's path (a clear error and the retries of CURL_RETRY, before
# Docker's own flow), and leaves an isolated Docker config that carries the token as
# the password of "oidc". Docker and oras read it through DOCKER_CONFIG, so neither the
# runner's own config nor any other credential is involved. Without the exchange it
# does nothing.
registry_login() {
  [[ -n "${PUBLISH_URL}" ]] || return 0
  local jwt="${SCRATCH}/publish-oidc.jwt" answer
  mint_token "${PUBLISH_AUDIENCE}" "${jwt}"
  [[ "$(cat "${jwt}")" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] \
    || fail "the publish token is not a JWT"
  local cacert=()
  [[ -z "${HOSTPLANE_PUBLISH_CA:-}" ]] || cacert=(--cacert "${HOSTPLANE_PUBLISH_CA}")
  answer="$(curl -sSf "${CURL_RETRY[@]}" --proto '=https' --tlsv1.2 "${cacert[@]}" --config - <<EOF
url = "${PUBLISH_URL}?scope=repository:ci/${WORKLOAD}/${ARTIFACT}:pull,push"
user = "oidc:$(cat "${jwt}")"
EOF
  )" || fail "the registry token exchange refused the job or is unreachable"
  [[ "${answer}" == *'"token"'* ]] || fail "the registry token exchange returned no token"
  mkdir -p "${SCRATCH}/docker"
  chmod 0700 "${SCRATCH}/docker"
  AUTH="oidc:$(cat "${jwt}")" REGISTRY="${REGISTRY}" python3 -I -c \
    'import base64, json, os; a = base64.b64encode(os.environ["AUTH"].encode()).decode(); print(json.dumps({"auths": {os.environ["REGISTRY"]: {"auth": a}}}))' \
    >"${SCRATCH}/docker/config.json"
  export DOCKER_CONFIG="${SCRATCH}/docker"
  rm -f "${jwt}"
}

# Runs attestation.py on a token file for <digest> and the given attesting ref.
verify_token() {
  local file="$1" digest="$2" ref="$3"
  local args=(
    "${file}" --audience "${AUDIENCE_PREFIX}:${digest}"
    --repository "${GITHUB_REPOSITORY}" --repository-id "${GITHUB_REPOSITORY_ID}"
    --sha "${GITHUB_SHA}" --ref "${ref}" --workflow "${CI_WORKFLOW}" --issuer "${OIDC_ISSUER}"
  )
  [[ -z "${RUNNER_ENVIRONMENT:-}" ]] || args+=(--runner-environment "${RUNNER_ENVIRONMENT}")
  [[ -z "${JWKS_FILE:-}" ]] || args+=(--jwks "${JWKS_FILE}")
  python3 -I "${HERE}/attestation.py" "${args[@]}"
}

emit() {
  printf '%s -> %s\n' "$1" "$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'image=%s\ndigest=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT}"
  fi
}

publish_commit() {
  local pushed resolved
  ORIGINAL_DOCKER_CONFIG="${DOCKER_CONFIG:-${HOME}/.docker}"
  registry_login
  if resolve "${IMAGE}" >/dev/null; then
    fail "${IMAGE} already exists; CI tags are pushed once, by the run that built them"
  fi
  # The build uses the runner's own Docker config (the read-only mirror); only the push
  # and the registry calls use the exchange, with a token minted after the build.
  DOCKER_CONFIG="${ORIGINAL_DOCKER_CONFIG}" docker build -f "${CONTAINERFILE}" -t "${IMAGE}" "$@" "${CONTEXT}"
  registry_login
  pushed="$(docker push "${IMAGE}" | tee /dev/stderr \
    | sed -n 's/.*digest: \(sha256:[0-9a-f]\{64\}\).*/\1/p' | tail -n 1)" \
    || fail "pushing ${IMAGE} failed"
  is_digest "${pushed}" || fail "docker push reported no digest for ${IMAGE}"
  resolved="$(resolve "${IMAGE}")" || fail "${IMAGE} does not resolve after the push"
  [[ "${resolved}" == "${pushed}" ]] \
    || fail "${IMAGE} resolves to ${resolved}, not the ${pushed} this run pushed"

  mint_token "${AUDIENCE_PREFIX}:${pushed}" "${SCRATCH}/ci-oidc.jwt"
  verify_token "${SCRATCH}/ci-oidc.jwt" "${pushed}" "${GITHUB_REF}" \
    || fail "the minted token does not attest ${pushed}"
  registry_login
  # oras refuses absolute file paths, so it attaches from the directory holding the token.
  (cd "${SCRATCH}" && "${ORAS}" attach "${ORAS_TLS[@]}" --no-tty --artifact-type "${ATTESTATION_TYPE}" \
    "${REPO}@${pushed}" "ci-oidc.jwt:${ATTESTATION_TYPE}" >/dev/null) \
    || fail "attaching the attestation to ${REPO}@${pushed} failed"
  emit "${IMAGE}" "${pushed}"
}

install_oras
oras_trust
publish_commit "$@"
