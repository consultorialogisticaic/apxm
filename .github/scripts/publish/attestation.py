#!/usr/bin/env -S python3 -I
"""Verify a CI attestation token (a GitHub Actions OIDC JWT) with the standard library only.

publish.sh runs it on the token it was just issued, before attaching it to the
image it pushed, so a token the promoter would refuse fails the CI run instead of
being attached and refused later. It checks an RS256 signature by a key of the
issuer's published key set, and claims that bind the token to this repository,
this commit, the release branch, the CI workflow, a push event and this digest,
plus that ``iat`` is not in the future.

It is a subset of what the promoter checks, not the same check: the promoter also
binds ``run_id`` and ``run_attempt`` to the run the GitHub API reports and
requires ``iat`` to fall within that run, which needs the GitHub API and is not
repeated here. Passing this check does not make a token promotable.

Why ``exp`` is not enforced. The token is checked seconds after it was issued, so
an ``exp`` check would add nothing here, and the token is used afterwards only by
the promoter, which polls and may read it long after its few minutes of validity;
the promoter ignores ``exp`` for that reason and relies on ``aud`` binding one
digest and on the run window of ``iat``. Keeping the two in line means a token
this module accepts is never refused for a reason the promoter does not have.
``iat`` must still be an integer no later than now plus ``CLOCK_SKEW_SECONDS``:
a token stamped in the future was not issued by an honest issuer for this run.

Usage:
    attestation.py TOKEN_FILE --audience A --repository OWNER/NAME --sha SHA
        --ref REF --workflow PATH [--repository-id ID] [--runner-environment E]
        [--issuer URL] [--jwks FILE]

Run it as ``python3 -I`` so nothing from the working directory or the environment
is imported.

The exit status is 0 only for a token that passes every check; the reason for a
refusal goes to stderr, and the token itself is never printed.

The module runs on CI runners with whatever Python 3 they carry, so it uses
nothing beyond the standard library and nothing newer than Python 3.9.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ISSUER = "https://token.actions.githubusercontent.com"
EVENT = "push"
# DER DigestInfo prefix of SHA-256 in an RSASSA-PKCS1-v1_5 signature (RFC 8017, 9.2).
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
MIN_MODULUS_BITS = 2048
MAX_TOKEN_BYTES = 16 * 1024
MAX_JWKS_BYTES = 256 * 1024
# A token never names its own key or asks for extensions (RFC 7515, 4.1).
FORBIDDEN_HEADERS = ("crit", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256")
SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Tolerance for the clocks of the issuer and the runner, as the promoter's default.
CLOCK_SKEW_SECONDS = 60


class Rejected(Exception):
    """The token is not an attestation of what was asked."""


def _b64(value: str) -> bytes:
    if not SEGMENT.fullmatch(value):
        raise Rejected("a segment is not base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as error:
        raise Rejected("a segment is not base64url") from error


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejected(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_object(raw: bytes, what: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as error:
        raise Rejected(f"the {what} is not JSON") from error
    if not isinstance(value, dict):
        raise Rejected(f"the {what} is not a JSON object")
    return value


def _rsa_key(key: dict) -> tuple[int, int]:
    if key.get("kty") != "RSA":
        raise Rejected("the signing key is not an RSA key")
    if key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
        raise Rejected("the signing key is not an RS256 signature key")
    n, e = key.get("n"), key.get("e")
    if not isinstance(n, str) or not isinstance(e, str):
        raise Rejected("the signing key has no modulus or exponent")
    modulus = int.from_bytes(_b64(n), "big")
    exponent = int.from_bytes(_b64(e), "big")
    if modulus.bit_length() < MIN_MODULUS_BITS:
        raise Rejected(f"the signing key is shorter than {MIN_MODULUS_BITS} bits")
    if exponent < 3 or exponent % 2 == 0:
        raise Rejected("the signing key has an invalid exponent")
    return modulus, exponent


def _signature_holds(signing_input: bytes, signature: bytes, key: dict) -> bool:
    modulus, exponent = _rsa_key(key)
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False
    recovered = pow(value, exponent, modulus).to_bytes(size, "big")
    digest = SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    return hmac.compare_digest(recovered, expected)


def _signing_key(jwks: dict, kid: str) -> dict:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise Rejected("the key set has no keys")
    matching = [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
    if not matching:
        raise Rejected("the token's kid is not in the issuer's key set")
    if len(matching) > 1:
        raise Rejected("the token's kid is duplicated in the issuer's key set")
    return matching[0]


def verify(
    token: str,
    jwks: dict,
    *,
    issuer: str,
    audience: str,
    repository: str,
    sha: str,
    ref: str,
    workflow: str,
    repository_id: str | None = None,
    runner_environment: str | None = None,
    now: int | None = None,
) -> dict:
    """Return the claims of a token that attests ``audience``, or raise Rejected."""
    token = token.strip()
    if len(token) > MAX_TOKEN_BYTES:
        raise Rejected("the token is too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise Rejected("not a compact JWS")
    header_part, payload_part, signature_part = parts
    header = _json_object(_b64(header_part), "header")
    if header.get("alg") != "RS256":
        raise Rejected("only RS256 is accepted")
    if header.get("typ", "JWT") != "JWT":
        raise Rejected("the token is not a JWT")
    for name in FORBIDDEN_HEADERS:
        if name in header:
            raise Rejected(f"the header carries {name}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise Rejected("the header has no kid")
    key = _signing_key(jwks, kid)
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    if not _signature_holds(signing_input, _b64(signature_part), key):
        raise Rejected("the signature does not verify against the issuer's keys")
    claims = _json_object(_b64(payload_part), "payload")
    expected = {
        "iss": issuer,
        "aud": audience,
        "repository": repository,
        "sha": sha,
        "ref": ref,
        "event_name": EVENT,
        "workflow_ref": f"{repository}/{workflow}@{ref}",
    }
    if repository_id is not None:
        expected["repository_id"] = repository_id
    if runner_environment is not None:
        expected["runner_environment"] = runner_environment
    for name, value in expected.items():
        actual = claims.get(name)
        if not isinstance(actual, str) or not hmac.compare_digest(actual, value):
            raise Rejected(f"claim {name} is not {value!r}")
    iat = claims.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise Rejected("claim iat is not an integer")
    current = int(time.time()) if now is None else now
    if iat > current + CLOCK_SKEW_SECONDS:
        raise Rejected(f"claim iat {iat} is in the future (now {current})")
    return claims


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


def fetch_jwks(issuer: str) -> dict:
    """Fetch the issuer's key set over HTTPS, without redirects and with a size cap."""
    if not issuer.startswith("https://"):
        raise Rejected("the issuer must be an https URL")
    return _fetch_key_set(issuer.rstrip("/") + "/.well-known/jwks")


def _fetch_key_set(url: str) -> dict:
    """Read a key set from ``url``; a redirect is refused, not followed."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=20) as response:
            body = response.read(MAX_JWKS_BYTES + 1)
    except (urllib.error.URLError, OSError) as error:
        raise Rejected(f"cannot fetch the issuer's keys: {error}") from error
    if len(body) > MAX_JWKS_BYTES:
        raise Rejected("the issuer's key set is too large")
    return _json_object(body, "key set")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("token_file", type=Path)
    parser.add_argument("--audience", required=True, help="<audience prefix>:<image digest>")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--ref", required=True, help="ref the attesting run ran on")
    parser.add_argument("--workflow", required=True, help="path of the CI workflow file")
    parser.add_argument("--repository-id")
    parser.add_argument("--runner-environment")
    parser.add_argument("--issuer", default=ISSUER)
    parser.add_argument("--jwks", type=Path, help="key set file; the issuer's when absent")
    args = parser.parse_args(argv)
    try:
        if not DIGEST.fullmatch(args.audience.partition(":")[2]):
            raise Rejected("the audience does not end in a sha256 digest")
        if args.token_file.stat().st_size > MAX_TOKEN_BYTES:
            raise Rejected("the token is too large")
        if args.jwks is not None:
            jwks = _json_object(args.jwks.read_bytes(), "key set")
        else:
            jwks = fetch_jwks(args.issuer)
        verify(
            args.token_file.read_text(encoding="ascii", errors="strict"),
            jwks,
            issuer=args.issuer,
            audience=args.audience,
            repository=args.repository,
            sha=args.sha,
            ref=args.ref,
            workflow=args.workflow,
            repository_id=args.repository_id,
            runner_environment=args.runner_environment,
        )
    except (Rejected, OSError, UnicodeDecodeError) as error:
        print(f"attestation rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
