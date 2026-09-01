#!/usr/bin/env python3
"""Mint a GitHub OIDC token and seal it to a one-time controller key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE_PREFIX = "urn:mitosu:release-gate:v1:"
ENVELOPE_SCHEMA = "io.mitosu.sealed-release-authorization/v1"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _decode_payload_without_verification(token: str) -> dict[str, Any]:
    """Decode only for runner sanity; the private controller verifies signing."""

    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("OIDC endpoint returned a malformed JWT")
    encoded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("OIDC endpoint returned an invalid JWT payload") from error
    if not isinstance(value, dict):
        raise RuntimeError("OIDC JWT payload must be an object")
    return value


def _validate_request(
    request_path: Path, certificate_path: Path, audience: str
) -> tuple[bytes, str]:
    request_bytes = request_path.read_bytes()
    if not request_bytes or len(request_bytes) > MAX_REQUEST_BYTES:
        raise RuntimeError("canonical request has an invalid size")
    try:
        request = json.loads(request_bytes)
    except json.JSONDecodeError as error:
        raise RuntimeError("canonical request is invalid JSON") from error
    if not isinstance(request, dict) or _canonical_json(request) != request_bytes:
        raise RuntimeError("request bytes are not canonical")

    digest = hashlib.sha256(request_bytes).hexdigest()
    kind = request.get("kind")
    expected_audience = f"{AUDIENCE_PREFIX}{kind}:sha256:{digest}"
    if audience != expected_audience:
        raise RuntimeError("OIDC audience is not bound to the request")

    certificate = certificate_path.read_bytes()
    expected_certificate_digest = request.get("controller", {}).get(
        "certificate_sha256"
    )
    if hashlib.sha256(certificate).hexdigest() != expected_certificate_digest:
        raise RuntimeError("controller certificate is not bound to the request")
    return request_bytes, digest


def _validate_certificate(certificate_path: Path) -> None:
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate_path),
            "-noout",
            "-checkend",
            "600",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("controller certificate is invalid or expires too soon")
    public_key = subprocess.run(
        ["openssl", "x509", "-in", str(certificate_path), "-pubkey", "-noout"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if public_key.returncode != 0:
        raise RuntimeError("controller certificate has no usable public key")
    details = subprocess.run(
        ["openssl", "pkey", "-pubin", "-pubcheck", "-text_pub", "-noout"],
        input=public_key.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    bit_match = re.search(rb"Public-Key:\s*\(([0-9]+) bit\)", details.stdout)
    if details.returncode != 0 or not bit_match or int(bit_match.group(1)) < 3072:
        raise RuntimeError("controller certificate must contain an RSA key of 3072+ bits")


def _fetch_token(audience: str) -> str:
    if not audience.startswith(AUDIENCE_PREFIX) or len(audience) > 256:
        raise RuntimeError("refusing an audience outside the Mitosu gate namespace")
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not request_url or not bearer:
        raise RuntimeError("GitHub OIDC request context is unavailable")
    if len(bearer) > 16_384 or "\n" in bearer or "\r" in bearer:
        raise RuntimeError("GitHub OIDC request token is malformed")

    parsed = urllib.parse.urlsplit(request_url)
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not hostname.endswith(".actions.githubusercontent.com")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
    ):
        raise RuntimeError("GitHub OIDC request URL is outside the trusted endpoint")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("audience", audience))
    url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")
    )
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("GitHub OIDC response exceeded the size limit")
    try:
        token = json.loads(payload)["value"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("GitHub OIDC response did not contain a token") from error
    if not isinstance(token, str) or len(token) > 16_384:
        raise RuntimeError("GitHub OIDC response contained an invalid token")

    claims = _decode_payload_without_verification(token)
    if claims.get("iss") != ISSUER or claims.get("aud") != audience:
        raise RuntimeError("GitHub OIDC token did not match the requested identity")
    if int(claims.get("exp", 0)) <= int(time.time()):
        raise RuntimeError("GitHub OIDC token was already expired")
    return token


def _seal(
    token: str,
    digest: str,
    certificate_path: Path,
    output_path: Path,
) -> None:
    plaintext = _canonical_json(
        {
            "oidc_token": token,
            "request_sha256": digest,
            "schema": ENVELOPE_SCHEMA,
        }
    )
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output_path.parent, 0o700)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            result = subprocess.run(
                [
                    "openssl",
                    "cms",
                    "-encrypt",
                    "-binary",
                    "-aes-256-gcm",
                    "-outform",
                    "DER",
                    str(certificate_path),
                ],
                input=plaintext,
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
        if result.returncode != 0 or output_path.stat().st_size == 0:
            output_path.unlink(missing_ok=True)
            raise RuntimeError("failed to encrypt the authorization envelope")
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audience", required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    _, digest = _validate_request(
        arguments.request, arguments.certificate, arguments.audience
    )
    _validate_certificate(arguments.certificate)
    token = _fetch_token(arguments.audience)
    _seal(token, digest, arguments.certificate, arguments.output)


if __name__ == "__main__":
    main()
