"""Build fail-closed, canonical release authorization requests."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "io.mitosu.release-authorization/v1"
GATE_REPOSITORY = "mitosu-cloud/mitosu-release-gate"
GATE_REPOSITORY_ID = "1353141754"
SOURCE_REPOSITORY = "mitosu-cloud/mitosuagent"
EXPECTED_REF = "refs/heads/main"
EXPECTED_EVENT = "workflow_dispatch"
WORKFLOW_REFS = {
    "release": (
        "mitosu-cloud/mitosu-release-gate/.github/workflows/"
        "authorize-release.yml@refs/heads/main"
    ),
    "promotion": (
        "mitosu-cloud/mitosu-release-gate/.github/workflows/"
        "authorize-promotion.yml@refs/heads/main"
    ),
}
AUDIENCE_PREFIX = "urn:mitosu:release-gate:v1"
REQUEST_TTL = timedelta(minutes=8)

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_CERTIFICATE_BEGIN = b"-----BEGIN CERTIFICATE-----\n"
_CERTIFICATE_END = b"-----END CERTIFICATE-----\n"


class RequestError(ValueError):
    """Raised when an authorization request is not safe to issue."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return the one canonical byte representation accepted by the controller."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def request_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def request_audience(kind: str, digest: str) -> str:
    if kind not in WORKFLOW_REFS:
        raise RequestError(f"unsupported authorization kind: {kind}")
    if not _SHA256.fullmatch(digest):
        raise RequestError("request digest must be lowercase SHA-256 hex")
    return f"{AUDIENCE_PREFIX}:{kind}:sha256:{digest}"


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise RequestError(f"missing required GitHub context: {name}")
    return value


def _positive_integer(value: str, label: str) -> int:
    if not _POSITIVE_INTEGER.fullmatch(value):
        raise RequestError(f"{label} must be a positive integer")
    return int(value)


def _version(value: str) -> str:
    if len(value) > 128:
        raise RequestError("version must be canonical SemVer without a leading v")
    match = _SEMVER.fullmatch(value)
    if not match:
        raise RequestError("version must be canonical SemVer without a leading v")
    prerelease = match.group(4)
    if prerelease and any(
        identifier.isdigit()
        and len(identifier) > 1
        and identifier.startswith("0")
        for identifier in prerelease.split(".")
    ):
        raise RequestError("numeric SemVer prerelease identifiers cannot have leading zeros")
    return value


def _sha(value: str, label: str) -> str:
    if not _SHA40.fullmatch(value):
        raise RequestError(f"{label} must be a lowercase 40-character commit SHA")
    return value


def _sha256(value: str, label: str) -> str:
    if not _SHA256.fullmatch(value):
        raise RequestError(f"{label} must be lowercase SHA-256 hex")
    return value


def decode_controller_certificate(value: str) -> bytes:
    """Decode the exact ephemeral PEM certificate supplied by the controller."""

    try:
        certificate = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise RequestError("controller certificate must be strict base64") from error
    if not 256 <= len(certificate) <= 16_384:
        raise RequestError("controller certificate has an invalid size")
    if not (
        certificate.startswith(_CERTIFICATE_BEGIN)
        and certificate.endswith(_CERTIFICATE_END)
    ):
        raise RequestError("controller certificate must be canonical PEM")
    try:
        certificate.decode("ascii")
    except UnicodeDecodeError as error:
        raise RequestError("controller certificate must be ASCII PEM") from error
    body = certificate[len(_CERTIFICATE_BEGIN) : -len(_CERTIFICATE_END)]
    compact_body = body.replace(b"\n", b"")
    try:
        decoded_body = base64.b64decode(compact_body, validate=True)
    except (ValueError, binascii.Error) as error:
        raise RequestError("controller certificate contains invalid PEM data") from error
    wrapped_body = b"\n".join(
        base64.b64encode(decoded_body)[offset : offset + 64]
        for offset in range(0, len(base64.b64encode(decoded_body)), 64)
    )
    canonical_certificate = _CERTIFICATE_BEGIN + wrapped_body + b"\n" + _CERTIFICATE_END
    if certificate != canonical_certificate:
        raise RequestError("controller certificate must use canonical 64-column PEM")
    return certificate


def _controller_request(
    request_id: str, certificate: bytes
) -> dict[str, str]:
    try:
        parsed = uuid.UUID(request_id)
    except ValueError as error:
        raise RequestError("controller request ID must be a UUIDv4") from error
    if parsed.version != 4 or str(parsed) != request_id:
        raise RequestError("controller request ID must be a canonical UUIDv4")
    return {
        "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        "request_id": request_id,
    }


def _github_context(
    kind: str, environment: Mapping[str, str]
) -> dict[str, str | int]:
    expected_workflow = WORKFLOW_REFS[kind]
    exact = {
        "GITHUB_REPOSITORY": GATE_REPOSITORY,
        "GITHUB_REPOSITORY_ID": GATE_REPOSITORY_ID,
        "GITHUB_REF": EXPECTED_REF,
        "GITHUB_EVENT_NAME": EXPECTED_EVENT,
        "GITHUB_WORKFLOW_REF": expected_workflow,
    }
    for name, expected in exact.items():
        actual = _required(environment, name)
        if actual != expected:
            raise RequestError(f"unexpected {name}: {actual!r}")

    actor_id = _positive_integer(_required(environment, "GITHUB_ACTOR_ID"), "actor ID")
    run_id = _positive_integer(_required(environment, "GITHUB_RUN_ID"), "run ID")
    run_attempt = _positive_integer(
        _required(environment, "GITHUB_RUN_ATTEMPT"), "run attempt"
    )
    workflow_sha = _sha(
        _required(environment, "GITHUB_WORKFLOW_SHA"), "workflow SHA"
    )

    return {
        "actor_id": actor_id,
        "event_name": EXPECTED_EVENT,
        "ref": EXPECTED_REF,
        "repository": GATE_REPOSITORY,
        "repository_id": int(GATE_REPOSITORY_ID),
        "run_attempt": run_attempt,
        "run_id": run_id,
        "workflow_ref": expected_workflow,
        "workflow_sha": workflow_sha,
    }


def _base_request(
    kind: str,
    environment: Mapping[str, str],
    now: datetime,
    controller_request_id: str,
    controller_certificate: bytes,
) -> dict[str, Any]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise RequestError("request time must be timezone-aware")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    context = _github_context(kind, environment)
    return {
        "controller": _controller_request(
            controller_request_id, controller_certificate
        ),
        "expires_at": (now + REQUEST_TTL).isoformat().replace("+00:00", "Z"),
        "gate": context,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "kind": kind,
        "schema": SCHEMA,
    }


def build_release_request(
    *,
    version: str,
    source_sha: str,
    build_run_id: str,
    controller_request_id: str,
    controller_certificate: bytes,
    environment: Mapping[str, str],
    now: datetime,
) -> dict[str, Any]:
    request = _base_request(
        "release",
        environment,
        now,
        controller_request_id,
        controller_certificate,
    )
    request["release"] = {
        "build_run_id": _positive_integer(build_run_id, "private build run ID"),
        "source_repository": SOURCE_REPOSITORY,
        "source_sha": _sha(source_sha, "source SHA"),
        "version": _version(version),
    }
    return request


def build_promotion_request(
    *,
    version: str,
    manifest_sha256: str,
    e2e_run_ids: Sequence[str],
    controller_request_id: str,
    controller_certificate: bytes,
    environment: Mapping[str, str],
    now: datetime,
) -> dict[str, Any]:
    if not e2e_run_ids:
        raise RequestError("at least one E2E run ID is required")
    if len(e2e_run_ids) > 16:
        raise RequestError("at most 16 E2E run IDs may be authorized")
    parsed_run_ids = [_positive_integer(value, "E2E run ID") for value in e2e_run_ids]
    if len(parsed_run_ids) != len(set(parsed_run_ids)):
        raise RequestError("E2E run IDs must be unique")

    request = _base_request(
        "promotion",
        environment,
        now,
        controller_request_id,
        controller_certificate,
    )
    request["promotion"] = {
        "e2e_run_ids": parsed_run_ids,
        "manifest_sha256": _sha256(manifest_sha256, "manifest digest"),
        "version": _version(version),
    }
    return request


def write_request_bundle(
    request: Mapping[str, Any],
    controller_certificate: bytes,
    output_directory: Path,
) -> tuple[str, str]:
    """Create a private-on-runner request directory and return digest/audience."""

    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output_directory, 0o700)
    request_bytes = canonical_json(request)
    digest = hashlib.sha256(request_bytes).hexdigest()
    audience = request_audience(str(request["kind"]), digest)

    for name, payload in (
        ("request.json", request_bytes),
        ("request.sha256", f"{digest}  request.json\n".encode("ascii")),
        ("controller-certificate.pem", controller_certificate),
    ):
        path = output_directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RequestError(f"unsafe file mode for {path}")
    return digest, audience


def _write_github_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise RequestError("GITHUB_OUTPUT is required")
    if "\n" in value or "\r" in value:
        raise RequestError("multiline GitHub output is not permitted")
    with open(output_path, "a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="kind", required=True)

    release = subparsers.add_parser("release")
    release.add_argument("--version", required=True)
    release.add_argument("--source-sha", required=True)
    release.add_argument("--build-run-id", required=True)
    release.add_argument("--controller-request-id", required=True)
    release.add_argument("--controller-certificate-b64", required=True)
    release.add_argument("--output", type=Path, required=True)

    promotion = subparsers.add_parser("promotion")
    promotion.add_argument("--version", required=True)
    promotion.add_argument("--manifest-sha256", required=True)
    promotion.add_argument("--e2e-run-id", action="append", required=True)
    promotion.add_argument("--controller-request-id", required=True)
    promotion.add_argument("--controller-certificate-b64", required=True)
    promotion.add_argument("--output", type=Path, required=True)

    arguments = parser.parse_args()
    now = datetime.now(timezone.utc)
    certificate = decode_controller_certificate(arguments.controller_certificate_b64)
    if arguments.kind == "release":
        request = build_release_request(
            version=arguments.version,
            source_sha=arguments.source_sha,
            build_run_id=arguments.build_run_id,
            controller_request_id=arguments.controller_request_id,
            controller_certificate=certificate,
            environment=os.environ,
            now=now,
        )
    else:
        request = build_promotion_request(
            version=arguments.version,
            manifest_sha256=arguments.manifest_sha256,
            e2e_run_ids=arguments.e2e_run_id,
            controller_request_id=arguments.controller_request_id,
            controller_certificate=certificate,
            environment=os.environ,
            now=now,
        )

    digest, audience = write_request_bundle(
        request, certificate, arguments.output
    )
    _write_github_output("digest", digest)
    _write_github_output("audience", audience)
    _write_github_output("request_id", str(request["controller"]["request_id"]))


if __name__ == "__main__":
    main()
