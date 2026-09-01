from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from release_gate.request import (
    GATE_REPOSITORY,
    GATE_REPOSITORY_ID,
    RequestError,
    WORKFLOW_REFS,
    build_promotion_request,
    build_release_request,
    canonical_json,
    decode_controller_certificate,
    request_audience,
    request_digest,
    write_request_bundle,
)


CONTROLLER_REQUEST_ID = "b7d1831c-2c41-44db-bf9e-739cd7234d76"
_FAKE_DER = b"A" * 300
_FAKE_BODY = base64.b64encode(_FAKE_DER)
CERTIFICATE = b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(
    _FAKE_BODY[offset : offset + 64] for offset in range(0, len(_FAKE_BODY), 64)
) + b"\n-----END CERTIFICATE-----\n"
NOW = datetime(2026, 8, 31, 18, 30, tzinfo=timezone.utc)


def github_environment(kind: str) -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": GATE_REPOSITORY,
        "GITHUB_REPOSITORY_ID": GATE_REPOSITORY_ID,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": WORKFLOW_REFS[kind],
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_ACTOR_ID": "1031878",
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
    }


class RequestTests(unittest.TestCase):
    def release_request(self) -> dict[str, object]:
        return build_release_request(
            version="0.1.0",
            source_sha="b" * 40,
            build_run_id="987654321",
            controller_request_id=CONTROLLER_REQUEST_ID,
            controller_certificate=CERTIFICATE,
            environment=github_environment("release"),
            now=NOW,
        )

    def test_release_request_binds_private_and_controller_facts(self) -> None:
        request = self.release_request()
        self.assertEqual(request["issued_at"], "2026-08-31T18:30:00Z")
        self.assertEqual(request["expires_at"], "2026-08-31T18:38:00Z")
        self.assertEqual(
            request["controller"],
            {
                "certificate_sha256": hashlib.sha256(CERTIFICATE).hexdigest(),
                "request_id": CONTROLLER_REQUEST_ID,
            },
        )
        self.assertEqual(
            request["release"],
            {
                "build_run_id": 987654321,
                "source_repository": "mitosu-cloud/mitosuagent",
                "source_sha": "b" * 40,
                "version": "0.1.0",
            },
        )

    def test_canonical_digest_and_audience_are_stable(self) -> None:
        request = self.release_request()
        encoded = canonical_json(request)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded, canonical_json(json.loads(encoded)))
        digest = request_digest(request)
        self.assertEqual(digest, hashlib.sha256(encoded).hexdigest())
        self.assertEqual(
            request_audience("release", digest),
            f"urn:mitosu:release-gate:v1:release:sha256:{digest}",
        )

    def test_context_must_match_exact_public_gate_identity(self) -> None:
        replacements = {
            "GITHUB_REPOSITORY": "attacker/fork",
            "GITHUB_REPOSITORY_ID": "1",
            "GITHUB_REF": "refs/heads/feature",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKFLOW_REF": "attacker/workflow@refs/heads/main",
        }
        for name, replacement in replacements.items():
            with self.subTest(name=name):
                environment = github_environment("release")
                environment[name] = replacement
                with self.assertRaises(RequestError):
                    build_release_request(
                        version="0.1.0",
                        source_sha="b" * 40,
                        build_run_id="1",
                        controller_request_id=CONTROLLER_REQUEST_ID,
                        controller_certificate=CERTIFICATE,
                        environment=environment,
                        now=NOW,
                    )

    def test_invalid_release_values_fail_closed(self) -> None:
        cases = (
            {"version": "v0.1.0"},
            {"version": "01.1.0"},
            {"version": "1.0.0-01"},
            {"source_sha": "B" * 40},
            {"source_sha": "b" * 39},
            {"build_run_id": "0"},
            {"build_run_id": "not-an-id"},
            {"build_run_id": "01"},
            {"controller_request_id": "not-a-uuid"},
        )
        defaults = {
            "version": "0.1.0",
            "source_sha": "b" * 40,
            "build_run_id": "1",
            "controller_request_id": CONTROLLER_REQUEST_ID,
            "controller_certificate": CERTIFICATE,
            "environment": github_environment("release"),
            "now": NOW,
        }
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(RequestError):
                    build_release_request(**(defaults | overrides))

    def test_promotion_requires_unique_e2e_evidence(self) -> None:
        with self.assertRaises(RequestError):
            build_promotion_request(
                version="0.1.0",
                manifest_sha256="c" * 64,
                e2e_run_ids=["11", "11"],
                controller_request_id=CONTROLLER_REQUEST_ID,
                controller_certificate=CERTIFICATE,
                environment=github_environment("promotion"),
                now=NOW,
            )
        request = build_promotion_request(
            version="0.1.0",
            manifest_sha256="c" * 64,
            e2e_run_ids=["11", "12"],
            controller_request_id=CONTROLLER_REQUEST_ID,
            controller_certificate=CERTIFICATE,
            environment=github_environment("promotion"),
            now=NOW,
        )
        self.assertEqual(request["promotion"]["e2e_run_ids"], [11, 12])

    def test_certificate_decode_is_strict(self) -> None:
        encoded = base64.b64encode(CERTIFICATE).decode("ascii")
        self.assertEqual(decode_controller_certificate(encoded), CERTIFICATE)
        for invalid in ("not base64!", base64.b64encode(b"not PEM").decode("ascii")):
            with self.assertRaises(RequestError):
                decode_controller_certificate(invalid)

    def test_bundle_has_restrictive_modes_and_cannot_overwrite(self) -> None:
        request = self.release_request()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "authorization"
            digest, audience = write_request_bundle(request, CERTIFICATE, output)
            self.assertEqual(digest, request_digest(request))
            self.assertEqual(audience, request_audience("release", digest))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for name in (
                "request.json",
                "request.sha256",
                "controller-certificate.pem",
            ):
                self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                write_request_bundle(request, CERTIFICATE, output)


if __name__ == "__main__":
    unittest.main()
