from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.seal_oidc_authorization import _seal, _validate_certificate


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class SealingTests(unittest.TestCase):
    def _certificate(self, directory: Path, bits: int) -> tuple[Path, Path]:
        certificate = directory / f"certificate-{bits}.pem"
        key = directory / f"key-{bits}.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                f"rsa:{bits}",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=mitosu-one-time-release-controller",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
        return certificate, key

    def test_oidc_envelope_is_only_recoverable_with_controller_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            certificate, key = self._certificate(directory, 3072)
            _validate_certificate(certificate)
            token = "header.sensitive-oidc-payload.signature"
            digest = "d" * 64
            ciphertext = directory / "authorization.cms"
            _seal(token, digest, certificate, ciphertext)

            self.assertNotIn(token.encode("ascii"), ciphertext.read_bytes())
            decrypted = subprocess.run(
                [
                    "openssl",
                    "cms",
                    "-decrypt",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    str(ciphertext),
                    "-recip",
                    str(certificate),
                    "-inkey",
                    str(key),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=15,
            )
            envelope = json.loads(decrypted.stdout)
            self.assertEqual(envelope["oidc_token"], token)
            self.assertEqual(envelope["request_sha256"], digest)

    def test_weak_controller_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certificate, _ = self._certificate(Path(temporary), 2048)
            with self.assertRaisesRegex(RuntimeError, "3072"):
                _validate_certificate(certificate)


if __name__ == "__main__":
    unittest.main()
