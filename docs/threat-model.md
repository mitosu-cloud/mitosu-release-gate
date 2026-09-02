# Threat model

## Security objective

A reviewed public GitHub environment may authorize, but can never itself build,
sign, notarize, publish, or promote a Mitosu release. Only a private controller
may perform those operations, and only after independently proving that a fresh,
single-use authorization names the exact private inputs and evidence it sees.

## Trust boundaries

- **Public gate repository:** policy and small authorization programs only. It
  is assumed readable by an attacker and holds no secret.
- **Approval runner:** a disposable, isolated self-hosted runner. It receives a
  GitHub OIDC request token during an approved job but has no private source,
  product artifact, signing key, production credential, or production-network
  access.
- **Public CI runner:** a different disposable, isolated self-hosted runner that
  assumes pull-request code is hostile. It has no secret, private or production
  network route, host mount, persistent state, or access to the approval runner;
  its VM and repository-scoped registration are destroyed after one job.
- **Public Actions artifact:** untrusted storage. It contains the canonical
  request, the controller's public certificate, and CMS ciphertext only. It
  never contains the OIDC JWT or another bearer credential in plaintext.
- **Private controller:** holds a one-time decryption private key, replay ledger,
  private-repository read access, signing/notarization credentials, and release
  state. It is the sole release authority.

## Authorization protocol

1. The controller records a pending operation, generates a UUIDv4 plus a
   one-time RSA certificate/key pair of at least 3072 bits, and keeps the key
   private. The gate requires CMS AuthEnvelopedData with AES-256-GCM so public
   storage cannot read or undetectably alter the authorization envelope.
2. The workflow inputs include the operation facts, UUID, and base64 public
   certificate. GitHub's protected environment pauses before runner allocation.
3. After review, the runner creates canonical request bytes. The request binds
   the operation facts, GitHub run identity, controller UUID, and certificate
   SHA-256.
4. The runner requests a GitHub OIDC JWT whose `aud` is the request SHA-256,
   embeds it with that digest in a canonical envelope, encrypts the envelope to
   the one-time certificate, and uploads only ciphertext and public data.
5. The controller downloads the artifact, checks the request against its pending
   operation, decrypts in memory, and verifies the JWT signature against GitHub's
   OIDC JWKS. It validates every claim in the policy, exact workflow SHA, times,
   audience/digest, environment subject, and run metadata, and separately checks
   through GitHub's API that `main` still has the required ruleset, that the
   environment still names the pinned reviewer, and that the run's review
   history records that reviewer approving the exact environment.
6. In one transaction the controller consumes the JWT `jti`, controller UUID,
   and GitHub run/attempt. It then revalidates private source, build, artifact,
   tag, and (for promotion) E2E evidence before acting.

The release and promotion authorizations are deliberately different workflows,
environments, subjects, audiences, request kinds, and ledger events. A release
authorization cannot promote an artifact.

## Attacks and controls

| Threat | Control |
| --- | --- |
| Public artifact is downloaded | It contains CMS ciphertext encrypted to a one-time controller key; the OIDC JWT is never uploaded in plaintext. |
| Workflow input or shell injection | Inputs enter via quoted environment variables and are accepted only after strict SemVer, hash, UUID, base64, and integer validation. |
| Request or certificate substitution | OIDC audience binds the canonical request digest; the request binds the exact certificate digest and pending UUID. |
| Replayed approval | Controller atomically consumes `jti`, pending UUID, and run/attempt; all have short expiry. |
| Gate repository fork or alternate ref | Request generator and controller require immutable repository ID, exact repository, protected `main`, event, workflow ref, and workflow SHA. |
| Pull request reaches privileged runner | Approval workflows have only `workflow_dispatch` and a `main`-pinned group. CI uses a different repository-restricted group containing only hostile-code runners; both groups use unique labels and isolated disposable VMs. |
| Approval runner compromise | Runner is disposable and has no private source, artifacts, credentials, persistent state, or production-network route. |
| Approved request names a bad private build | The private controller re-fetches and validates the source commit, run conclusion, artifact digests/provenance, version, and tag state. Approval is not evidence. |
| Gate maintainer weakens policy | `main` rules, CODEOWNERS, CI invariants, protected environments, immutable workflow SHA validation, and private controller policy fail closed. |
| Signing controller is compromised | Out of scope for the public gate; minimize credentials, isolate the controller, retain an append-only audit log, and support key revocation. |

## Non-goals

- The public gate does not establish private build correctness.
- The public gate does not distribute artifacts or secrets.
- GitHub approval does not bypass the private controller's policy or evidence
  checks.
- This design does not make an existing long-lived self-hosted runner safe for
  pull requests; the approval runner must be dedicated and disposable.
