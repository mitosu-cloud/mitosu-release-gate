# Mitosu release gate

This public repository is a deliberately source-free approval gate for Mitosu
production releases. It exists because GitHub Free does not support required
reviewers on environments in private repositories.

The gate never checks out private source, builds a product, signs an artifact,
holds a credential, or deploys anything. A reviewed workflow creates a
short-lived GitHub OIDC identity token whose audience is bound to the SHA-256
digest of a canonical release request. A private controller verifies that token
and independently verifies every private release fact before it may act.

## Trust flow

1. Private CI builds and tests an exact private-source commit.
2. An operator dispatches `Authorize release` with the version, source commit,
   and private build run ID.
3. GitHub pauses at the protected `agent-release-approve` environment.
4. The private controller supplies a one-time UUID and RSA public certificate.
   After review, an isolated self-hosted approval runner creates the canonical
   request, asks GitHub for an OIDC token bound to its digest, and encrypts the
   token to that one-time certificate without writing it to disk.
5. The private release controller downloads the one-day encrypted artifact,
   verifies its pending UUID and certificate digest, decrypts it, validates the
   signed OIDC claims and request, consumes its `jti` and request ID exactly
   once, and revalidates the private source/build/artifact facts.
6. The private controller signs and notarizes the release. Credentials never
   enter this repository or its runner.
7. Promotion uses a second request, workflow, and protected environment after
   clean-machine E2E evidence exists.

Approval is an authorization input, not proof that a build is safe. The private
controller remains fail-closed and authoritative.

## Required repository configuration

- Repository visibility: public.
- Actions token default: read-only.
- Environments: `agent-release-approve` and `agent-release-promote`, each with a
  required reviewer and deployment branches restricted to `main`.
- Runner group `release-approval`, restricted to this repository and the two
  approval workflows. Its disposable runner is isolated from private source,
  signing credentials, production networks, and persistent state; labels are
  `self-hosted`, `Linux`, `X64`, and `mitosu-release-gate`.
- Runner group `public-gate-ci`, accessible only to this repository. GitHub
  workflow restrictions require a pinned ref and therefore cannot represent
  arbitrary pull-request refs. This group instead contains only independently
  disposable zero-trust runners, has no credential or private/LAN/production
  access, and uses the unique `mitosu-public-gate-ci` label. The VM is destroyed
  after each job and the group is never shared with another repository.
- Branch protection or a ruleset on `main`, including pull requests, passing CI,
  and CODEOWNERS coverage for workflow/policy changes. The private controller
  separately pins accepted workflow commits.

Never add repository secrets, private source, product artifacts, deployment
credentials, signing credentials, or a pull-request-triggered job targeting the
approval runner. Never reuse either public-repository runner for a private
repository or a trusted workload.

## Local checks

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_workflows.py
```

See [the threat model](docs/threat-model.md) and
[`policy/release-gate-v1.json`](policy/release-gate-v1.json) for the claims the
private controller must enforce.
