# 0005. Image signing with cosign and admission-time verification

- Status: accepted
- Date: 2026-10-23

## Context

CI scans, tests and publishes both service images to GHCR with provenance and an SBOM, but nothing stops a cluster from running *some other* image under the same name: a tag pushed by a leaked token, a typo-squatted registry, or an image built on a laptop. The deployment must be able to prove that each image came from this repository's CI on `main`, and refuse anything else at admission time.

## Options considered

1. **Long-lived signing key in a CI secret.** It works offline, but the key can leak, needs rotating, and proves only "someone with the key".
2. **Keyless signing (Sigstore).** The job exchanges GitHub's OIDC token for a short-lived Fulcio certificate whose identity is the workflow file and ref, and the signature is recorded in the Rekor transparency log. There is no key to steal, and the identity is exactly the property we want to check.
3. **Admission controller.** sigstore policy-controller, Kyverno's legacy `ClusterPolicy.verifyImages`, or Kyverno's `ImageValidatingPolicy` (CEL, `policies.kyverno.io/v1`, GA since 1.17). The last is Kyverno's current API and supports keyless identities, attestations, digest mutation and controller autogen.
4. **Restricting registries:** inside the signature policy, or a native `ValidatingAdmissionPolicy` (Kubernetes 1.30+, no extra controller).

## Decision

- **CI (publish job, `main` only):**
  - `cosign sign` the pushed **digest**, keyless, with `id-token: write`;
  - `cosign attest` BuildKit's own SPDX SBOM for that image as an in-toto attestation;
  - verify both with `--certificate-identity https://github.com/<repo>/.github/workflows/ci.yml@refs/heads/main` and GitHub's OIDC issuer, exactly as the cluster will.

  cosign comes from the official installer (which verifies the binary), pinned to v3.1.3.
- **Cluster** (`deploy/k8s/admission`, applied by a cluster admin):
  - **`ImageValidatingPolicy` `secure-platform-signed-images`:** in namespace `secure-platform`, every image under `ghcr.io/arya-9989/secure-cloud-microservices-platform/*` must carry a signature *and* an SPDX attestation from that identity (Rekor-checked). Tags are pinned to the verified digest (`mutateDigest`). The webhook fails closed (`failurePolicy: Fail`), and Kyverno's autogen applies the same check to Deployments, Jobs and the like.
  - **`ValidatingAdmissionPolicy` `secure-platform-trusted-registry`:** pods in that namespace may only use images under that prefix, including init and ephemeral containers. Without it, an image from any other registry wouldn't be *matched* by the signature policy and would slip through unchecked.
- **Proof on a real cluster** (`tests/admission/kind-admission-test.sh`, also a CI job): kind and a local registry, Kyverno 1.19.1 from its Helm chart, and the shipped policies through a kustomize overlay that changes only the attestor (a test key instead of the keyless identity, no public Rekor) and the registry prefix. Seven cases (expected result in brackets):
  - signed with SBOM [admitted, and pinned to the digest];
  - unsigned [denied];
  - signed without SBOM [denied];
  - signed by another key [denied];
  - another registry [denied];
  - a Deployment with an unsigned image [denied];
  - a Deployment with the signed image [admitted].

## Consequences

- A cluster without Kyverno (≥ 1.17) can't apply `deploy/k8s/admission`. The app manifests don't depend on it, but production should never run without it.
- Images built outside `main` (pull requests, forks, laptops) can't run in `secure-platform`. That's intended. A staging namespace that accepts other refs would need its own identity rule.
- If the Kyverno webhook is down, pod creation in the namespace fails. That's the right default for a supply-chain control. Run it with replicas and a PodDisruptionBudget in production.
- cosign v3 writes signatures in the new bundle format. The kind test signs with the same format and default flags (minus the transparency log), so it covers what CI produces.
