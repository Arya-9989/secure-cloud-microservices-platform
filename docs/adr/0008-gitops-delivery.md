# 0008. GitOps delivery: a Helm chart and Argo CD, consistent with the Kustomize base

- Status: accepted
- Date: 2026-10-23

## Context

`deploy/k8s` is a Kustomize base that CI validates but nobody applies continuously: deploying means someone running `kubectl apply -k` by hand, and nothing notices drift. Teams also want configurable installs (registry, digests, host, signer, tracing) without forking YAML. Adding a second packaging format risks two descriptions of the deployment that slowly disagree.

## Options considered

1. **Kustomize only, plus Argo CD.** Argo CD applies Kustomize natively, but overlays don't give operators a typed, validated set of knobs.
2. **Helm only.** It would replace the Kustomize base that the docs, CI and the admission test already use.
3. **Both, with the chart proven equal to the base.** Kustomize stays the readable reference and the source for `deploy/k8s/admission`. The chart adds values with a JSON schema, and CI renders both and compares them resource by resource.

## Decision

Option 3.

- **`deploy/helm/secure-platform`:**
  - the same Deployments, Services, PDBs, HPAs, NetworkPolicies, Traefik Middlewares and Ingresses as `deploy/k8s`;
  - `values.schema.json` rejects bad values at install time (an unknown signer, a malformed image digest, a rate limit without a period);
  - images by tag or pinned by digest (`registry/repo@sha256:…`), which is what the admission policy verifies;
  - `authService.signer=vault` switches the signing key to Vault transit (ADR 0007) and refuses to render without an address and a token Secret;
  - the auth migration is a `pre-install,pre-upgrade` hook with its own ServiceAccount and environment, since hooks run before the release's other resources exist;
  - a `checksum/config` annotation rolls the pods when the platform ConfigMap changes, as Kustomize's hashed ConfigMap name does;
  - Secrets are never templated: they're created out-of-band, as with Kustomize.
- **Parity check (`scripts/check_helm_kustomize.py`, in CI):** `helm template` with the defaults against `kubectl kustomize deploy/k8s`. Every resource must exist in both with the same spec. Only bookkeeping is ignored: Helm labels and hook annotations, `imagePullPolicy`, the ConfigMap hash suffix, and the migration hook's own configuration. A change to one side without the other fails CI, and the check was confirmed to fail on a divergent render.
- **Argo CD (`deploy/argocd`):**
  - an `AppProject` limited to this repository and the `secure-platform` namespace. Its cluster-scoped kinds are only the three admission-policy kinds, and Secrets are blacklisted, so Git can't overwrite them.
  - two Applications: `platform-admission` (sync wave −1, so the signature policies are in place before any workload) and `secure-platform` (the chart), automated with prune and self-heal. They use server-side apply, ignore `spec.replicas` (the HPA owns it), and don't create the namespace, because its Pod Security labels come from `namespace.yaml`.
- **CI:** `helm lint --strict`; `helm template | kubeconform -strict` (with CRD schemas) for the default values and a Vault-plus-tracing variant; the parity check; and kubeconform of the Argo CD manifests. Helm is the official v4.3.0 release, checked against its published SHA-256.

## Consequences

- Promotion is a pull request: bump `targetRevision` or the image digests, and Argo CD rolls it out. Manual drift is reverted.
- Two packaging formats stay in the repository, but CI keeps them provably equivalent for the defaults. Options that exist only in the chart (Vault signer, tracing, digests) are rendered and schema-validated in CI too.
- The chart hasn't been installed on a live cluster as part of this work. It's validated against the Kubernetes and CRD schemas, and the admission policies it relies on were exercised on kind (ADR 0005).
