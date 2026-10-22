#!/usr/bin/env bash
# Proves the admission policies in deploy/k8s/admission on a real cluster:
#
#   tests/admission/kind-admission-test.sh
#
# A throwaway kind cluster plus a local registry, Kyverno installed from its Helm
# chart, images signed with a test key (cosign), and the policies applied through
# tests/admission/kustomization.yaml (the shipped policies with a test key and the
# local registry). Each case is admitted or rejected exactly as expected, or the
# script fails. The cluster and the registry are deleted on exit (KEEP=1 keeps them).
#
# Needs docker, kind, kubectl, helm, cosign and python3 on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-platform-admission}"
REG_NAME="${REG_NAME:-platform-admission-registry}"
REG_PORT="${REG_PORT:-5449}" # host port of the local registry (127.0.0.1 only)
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
REGISTRY_IMAGE="registry:3.1.1"
BASE_IMAGE="registry.k8s.io/pause:3.10" # tiny, runs as non-root: passes "restricted" Pod Security
KYVERNO_CHART_VERSION="3.9.1" # Kyverno 1.19.1
NAMESPACE="secure-platform"
WORK="$(mktemp -d)"
export COSIGN_PASSWORD="" COSIGN_YES=true

log() { printf '\n== %s\n' "$*"; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "KEEP=1: leaving cluster $CLUSTER and registry $REG_NAME running"
    return
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

log "local registry and kind cluster"
docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$REG_NAME" -p "127.0.0.1:${REG_PORT}:5000" "$REGISTRY_IMAGE" >/dev/null
cat > "$WORK/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.cri.v1.images".registry]
      config_path = "/etc/containerd/certs.d"
EOF
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$WORK/kind.yaml" --wait 120s
docker network connect kind "$REG_NAME" 2>/dev/null || true
REG_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$REG_NAME")"
REGISTRY="${REG_IP}:5000" # how the cluster (nodes and Kyverno's pods) reaches the registry
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" mkdir -p "/etc/containerd/certs.d/${REGISTRY}"
  printf '[host."http://%s"]\n  capabilities = ["pull", "resolve"]\n' "$REGISTRY" |
    docker exec -i "$node" tee "/etc/containerd/certs.d/${REGISTRY}/hosts.toml" >/dev/null
done

log "Kyverno ${KYVERNO_CHART_VERSION} (admission controller only)"
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
helm install kyverno kyverno/kyverno --version "$KYVERNO_CHART_VERSION" \
  --namespace kyverno --create-namespace --wait --timeout 5m \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false >/dev/null

log "test images: one repository per case, all from $BASE_IMAGE"
docker pull -q "$BASE_IMAGE" >/dev/null
declare -A REF
for repo in signed unsigned no-sbom wrong-key; do
  docker tag "$BASE_IMAGE" "localhost:${REG_PORT}/platform/${repo}:1"
  docker push -q "localhost:${REG_PORT}/platform/${repo}:1" >/dev/null
  digest="$(docker buildx imagetools inspect "localhost:${REG_PORT}/platform/${repo}:1" --format '{{json .Manifest}}' |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')"
  REF[$repo]="platform/${repo}@${digest}"
done

log "sign with a test key; the attacker uses their own key"
(cd "$WORK" && cosign generate-key-pair --output-key-prefix ci >/dev/null && cosign generate-key-pair --output-key-prefix attacker >/dev/null)
cat > "$WORK/sbom.spdx.json" <<'EOF'
{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
 "name": "admission-test", "documentNamespace": "https://example.invalid/admission-test",
 "creationInfo": {"created": "2026-10-23T00:00:00Z", "creators": ["Tool: kind-admission-test"]},
 "packages": [{"name": "pause", "SPDXID": "SPDXRef-pause", "downloadLocation": "NOASSERTION"}]}
EOF
# cosign v3 defaults (signing config, bundle format), minus the public transparency log:
COSIGN_FLAGS=(--allow-insecure-registry --allow-http-registry --use-signing-config=false --tlog-upload=false)
quietly() { # run a command, show its output only if it fails
  local out
  if ! out="$("$@" 2>&1)"; then
    printf 'command failed: %s\n%s\n' "$*" "$out" >&2
    return 1
  fi
}
sign() { # key repo
  quietly cosign sign --key "$WORK/$1.key" "${COSIGN_FLAGS[@]}" "localhost:${REG_PORT}/${REF[$2]}"
}
attest() { # key repo
  quietly cosign attest --key "$WORK/$1.key" "${COSIGN_FLAGS[@]}" --type spdxjson \
    --predicate "$WORK/sbom.spdx.json" "localhost:${REG_PORT}/${REF[$2]}"
}
sign ci signed && attest ci signed
sign ci no-sbom
sign attacker wrong-key && attest attacker wrong-key
# Sanity: the signature really is in the registry and verifies with the CI key.
cosign verify --key "$WORK/ci.pub" --insecure-ignore-tlog --allow-insecure-registry --allow-http-registry \
  "localhost:${REG_PORT}/${REF[signed]}" >/dev/null 2>&1

log "namespace and policies (deploy/k8s/admission through tests/admission)"
kubectl apply -f "$ROOT/deploy/k8s/namespace.yaml" >/dev/null
kubectl kustomize "$ROOT/tests/admission" > "$WORK/policies.yaml"
python3 - "$WORK/policies.yaml" "$WORK/ci.pub" "$REGISTRY" <<'EOF'
import json, sys
path, key_path, registry = sys.argv[1:]
text = open(path, encoding="utf-8").read()
text = text.replace("__PUBLIC_KEY__", json.dumps(open(key_path, encoding="utf-8").read()))
text = text.replace("__REGISTRY__", registry)
open(path, "w", encoding="utf-8").write(text)
EOF
kubectl apply -f "$WORK/policies.yaml" >/dev/null

pod() { # name image [extra yaml for the container]
  cat <<EOF
apiVersion: v1
kind: Pod
metadata: { name: $1, namespace: $NAMESPACE }
spec:
  securityContext: { runAsNonRoot: true, runAsUser: 65535, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: app
      image: $2
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
EOF
}
deployment() { # name image
  cat <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: $1, namespace: $NAMESPACE }
spec:
  replicas: 1
  selector: { matchLabels: { app: $1 } }
  template:
    metadata: { labels: { app: $1 } }
    spec:
      securityContext: { runAsNonRoot: true, runAsUser: 65535, seccompProfile: { type: RuntimeDefault } }
      containers:
        - name: app
          image: $2
          securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
EOF
}

log "waiting for the policies to be enforced"
for _ in $(seq 1 60); do
  if ! pod probe "${REGISTRY}/${REF[unsigned]}" | kubectl apply --dry-run=server -f - >/dev/null 2>&1; then
    break # an unsigned image is refused: the webhook is live
  fi
  sleep 2
done

failures=0
expect() { # allow|deny description manifest-producing command...
  local want="$1" what="$2"
  shift 2
  local out
  if out="$("$@" | kubectl apply -f - 2>&1)"; then got=allow; else got=deny; fi
  if [ "$got" = "$want" ]; then
    printf 'ok    %-5s %s\n' "$want" "$what"
  else
    printf 'FAIL  wanted %s, got %s: %s\n      %s\n' "$want" "$got" "$what" "$out"
    failures=$((failures + 1))
  fi
  [ "$got" = deny ] && printf '      reason: %s\n' "$(echo "$out" | tr '\n' ' ' | cut -c1-220)"
  return 0
}

log "cases"
signed_tag="${REGISTRY}/platform/signed:1"
expect allow "signed by CI with a signed SBOM (referenced by tag)" pod signed "$signed_tag"
expect deny "unsigned image in the trusted registry" pod unsigned "${REGISTRY}/${REF[unsigned]}"
expect deny "signed by CI but without an SBOM attestation" pod no-sbom "${REGISTRY}/${REF[no-sbom]}"
expect deny "signed and attested with someone else's key" pod wrong-key "${REGISTRY}/${REF[wrong-key]}"
expect deny "image from a registry outside the trusted one" pod elsewhere "docker.io/library/busybox:1.37"
expect deny "Deployment with an unsigned image (policy autogen)" deployment unsigned-deploy "${REGISTRY}/${REF[unsigned]}"
expect allow "Deployment with the signed image" deployment signed-deploy "$signed_tag"

log "the admitted pod is pinned to the verified digest"
image="$(kubectl -n "$NAMESPACE" get pod signed -o jsonpath='{.spec.containers[0].image}')"
echo "spec image: $image"
# Kyverno keeps the tag for readability and appends the digest it verified; the
# runtime pulls by digest, so a re-pushed tag cannot swap the image afterwards.
if [ "$image" != "${signed_tag}@${REF[signed]#*@}" ]; then
  echo "FAIL  expected ${signed_tag}@${REF[signed]#*@}"
  failures=$((failures + 1))
else
  echo "ok    tag pinned to the verified digest"
fi
kubectl -n "$NAMESPACE" wait pod/signed --for=condition=Ready --timeout=120s >/dev/null &&
  echo "ok    the signed pod is Running (pulled from the local registry)"

if [ "$failures" -ne 0 ]; then
  log "$failures admission expectation(s) failed"
  exit 1
fi
log "all admission expectations hold"
