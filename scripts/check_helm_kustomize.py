#!/usr/bin/env python3
"""Fail if the Helm chart and the Kustomize base would deploy different things.

    kubectl kustomize deploy/k8s > kustomize.yaml
    helm template platform deploy/helm/secure-platform -n secure-platform > helm.yaml
    python scripts/check_helm_kustomize.py kustomize.yaml helm.yaml

Every resource must exist in both with the same spec. Bookkeeping that legitimately
differs is ignored: Helm's own labels and hook annotations, image pull policy, and how
the migration hook gets its configuration (a Helm hook runs before the ConfigMap and
the app's ServiceAccount exist, so it carries its own). The Namespace is created by
Kustomize only; with Helm it must exist before the install.
"""

from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from typing import Any

import yaml

Key = tuple[str, str]

KUSTOMIZE_ONLY = {("Namespace", "secure-platform")}
HELM_ONLY = {("ServiceAccount", "auth-service-migrate")}
# configMapGenerator appends a content hash so pods roll on change; the chart gets the
# same effect from a checksum/config pod annotation instead.
GENERATED = re.compile(r"^(platform-config)-[a-z0-9]{10}$")


def unhash(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: unhash(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unhash(v) for v in value]
    if isinstance(value, str) and (match := GENERATED.match(value)):
        return match.group(1)
    return value


def load(path: str) -> dict[Key, dict[str, Any]]:
    docs = [unhash(d) for d in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if d]
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def normalise(doc: dict[str, Any]) -> dict[str, Any]:
    doc = copy.deepcopy(doc)
    metadata = doc.get("metadata", {})
    metadata.pop("labels", None)
    annotations = {
        k: v for k, v in metadata.pop("annotations", {}).items() if not k.startswith("helm.sh/")
    }
    if annotations:
        metadata["annotations"] = annotations
    pod_metadata = doc.get("spec", {}).get("template", {}).get("metadata", {})
    pod_metadata.get("annotations", {}).pop("checksum/config", None)
    template = doc.get("spec", {}).get("template", {}).get("spec", {})
    for container in template.get("containers", []):
        container.pop("imagePullPolicy", None)
    if doc["kind"] == "Job":  # the migration hook brings its own config (see docstring)
        template.pop("serviceAccountName", None)
        for container in template.get("containers", []):
            container.pop("env", None)
            container.pop("envFrom", None)
    return doc


def diff(a: Any, b: Any, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            if key not in a:
                out.append(f"{path}.{key}: only in helm")
            elif key not in b:
                out.append(f"{path}.{key}: only in kustomize")
            else:
                out += diff(a[key], b[key], f"{path}.{key}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [
            d for i, (x, y) in enumerate(zip(a, b, strict=True)) for d in diff(x, y, f"{path}[{i}]")
        ]
    return [] if a == b else [f"{path}: kustomize={a!r} helm={b!r}"]


def main(kustomize_file: str, helm_file: str) -> int:
    kustomize, helm = load(kustomize_file), load(helm_file)
    problems = [
        f"{k}: only in kustomize" for k in sorted(set(kustomize) - set(helm) - KUSTOMIZE_ONLY)
    ]
    problems += [f"{k}: only in helm" for k in sorted(set(helm) - set(kustomize) - HELM_ONLY)]
    for key in sorted(set(kustomize) & set(helm)):
        problems += [
            f"{key[0]}/{key[1]}{d}" for d in diff(normalise(kustomize[key]), normalise(helm[key]))
        ]
    for problem in problems:
        print("MISMATCH", problem)
    compared = len(set(kustomize) & set(helm))
    print(f"{compared} resources compared, {len(problems)} mismatch(es)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
