#!/usr/bin/env bash
# render-helm-fixture.sh — verify that the Helm chart with default values
# renders to the same Kubernetes shape as the raw manifests under
# observability/examples/kubernetes/.
#
# Why: the raw manifests are the social contract — they're linked from the
# docs and adopters cross-reference them with the chart. If the two paths
# silently drift, every operator comparing them hits "but the docs said…".
#
# Strategy: render the chart with `mode=daemonset` + a stub token, then
# diff key fields (image, args, volumeMounts, security context) against
# the raw manifests. Pure cosmetic differences (`helm.sh/chart`,
# `app.kubernetes.io/managed-by`, the Helm-generated Secret) are filtered
# out by jq projection so the diff is meaningful.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

command -v helm >/dev/null || { echo "helm not installed" >&2; exit 1; }
command -v yq   >/dev/null || { echo "yq not installed (use 'go install github.com/mikefarah/yq/v4@latest')" >&2; exit 1; }

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# 1. Render the chart with defaults + a fake bearer token so the Secret
#    template materialises and the Helm-rendered manifest is complete.
helm template fixture charts/varta-watch \
    --namespace varta \
    --set 'prometheusToken.token=00000000000000000000000000000000000000000000000000000000deadbeef' \
    --set 'image.tag=0.1.0' \
    --set 'prometheus.serviceMonitor.release=kube-prometheus-stack' \
    > "$out/chart.rendered.yaml"

# 2. Extract the daemonset's container spec from both sides.
chart_image=$(yq 'select(.kind == "DaemonSet") | .spec.template.spec.containers[0].image' "$out/chart.rendered.yaml" \
              | head -n1)
chart_args=$(yq -o=json 'select(.kind == "DaemonSet") | .spec.template.spec.containers[0].args' "$out/chart.rendered.yaml")
chart_mounts=$(yq -o=json 'select(.kind == "DaemonSet") | .spec.template.spec.containers[0].volumeMounts' "$out/chart.rendered.yaml")

raw_image=$(yq '.spec.template.spec.containers[0].image' observability/examples/kubernetes/varta-watch.deployment.yaml)
raw_args=$(yq -o=json '.spec.template.spec.containers[0].args' observability/examples/kubernetes/varta-watch.deployment.yaml)
raw_mounts=$(yq -o=json '.spec.template.spec.containers[0].volumeMounts' observability/examples/kubernetes/varta-watch.deployment.yaml)

fail=0

check() {
    local label="$1" got="$2" want="$3"
    if [ "$got" != "$want" ]; then
        echo "MISMATCH ($label):" >&2
        diff -u <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true
        fail=1
    else
        echo "ok  $label"
    fi
}

# The raw example pins :latest; the chart renders the Chart.appVersion tag.
# Strip the tag from both sides — the chart's tag pinning is verified by
# release.yml syncing appVersion to the v* tag.
check "image (repo)" \
    "$(printf '%s\n' "$chart_image" | sed 's/:.*//')" \
    "$(printf '%s\n' "$raw_image"   | sed 's/:.*//')"

check "args"         "$chart_args"   "$raw_args"
check "volumeMounts" "$chart_mounts" "$raw_mounts"

if [ "$fail" -ne 0 ]; then
    echo
    echo "Helm chart drifted from observability/examples/kubernetes/. Either:" >&2
    echo "  - Update charts/varta-watch/ to match the raw example, or" >&2
    echo "  - Update the raw example to match the chart and bump the chart docs." >&2
    exit 1
fi

echo
echo "Helm chart and raw manifest examples are in sync."
