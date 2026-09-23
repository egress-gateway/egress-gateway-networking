#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../install/versions.env
source "$root/install/versions.env"
# shellcheck source=ci-tools.env
source "$root/scripts/ci-tools.env"
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] || { echo 'CI bootstrap requires Linux AMD64' >&2; exit 2; }
destination="$root/.cache/ci-tools"
mkdir -p "$destination"
download() {
  local name=$1 url=$2 digest=$3
  curl --fail --location --retry 3 --output "$destination/$name" "$url"
  printf '%s  %s\n' "$digest" "$destination/$name" | sha256sum --check --strict
}
download kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$KIND_LINUX_AMD64_SHA256"
download kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_LINUX_AMD64_SHA256"
download helm.tar.gz "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_LINUX_AMD64_SHA256"
tar -xzf "$destination/helm.tar.gz" -C "$destination" linux-amd64/helm
mv "$destination/linux-amd64/helm" "$destination/helm"
chmod +x "$destination/kind" "$destination/kubectl" "$destination/helm"
[[ -z "${GITHUB_PATH:-}" ]] || printf '%s\n' "$destination" >> "$GITHUB_PATH"
