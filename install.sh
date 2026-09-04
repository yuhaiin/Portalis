#!/usr/bin/env bash
set -euo pipefail

repo="${PORTALIS_REPO:-asutorufa/portalis}"
version="${PORTALIS_VERSION:-latest}"
arch="$(uname -m)"
case "$arch" in
  x86_64) artifact="portalis-linux-amd64" ;;
  aarch64|arm64) artifact="portalis-linux-arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [[ "$version" == "latest" ]]; then base="https://github.com/$repo/releases/latest/download"; else base="https://github.com/$repo/releases/download/$version"; fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --fail --location --retry 3 "$base/$artifact" -o "$tmp/portalis"
ctl_artifact="portalisctl-${artifact#portalis-}"
curl --fail --location --retry 3 "$base/$ctl_artifact" -o "$tmp/portalisctl"
curl --fail --location --retry 3 "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && { grep "  $artifact$" checksums.txt; grep "  $ctl_artifact$" checksums.txt; } | sha256sum --check -)
install -D -m 0755 "$tmp/portalis" /usr/local/bin/portalisd
install -D -m 0755 "$tmp/portalisctl" /usr/local/bin/portalisctl
curl --fail --location --retry 3 "https://raw.githubusercontent.com/$repo/main/packaging/portalis.service" -o /etc/systemd/system/portalis.service
getent group portalis >/dev/null || groupadd --system portalis
install -d -m 0750 /etc/portalis /var/lib/portalis /run/portalis
systemctl daemon-reload
systemctl enable --now portalis.service
echo "Portalis installed. Open http://127.0.0.1:17890/ through an SSH tunnel."
