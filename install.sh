#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "run this installer as root (for example: curl ... | sudo bash)" >&2
  exit 1
fi

repo="${PORTALIS_REPO:-yuhaiin/Portalis}"
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
curl --fail --location --retry 3 "$base/portalis.service" -o "$tmp/portalis.service"
curl --fail --location --retry 3 "$base/checksums.txt" -o "$tmp/checksums.txt"
(cd "$tmp" && {
  grep "  $artifact$" checksums.txt
  grep "  $ctl_artifact$" checksums.txt
  grep "  portalis.service$" checksums.txt
} | sha256sum --check -)
install -D -m 0755 "$tmp/portalis" /usr/local/bin/portalisd
install -D -m 0755 "$tmp/portalisctl" /usr/local/bin/portalisctl
install -D -m 0644 "$tmp/portalis.service" /etc/systemd/system/portalis.service
getent group portalis >/dev/null || groupadd --system portalis
install -d -m 0750 /etc/portalis /var/lib/portalis /run/portalis
systemctl daemon-reload
systemctl enable portalis.service
systemctl restart portalis.service
echo "Portalis installed. Open http://127.0.0.1:17890/ through an SSH tunnel."
