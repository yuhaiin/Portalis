#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_script="$root/install.sh"
readme="$root/README.md"

grep -Fq 'repo="${PORTALIS_REPO:-yuhaiin/Portalis}"' "$install_script"
grep -Fq '"$base/portalis.service"' "$install_script"
! grep -Fq 'raw.githubusercontent.com/$repo/main/packaging/portalis.service' "$install_script"
grep -Fq 'https://raw.githubusercontent.com/yuhaiin/Portalis/main/install.sh' "$readme"
grep -Fq 'systemctl restart portalis.service' "$install_script"

echo "install regression: ok"
