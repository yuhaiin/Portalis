# Portalis

Portalis is a Rust-native control plane for safe single-host nftables port forwarding on Linux VPS machines. It provides a bilingual web UI, a local Unix control socket, live kernel counters, revision history, and S3-compatible backups.

The name comes from “portal”: a controlled gateway between a listening address and a destination. Portalis deliberately manages only its own `inet portalis` table. It never edits unrelated nftables tables, SSH configuration, the global forward policy, or input/output policies.

## Safety model

- Save creates a draft. Apply validates the draft and sends one nftables Netlink batch.
- A rule with TCP and UDP becomes two kernel rules. Equal-length ranges are expanded per port so `12102-12104` maps one-to-one to the target range.
- SSH ports detected from `/etc/ssh/sshd_config` (22 by default) are rejected. The default web listener is `127.0.0.1:17890`; exposing it elsewhere requires a password for non-loopback clients.
- Portalis uses passive NAT chains with `accept` policy. Existing firewall policy remains responsible for forwarding; the UI warns about forwarding/sysctl and kernel drift.
- IPv4/IPv6 forwarding is enabled only when an active rule requires that family, and persisted in `/etc/sysctl.d/99-portalis.conf`.
- Route selection failures are warnings only. A destination being temporarily offline never prevents a valid nftables transaction from applying.

## Install

GitHub releases contain static-musl Linux binaries for amd64 and arm64, checksums, the systemd unit, and this installer. As root:

```sh
curl -fsSL https://raw.githubusercontent.com/asutorufa/portalis/main/install.sh | sh
```

Set `PORTALIS_REPO=owner/repository` when installing from another repository. The service runs as root because Netfilter configuration needs `CAP_NET_ADMIN`; its web API remains loopback-only by default.

Open the UI through an SSH tunnel:

```sh
ssh -L 17890:127.0.0.1:17890 root@your-vps
# browser: http://127.0.0.1:17890
```

The first start creates `/var/lib/portalis/web-auth.secret` with mode 0600. Loopback requests are passwordless by design. Configure a 12+ character password in Settings before changing `--listen` to a non-loopback address. The CLI uses `/run/portalis/control.sock` and is intended for root or a dedicated local `portalis` group.

## Usage

```sh
portalisd status
portalisd rules
portalisd apply
portalisctl status
portalisctl rules
```

The API lives under `/api/v1`. `PUT /draft` saves structured JSON, `POST /draft/validate` previews the generated plan, `POST /apply` performs the transaction, and `GET /rules` reads counters directly from the kernel. Counters are not copied into SQLite and reset when managed rules are replaced.

S3 settings support AWS S3, MinIO, Cloudflare R2, and custom endpoints with region and path-style options. Credentials are stored separately under `/var/lib/portalis` with mode 0600 and are never sent to the browser or included in backups. Manual backups are available in the UI and via `portalisd backup`; the scheduler runs daily at 03:00, backs up only a new active revision, and keeps the newest ten remote objects. Restore verifies SHA-256 metadata, imports a draft, and waits for explicit Apply.

## Development

The daemon uses [`nftnl-rs`](https://github.com/mullvad/nftnl-rs) for native Netlink message construction rather than invoking the `nft` CLI. Local Linux builds need `libmnl` and `libnftnl` development packages:

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cd web && npm ci && npm run build
```

Privileged nftables tests should run in a disposable Podman container or network namespace. They must never use the host's `inet portalis` table.
