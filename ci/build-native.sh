#!/usr/bin/env bash
set -euo pipefail

target="${1:?target is required}"
root="$(pwd)/.native/$target"
src="$(pwd)/.native/src"
mkdir -p "$root" "$src"

download() {
  local url="$1" file="$2"
  if [[ ! -f "$src/$file" ]]; then curl --fail --location --retry 3 "$url" -o "$src/$file"; fi
}

download https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2 libmnl-1.0.5.tar.bz2
download https://netfilter.org/projects/libnftnl/files/libnftnl-1.3.2.tar.xz libnftnl-1.3.2.tar.xz

cc="${TARGET_CC:-cc}"
ar="${TARGET_AR:-ar}"
host="${TARGET_HOST:?TARGET_HOST is required}"
build_one() {
  local source_dir="$1" output_name="$2" archive="$3"
  local dir="$src/$source_dir"
  if [[ ! -f "$root/lib/lib${output_name}.a" ]]; then
    if [[ ! -d "$dir" ]]; then tar -xf "$src/$archive" -C "$src"; fi
    pushd "$dir" >/dev/null
    # stdout is reserved for the LIB*=... lines consumed by GitHub Actions.
    ./configure --host="$host" --prefix="$root" --disable-shared --enable-static CC="$cc" AR="$ar" CFLAGS="-O2 -fPIC" LDFLAGS="-static" >&2
    make -j"$(nproc)" >&2
    make install >&2
    popd >/dev/null
  fi
}

build_one libmnl-1.0.5 mnl libmnl-1.0.5.tar.bz2
export PKG_CONFIG_PATH="$root/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
build_one libnftnl-1.3.2 nftnl libnftnl-1.3.2.tar.xz
echo "LIBMNL_LIB_DIR=$root/lib"
echo "LIBNFTNL_LIB_DIR=$root/lib"
