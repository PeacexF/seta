#!/bin/sh
# Installs a seta release binary after verifying its checksum.
#
#   install.sh [VERSION|latest] [DIR]
set -eu

version=${1:-latest}
dir=${2:-.}
repo=https://github.com/PeacexF/seta

if [ "$version" = latest ]; then
	# The latest-release URL redirects to .../releases/tag/<version>.
	version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
	version=${version##*/}
fi
case $version in v*) ;; *) version=v$version ;; esac

ext=tar.gz
case $(uname -s) in
Linux) os=linux ;;
Darwin) os=darwin ;;
MINGW* | MSYS* | CYGWIN*) os=windows ext=zip ;;
*) echo "install.sh: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "install.sh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

archive=seta_${version#v}_${os}_${arch}.$ext
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$archive" "$repo/releases/download/$version/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$repo/releases/download/$version/checksums.txt"

cd "$tmp"
grep "  $archive\$" checksums.txt >sum.txt || { echo "install.sh: $archive is not in checksums.txt" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
	sha256sum -c sum.txt >/dev/null
else
	shasum -a 256 -c sum.txt >/dev/null
fi
if [ "$ext" = zip ]; then unzip -q "$archive"; else tar -xzf "$archive"; fi
cd - >/dev/null

bin=seta
[ "$os" = windows ] && bin=seta.exe
mkdir -p "$dir"
mv "$tmp/$bin" "$dir/$bin"
echo "Installed seta $version to $dir" >&2
