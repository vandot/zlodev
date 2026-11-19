#!/bin/sh
# Fill a package manifest template with a release's version and checksums.
#   packaging/render.sh VERSION SHA256SUMS TEMPLATE > OUTPUT
set -eu

version=$1
sums=$2
template=$3

sha() {
    s=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$sums")
    if [ -z "$s" ]; then
        echo "render.sh: no checksum for $1 in $sums" >&2
        exit 1
    fi
    echo "$s"
}

darwin_arm64=$(sha zlodev-darwin-arm64.tar.gz)
darwin_amd64=$(sha zlodev-darwin-amd64.tar.gz)
linux_arm64=$(sha zlodev-linux-arm64.tar.gz)
linux_amd64=$(sha zlodev-linux-amd64.tar.gz)
windows_amd64=$(sha zlodev-windows-amd64.zip)

sed \
    -e "s/@VERSION@/$version/g" \
    -e "s/@SHA_DARWIN_ARM64@/$darwin_arm64/g" \
    -e "s/@SHA_DARWIN_AMD64@/$darwin_amd64/g" \
    -e "s/@SHA_LINUX_ARM64@/$linux_arm64/g" \
    -e "s/@SHA_LINUX_AMD64@/$linux_amd64/g" \
    -e "s/@SHA_WINDOWS_AMD64@/$windows_amd64/g" \
    "$template"
