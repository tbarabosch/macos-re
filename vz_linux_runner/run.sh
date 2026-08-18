#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARTIFACT_DIR="$SCRIPT_DIR/.artifacts"
BUILD_DIR="$SCRIPT_DIR/.build"
ALPINE_VERSION=3.24.1
ALPINE_NAME="alpine-virt-$ALPINE_VERSION-aarch64.iso"
ALPINE_BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64"
ALPINE_ISO="$ARTIFACT_DIR/$ALPINE_NAME"
ALPINE_CHECKSUM="$ARTIFACT_DIR/$ALPINE_NAME.sha256"
EXTRACT_DIR="$ARTIFACT_DIR/alpine-$ALPINE_VERSION"
RAW_KERNEL="$EXTRACT_DIR/boot/vmlinuz-virt"
KERNEL="$ARTIFACT_DIR/Image-$ALPINE_VERSION"
INITRAMFS="$EXTRACT_DIR/boot/initramfs-virt"
RUNNER_SOURCE="$SCRIPT_DIR/VZLinuxRunner.swift"
KERNEL_EXTRACTOR="$SCRIPT_DIR/extract-arm64-image.py"
ENTITLEMENTS="$SCRIPT_DIR/vz-linux-runner.entitlements"
RUNNER="$BUILD_DIR/vz-linux-runner"
DISK=
NETWORK=0

usage()
{
    echo "usage: $0 [--disk] [--network]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --disk)
            DISK="$ARTIFACT_DIR/scratch.$$.raw"
            ;;
        --network)
            NETWORK=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
    shift
done

[ "$(/usr/bin/uname -s)" = Darwin ] || {
    echo "error: Virtualization.framework requires macOS" >&2
    exit 1
}
[ "$(/usr/bin/uname -m)" = arm64 ] || {
    echo "error: this runner supports Apple Silicon only" >&2
    exit 1
}

/bin/mkdir -p "$ARTIFACT_DIR" "$BUILD_DIR"

download()
{
    destination=$1
    url=$2
    if [ ! -f "$destination" ]; then
        echo "Downloading $(basename "$destination")..." >&2
        part="$destination.part"
        /bin/rm -f -- "$part"
        /usr/bin/curl --fail --location --output "$part" "$url"
        /bin/mv -- "$part" "$destination"
    fi
}

download "$ALPINE_ISO" "$ALPINE_BASE_URL/$ALPINE_NAME"
download "$ALPINE_CHECKSUM" "$ALPINE_BASE_URL/$ALPINE_NAME.sha256"

(
    cd "$ARTIFACT_DIR"
    /usr/bin/shasum -a 256 -c "$(basename "$ALPINE_CHECKSUM")"
)

if [ ! -f "$RAW_KERNEL" ] || [ ! -f "$INITRAMFS" ]; then
    echo "Extracting the Alpine kernel and initramfs..." >&2
    /bin/rm -rf -- "$EXTRACT_DIR"
    /bin/mkdir -p "$EXTRACT_DIR"
    /usr/bin/bsdtar -xf "$ALPINE_ISO" -C "$EXTRACT_DIR" \
        boot/vmlinuz-virt boot/initramfs-virt
fi

/usr/bin/python3 "$KERNEL_EXTRACTOR" "$RAW_KERNEL" "$KERNEL.part"
/bin/mv -- "$KERNEL.part" "$KERNEL"

kernel_magic=$(
    /bin/dd if="$KERNEL" bs=1 skip=56 count=4 2>/dev/null |
        /usr/bin/od -An -tx1 |
        /usr/bin/tr -d ' \n'
)
[ "$kernel_magic" = 41524d64 ] || {
    echo "error: extracted kernel lacks the AArch64 Image magic" >&2
    exit 1
}
[ -s "$INITRAMFS" ] || {
    echo "error: extracted initramfs is empty" >&2
    exit 1
}

if [ ! -x "$RUNNER" ] || [ "$RUNNER_SOURCE" -nt "$RUNNER" ] ||
   [ "$ENTITLEMENTS" -nt "$RUNNER" ]; then
    echo "Compiling and signing the VZ runner..." >&2
    /usr/bin/xcrun swiftc \
        -parse-as-library \
        -warnings-as-errors \
        -O \
        -framework Virtualization \
        "$RUNNER_SOURCE" \
        -o "$RUNNER.part"
    /usr/bin/codesign \
        --force \
        --sign - \
        --timestamp=none \
        --entitlements "$ENTITLEMENTS" \
        "$RUNNER.part"
    /bin/mv -- "$RUNNER.part" "$RUNNER"
fi

cleanup()
{
    [ -z "$DISK" ] || /bin/rm -f -- "$DISK"
}
interrupted()
{
    exit 130
}
trap cleanup EXIT
trap interrupted HUP INT TERM

set --
if [ -n "$DISK" ]; then
    /usr/sbin/mkfile -n 64m "$DISK"
    set -- "$@" --disk "$DISK"
fi
[ "$NETWORK" -eq 0 ] || set -- "$@" --network
set -- "$@" "$KERNEL" "$INITRAMFS"

"$RUNNER" "$@"
