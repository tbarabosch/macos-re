# Tiny Linux VM with Apple VZ

This companion boots the initramfs from Alpine Linux 3.24.1 on Apple Silicon
with macOS Virtualization.framework. It uses a direct ARM64 kernel boot, a
Virtio serial console and a Virtio entropy source. A scratch Virtio block disk
and a NAT-backed Virtio network interface are optional.

The wrapper downloads Alpine's official virtual ISO on first use, verifies its
published SHA-256 checksum, extracts the raw ARM64 kernel and initramfs,
compiles the Swift runner and signs it with the required virtualization
entitlement. Downloaded and generated files stay under ignored project-local
directories.

## Requirements

- Apple Silicon Mac
- macOS with Virtualization.framework
- Xcode or the Xcode Command Line Tools
- Python 3
- `curl` access to the official Alpine mirror on the first run

## Run it

Boot the minimal, networkless VM:

```sh
./run.sh
```

Add a disposable 64 MiB raw disk, VZ NAT networking, or both:

```sh
./run.sh --disk
./run.sh --network
./run.sh --disk --network
```

The direct boot uses `console=hvc0 rdinit=/bin/sh`. At the initramfs shell,
mount the kernel filesystems before inspecting the guest:

```sh
/bin/busybox --install -s /bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
modprobe virtio-rng
cat /proc/cmdline
ls -l /dev/hvc0 /dev/hwrng
ls /sys/bus/virtio/devices
```

With `--disk`, load `virtio_blk` and look for `/dev/vda`:

```sh
modprobe virtio_blk
ls -l /dev/vda
```

With `--network`, load `virtio_net`, bring up `eth0` and request a lease. The
following commands test only the VZ NAT gateway; they do not contact a public
host:

```sh
modprobe virtio_net
ip link set eth0 up
udhcpc -i eth0 -n -q
gateway=$(ip route | awk '$1 == "default" {print $3; exit}')
ping -c 1 -W 3 "$gateway"
```

Stop the VM from the guest when finished:

```sh
poweroff -f
```

## What the code demonstrates

`VZLinuxRunner.swift` deliberately keeps the host side small:

- `VZLinuxBootLoader` maps the kernel and initramfs into the VM.
- `VZVirtualMachineConfiguration` fixes the CPUs, memory and devices before
  startup.
- `VZFileHandleSerialPortAttachment` connects the guest console to the host
  terminal.
- `VZDiskImageStorageDeviceAttachment` and `VZNATNetworkDeviceAttachment`
  back the two optional devices.
- `validate()` rejects an unsupported configuration before the VM starts.

The runner was tested on Apple Silicon with macOS 26.6.1, Xcode 26.6, Swift
6.3.3 and the macOS 26.5 SDK. The guest is Alpine Linux 3.24.1 for AArch64.
