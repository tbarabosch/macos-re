# MacRE
Scripts and tools for macOS reversing

## Projects

- [Apple Container Detection](apple_container_detect/) — detects Apple Container virtualization from inside a Linux guest by inspecting the device tree and kernel command line.

- [Tiny Linux VM with Apple VZ](vz_linux_runner/) — boots an Alpine ARM64 kernel and initramfs directly with macOS Virtualization.framework.

- [Tiny macOS EDR](mini_edr/) — uses Apple's `eslogger`, three small Python rules, JSONL evidence, and one guarded response to demonstrate an endpoint detection flow.

- App Security Passport — extracts signed macOS app metadata and produces a short, validated plain-language passport using Apple's on-device Foundation Models SDK. See app-security-passport/README.md for requirements and usage.

- MachoEntropy — compute entropy for Mach-O sections to help detect packed or encrypted sections. See machoentropy/README.md.

- Malware Toys — assorted analysis scripts for malware datasets (parse_vtreports.py, classify_macho.py, plot_entropy.py). See malware_toys/ for examples.

- x64-shellcode-loader — minimal C loader and helper scripts to experiment with x64 shellcode. See x64-shellcode-loader/.
