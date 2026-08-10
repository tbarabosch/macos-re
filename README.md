# MacRE
Scripts and tools for macOS reversing

## Projects

- App Security Passport — extracts signed macOS app metadata and produces a short, validated plain-language passport using Apple's on-device Foundation Models SDK. See app-security-passport/README.md for requirements and usage.

- MachoEntropy — compute entropy for Mach-O sections to help detect packed or encrypted sections. See machoentropy/README.md.

- Malware Toys — assorted analysis scripts for malware datasets (parse_vtreports.py, classify_macho.py, plot_entropy.py). See malware_toys/ for examples.

- x64-shellcode-loader — minimal C loader and helper scripts to experiment with x64 shellcode. See x64-shellcode-loader/.

## Tool highlights

- [App Security Passport](app-security-passport/) extracts signed macOS app metadata and uses Apple's on-device Foundation Models Python SDK to explain it in plain language.
