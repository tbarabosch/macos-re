# App Security Passport

`app_security_passport.py` reads the signed metadata of one or more macOS applications and asks Apple's on-device foundation model to summarize the resulting capabilities. The deterministic scanner remains the source of truth; the model only writes a short explanation and selects tags from categories established by the scanner.

The tool is read-only. It does not launch, modify, quarantine, or assign a risk score to an application.

## Requirements

- Apple silicon Mac with Apple Intelligence enabled
- macOS 26 or later
- Xcode 26 or later with its license accepted
- Python 3.10 or later

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install apple-fm-sdk==0.2.1
```

The Apple SDK is the tool's only direct third-party dependency. It uses the system model locally and requires no API key.

## Usage

Pass explicit application bundles, directories, or both:

```bash
python app_security_passport.py "/System/Applications/TextEdit.app"
python app_security_passport.py "/Applications/Visual Studio Code.app" "/Applications/WhatsApp.app"
python app_security_passport.py /Applications
```

A directory scan considers only its immediate `.app` children. Inputs are sorted and deduplicated before scanning.

The passport reports bundle identity, signature metadata, App Sandbox state, interpreted entitlements, Hardened Runtime exceptions, unknown entitlement keys, model-selected tags, and a short explanation. An unknown key remains unknown. If the model is unavailable or its output fails validation, the deterministic passport is still printed and the process exits nonzero.

## Boundaries

Entitlements are signed claims used by macOS security mechanisms. They do not prove that an application exercised a capability, that the user granted a protected resource, or that the application is trustworthy. See Apple's [Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements), [App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox), and [Foundation Models SDK for Python](https://apple.github.io/python-apple-fm-sdk/) documentation.
